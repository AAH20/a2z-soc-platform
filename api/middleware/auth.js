const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// JWT secret - consistent across all auth operations
const JWT_SECRET = process.env.JWT_SECRET || 'a2z-soc-jwt-secret-2025-secure';

// In production, store these in a database
const apiKeys = new Map();

/**
 * Generate a new API key
 * @param {Object} options - Configuration options
 * @param {string} options.name - Name of the API key
 * @param {Array<string>} options.permissions - Permissions for the API key
 * @param {string} options.expiresIn - Expiration time (e.g., '365d')
 * @returns {Object} The generated API key data
 */
const generateApiKey = async (options) => {
  const key = options.key || crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date();
  
  // Default to 1 year expiration
  if (options.expiresIn) {
    const timeValue = parseInt(options.expiresIn.slice(0, -1));
    const timeUnit = options.expiresIn.slice(-1);
    
    if (timeUnit === 'd') {
      expiresAt.setDate(expiresAt.getDate() + timeValue);
    } else if (timeUnit === 'h') {
      expiresAt.setHours(expiresAt.getHours() + timeValue);
    } else if (timeUnit === 'm') {
      expiresAt.setMinutes(expiresAt.getMinutes() + timeValue);
    } else {
      expiresAt.setDate(expiresAt.getDate() + 365); // Default to 1 year
    }
  } else {
    expiresAt.setDate(expiresAt.getDate() + 365);
  }
  
  const keyData = {
    key,
    permissions: options.permissions || ['read'],
    expiresAt,
    name: options.name || 'API Key',
    createdAt: new Date(),
    tier: options.tier || 'basic'
  };
  
  // In production, save to database
  apiKeys.set(key, keyData);
  
  return keyData;
};

/**
 * Validate an API key
 * @param {string} apiKey - The API key to validate
 * @returns {Object} The API key data if valid
 * @throws {Error} If the API key is invalid or expired
 */
const validateApiKey = async (apiKey) => {
  // In production, fetch from database
  const keyData = apiKeys.get(apiKey);
  
  if (!keyData) {
    throw new Error('Invalid API key');
  }
  
  if (new Date() > keyData.expiresAt) {
    throw new Error('API key expired');
  }
  
  return keyData;
};

/**
 * Middleware to require an API key with specific permissions
 * @param {Array<string>} requiredPermissions - Required permissions
 * @returns {Function} Express middleware
 */
const requireApiKey = (requiredPermissions = ['read']) => {
  return async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({ error: 'API key required' });
    }
    
    try {
      const keyData = await validateApiKey(apiKey);
      
      // Check if the key has all required permissions
      const hasPermission = requiredPermissions.every(p => 
        keyData.permissions.includes(p) || keyData.permissions.includes('admin')
      );
      
      if (!hasPermission) {
        return res.status(403).json({ 
          error: 'Insufficient permissions',
          required: requiredPermissions,
          provided: keyData.permissions
        });
      }
      
      // Add API key info to request for downstream use
      req.apiKey = keyData;
      next();
    } catch (error) {
      res.status(401).json({ error: error.message });
    }
  };
};

/**
 * Middleware to validate RapidAPI headers
 */
const validateRapidApiHeaders = (req, res, next) => {
  // Check for RapidAPI proxy headers
  const rapidApiProxy = req.headers['x-rapidapi-proxy'];
  const rapidApiKey = req.headers['x-rapidapi-key'];
  
  if (!rapidApiProxy && !rapidApiKey) {
    // Direct API call, not through RapidAPI
    return next();
  }
  
  // For RapidAPI calls, extract the subscriber info
  req.rapidApiSubscriber = {
    key: rapidApiKey,
    proxy: rapidApiProxy,
    user: req.headers['x-rapidapi-user']
  };
  
  // In production, you might want to validate these against RapidAPI's validation endpoint
  
  next();
};

/**
 * JWT authentication middleware for protected routes - SECURE VERSION
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: 'Access token required',
      message: 'Please provide a valid access token',
      code: 'NO_TOKEN'
    });
  }

  try {
    // Use synchronous verification for better error handling
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'], // Specify algorithm to prevent algorithm confusion attacks
      clockTolerance: 30,    // Allow 30 seconds clock skew
      maxAge: '24h'          // Maximum token age
    });

    // Validate required fields in token
    if (!decoded.id || !decoded.organizationId) {
      return res.status(403).json({
        error: 'Invalid token structure',
        message: 'Token missing required fields',
        code: 'INVALID_TOKEN_STRUCTURE'
      });
    }

    // Add decoded user info to request
    req.user = {
      id: decoded.id,
      email: decoded.email,
      organizationId: decoded.organizationId,
      role: decoded.role || 'user',
      permissions: decoded.permissions || [],
      iat: decoded.iat,
      exp: decoded.exp
    };
    
    next();
  } catch (err) {
    console.error('JWT verification error:', {
      error: err.message,
      token: token.substring(0, 20) + '...',
      timestamp: new Date().toISOString()
    });
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired',
        message: 'Access token has expired. Please refresh your token.',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    if (err.name === 'JsonWebTokenError') {
      return res.status(403).json({
        error: 'Invalid token',
        message: 'The provided access token is malformed or invalid',
        code: 'INVALID_TOKEN'
      });
    }
    
    if (err.name === 'NotBeforeError') {
      return res.status(403).json({
        error: 'Token not active',
        message: 'Token not active yet',
        code: 'TOKEN_NOT_ACTIVE'
      });
    }
    
    // Generic error for any other JWT errors
    return res.status(403).json({
      error: 'Token validation failed',
      message: 'Unable to validate the provided token',
      code: 'TOKEN_VALIDATION_FAILED'
    });
  }
};

// Create a test API key for development using our custom key from .env file
if (process.env.NODE_ENV !== 'production') {
  // Use our specified VirusTotal API key if available
  const customApiKey = process.env.VIRUSTOTAL_API_KEY || crypto.randomBytes(32).toString('hex');
  
  generateApiKey({
    key: customApiKey,
    name: 'User API Key',
    permissions: ['read', 'write', 'admin'],
    expiresIn: '365d',
    tier: 'enterprise'
  }).then(keyData => {
    console.log('Using API key for development:', keyData.key);
  });
}

module.exports = {
  generateApiKey,
  validateApiKey,
  requireApiKey,
  validateRapidApiHeaders,
  authenticateToken,
  JWT_SECRET
}; 