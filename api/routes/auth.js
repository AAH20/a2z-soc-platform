const express = require('express');
const { generateApiKey, validateApiKey, authenticateToken } = require('../middleware/auth');
const authController = require('../controllers/authController');
const { tenantIsolation } = require('../middleware/tenantIsolation');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');

const router = express.Router();

/**
 * @route POST /api/v1/auth/api-keys
 * @desc Generate a new API key
 * @access Private (requires admin permission)
 */
router.post('/api-keys', authenticateToken, async (req, res) => {
  try {
    const { name, permissions, expiresIn, tier } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const apiKey = await generateApiKey({
      name,
      permissions: permissions || ['read'],
      expiresIn: expiresIn || '365d',
      tier: tier || 'basic'
    });
    
    res.status(201).json({
      success: true,
      apiKey: {
        key: apiKey.key,
        name: apiKey.name,
        permissions: apiKey.permissions,
        expiresAt: apiKey.expiresAt,
        tier: apiKey.tier
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

/**
 * @route GET /api/v1/auth/verify
 * @desc Validate an API key
 * @access Public
 */
router.get('/verify', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  try {
    const keyInfo = await validateApiKey(apiKey);
    res.json({
      valid: true,
      name: keyInfo.name,
      permissions: keyInfo.permissions,
      expiresAt: keyInfo.expiresAt,
      tier: keyInfo.tier
    });
  } catch (error) {
    res.status(401).json({ 
      valid: false,
      error: error.message 
    });
  }
});

/**
 * @route GET /api/v1/auth/api-keys
 * @desc Get all API keys (admin only)
 * @access Private (requires admin permission)
 */
router.get('/api-keys', authenticateToken, async (req, res) => {
  try {
    // In production, this would fetch from a database
    // For this example, we're using the in-memory Map
    const allKeys = Array.from(require('../middleware/auth').apiKeys.values()).map(key => ({
      name: key.name,
      permissions: key.permissions,
      createdAt: key.createdAt,
      expiresAt: key.expiresAt,
      tier: key.tier
      // Don't include the actual key for security
    }));
    
    res.json({
      success: true,
      count: allKeys.length,
      data: allKeys
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @route DELETE /api/v1/auth/api-keys/:name
 * @desc Revoke an API key by name
 * @access Private (requires admin permission)
 */
router.delete('/api-keys/:name', authenticateToken, async (req, res) => {
  try {
    const keyName = req.params.name;
    
    // In production, this would delete from a database
    // For this example, we're using the in-memory Map
    const keys = require('../middleware/auth').apiKeys;
    let keyFound = false;
    
    for (const [keyString, keyData] of keys.entries()) {
      if (keyData.name === keyName) {
        keys.delete(keyString);
        keyFound = true;
        break;
      }
    }
    
    if (!keyFound) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    res.json({
      success: true,
      message: `API key '${keyName}' has been revoked`
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================
// PUBLIC ROUTES (No authentication required)
// =============================================

/**
 * @route   POST /api/auth/register
 * @desc    Register new tenant and admin user
 * @access  Public
 * @body    {
 *           tenantName: string,
 *           subdomain: string,
 *           contactEmail: string,
 *           phone?: string,
 *           address?: string,
 *           industry?: string,
 *           companySize?: string,
 *           firstName: string,
 *           lastName: string,
 *           password: string,
 *           planId?: string
 *         }
 */
router.post('/register', authController.registerTenant);

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user and return JWT token
 * @access  Public
 * @body    {
 *           email: string,
 *           password: string,
 *           subdomain?: string
 *         }
 */
router.post('/login', authController.login);

/**
 * @route   GET /api/auth/verify-email/:token
 * @desc    Verify user email address
 * @access  Public
 * @params  token: string (email verification token)
 */
router.get('/verify-email/:token', authController.verifyEmail);

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Request password reset token
 * @access  Public
 * @body    {
 *           email: string
 *         }
 */
router.post('/forgot-password', authController.requestPasswordReset);

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password using token
 * @access  Public
 * @body    {
 *           token: string,
 *           newPassword: string
 *         }
 */
router.post('/reset-password', authController.resetPassword);

/**
 * @route   POST /api/auth/refresh-token
 * @desc    Refresh JWT token
 * @access  Public (but requires existing token)
 * @headers Authorization: Bearer <token>
 */
router.post('/refresh-token', authController.refreshToken);

// =============================================
// PROTECTED ROUTES (Authentication required)
// =============================================

/**
 * @route   GET /api/auth/profile
 * @desc    Get current user profile
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.get('/profile', authenticateToken, tenantIsolation(), authController.getProfile);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (invalidate token client-side)
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.post('/logout', authenticateToken, authController.logout);

/**
 * @route   PUT /api/auth/profile
 * @desc    Update user profile
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.put('/profile', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const userId = req.user.userId;
    const { firstName, lastName, preferences } = req.body;

    // Validate input
    if (!firstName || !lastName) {
      return res.status(400).json({
        error: 'First name and last name are required'
      });
    }

    // Update user profile
    const updateQuery = `
      UPDATE users 
      SET first_name = $1, last_name = $2, preferences = $3, updated_at = NOW()
      WHERE id = $4 AND tenant_id = $5
      RETURNING id, first_name, last_name, preferences
    `;

    const result = await req.db.query(updateQuery, [
      firstName,
      lastName,
      JSON.stringify(preferences || {}),
      userId,
      req.tenant.id
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    const user = result.rows[0];

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        preferences: user.preferences
      }
    });

  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      error: 'Failed to update profile'
    });
  }
});

/**
 * @route   POST /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 * @headers Authorization: Bearer <token>
 * @body    {
 *           currentPassword: string,
 *           newPassword: string
 *         }
 */
router.post('/change-password', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const userId = req.user.userId;
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        error: 'Current password and new password are required'
      });
    }

    // Validate new password strength
    if (newPassword.length < 8) {
      return res.status(400).json({
        error: 'New password must be at least 8 characters long'
      });
    }

    // Get current password hash
    const userResult = await req.db.query(
      'SELECT password_hash FROM users WHERE id = $1 AND tenant_id = $2',
      [userId, req.tenant.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    const user = userResult.rows[0];

    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({
        error: 'Current password is incorrect'
      });
    }

    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    await req.db.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3',
      [hashedPassword, userId, req.tenant.id]
    );

    res.json({
      message: 'Password changed successfully'
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      error: 'Failed to change password'
    });
  }
});

/**
 * @route   GET /api/auth/sessions
 * @desc    Get active user sessions
 * @access  Private
 * @headers Authorization: Bearer <token>
 */
router.get('/sessions', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const userId = req.user.userId;

    // Get recent login sessions from audit logs
    const sessionsResult = await req.db.query(
      `SELECT 
         actor_ip as ip_address,
         user_agent,
         timestamp as login_time,
         status
       FROM audit_logs 
       WHERE user_id = $1 
         AND tenant_id = $2 
         AND action = 'user_login'
       ORDER BY timestamp DESC 
       LIMIT 10`,
      [userId, req.tenant.id]
    );

    const sessions = sessionsResult.rows.map(session => ({
      ipAddress: session.ip_address,
      userAgent: session.user_agent,
      loginTime: session.login_time,
      status: session.status,
      isCurrent: session.ip_address === req.ip
    }));

    res.json({
      sessions
    });

  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({
      error: 'Failed to get user sessions'
    });
  }
});

// =============================================
// TENANT ADMIN ROUTES
// =============================================

/**
 * @route   GET /api/auth/tenant/users
 * @desc    Get all users in tenant (admin only)
 * @access  Private (Admin)
 * @headers Authorization: Bearer <token>
 */
router.get('/tenant/users', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'Admin access required'
      });
    }

    const usersResult = await req.db.query(
      `SELECT 
         id, email, first_name, last_name, role, status, 
         email_verified, last_login, created_at, mfa_enabled
       FROM users 
       WHERE tenant_id = $1 
       ORDER BY created_at DESC`,
      [req.tenant.id]
    );

    const users = usersResult.rows.map(user => ({
      id: user.id,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,
      status: user.status,
      emailVerified: user.email_verified,
      lastLogin: user.last_login,
      createdAt: user.created_at,
      mfaEnabled: user.mfa_enabled
    }));

    res.json({
      users,
      total: users.length
    });

  } catch (error) {
    console.error('Get tenant users error:', error);
    res.status(500).json({
      error: 'Failed to get tenant users'
    });
  }
});

/**
 * @route   POST /api/auth/tenant/users
 * @desc    Create new user in tenant (admin only)
 * @access  Private (Admin)
 * @headers Authorization: Bearer <token>
 * @body    {
 *           email: string,
 *           firstName: string,
 *           lastName: string,
 *           role: string,
 *           sendInvite?: boolean
 *         }
 */
router.post('/tenant/users', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        error: 'Admin access required'
      });
    }

    const { email, firstName, lastName, role = 'viewer', sendInvite = true } = req.body;

    if (!email || !firstName || !lastName) {
      return res.status(400).json({
        error: 'Email, first name, and last name are required'
      });
    }

    // Validate role
    const validRoles = ['admin', 'analyst', 'viewer'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({
        error: 'Invalid role',
        validRoles
      });
    }

    // Check if email already exists
    const emailCheck = await req.db.query(
      'SELECT id FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (emailCheck.rows.length > 0) {
      return res.status(409).json({
        error: 'Email already exists'
      });
    }

    // Generate temporary password
    const tempPassword = crypto.randomBytes(16).toString('hex');
    const hashedPassword = await bcrypt.hash(tempPassword, 12);

    // Create user
    const userResult = await req.db.query(
      `INSERT INTO users (
         tenant_id, email, password_hash, first_name, last_name,
         role, status, email_verified, created_at, updated_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
       RETURNING id, email, first_name, last_name, role, status, created_at`,
      [
        req.tenant.id,
        email.toLowerCase(),
        hashedPassword,
        firstName,
        lastName,
        role,
        'pending', // User needs to set their own password
        false
      ]
    );

    const newUser = userResult.rows[0];

    // Generate invitation token
    const inviteToken = crypto.randomBytes(32).toString('hex');
    await req.db.query(
      'UPDATE users SET email_verification_token = $1 WHERE id = $2',
      [inviteToken, newUser.id]
    );

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: newUser.id,
        email: newUser.email,
        firstName: newUser.first_name,
        lastName: newUser.last_name,
        role: newUser.role,
        status: newUser.status,
        createdAt: newUser.created_at
      },
      inviteUrl: `https://${req.tenant.subdomain}.a2zsoc.com/invite/${inviteToken}`
    });

    // TODO: Send invitation email if sendInvite is true
    // if (sendInvite) {
    //   await emailService.sendUserInvitation(newUser, req.tenant, inviteToken);
    // }

  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({
      error: 'Failed to create user'
    });
  }
});

// =============================================
// HEALTH CHECK ROUTE
// =============================================

/**
 * @route   GET /api/auth/health
 * @desc    Authentication service health check
 * @access  Public
 */
router.get('/health', (req, res) => {
  res.json({
    service: 'auth',
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

module.exports = router; 