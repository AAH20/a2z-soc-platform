const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('../services/databaseService');
const router = express.Router();

// Import auth middleware
const { authenticateToken } = require('../middleware/auth');

// Subscription tiers
const SUBSCRIPTION_TIERS = {
  STARTER: {
    name: 'Starter',
    price: 500,
    endpoints: 500,
    features: ['Basic Monitoring', 'Email Alerts', 'Standard Reports']
  },
  PROFESSIONAL: {
    name: 'Professional',
    price: 2500,
    endpoints: 5000,
    features: ['Advanced Monitoring', 'Real-time Alerts', 'Custom Reports', 'API Access']
  },
  ENTERPRISE: {
    name: 'Enterprise',
    price: 10000,
    endpoints: 50000,
    features: ['Full Platform', 'Custom Integration', 'Dedicated Support', 'SLA']
  }
};

// Helper function to get organization by domain
async function getOrCreateOrganization(company, email) {
  const domain = email.split('@')[1];
  
  // Check if organization exists
  const existingOrg = await db.query(
    'SELECT * FROM organizations WHERE domain = $1 OR name = $2 LIMIT 1',
    [domain, company]
  );

  if (existingOrg.rows.length > 0) {
    return existingOrg.rows[0];
  }

  // Create new organization
  const orgId = uuidv4();
  const organization = {
    id: orgId,
    name: company,
    domain: domain,
    subscription_tier: 'starter',
    subscription_status: 'trial'
  };

  await db.query(
    `INSERT INTO organizations (id, name, domain, subscription_tier, subscription_status) 
     VALUES ($1, $2, $3, $4, $5)`,
    [organization.id, organization.name, organization.domain, 
     organization.subscription_tier, organization.subscription_status]
  );

  return organization;
}

// Customer registration
router.post('/register', async (req, res) => {
  try {
    const { company, email, password, firstName, lastName } = req.body;

    // Validate required fields
    if (!company || !email || !password || !firstName || !lastName) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['company', 'email', 'password', 'firstName', 'lastName']
      });
    }

    // Strong password validation
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        error: 'Password does not meet security requirements',
        requirements: [
          'At least 8 characters long',
          'Contains at least one uppercase letter',
          'Contains at least one lowercase letter', 
          'Contains at least one number',
          'Contains at least one special character (@$!%*?&)'
        ]
      });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        error: 'Invalid email format'
      });
    }

    // Check if user already exists
    const existingUser = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'User already exists with this email' });
    }

    // Hash password
    const hashedPassword = await bcryptjs.hash(password, 10);

    // Get or create organization
    const organization = await getOrCreateOrganization(company, email);

    // Create user
    const userId = uuidv4();
    
    await db.query(
      `INSERT INTO users (id, organization_id, email, password_hash, first_name, last_name, 
       role, email_verified, is_active) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        userId,
        organization.id,
        email,
        hashedPassword,
        firstName,
        lastName,
        'admin',
        true, // email_verified = true (skip verification)
        true  // is_active = true
      ]
    );

    // Get the created user
    const userResult = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    const user = userResult.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id,
        email: user.email,
        organizationId: organization.id,
        company: organization.name,
        role: 'admin'
      },
      process.env.JWT_SECRET || 'a2z-soc-jwt-secret-2025-secure',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        company: organization.name,
        role: user.role,
        emailVerified: true // Always true now
      },
      organization: {
        id: organization.id,
        name: organization.name,
        subscriptionTier: organization.subscription_tier,
        subscriptionStatus: organization.subscription_status
      },
      subscription: {
        tier: organization.subscription_tier.toUpperCase(),
        status: organization.subscription_status,
        endpointsLimit: SUBSCRIPTION_TIERS[organization.subscription_tier.toUpperCase()]?.endpoints || 500,
        features: SUBSCRIPTION_TIERS[organization.subscription_tier.toUpperCase()]?.features || []
      },
      token,
      onboardingSteps: [
        { step: 1, title: 'Download Agent', status: 'pending' },
        { step: 2, title: 'Configure Network', status: 'pending' },
        { step: 3, title: 'Setup Alerts', status: 'pending' },
        { step: 4, title: 'Complete Setup', status: 'pending' }
      ],
      emailVerificationRequired: false // No email verification needed
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Customer login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user with organization
    const userResult = await db.query(
      `SELECT u.*, o.name as organization_name, o.subscription_tier, o.subscription_status 
       FROM users u 
       JOIN organizations o ON u.organization_id = o.id 
       WHERE u.email = $1`,
      [email]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = userResult.rows[0];

    // Verify password
    const validPassword = await bcryptjs.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    await db.query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [user.id]
    );

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id,
        email: user.email,
        organizationId: user.organization_id,
        company: user.organization_name,
        role: user.role
      },
      process.env.JWT_SECRET || 'a2z-soc-jwt-secret-2025-secure',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        company: user.organization_name,
        role: user.role,
        status: user.status,
        trialEndsAt: user.trial_ends_at,
        apiKey: user.api_key
      },
      organization: {
        id: user.organization_id,
        name: user.organization_name,
        subscriptionTier: user.subscription_tier,
        subscriptionStatus: user.subscription_status
      },
      subscription: {
        tier: user.subscription_tier.toUpperCase(),
        status: user.subscription_status,
        endpointsLimit: SUBSCRIPTION_TIERS[user.subscription_tier.toUpperCase()]?.endpoints || 500,
        features: SUBSCRIPTION_TIERS[user.subscription_tier.toUpperCase()]?.features || []
      },
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Get subscription tiers
router.get('/tiers', (req, res) => {
  res.json({
    tiers: Object.entries(SUBSCRIPTION_TIERS).map(([key, tier]) => ({
      id: key,
      name: tier.name,
      price: tier.price,
      endpoints: tier.endpoints,
      features: tier.features,
      recommended: key === 'PROFESSIONAL'
    }))
  });
});

// Upgrade subscription
router.post('/upgrade', authenticateToken, async (req, res) => {
  try {
    const { tier } = req.body;
    const { organizationId } = req.user;

    if (!SUBSCRIPTION_TIERS[tier]) {
      return res.status(400).json({ error: 'Invalid subscription tier' });
    }

    // Update organization subscription
    await db.query(
      'UPDATE organizations SET subscription_tier = $1, subscription_status = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3',
      [tier.toLowerCase(), 'active', organizationId]
    );

    // Log the upgrade
    await db.createAuditLog({
      organization_id: organizationId,
      user_id: req.user.id,
      action: 'subscription_upgrade',
      resource_type: 'organization',
      resource_id: organizationId,
      details: { old_tier: 'trial', new_tier: tier },
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });

    res.json({
      message: 'Subscription upgraded successfully',
      subscription: {
        tier,
        status: 'active',
        endpointsLimit: SUBSCRIPTION_TIERS[tier].endpoints,
        features: SUBSCRIPTION_TIERS[tier].features
      }
    });

  } catch (error) {
    console.error('Upgrade error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get customer profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;

    const userResult = await db.query(
      `SELECT u.*, o.name as organization_name, o.subscription_tier, o.subscription_status 
       FROM users u 
       JOIN organizations o ON u.organization_id = o.id 
       WHERE u.id = $1`,
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    res.json({
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        company: user.organization_name,
        role: user.role,
        createdAt: user.created_at,
        lastLoginAt: user.last_login
      },
      organization: {
        id: user.organization_id,
        name: user.organization_name,
        subscriptionTier: user.subscription_tier,
        subscriptionStatus: user.subscription_status
      },
      subscription: {
        tier: user.subscription_tier.toUpperCase(),
        status: user.subscription_status,
        endpointsLimit: SUBSCRIPTION_TIERS[user.subscription_tier.toUpperCase()]?.endpoints || 500,
        features: SUBSCRIPTION_TIERS[user.subscription_tier.toUpperCase()]?.features || []
      }
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update onboarding progress
router.post('/onboarding/progress', authenticateToken, async (req, res) => {
  try {
    const { step, status } = req.body;
    const { userId, organizationId } = req.user;

    // Store onboarding progress in system config
    const configKey = `onboarding_step_${step}`;
    
    await db.query(
      `INSERT INTO system_config (organization_id, config_key, config_value, updated_by) 
       VALUES ($1, $2, $3, $4) 
       ON CONFLICT (organization_id, config_key) 
       DO UPDATE SET config_value = $3, updated_by = $4, updated_at = CURRENT_TIMESTAMP`,
      [organizationId, configKey, JSON.stringify({ status, completedAt: new Date().toISOString() }), userId]
    );

    res.json({
      message: 'Onboarding progress updated',
      step,
      status
    });

  } catch (error) {
    console.error('Onboarding progress error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get onboarding status
router.get('/onboarding/status', authenticateToken, async (req, res) => {
  try {
    const { organizationId } = req.user;

    // Get onboarding progress from system config
    const configResult = await db.query(
      `SELECT config_key, config_value FROM system_config 
       WHERE organization_id = $1 AND config_key LIKE 'onboarding_step_%'`,
      [organizationId]
    );

    const progress = {};
    configResult.rows.forEach(row => {
      const step = row.config_key.replace('onboarding_step_', '');
      progress[step] = JSON.parse(row.config_value);
    });

    const steps = [
      { step: 1, title: 'Download Agent', status: progress['1']?.status || 'pending' },
      { step: 2, title: 'Configure Network', status: progress['2']?.status || 'pending' },
      { step: 3, title: 'Setup Alerts', status: progress['3']?.status || 'pending' },
      { step: 4, title: 'Complete Setup', status: progress['4']?.status || 'pending' }
    ];

    res.json({
      steps,
      progress: {
        completed: steps.filter(s => s.status === 'completed').length,
        total: steps.length
      }
    });

  } catch (error) {
    console.error('Onboarding status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user information (for SaaS tenant isolation testing)
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // Get user with organization details
    const userResult = await db.query(
      `SELECT u.*, o.name as organization_name, o.subscription_tier, o.subscription_status 
       FROM users u 
       JOIN organizations o ON u.organization_id = o.id 
       WHERE u.id = $1`,
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role,
        organizationId: user.organization_id,
        company: user.organization_name,
        subscription: {
          tier: user.subscription_tier,
          status: user.subscription_status
        },
        lastLogin: user.last_login,
        emailVerified: user.email_verified,
        isActive: user.is_active
      }
    });
  } catch (error) {
    console.error('Get user info error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error',
      details: error.message 
    });
  }
});

module.exports = router; 