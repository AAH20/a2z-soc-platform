const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const UserService = require('../services/userService');
const TenantService = require('../services/tenantService');
const EmailService = require('../services/emailService');
const { authenticateToken } = require('../middleware/auth');

// Initialize services
let userService, tenantService, emailService;

// Middleware to initialize services with database connection
router.use((req, res, next) => {
  if (!userService) {
    userService = new UserService(req.db);
    tenantService = new TenantService(req.db);
    emailService = new EmailService();
  }
  next();
});

// =============================================================================
// AUTHENTICATION ROUTES
// =============================================================================

// User Registration
router.post('/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }),
  body('firstName').notEmpty().trim(),
  body('lastName').notEmpty().trim(),
  body('company').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const result = await userService.registerUser(req.body);
    
    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Email Verification
router.post('/verify-email', [
  body('token').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const result = await userService.verifyEmail(req.body.token);
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// User Login
router.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const result = await userService.loginUser(req.body.email, req.body.password);
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Password Reset Request
router.post('/password-reset-request', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const result = await userService.requestPasswordReset(req.body.email);
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Password Reset
router.post('/password-reset', [
  body('token').notEmpty(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const result = await userService.resetPassword(req.body.token, req.body.password);
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// =============================================================================
// PROTECTED USER ROUTES
// =============================================================================

// Get User Profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await userService.getUserProfile(req.user.userId);
    
    res.json(user);
  } catch (error) {
    res.status(404).json({ error: error.message });
  }
});

// Update User Profile
router.put('/profile', authenticateToken, [
  body('firstName').optional().trim(),
  body('lastName').optional().trim(),
  body('phone').optional().trim(),
  body('timezone').optional().trim(),
  body('preferences').optional().isObject()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const user = await userService.updateUserProfile(req.user.userId, req.body);
    
    res.json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Change Password
router.post('/change-password', authenticateToken, [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const result = await userService.changePassword(
      req.user.userId,
      req.body.currentPassword,
      req.body.newPassword
    );
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// =============================================================================
// TEAM MANAGEMENT ROUTES
// =============================================================================

// Get Team Members
router.get('/team', authenticateToken, async (req, res) => {
  try {
    const members = await userService.getTeamMembers(req.user.tenantId, req.user.userId);
    
    res.json(members);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Invite Team Member
router.post('/team/invite', authenticateToken, [
  body('email').isEmail().normalizeEmail(),
  body('role').isIn(['admin', 'user', 'viewer']),
  body('firstName').notEmpty().trim(),
  body('lastName').notEmpty().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    // Check if user has permission to invite
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only administrators can invite team members' });
    }

    const result = await userService.inviteTeamMember(
      req.user.tenantId,
      req.user.userId,
      req.body
    );
    
    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Accept Invitation
router.post('/invitation/accept', [
  body('token').notEmpty(),
  body('password').isLength({ min: 8 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const result = await userService.acceptInvitation(req.body.token, req.body.password);
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Remove Team Member (Admin only)
router.delete('/team/:userId', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only administrators can remove team members' });
    }

    if (req.params.userId === req.user.userId) {
      return res.status(400).json({ error: 'Cannot remove yourself' });
    }

    await req.db.query(
      'UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3',
      ['deactivated', req.params.userId, req.user.tenantId]
    );

    res.json({ message: 'Team member removed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Team Member Role (Admin only)
router.put('/team/:userId/role', authenticateToken, [
  body('role').isIn(['admin', 'user', 'viewer'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only administrators can update roles' });
    }

    if (req.params.userId === req.user.userId) {
      return res.status(400).json({ error: 'Cannot change your own role' });
    }

    const result = await req.db.query(
      'UPDATE users SET role = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3 RETURNING *',
      [req.body.role, req.params.userId, req.user.tenantId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Team member not found' });
    }

    res.json({ 
      message: 'Role updated successfully',
      user: userService.sanitizeUser(result.rows[0])
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// ACCOUNT SETTINGS ROUTES
// =============================================================================

// Get Account Settings
router.get('/settings', authenticateToken, async (req, res) => {
  try {
    const [user, tenant, settings] = await Promise.all([
      userService.getUserProfile(req.user.userId),
      tenantService.getTenant(req.user.tenantId),
      tenantService.getTenantSettings(req.user.tenantId)
    ]);

    res.json({
      user,
      tenant,
      settings
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Account Settings
router.put('/settings', authenticateToken, [
  body('settings').isObject()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only administrators can update settings' });
    }

    const settings = await tenantService.updateTenantSettings(
      req.user.tenantId,
      req.body.settings
    );
    
    res.json({ settings });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// =============================================================================
// API KEY MANAGEMENT ROUTES
// =============================================================================

// Get API Keys
router.get('/api-keys', authenticateToken, async (req, res) => {
  try {
    const apiKeys = await tenantService.getApiKeys(req.user.tenantId);
    
    res.json(apiKeys);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create API Key
router.post('/api-keys', authenticateToken, [
  body('name').notEmpty().trim(),
  body('permissions').isArray(),
  body('expiresAt').optional().isISO8601()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only administrators can create API keys' });
    }

    const apiKey = await tenantService.createApiKey(
      req.user.tenantId,
      req.user.userId,
      req.body
    );
    
    res.status(201).json(apiKey);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Revoke API Key
router.delete('/api-keys/:keyId', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only administrators can revoke API keys' });
    }

    const result = await tenantService.revokeApiKey(req.user.tenantId, req.params.keyId);
    
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// =============================================================================
// USAGE AND ANALYTICS ROUTES
// =============================================================================

// Get Usage Analytics
router.get('/usage', authenticateToken, async (req, res) => {
  try {
    const timeRange = req.query.timeRange || '30d';
    const usage = await tenantService.getTenantUsage(req.user.tenantId, timeRange);
    
    res.json(usage);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Billing Information
router.get('/billing', authenticateToken, async (req, res) => {
  try {
    const billing = await tenantService.getTenantBilling(req.user.tenantId);
    
    res.json(billing);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Tenant Alerts
router.get('/alerts', authenticateToken, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const alerts = await tenantService.getTenantAlerts(req.user.tenantId, limit);
    
    res.json(alerts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// SECURITY ROUTES
// =============================================================================

// Get Security Events
router.get('/security/events', authenticateToken, async (req, res) => {
  try {
    // This would integrate with your security monitoring systems
    const events = []; // Placeholder
    
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Login History
router.get('/security/login-history', authenticateToken, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    
    const result = await req.db.query(
      `SELECT login_at, ip_address, user_agent, location 
       FROM user_sessions 
       WHERE user_id = $1 
       ORDER BY login_at DESC 
       LIMIT $2`,
      [req.user.userId, limit]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// NOTIFICATION ROUTES
// =============================================================================

// Get Notifications
router.get('/notifications', authenticateToken, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    
    const result = await req.db.query(
      `SELECT * FROM user_notifications 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT $2`,
      [req.user.userId, limit]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark Notification as Read
router.put('/notifications/:notificationId/read', authenticateToken, async (req, res) => {
  try {
    await req.db.query(
      'UPDATE user_notifications SET read_at = NOW() WHERE id = $1 AND user_id = $2',
      [req.params.notificationId, req.user.userId]
    );

    res.json({ message: 'Notification marked as read' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// SUPPORT ROUTES
// =============================================================================

// Submit Support Request
router.post('/support', authenticateToken, [
  body('subject').notEmpty().trim(),
  body('message').notEmpty().trim(),
  body('priority').isIn(['low', 'medium', 'high', 'urgent'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { v4: uuidv4 } = require('uuid');
    
    const result = await req.db.query(
      `INSERT INTO support_tickets (id, tenant_id, user_id, subject, message, priority, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *`,
      [
        uuidv4(),
        req.user.tenantId,
        req.user.userId,
        req.body.subject,
        req.body.message,
        req.body.priority,
        'open'
      ]
    );

    res.status(201).json({
      ticket: result.rows[0],
      message: 'Support request submitted successfully'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Support Tickets
router.get('/support', authenticateToken, async (req, res) => {
  try {
    const result = await req.db.query(
      `SELECT * FROM support_tickets 
       WHERE tenant_id = $1 
       ORDER BY created_at DESC`,
      [req.user.tenantId]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router; 