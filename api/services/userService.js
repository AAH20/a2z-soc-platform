const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

class UserService {
  constructor(db) {
    this.db = db;
  }

  // User Registration
  async registerUser(userData) {
    const { email, password, firstName, lastName, company, role = 'admin' } = userData;
    
    try {
      // Check if user already exists
      const existingUser = await this.db.query(
        'SELECT id FROM users WHERE email = $1',
        [email.toLowerCase()]
      );

      if (existingUser.rows.length > 0) {
        throw new Error('User already exists with this email');
      }

      // Hash password
      const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Generate verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      // Create tenant first
      const tenantId = uuidv4();
      const tenantResult = await this.db.query(
        `INSERT INTO tenants (id, name, domain, status, plan_id, created_at) 
         VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
        [tenantId, company || `${firstName}'s Organization`, null, 'trial', 'trial']
      );

      // Create user
      const userResult = await this.db.query(
        `INSERT INTO users (id, tenant_id, email, password_hash, first_name, last_name, 
         role, status, email_verification_token, email_verification_expires, created_at) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()) RETURNING *`,
        [
          uuidv4(), 
          tenantId, 
          email.toLowerCase(), 
          hashedPassword, 
          firstName, 
          lastName, 
          role, 
          'pending_verification',
          verificationToken,
          verificationExpiry
        ]
      );

      const user = userResult.rows[0];
      const tenant = tenantResult.rows[0];

      // Initialize tenant settings
      await this.initializeTenantSettings(tenantId);

      // Send verification email
      await this.sendVerificationEmail(user, verificationToken);

      return {
        user: this.sanitizeUser(user),
        tenant: tenant,
        message: 'Registration successful. Please check your email to verify your account.'
      };
    } catch (error) {
      throw new Error(`Registration failed: ${error.message}`);
    }
  }

  // Email Verification
  async verifyEmail(token) {
    try {
      const result = await this.db.query(
        `UPDATE users SET status = 'active', email_verified_at = NOW(), 
         email_verification_token = NULL, email_verification_expires = NULL 
         WHERE email_verification_token = $1 AND email_verification_expires > NOW()
         RETURNING *`,
        [token]
      );

      if (result.rows.length === 0) {
        throw new Error('Invalid or expired verification token');
      }

      const user = result.rows[0];

      // Activate tenant
      await this.db.query(
        'UPDATE tenants SET status = $1 WHERE id = $2',
        ['active', user.tenant_id]
      );

      return {
        user: this.sanitizeUser(user),
        message: 'Email verified successfully'
      };
    } catch (error) {
      throw new Error(`Email verification failed: ${error.message}`);
    }
  }

  // User Login
  async loginUser(email, password) {
    try {
      const result = await this.db.query(
        `SELECT u.*, t.name as tenant_name, t.status as tenant_status, t.plan_id 
         FROM users u 
         JOIN tenants t ON u.tenant_id = t.id 
         WHERE u.email = $1`,
        [email.toLowerCase()]
      );

      if (result.rows.length === 0) {
        throw new Error('Invalid email or password');
      }

      const user = result.rows[0];

      // Check password
      const isValidPassword = await bcrypt.compare(password, user.password_hash);
      if (!isValidPassword) {
        throw new Error('Invalid email or password');
      }

      // Check user status
      if (user.status === 'pending_verification') {
        throw new Error('Please verify your email before logging in');
      }

      if (user.status === 'suspended') {
        throw new Error('Your account has been suspended');
      }

      if (user.tenant_status === 'suspended') {
        throw new Error('Your organization account has been suspended');
      }

      // Update last login
      await this.db.query(
        'UPDATE users SET last_login_at = NOW() WHERE id = $1',
        [user.id]
      );

      // Generate JWT token
      const token = this.generateJWT(user);
      const refreshToken = this.generateRefreshToken();

      // Store refresh token
      await this.db.query(
        `INSERT INTO refresh_tokens (user_id, token, expires_at) 
         VALUES ($1, $2, $3)`,
        [user.id, refreshToken, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
      );

      return {
        user: this.sanitizeUser(user),
        token,
        refreshToken,
        expiresIn: '24h'
      };
    } catch (error) {
      throw new Error(`Login failed: ${error.message}`);
    }
  }

  // Password Reset Request
  async requestPasswordReset(email) {
    try {
      const user = await this.db.query(
        'SELECT * FROM users WHERE email = $1',
        [email.toLowerCase()]
      );

      if (user.rows.length === 0) {
        // Don't reveal if email exists
        return { message: 'If the email exists, a reset link has been sent' };
      }

      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      await this.db.query(
        `UPDATE users SET password_reset_token = $1, password_reset_expires = $2 
         WHERE id = $3`,
        [resetToken, resetExpiry, user.rows[0].id]
      );

      // Send reset email
      await this.sendPasswordResetEmail(user.rows[0], resetToken);

      return { message: 'If the email exists, a reset link has been sent' };
    } catch (error) {
      throw new Error(`Password reset request failed: ${error.message}`);
    }
  }

  // Password Reset
  async resetPassword(token, newPassword) {
    try {
      const user = await this.db.query(
        `SELECT * FROM users WHERE password_reset_token = $1 
         AND password_reset_expires > NOW()`,
        [token]
      );

      if (user.rows.length === 0) {
        throw new Error('Invalid or expired reset token');
      }

      const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

      await this.db.query(
        `UPDATE users SET password_hash = $1, password_reset_token = NULL, 
         password_reset_expires = NULL WHERE id = $2`,
        [hashedPassword, user.rows[0].id]
      );

      return { message: 'Password reset successful' };
    } catch (error) {
      throw new Error(`Password reset failed: ${error.message}`);
    }
  }

  // Get User Profile
  async getUserProfile(userId) {
    try {
      const result = await this.db.query(
        `SELECT u.*, t.name as tenant_name, t.plan_id, t.status as tenant_status
         FROM users u 
         JOIN tenants t ON u.tenant_id = t.id 
         WHERE u.id = $1`,
        [userId]
      );

      if (result.rows.length === 0) {
        throw new Error('User not found');
      }

      return this.sanitizeUser(result.rows[0]);
    } catch (error) {
      throw new Error(`Failed to get user profile: ${error.message}`);
    }
  }

  // Update User Profile
  async updateUserProfile(userId, updates) {
    const allowedFields = ['first_name', 'last_name', 'phone', 'timezone', 'preferences'];
    const updateFields = [];
    const values = [];
    let paramIndex = 1;

    for (const [key, value] of Object.entries(updates)) {
      if (allowedFields.includes(key)) {
        updateFields.push(`${key} = $${paramIndex}`);
        values.push(value);
        paramIndex++;
      }
    }

    if (updateFields.length === 0) {
      throw new Error('No valid fields to update');
    }

    values.push(userId);

    try {
      const result = await this.db.query(
        `UPDATE users SET ${updateFields.join(', ')}, updated_at = NOW() 
         WHERE id = $${paramIndex} RETURNING *`,
        values
      );

      return this.sanitizeUser(result.rows[0]);
    } catch (error) {
      throw new Error(`Failed to update profile: ${error.message}`);
    }
  }

  // Change Password
  async changePassword(userId, currentPassword, newPassword) {
    try {
      const user = await this.db.query(
        'SELECT password_hash FROM users WHERE id = $1',
        [userId]
      );

      if (user.rows.length === 0) {
        throw new Error('User not found');
      }

      const isValidPassword = await bcrypt.compare(currentPassword, user.rows[0].password_hash);
      if (!isValidPassword) {
        throw new Error('Current password is incorrect');
      }

      const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

      await this.db.query(
        'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
        [hashedPassword, userId]
      );

      return { message: 'Password changed successfully' };
    } catch (error) {
      throw new Error(`Password change failed: ${error.message}`);
    }
  }

  // Get Team Members
  async getTeamMembers(tenantId, userId) {
    try {
      const result = await this.db.query(
        `SELECT id, email, first_name, last_name, role, status, created_at, last_login_at
         FROM users WHERE tenant_id = $1 ORDER BY created_at DESC`,
        [tenantId]
      );

      return result.rows.map(user => this.sanitizeUser(user));
    } catch (error) {
      throw new Error(`Failed to get team members: ${error.message}`);
    }
  }

  // Invite Team Member
  async inviteTeamMember(tenantId, inviterUserId, { email, role, firstName, lastName }) {
    try {
      // Check if user already exists
      const existingUser = await this.db.query(
        'SELECT id FROM users WHERE email = $1',
        [email.toLowerCase()]
      );

      if (existingUser.rows.length > 0) {
        throw new Error('User already exists with this email');
      }

      // Generate invitation token
      const invitationToken = crypto.randomBytes(32).toString('hex');
      const invitationExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      // Create pending user
      const userResult = await this.db.query(
        `INSERT INTO users (id, tenant_id, email, first_name, last_name, role, status, 
         invitation_token, invitation_expires, invited_by, created_at) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW()) RETURNING *`,
        [
          uuidv4(),
          tenantId,
          email.toLowerCase(),
          firstName,
          lastName,
          role,
          'invited',
          invitationToken,
          invitationExpiry,
          inviterUserId
        ]
      );

      // Send invitation email
      await this.sendInvitationEmail(userResult.rows[0], invitationToken);

      return {
        user: this.sanitizeUser(userResult.rows[0]),
        message: 'Invitation sent successfully'
      };
    } catch (error) {
      throw new Error(`Failed to invite team member: ${error.message}`);
    }
  }

  // Accept Invitation
  async acceptInvitation(token, password) {
    try {
      const user = await this.db.query(
        `SELECT * FROM users WHERE invitation_token = $1 
         AND invitation_expires > NOW() AND status = 'invited'`,
        [token]
      );

      if (user.rows.length === 0) {
        throw new Error('Invalid or expired invitation token');
      }

      const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      const result = await this.db.query(
        `UPDATE users SET password_hash = $1, status = 'active', 
         invitation_token = NULL, invitation_expires = NULL, 
         email_verified_at = NOW(), updated_at = NOW()
         WHERE id = $2 RETURNING *`,
        [hashedPassword, user.rows[0].id]
      );

      return {
        user: this.sanitizeUser(result.rows[0]),
        message: 'Invitation accepted successfully'
      };
    } catch (error) {
      throw new Error(`Failed to accept invitation: ${error.message}`);
    }
  }

  // Helper Methods
  generateJWT(user) {
    const payload = {
      userId: user.id,
      tenantId: user.tenant_id,
      email: user.email,
      role: user.role,
      planId: user.plan_id
    };

    return jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRE || '24h',
      issuer: 'a2z-soc',
      audience: 'a2z-soc-users'
    });
  }

  generateRefreshToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  sanitizeUser(user) {
    const { password_hash, password_reset_token, email_verification_token, 
            invitation_token, ...sanitizedUser } = user;
    return sanitizedUser;
  }

  async initializeTenantSettings(tenantId) {
    const defaultSettings = {
      security: {
        password_policy: {
          min_length: 8,
          require_uppercase: true,
          require_lowercase: true,
          require_numbers: true,
          require_symbols: true
        },
        session_timeout: 24,
        two_factor_required: false
      },
      notifications: {
        email_alerts: true,
        slack_integration: false,
        webhook_url: null
      },
      features: {
        ai_insights: true,
        threat_intelligence: true,
        compliance_reporting: true,
        cloud_integrations: true
      }
    };

    await this.db.query(
      'INSERT INTO tenant_settings (tenant_id, settings) VALUES ($1, $2)',
      [tenantId, JSON.stringify(defaultSettings)]
    );
  }

  async sendVerificationEmail(user, token) {
    // This would integrate with your email service
    console.log(`Send verification email to ${user.email} with token: ${token}`);
    // Implementation would go here
  }

  async sendPasswordResetEmail(user, token) {
    // This would integrate with your email service
    console.log(`Send password reset email to ${user.email} with token: ${token}`);
    // Implementation would go here
  }

  async sendInvitationEmail(user, token) {
    // This would integrate with your email service
    console.log(`Send invitation email to ${user.email} with token: ${token}`);
    // Implementation would go here
  }
}

module.exports = UserService; 