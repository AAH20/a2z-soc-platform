const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

/**
 * Authentication Controller for A2Z SOC Multi-Tenant Platform
 */
class AuthController {
  /**
   * Register a new tenant and admin user
   */
  async registerTenant(req, res) {
    const client = await dbPool.connect();
    
    try {
      await client.query('BEGIN');

      const {
        // Tenant information
        tenantName,
        subdomain,
        contactEmail,
        phone,
        address,
        industry,
        companySize,
        
        // Admin user information
        firstName,
        lastName,
        password,
        
        // Subscription
        planId = 'trial'
      } = req.body;

      // Validate required fields
      if (!tenantName || !subdomain || !contactEmail || !firstName || !lastName || !password) {
        return res.status(400).json({
          error: 'Missing required fields',
          required: ['tenantName', 'subdomain', 'contactEmail', 'firstName', 'lastName', 'password']
        });
      }

      // Validate subdomain format (alphanumeric, hyphens, 3-50 chars)
      const subdomainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,48}[a-zA-Z0-9]$/;
      if (!subdomainRegex.test(subdomain)) {
        return res.status(400).json({
          error: 'Invalid subdomain format',
          message: 'Subdomain must be 3-50 characters, alphanumeric with hyphens'
        });
      }

      // Check if subdomain is already taken
      const subdomainCheck = await client.query(
        'SELECT id FROM tenants WHERE subdomain = $1',
        [subdomain.toLowerCase()]
      );

      if (subdomainCheck.rows.length > 0) {
        return res.status(409).json({
          error: 'Subdomain already exists',
          message: 'Please choose a different subdomain'
        });
      }

      // Check if email is already used
      const emailCheck = await client.query(
        'SELECT id FROM users WHERE email = $1',
        [contactEmail.toLowerCase()]
      );

      if (emailCheck.rows.length > 0) {
        return res.status(409).json({
          error: 'Email already registered',
          message: 'An account with this email already exists'
        });
      }

      // Generate tenant encryption key
      const encryptionKey = crypto.randomBytes(32).toString('hex');

      // Create tenant
      const tenantQuery = `
        INSERT INTO tenants (
          name, subdomain, contact_email, phone, address, industry, 
          company_size, plan, status, encryption_key, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
        RETURNING id, name, subdomain, plan, status, created_at
      `;

      const tenantResult = await client.query(tenantQuery, [
        tenantName,
        subdomain.toLowerCase(),
        contactEmail.toLowerCase(),
        phone,
        address,
        industry,
        companySize,
        planId,
        'trial', // Default status for new tenants
        encryptionKey
      ]);

      const tenant = tenantResult.rows[0];

      // Hash password
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Create admin user
      const userQuery = `
        INSERT INTO users (
          tenant_id, email, password_hash, first_name, last_name, 
          role, status, email_verified, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING id, email, first_name, last_name, role, status, created_at
      `;

      const userResult = await client.query(userQuery, [
        tenant.id,
        contactEmail.toLowerCase(),
        hashedPassword,
        firstName,
        lastName,
        'admin',
        'active',
        false // Email verification required
      ]);

      const user = userResult.rows[0];

      // Generate email verification token
      const emailVerificationToken = crypto.randomBytes(32).toString('hex');
      await client.query(
        'UPDATE users SET email_verification_token = $1 WHERE id = $2',
        [emailVerificationToken, user.id]
      );

      await client.query('COMMIT');

      // Generate JWT token for immediate login
      const jwtPayload = {
        userId: user.id,
        tenantId: tenant.id,
        role: user.role,
        permissions: ['admin:all'],
        emailVerified: false
      };

      const token = jwt.sign(jwtPayload, process.env.JWT_SECRET, {
        expiresIn: '7d',
        issuer: 'a2z-soc',
        audience: tenant.subdomain
      });

      res.status(201).json({
        message: 'Tenant and admin user created successfully',
        tenant: {
          id: tenant.id,
          name: tenant.name,
          subdomain: tenant.subdomain,
          plan: tenant.plan,
          status: tenant.status
        },
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role,
          emailVerified: false
        },
        token,
        emailVerificationRequired: true,
        onboardingUrl: `https://${subdomain}.a2zsoc.com/onboarding`
      });

      // TODO: Send welcome email with verification link
      // await this.sendWelcomeEmail(user, tenant, emailVerificationToken);

    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Tenant registration error:', error);
      
      res.status(500).json({
        error: 'Failed to create tenant',
        message: 'An internal error occurred during registration'
      });
    } finally {
      client.release();
    }
  }

  /**
   * Authenticate user login
   */
  async login(req, res) {
    try {
      const { email, password, subdomain } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          error: 'Missing credentials',
          message: 'Email and password are required'
        });
      }

      // Find user and tenant
      let userQuery = `
        SELECT 
          u.id, u.tenant_id, u.email, u.password_hash, u.first_name, u.last_name,
          u.role, u.permissions, u.status, u.email_verified, u.failed_login_attempts,
          u.locked_until, u.last_login,
          t.id as tenant_id, t.name as tenant_name, t.subdomain, t.plan, t.status as tenant_status
        FROM users u
        JOIN tenants t ON u.tenant_id = t.id
        WHERE u.email = $1
      `;

      let queryParams = [email.toLowerCase()];

      // If subdomain is provided, filter by it
      if (subdomain) {
        userQuery += ' AND t.subdomain = $2';
        queryParams.push(subdomain.toLowerCase());
      }

      const userResult = await dbPool.query(userQuery, queryParams);

      if (userResult.rows.length === 0) {
        return res.status(401).json({
          error: 'Invalid credentials',
          message: 'Email or password is incorrect'
        });
      }

      const user = userResult.rows[0];

      // Check if account is locked
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        return res.status(423).json({
          error: 'Account locked',
          message: 'Account is temporarily locked due to too many failed login attempts',
          unlockTime: user.locked_until
        });
      }

      // Check if tenant is active
      if (user.tenant_status !== 'active' && user.tenant_status !== 'trial') {
        return res.status(403).json({
          error: 'Account suspended',
          message: 'Your organization account has been suspended',
          tenantStatus: user.tenant_status
        });
      }

      // Check if user is active
      if (user.status !== 'active') {
        return res.status(403).json({
          error: 'User account disabled',
          message: 'Your user account has been disabled',
          userStatus: user.status
        });
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(password, user.password_hash);

      if (!isValidPassword) {
        // Increment failed login attempts
        const failedAttempts = (user.failed_login_attempts || 0) + 1;
        let lockUntil = null;

        if (failedAttempts >= 5) {
          // Lock account for 30 minutes after 5 failed attempts
          lockUntil = new Date(Date.now() + 30 * 60 * 1000);
        }

        await dbPool.query(
          'UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3',
          [failedAttempts, lockUntil, user.id]
        );

        return res.status(401).json({
          error: 'Invalid credentials',
          message: 'Email or password is incorrect',
          attemptsRemaining: Math.max(0, 5 - failedAttempts)
        });
      }

      // Reset failed login attempts on successful login
      await dbPool.query(
        'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1',
        [user.id]
      );

      // Generate JWT token
      const jwtPayload = {
        userId: user.id,
        tenantId: user.tenant_id,
        role: user.role,
        permissions: user.permissions || [],
        emailVerified: user.email_verified
      };

      const token = jwt.sign(jwtPayload, process.env.JWT_SECRET, {
        expiresIn: '7d',
        issuer: 'a2z-soc',
        audience: user.subdomain
      });

      res.json({
        message: 'Login successful',
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role,
          emailVerified: user.email_verified
        },
        tenant: {
          id: user.tenant_id,
          name: user.tenant_name,
          subdomain: user.subdomain,
          plan: user.plan
        },
        token,
        dashboardUrl: `https://${user.subdomain}.a2zsoc.com/dashboard`
      });

    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        error: 'Login failed',
        message: 'An internal error occurred during login'
      });
    }
  }

  /**
   * Verify email address
   */
  async verifyEmail(req, res) {
    try {
      const { token } = req.params;

      if (!token) {
        return res.status(400).json({
          error: 'Missing verification token'
        });
      }

      // Find user by verification token
      const userResult = await dbPool.query(
        `SELECT u.id, u.email, u.first_name, u.tenant_id, t.name as tenant_name, t.subdomain
         FROM users u
         JOIN tenants t ON u.tenant_id = t.id
         WHERE u.email_verification_token = $1 AND u.email_verified = false`,
        [token]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({
          error: 'Invalid or expired verification token'
        });
      }

      const user = userResult.rows[0];

      // Update user as verified
      await dbPool.query(
        'UPDATE users SET email_verified = true, email_verification_token = NULL, updated_at = NOW() WHERE id = $1',
        [user.id]
      );

      res.json({
        message: 'Email verified successfully',
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          emailVerified: true
        },
        tenant: {
          name: user.tenant_name,
          subdomain: user.subdomain
        },
        dashboardUrl: `https://${user.subdomain}.a2zsoc.com/dashboard`
      });

    } catch (error) {
      console.error('Email verification error:', error);
      res.status(500).json({
        error: 'Email verification failed',
        message: 'An internal error occurred during verification'
      });
    }
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(req, res) {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({
          error: 'Email is required'
        });
      }

      // Find user
      const userResult = await dbPool.query(
        'SELECT id, email, first_name FROM users WHERE email = $1 AND status = $2',
        [email.toLowerCase(), 'active']
      );

      // Always return success to prevent email enumeration
      if (userResult.rows.length === 0) {
        return res.json({
          message: 'If an account with that email exists, a password reset link has been sent'
        });
      }

      const user = userResult.rows[0];

      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      await dbPool.query(
        'UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE id = $3',
        [resetToken, resetExpires, user.id]
      );

      res.json({
        message: 'If an account with that email exists, a password reset link has been sent'
      });

      // TODO: Send password reset email
      // await this.sendPasswordResetEmail(user, resetToken);

    } catch (error) {
      console.error('Password reset request error:', error);
      res.status(500).json({
        error: 'Failed to process password reset request'
      });
    }
  }

  /**
   * Reset password with token
   */
  async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body;

      if (!token || !newPassword) {
        return res.status(400).json({
          error: 'Token and new password are required'
        });
      }

      // Validate password strength
      if (newPassword.length < 8) {
        return res.status(400).json({
          error: 'Password must be at least 8 characters long'
        });
      }

      // Find user by reset token
      const userResult = await dbPool.query(
        'SELECT id, email FROM users WHERE password_reset_token = $1 AND password_reset_expires > NOW()',
        [token]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({
          error: 'Invalid or expired reset token'
        });
      }

      const user = userResult.rows[0];

      // Hash new password
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

      // Update password and clear reset token
      await dbPool.query(
        `UPDATE users SET 
         password_hash = $1, 
         password_reset_token = NULL, 
         password_reset_expires = NULL,
         failed_login_attempts = 0,
         locked_until = NULL,
         updated_at = NOW()
         WHERE id = $2`,
        [hashedPassword, user.id]
      );

      res.json({
        message: 'Password reset successfully'
      });

    } catch (error) {
      console.error('Password reset error:', error);
      res.status(500).json({
        error: 'Failed to reset password'
      });
    }
  }

  /**
   * Refresh JWT token
   */
  async refreshToken(req, res) {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '');

      if (!token) {
        return res.status(401).json({
          error: 'No token provided'
        });
      }

      // Verify existing token (even if expired)
      let decoded;
      try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
      } catch (error) {
        if (error.name === 'TokenExpiredError') {
          // Allow refresh of expired tokens
          decoded = jwt.decode(token);
        } else {
          return res.status(401).json({
            error: 'Invalid token'
          });
        }
      }

      // Get current user and tenant info
      const userResult = await dbPool.query(
        `SELECT 
           u.id, u.role, u.permissions, u.status, u.email_verified,
           t.id as tenant_id, t.subdomain, t.status as tenant_status
         FROM users u
         JOIN tenants t ON u.tenant_id = t.id
         WHERE u.id = $1`,
        [decoded.userId]
      );

      if (userResult.rows.length === 0) {
        return res.status(401).json({
          error: 'User not found'
        });
      }

      const user = userResult.rows[0];

      // Check if user and tenant are still active
      if (user.status !== 'active' || !['active', 'trial'].includes(user.tenant_status)) {
        return res.status(403).json({
          error: 'Account is no longer active'
        });
      }

      // Generate new token
      const jwtPayload = {
        userId: user.id,
        tenantId: user.tenant_id,
        role: user.role,
        permissions: user.permissions || [],
        emailVerified: user.email_verified
      };

      const newToken = jwt.sign(jwtPayload, process.env.JWT_SECRET, {
        expiresIn: '7d',
        issuer: 'a2z-soc',
        audience: user.subdomain
      });

      res.json({
        token: newToken,
        expiresIn: '7d'
      });

    } catch (error) {
      console.error('Token refresh error:', error);
      res.status(500).json({
        error: 'Failed to refresh token'
      });
    }
  }

  /**
   * Logout user (client-side token invalidation)
   */
  async logout(req, res) {
    try {
      // In a more sophisticated implementation, you might maintain a blacklist of tokens
      // For now, we rely on client-side token removal
      
      res.json({
        message: 'Logged out successfully'
      });

    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({
        error: 'Failed to logout'
      });
    }
  }

  /**
   * Get current user profile
   */
  async getProfile(req, res) {
    try {
      const userId = req.user.userId;

      const userResult = await dbPool.query(
        `SELECT 
           u.id, u.email, u.first_name, u.last_name, u.role, u.permissions,
           u.status, u.email_verified, u.last_login, u.created_at,
           u.preferences, u.mfa_enabled,
           t.id as tenant_id, t.name as tenant_name, t.subdomain, t.plan
         FROM users u
         JOIN tenants t ON u.tenant_id = t.id
         WHERE u.id = $1`,
        [userId]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({
          error: 'User not found'
        });
      }

      const user = userResult.rows[0];

      res.json({
        user: {
          id: user.id,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role,
          permissions: user.permissions,
          status: user.status,
          emailVerified: user.email_verified,
          lastLogin: user.last_login,
          createdAt: user.created_at,
          preferences: user.preferences,
          mfaEnabled: user.mfa_enabled
        },
        tenant: {
          id: user.tenant_id,
          name: user.tenant_name,
          subdomain: user.subdomain,
          plan: user.plan
        }
      });

    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({
        error: 'Failed to get user profile'
      });
    }
  }
}

module.exports = new AuthController(); 