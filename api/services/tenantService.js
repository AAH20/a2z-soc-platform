const { v4: uuidv4 } = require('uuid');

class TenantService {
  constructor(db) {
    this.db = db;
  }

  // Get Tenant Details
  async getTenant(tenantId) {
    try {
      const result = await this.db.query(
        `SELECT t.*, ts.settings, 
         COUNT(u.id) as user_count,
         s.status as subscription_status,
         s.current_period_end,
         s.cancel_at_period_end
         FROM tenants t
         LEFT JOIN tenant_settings ts ON t.id = ts.tenant_id
         LEFT JOIN users u ON t.id = u.tenant_id AND u.status = 'active'
         LEFT JOIN subscriptions s ON t.id = s.tenant_id AND s.status = 'active'
         WHERE t.id = $1
         GROUP BY t.id, ts.settings, s.status, s.current_period_end, s.cancel_at_period_end`,
        [tenantId]
      );

      if (result.rows.length === 0) {
        throw new Error('Tenant not found');
      }

      const tenant = result.rows[0];
      tenant.settings = tenant.settings ? JSON.parse(tenant.settings) : this.getDefaultSettings();

      return tenant;
    } catch (error) {
      throw new Error(`Failed to get tenant: ${error.message}`);
    }
  }

  // Update Tenant
  async updateTenant(tenantId, updates) {
    const allowedFields = ['name', 'domain', 'logo_url', 'timezone', 'industry'];
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

    values.push(tenantId);

    try {
      const result = await this.db.query(
        `UPDATE tenants SET ${updateFields.join(', ')}, updated_at = NOW() 
         WHERE id = $${paramIndex} RETURNING *`,
        values
      );

      return result.rows[0];
    } catch (error) {
      throw new Error(`Failed to update tenant: ${error.message}`);
    }
  }

  // Get Tenant Settings
  async getTenantSettings(tenantId) {
    try {
      const result = await this.db.query(
        'SELECT settings FROM tenant_settings WHERE tenant_id = $1',
        [tenantId]
      );

      if (result.rows.length === 0) {
        return this.getDefaultSettings();
      }

      return JSON.parse(result.rows[0].settings);
    } catch (error) {
      throw new Error(`Failed to get tenant settings: ${error.message}`);
    }
  }

  // Update Tenant Settings
  async updateTenantSettings(tenantId, settings) {
    try {
      const currentSettings = await this.getTenantSettings(tenantId);
      const mergedSettings = this.mergeSettings(currentSettings, settings);

      const result = await this.db.query(
        `INSERT INTO tenant_settings (tenant_id, settings, updated_at) 
         VALUES ($1, $2, NOW()) 
         ON CONFLICT (tenant_id) 
         DO UPDATE SET settings = $2, updated_at = NOW()
         RETURNING *`,
        [tenantId, JSON.stringify(mergedSettings)]
      );

      return JSON.parse(result.rows[0].settings);
    } catch (error) {
      throw new Error(`Failed to update tenant settings: ${error.message}`);
    }
  }

  // Get Tenant Usage Analytics
  async getTenantUsage(tenantId, timeRange = '30d') {
    try {
      const endDate = new Date();
      const startDate = new Date();
      
      if (timeRange === '7d') {
        startDate.setDate(endDate.getDate() - 7);
      } else if (timeRange === '30d') {
        startDate.setDate(endDate.getDate() - 30);
      } else if (timeRange === '90d') {
        startDate.setDate(endDate.getDate() - 90);
      }

      const [apiUsage, storageUsage, userActivity] = await Promise.all([
        this.getApiUsage(tenantId, startDate, endDate),
        this.getStorageUsage(tenantId),
        this.getUserActivity(tenantId, startDate, endDate)
      ]);

      return {
        api_usage: apiUsage,
        storage_usage: storageUsage,
        user_activity: userActivity,
        period: timeRange,
        start_date: startDate.toISOString(),
        end_date: endDate.toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get tenant usage: ${error.message}`);
    }
  }

  // Get API Usage
  async getApiUsage(tenantId, startDate, endDate) {
    try {
      const result = await this.db.query(
        `SELECT 
           DATE(created_at) as date,
           COUNT(*) as request_count,
           COUNT(DISTINCT user_id) as unique_users,
           AVG(response_time) as avg_response_time
         FROM api_usage_logs 
         WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3
         GROUP BY DATE(created_at)
         ORDER BY date`,
        [tenantId, startDate, endDate]
      );

      const totalRequests = await this.db.query(
        `SELECT COUNT(*) as total FROM api_usage_logs 
         WHERE tenant_id = $1 AND created_at BETWEEN $2 AND $3`,
        [tenantId, startDate, endDate]
      );

      return {
        total_requests: parseInt(totalRequests.rows[0].total),
        daily_usage: result.rows,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return { total_requests: 0, daily_usage: [], timestamp: new Date().toISOString() };
    }
  }

  // Get Storage Usage
  async getStorageUsage(tenantId) {
    try {
      const result = await this.db.query(
        `SELECT 
           SUM(CASE WHEN table_name = 'threat_intelligence' THEN size_bytes ELSE 0 END) as threat_intel_size,
           SUM(CASE WHEN table_name = 'ai_insights' THEN size_bytes ELSE 0 END) as ai_insights_size,
           SUM(CASE WHEN table_name = 'audit_logs' THEN size_bytes ELSE 0 END) as audit_logs_size,
           SUM(size_bytes) as total_size
         FROM tenant_storage_usage 
         WHERE tenant_id = $1`,
        [tenantId]
      );

      return result.rows[0] || {
        threat_intel_size: 0,
        ai_insights_size: 0,
        audit_logs_size: 0,
        total_size: 0
      };
    } catch (error) {
      return {
        threat_intel_size: 0,
        ai_insights_size: 0,
        audit_logs_size: 0,
        total_size: 0
      };
    }
  }

  // Get User Activity
  async getUserActivity(tenantId, startDate, endDate) {
    try {
      const result = await this.db.query(
        `SELECT 
           COUNT(DISTINCT user_id) as active_users,
           COUNT(*) as total_sessions,
           AVG(EXTRACT(EPOCH FROM (logout_at - login_at))/60) as avg_session_duration
         FROM user_sessions 
         WHERE tenant_id = $1 AND login_at BETWEEN $2 AND $3`,
        [tenantId, startDate, endDate]
      );

      const dailyActivity = await this.db.query(
        `SELECT 
           DATE(login_at) as date,
           COUNT(DISTINCT user_id) as active_users,
           COUNT(*) as sessions
         FROM user_sessions 
         WHERE tenant_id = $1 AND login_at BETWEEN $2 AND $3
         GROUP BY DATE(login_at)
         ORDER BY date`,
        [tenantId, startDate, endDate]
      );

      return {
        summary: result.rows[0],
        daily_activity: dailyActivity.rows
      };
    } catch (error) {
      return {
        summary: { active_users: 0, total_sessions: 0, avg_session_duration: 0 },
        daily_activity: []
      };
    }
  }

  // Get Tenant Billing Information
  async getTenantBilling(tenantId) {
    try {
      const result = await this.db.query(
        `SELECT s.*, p.name as plan_name, p.price_monthly, p.features, p.limits,
         t.name as tenant_name
         FROM subscriptions s
         JOIN plans p ON s.plan_id = p.id
         JOIN tenants t ON s.tenant_id = t.id
         WHERE s.tenant_id = $1 AND s.status = 'active'`,
        [tenantId]
      );

      if (result.rows.length === 0) {
        return null;
      }

      const subscription = result.rows[0];
      subscription.features = JSON.parse(subscription.features || '[]');
      subscription.limits = JSON.parse(subscription.limits || '{}');

      // Get recent invoices
      const invoices = await this.db.query(
        `SELECT * FROM invoices 
         WHERE tenant_id = $1 
         ORDER BY created_at DESC 
         LIMIT 10`,
        [tenantId]
      );

      return {
        subscription,
        recent_invoices: invoices.rows
      };
    } catch (error) {
      throw new Error(`Failed to get tenant billing: ${error.message}`);
    }
  }

  // Create API Key
  async createApiKey(tenantId, userId, { name, permissions, expiresAt }) {
    try {
      const apiKey = this.generateApiKey();
      const hashedKey = await this.hashApiKey(apiKey);

      const result = await this.db.query(
        `INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, permissions, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *`,
        [
          uuidv4(),
          tenantId,
          userId,
          name,
          hashedKey,
          JSON.stringify(permissions),
          expiresAt
        ]
      );

      return {
        ...result.rows[0],
        key: apiKey // Return the plain key only once
      };
    } catch (error) {
      throw new Error(`Failed to create API key: ${error.message}`);
    }
  }

  // Get API Keys
  async getApiKeys(tenantId) {
    try {
      const result = await this.db.query(
        `SELECT ak.id, ak.name, ak.permissions, ak.expires_at, ak.last_used_at, 
         ak.created_at, u.first_name, u.last_name, u.email
         FROM api_keys ak
         JOIN users u ON ak.user_id = u.id
         WHERE ak.tenant_id = $1 AND ak.status = 'active'
         ORDER BY ak.created_at DESC`,
        [tenantId]
      );

      return result.rows.map(key => ({
        ...key,
        permissions: JSON.parse(key.permissions || '[]'),
        key_preview: '••••••••' + key.id.slice(-4)
      }));
    } catch (error) {
      throw new Error(`Failed to get API keys: ${error.message}`);
    }
  }

  // Revoke API Key
  async revokeApiKey(tenantId, keyId) {
    try {
      await this.db.query(
        `UPDATE api_keys SET status = 'revoked', updated_at = NOW() 
         WHERE id = $1 AND tenant_id = $2`,
        [keyId, tenantId]
      );

      return { message: 'API key revoked successfully' };
    } catch (error) {
      throw new Error(`Failed to revoke API key: ${error.message}`);
    }
  }

  // Get Tenant Alerts
  async getTenantAlerts(tenantId, limit = 50) {
    try {
      const result = await this.db.query(
        `SELECT * FROM tenant_alerts 
         WHERE tenant_id = $1 
         ORDER BY created_at DESC 
         LIMIT $2`,
        [tenantId, limit]
      );

      return result.rows;
    } catch (error) {
      throw new Error(`Failed to get tenant alerts: ${error.message}`);
    }
  }

  // Create Tenant Alert
  async createTenantAlert(tenantId, { type, severity, title, message, metadata }) {
    try {
      const result = await this.db.query(
        `INSERT INTO tenant_alerts (id, tenant_id, type, severity, title, message, metadata, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *`,
        [uuidv4(), tenantId, type, severity, title, message, JSON.stringify(metadata || {})]
      );

      return result.rows[0];
    } catch (error) {
      throw new Error(`Failed to create tenant alert: ${error.message}`);
    }
  }

  // Get Tenant Integrations Status
  async getTenantIntegrations(tenantId) {
    try {
      const result = await this.db.query(
        `SELECT * FROM tenant_integrations 
         WHERE tenant_id = $1 
         ORDER BY created_at DESC`,
        [tenantId]
      );

      return result.rows.map(integration => ({
        ...integration,
        config: JSON.parse(integration.config || '{}'),
        last_sync: integration.last_sync_at
      }));
    } catch (error) {
      throw new Error(`Failed to get tenant integrations: ${error.message}`);
    }
  }

  // Update Integration Status
  async updateIntegrationStatus(tenantId, integrationType, status, config = {}) {
    try {
      const result = await this.db.query(
        `INSERT INTO tenant_integrations (tenant_id, type, status, config, updated_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (tenant_id, type)
         DO UPDATE SET status = $3, config = $4, updated_at = NOW()
         RETURNING *`,
        [tenantId, integrationType, status, JSON.stringify(config)]
      );

      return result.rows[0];
    } catch (error) {
      throw new Error(`Failed to update integration status: ${error.message}`);
    }
  }

  // Helper Methods
  getDefaultSettings() {
    return {
      security: {
        password_policy: {
          min_length: 8,
          require_uppercase: true,
          require_lowercase: true,
          require_numbers: true,
          require_symbols: true
        },
        session_timeout: 24,
        two_factor_required: false,
        allowed_ip_ranges: []
      },
      notifications: {
        email_alerts: true,
        slack_integration: false,
        webhook_url: null,
        alert_frequency: 'immediate'
      },
      features: {
        ai_insights: true,
        threat_intelligence: true,
        compliance_reporting: true,
        cloud_integrations: true,
        api_access: true
      },
      branding: {
        logo_url: null,
        primary_color: '#3b82f6',
        custom_domain: null
      }
    };
  }

  mergeSettings(current, updates) {
    const merged = { ...current };
    
    for (const [key, value] of Object.entries(updates)) {
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        merged[key] = { ...merged[key], ...value };
      } else {
        merged[key] = value;
      }
    }
    
    return merged;
  }

  generateApiKey() {
    const prefix = 'ak_';
    const randomBytes = require('crypto').randomBytes(32);
    return prefix + randomBytes.toString('hex');
  }

  async hashApiKey(apiKey) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(apiKey).digest('hex');
  }

  // Validate tenant limits
  async validateTenantLimits(tenantId, action, amount = 1) {
    try {
      const billing = await this.getTenantBilling(tenantId);
      if (!billing || !billing.subscription) {
        throw new Error('No active subscription found');
      }

      const limits = billing.subscription.limits;
      const usage = await this.getTenantUsage(tenantId, '30d');

      // Check specific limits based on action
      switch (action) {
        case 'api_request':
          if (limits.api_requests && usage.api_usage.total_requests >= limits.api_requests) {
            throw new Error('API request limit exceeded');
          }
          break;
        
        case 'storage':
          if (limits.storage_gb && (usage.storage_usage.total_size / (1024 * 1024 * 1024)) >= limits.storage_gb) {
            throw new Error('Storage limit exceeded');
          }
          break;
        
        case 'users':
          const userCount = await this.db.query(
            'SELECT COUNT(*) as count FROM users WHERE tenant_id = $1 AND status = $2',
            [tenantId, 'active']
          );
          if (limits.users && userCount.rows[0].count >= limits.users) {
            throw new Error('User limit exceeded');
          }
          break;
      }

      return true;
    } catch (error) {
      throw new Error(`Limit validation failed: ${error.message}`);
    }
  }
}

module.exports = TenantService; 