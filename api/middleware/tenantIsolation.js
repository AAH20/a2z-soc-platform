const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// Database connection pool with tenant isolation
const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

/**
 * Middleware to ensure tenant isolation across all API requests
 * This middleware must be applied after authentication to access user.organizationId
 */
const tenantIsolation = () => {
  return async (req, res, next) => {
    try {
      // Skip tenant isolation for health checks and public endpoints
      if (req.path === '/health' || req.path.startsWith('/public/')) {
        return next();
      }

      // Ensure user is authenticated and has organizationId (our tenant identifier)
      if (!req.user || !req.user.organizationId) {
        return res.status(401).json({
          error: 'Authentication required',
          code: 'TENANT_ISOLATION_FAILED',
          details: 'Organization ID missing from token'
        });
      }

      const organizationId = req.user.organizationId;

      // Validate organization exists and is active (using our actual database schema)
      const orgQuery = 'SELECT id, subscription_status, subscription_tier FROM organizations WHERE id = $1';
      const orgResult = await dbPool.query(orgQuery, [organizationId]);
      
      if (orgResult.rows.length === 0) {
        return res.status(403).json({
          error: 'Organization not found',
          code: 'INVALID_TENANT'
        });
      }

      const organization = orgResult.rows[0];
      
      if (organization.subscription_status === 'suspended') {
        return res.status(403).json({
          error: 'Organization account suspended',
          code: 'TENANT_SUSPENDED',
          status: organization.subscription_status
        });
      }

      // Add organization context to request for tenant isolation
      req.tenant = {
        id: organizationId,
        status: organization.subscription_status,
        plan: organization.subscription_tier
      };
      
      // Add organizationId directly to request for easy access
      req.organizationId = organizationId;

      // Set up database connection with tenant context
      req.db = {
        query: async (text, params = []) => {
          // Automatically add tenant_id to WHERE clauses for data isolation
          const tenantAwareQuery = addTenantFilter(text, organizationId);
          return dbPool.query(tenantAwareQuery, params);
        }
      };

      next();
    } catch (error) {
      console.error('Tenant isolation error:', error);
      res.status(500).json({
        error: 'Internal server error during tenant validation',
        code: 'TENANT_ISOLATION_ERROR',
        details: error.message
      });
    }
  };
};

/**
 * Add tenant filtering to SQL queries automatically
 * This ensures data isolation at the database level
 */
const addTenantFilter = (query, tenantId) => {
  // List of tables that should have tenant filtering
  const tenantTables = [
    'alerts',
    'incidents',
    'configurations',
    'integrations',
    'reports',
    'analytics',
    'ai_insights',
    'compliance_data'
  ];

  let modifiedQuery = query;

  // Add tenant_id filter to SELECT, UPDATE, DELETE queries
  tenantTables.forEach(table => {
    const selectRegex = new RegExp(`(SELECT.*FROM\\s+${table})(?!.*WHERE.*tenant_id)`, 'gi');
    const updateRegex = new RegExp(`(UPDATE\\s+${table}\\s+SET.*?)(?!.*WHERE.*tenant_id)(\\s+WHERE|$)`, 'gi');
    const deleteRegex = new RegExp(`(DELETE\\s+FROM\\s+${table})(?!.*WHERE.*tenant_id)(\\s+WHERE|$)`, 'gi');

    modifiedQuery = modifiedQuery.replace(selectRegex, `$1 WHERE tenant_id = '${tenantId}'`);
    modifiedQuery = modifiedQuery.replace(updateRegex, `$1 WHERE tenant_id = '${tenantId}'$2`);
    modifiedQuery = modifiedQuery.replace(deleteRegex, `$1 WHERE tenant_id = '${tenantId}'$2`);
  });

  return modifiedQuery;
};

/**
 * Rate limiting per tenant to prevent abuse
 */
const tenantRateLimit = () => {
  const tenantLimits = new Map();

  return (req, res, next) => {
    const tenantId = req.tenant?.id;
    if (!tenantId) return next();

    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxRequests = getTenantRateLimit(req.tenant.plan);

    if (!tenantLimits.has(tenantId)) {
      tenantLimits.set(tenantId, {
        count: 1,
        resetTime: now + windowMs
      });
      return next();
    }

    const tenantData = tenantLimits.get(tenantId);

    if (now > tenantData.resetTime) {
      // Reset the window
      tenantLimits.set(tenantId, {
        count: 1,
        resetTime: now + windowMs
      });
      return next();
    }

    if (tenantData.count >= maxRequests) {
      return res.status(429).json({
        error: 'Rate limit exceeded for tenant',
        code: 'TENANT_RATE_LIMIT',
        resetTime: tenantData.resetTime
      });
    }

    tenantData.count++;
    next();
  };
};

/**
 * Get rate limit based on tenant plan
 */
const getTenantRateLimit = (plan) => {
  const limits = {
    starter: 1000,      // 1000 requests per 15 minutes
    professional: 5000, // 5000 requests per 15 minutes
    enterprise: 20000   // 20000 requests per 15 minutes
  };
  return limits[plan] || limits.starter;
};

/**
 * Feature access control based on tenant plan
 */
const featureAccess = (feature) => {
  return (req, res, next) => {
    const plan = req.tenant?.plan;
    if (!plan) {
      return res.status(403).json({
        error: 'Tenant plan not found',
        code: 'PLAN_NOT_FOUND'
      });
    }

    const hasAccess = checkFeatureAccess(feature, plan);
    if (!hasAccess) {
      return res.status(403).json({
        error: `Feature '${feature}' not available in ${plan} plan`,
        code: 'FEATURE_NOT_AVAILABLE',
        plan: plan,
        feature: feature,
        upgradeRequired: true
      });
    }

    next();
  };
};

/**
 * Check if tenant plan has access to specific feature
 */
const checkFeatureAccess = (feature, plan) => {
  const planFeatures = {
    starter: [
      'basic_alerts',
      'basic_integrations',
      'basic_reports',
      'email_support'
    ],
    professional: [
      'basic_alerts',
      'advanced_alerts',
      'basic_integrations',
      'premium_integrations',
      'basic_reports',
      'custom_reports',
      'ai_insights',
      'email_support',
      'phone_support'
    ],
    enterprise: [
      'basic_alerts',
      'advanced_alerts',
      'custom_alerts',
      'basic_integrations',
      'premium_integrations',
      'custom_integrations',
      'basic_reports',
      'custom_reports',
      'advanced_reports',
      'ai_insights',
      'custom_ai_models',
      'white_label',
      'email_support',
      'phone_support',
      'dedicated_support',
      'sla_guarantees'
    ]
  };

  return planFeatures[plan]?.includes(feature) || false;
};

/**
 * Usage tracking middleware for billing purposes
 */
const trackUsage = (eventType) => {
  return async (req, res, next) => {
    const tenantId = req.tenant?.id;
    if (!tenantId) return next();

    try {
      // Track usage for billing
      const usageQuery = `
        INSERT INTO usage_events (tenant_id, event_type, timestamp, metadata)
        VALUES ($1, $2, NOW(), $3)
      `;
      
      const metadata = {
        endpoint: req.path,
        method: req.method,
        userAgent: req.get('User-Agent'),
        ip: req.ip
      };

      await dbPool.query(usageQuery, [tenantId, eventType, JSON.stringify(metadata)]);
      
      next();
    } catch (error) {
      console.error('Usage tracking error:', error);
      // Don't fail the request if usage tracking fails
      next();
    }
  };
};

module.exports = {
  tenantIsolation,
  tenantRateLimit,
  featureAccess,
  trackUsage,
  checkFeatureAccess
}; 