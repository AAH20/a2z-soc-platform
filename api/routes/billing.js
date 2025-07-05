const express = require('express');
const router = express.Router();

// Get subscription information
router.get('/subscription', async (req, res) => {
  try {
    const db = require('../services/databaseService');
    
    // For now, return a basic subscription from system config
    const query = `
      SELECT value 
      FROM system_config 
      WHERE key = 'subscription_info'
    `;
    
    const { rows } = await db.pool.query(query);
    
    let subscription = {
      id: 'basic_subscription',
      plan_name: 'Community',
      status: 'active',
      current_period_start: new Date().toISOString(),
      current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      cancel_at_period_end: false,
      amount: 0,
      currency: 'USD',
      features: ['Basic Security Monitoring', 'Community Support'],
      limits: {
        users: 10,
        api_requests: 10000,
        storage_gb: 100,
        integrations: 5
      }
    };
    
    if (rows.length > 0 && rows[0].value) {
      try {
        subscription = { ...subscription, ...JSON.parse(rows[0].value) };
      } catch (e) {
        console.log('Using default subscription data');
      }
    }
    
    res.json({
      success: true,
      data: subscription
    });
    
  } catch (error) {
    console.error('Error fetching subscription:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch subscription information'
    });
  }
});

// Get usage information
router.get('/usage', async (req, res) => {
  try {
    const db = require('../services/databaseService');
    
    // Calculate current usage from database
    const [eventsCount, usersCount, agentsCount] = await Promise.all([
      db.pool.query('SELECT COUNT(*) as count FROM security_events WHERE timestamp >= NOW() - INTERVAL \'30 days\''),
      db.pool.query('SELECT COUNT(*) as count FROM users'),
      db.pool.query('SELECT COUNT(*) as count FROM network_agents')
    ]);
    
    const usage = {
      api_requests: {
        current: parseInt(eventsCount.rows[0].count) || 0,
        limit: 10000,
        percentage: Math.min((parseInt(eventsCount.rows[0].count) || 0) / 10000 * 100, 100)
      },
      users: {
        current: parseInt(usersCount.rows[0].count) || 0,
        limit: 10,
        percentage: Math.min((parseInt(usersCount.rows[0].count) || 0) / 10 * 100, 100)
      },
      storage: {
        current: 0, // Would need to calculate actual storage usage
        limit: 100,
        percentage: 0
      },
      integrations: {
        current: parseInt(agentsCount.rows[0].count) || 0,
        limit: 5,
        percentage: Math.min((parseInt(agentsCount.rows[0].count) || 0) / 5 * 100, 100)
      }
    };
    
    res.json({
      success: true,
      data: usage
    });
    
  } catch (error) {
    console.error('Error fetching usage:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch usage information'
    });
  }
});

// Get invoices
router.get('/invoices', async (req, res) => {
  try {
    // For community version, return empty invoices
    res.json({
      success: true,
      data: []
    });
    
  } catch (error) {
    console.error('Error fetching invoices:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch invoices'
    });
  }
});

// Get available plans
router.get('/plans', async (req, res) => {
  try {
    const plans = [
      {
        id: 'community',
        name: 'Community',
        description: 'Open source security monitoring',
        price: 0,
        currency: 'USD',
        interval: 'month',
        features: ['Basic Security Monitoring', 'Community Support', 'Open Source'],
        limits: { users: 10, api_requests: 10000, storage_gb: 100, integrations: 5 }
      },
      {
        id: 'professional',
        name: 'Professional',
        description: 'Advanced security operations',
        price: 149,
        currency: 'USD',
        interval: 'month',
        features: ['Advanced Monitoring', 'Priority Support', 'AI Analysis', 'Cloud Integration'],
        limits: { users: 50, api_requests: 100000, storage_gb: 500, integrations: 25 },
        popular: true
      },
      {
        id: 'enterprise',
        name: 'Enterprise',
        description: 'Enterprise-grade security platform',
        price: 499,
        currency: 'USD',
        interval: 'month',
        features: ['Everything', 'Dedicated Support', 'Custom Integration', 'SLA'],
        limits: { users: 999, api_requests: 1000000, storage_gb: 5000, integrations: 100 }
      }
    ];
    
    res.json({
      success: true,
      data: plans
    });
    
  } catch (error) {
    console.error('Error fetching plans:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch plans'
    });
  }
});

module.exports = router; 