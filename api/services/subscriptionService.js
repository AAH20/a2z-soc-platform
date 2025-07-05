const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { Pool } = require('pg');

const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

/**
 * Subscription Management Service
 * Handles billing, plan changes, usage tracking, and subscription lifecycle
 */
class SubscriptionService {
  constructor() {
    this.plans = {
      starter: {
        id: 'starter',
        name: 'Starter',
        price: 49900, // $499 in cents
        interval: 'month',
        limits: {
          events_per_day: 1000,
          integrations: 5,
          users: 5,
          storage_gb: 10,
          api_calls_per_month: 10000
        },
        features: [
          'basic_alerts',
          'basic_integrations', 
          'basic_reports',
          'email_support'
        ]
      },
      professional: {
        id: 'professional',
        name: 'Professional',
        price: 199900, // $1999 in cents
        interval: 'month',
        limits: {
          events_per_day: 50000,
          integrations: 20,
          users: 25,
          storage_gb: 100,
          api_calls_per_month: 100000
        },
        features: [
          'basic_alerts',
          'advanced_alerts',
          'basic_integrations',
          'premium_integrations',
          'basic_reports',
          'custom_reports',
          'ai_insights',
          'email_support',
          'phone_support'
        ]
      },
      enterprise: {
        id: 'enterprise',
        name: 'Enterprise',
        price: null, // Custom pricing
        interval: 'month',
        limits: {
          events_per_day: -1, // Unlimited
          integrations: -1,
          users: -1,
          storage_gb: -1,
          api_calls_per_month: -1
        },
        features: [
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
      }
    };
  }

  /**
   * Create a new subscription for a tenant
   */
  async createSubscription(tenantId, planId, paymentMethodId, trialDays = 14) {
    try {
      const plan = this.plans[planId];
      if (!plan) {
        throw new Error(`Invalid plan: ${planId}`);
      }

      // Get tenant information
      const tenantQuery = 'SELECT * FROM tenants WHERE id = $1';
      const tenantResult = await dbPool.query(tenantQuery, [tenantId]);
      
      if (tenantResult.rows.length === 0) {
        throw new Error('Tenant not found');
      }

      const tenant = tenantResult.rows[0];

      // Create Stripe customer if doesn't exist
      let stripeCustomerId = tenant.stripe_customer_id;
      if (!stripeCustomerId) {
        const customer = await stripe.customers.create({
          email: tenant.contact_email,
          metadata: {
            tenant_id: tenantId,
            company_name: tenant.name
          }
        });
        stripeCustomerId = customer.id;

        // Update tenant with Stripe customer ID
        await dbPool.query(
          'UPDATE tenants SET stripe_customer_id = $1 WHERE id = $2',
          [stripeCustomerId, tenantId]
        );
      }

      // Attach payment method to customer
      await stripe.paymentMethods.attach(paymentMethodId, {
        customer: stripeCustomerId,
      });

      // Set as default payment method
      await stripe.customers.update(stripeCustomerId, {
        invoice_settings: {
          default_payment_method: paymentMethodId,
        },
      });

      // Create Stripe subscription
      const subscriptionData = {
        customer: stripeCustomerId,
        items: [{
          price_data: {
            currency: 'usd',
            product_data: {
              name: plan.name,
              metadata: {
                plan_id: planId
              }
            },
            unit_amount: plan.price,
            recurring: {
              interval: plan.interval
            }
          }
        }],
        metadata: {
          tenant_id: tenantId,
          plan_id: planId
        }
      };

      if (trialDays > 0) {
        subscriptionData.trial_period_days = trialDays;
      }

      const stripeSubscription = await stripe.subscriptions.create(subscriptionData);

      // Save subscription to database
      const subscriptionInsert = `
        INSERT INTO subscriptions (
          id, tenant_id, stripe_subscription_id, plan_id, status, 
          current_period_start, current_period_end, trial_end, 
          created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        RETURNING *
      `;

      const subscriptionValues = [
        stripeSubscription.id,
        tenantId,
        stripeSubscription.id,
        planId,
        stripeSubscription.status,
        new Date(stripeSubscription.current_period_start * 1000),
        new Date(stripeSubscription.current_period_end * 1000),
        stripeSubscription.trial_end ? new Date(stripeSubscription.trial_end * 1000) : null
      ];

      const subscriptionResult = await dbPool.query(subscriptionInsert, subscriptionValues);

      // Update tenant plan
      await dbPool.query(
        'UPDATE tenants SET plan = $1, status = $2 WHERE id = $3',
        [planId, 'active', tenantId]
      );

      return {
        subscription: subscriptionResult.rows[0],
        stripe_subscription: stripeSubscription
      };

    } catch (error) {
      console.error('Error creating subscription:', error);
      throw error;
    }
  }

  /**
   * Update subscription plan
   */
  async updateSubscription(tenantId, newPlanId) {
    try {
      const newPlan = this.plans[newPlanId];
      if (!newPlan) {
        throw new Error(`Invalid plan: ${newPlanId}`);
      }

      // Get current subscription
      const subscriptionQuery = `
        SELECT * FROM subscriptions 
        WHERE tenant_id = $1 AND status IN ('active', 'trialing')
        ORDER BY created_at DESC LIMIT 1
      `;
      
      const subscriptionResult = await dbPool.query(subscriptionQuery, [tenantId]);
      
      if (subscriptionResult.rows.length === 0) {
        throw new Error('No active subscription found');
      }

      const subscription = subscriptionResult.rows[0];

      // Update Stripe subscription
      const stripeSubscription = await stripe.subscriptions.retrieve(subscription.stripe_subscription_id);
      
      const updatedSubscription = await stripe.subscriptions.update(subscription.stripe_subscription_id, {
        items: [{
          id: stripeSubscription.items.data[0].id,
          price_data: {
            currency: 'usd',
            product_data: {
              name: newPlan.name,
              metadata: {
                plan_id: newPlanId
              }
            },
            unit_amount: newPlan.price,
            recurring: {
              interval: newPlan.interval
            }
          }
        }],
        proration_behavior: 'create_prorations',
        metadata: {
          tenant_id: tenantId,
          plan_id: newPlanId
        }
      });

      // Update subscription in database
      await dbPool.query(
        `UPDATE subscriptions 
         SET plan_id = $1, updated_at = NOW() 
         WHERE id = $2`,
        [newPlanId, subscription.id]
      );

      // Update tenant plan
      await dbPool.query(
        'UPDATE tenants SET plan = $1 WHERE id = $2',
        [newPlanId, tenantId]
      );

      return {
        subscription: updatedSubscription,
        previous_plan: subscription.plan_id,
        new_plan: newPlanId
      };

    } catch (error) {
      console.error('Error updating subscription:', error);
      throw error;
    }
  }

  /**
   * Cancel subscription
   */
  async cancelSubscription(tenantId, cancelAtPeriodEnd = true) {
    try {
      // Get current subscription
      const subscriptionQuery = `
        SELECT * FROM subscriptions 
        WHERE tenant_id = $1 AND status IN ('active', 'trialing')
        ORDER BY created_at DESC LIMIT 1
      `;
      
      const subscriptionResult = await dbPool.query(subscriptionQuery, [tenantId]);
      
      if (subscriptionResult.rows.length === 0) {
        throw new Error('No active subscription found');
      }

      const subscription = subscriptionResult.rows[0];

      // Cancel Stripe subscription
      const canceledSubscription = await stripe.subscriptions.update(subscription.stripe_subscription_id, {
        cancel_at_period_end: cancelAtPeriodEnd
      });

      // Update subscription status
      const newStatus = cancelAtPeriodEnd ? 'cancel_at_period_end' : 'canceled';
      
      await dbPool.query(
        `UPDATE subscriptions 
         SET status = $1, canceled_at = $2, updated_at = NOW() 
         WHERE id = $3`,
        [newStatus, cancelAtPeriodEnd ? null : new Date(), subscription.id]
      );

      if (!cancelAtPeriodEnd) {
        // Immediately downgrade tenant to free plan
        await dbPool.query(
          'UPDATE tenants SET plan = $1, status = $2 WHERE id = $3',
          ['free', 'suspended', tenantId]
        );
      }

      return {
        subscription: canceledSubscription,
        cancel_at_period_end: cancelAtPeriodEnd
      };

    } catch (error) {
      console.error('Error canceling subscription:', error);
      throw error;
    }
  }

  /**
   * Track usage for billing
   */
  async trackUsage(tenantId, eventType, quantity = 1, metadata = {}) {
    try {
      const usageInsert = `
        INSERT INTO usage_events (
          tenant_id, event_type, quantity, metadata, timestamp
        ) VALUES ($1, $2, $3, $4, NOW())
      `;

      await dbPool.query(usageInsert, [
        tenantId, 
        eventType, 
        quantity, 
        JSON.stringify(metadata)
      ]);

      // Check usage limits
      await this.checkUsageLimits(tenantId);

    } catch (error) {
      console.error('Error tracking usage:', error);
      // Don't throw error for usage tracking failures
    }
  }

  /**
   * Check if tenant is within usage limits
   */
  async checkUsageLimits(tenantId) {
    try {
      // Get tenant plan
      const tenantQuery = 'SELECT plan FROM tenants WHERE id = $1';
      const tenantResult = await dbPool.query(tenantQuery, [tenantId]);
      
      if (tenantResult.rows.length === 0) {
        return false;
      }

      const plan = this.plans[tenantResult.rows[0].plan];
      if (!plan || plan.limits.events_per_day === -1) {
        return true; // Unlimited plan
      }

      // Check daily event limit
      const dailyUsageQuery = `
        SELECT COUNT(*) as daily_events
        FROM usage_events 
        WHERE tenant_id = $1 
          AND event_type = 'security_event'
          AND timestamp >= CURRENT_DATE
      `;

      const usageResult = await dbPool.query(dailyUsageQuery, [tenantId]);
      const dailyEvents = parseInt(usageResult.rows[0].daily_events);

      if (dailyEvents > plan.limits.events_per_day) {
        // Tenant exceeded limits, suspend processing
        await dbPool.query(
          'UPDATE tenants SET status = $1 WHERE id = $2',
          ['over_limit', tenantId]
        );
        
        return false;
      }

      return true;

    } catch (error) {
      console.error('Error checking usage limits:', error);
      return true; // Allow processing if check fails
    }
  }

  /**
   * Get usage statistics for a tenant
   */
  async getUsageStats(tenantId, startDate, endDate) {
    try {
      const usageQuery = `
        SELECT 
          event_type,
          DATE(timestamp) as date,
          COUNT(*) as count,
          SUM(quantity) as total_quantity
        FROM usage_events 
        WHERE tenant_id = $1 
          AND timestamp BETWEEN $2 AND $3
        GROUP BY event_type, DATE(timestamp)
        ORDER BY date DESC, event_type
      `;

      const result = await dbPool.query(usageQuery, [tenantId, startDate, endDate]);
      
      return result.rows;

    } catch (error) {
      console.error('Error getting usage stats:', error);
      throw error;
    }
  }

  /**
   * Process subscription webhooks from Stripe
   */
  async handleWebhook(event) {
    try {
      switch (event.type) {
        case 'customer.subscription.created':
          await this.handleSubscriptionCreated(event.data.object);
          break;
          
        case 'customer.subscription.updated':
          await this.handleSubscriptionUpdated(event.data.object);
          break;
          
        case 'customer.subscription.deleted':
          await this.handleSubscriptionDeleted(event.data.object);
          break;
          
        case 'invoice.payment_succeeded':
          await this.handlePaymentSucceeded(event.data.object);
          break;
          
        case 'invoice.payment_failed':
          await this.handlePaymentFailed(event.data.object);
          break;
          
        default:
          console.log(`Unhandled webhook event type: ${event.type}`);
      }

    } catch (error) {
      console.error('Error handling webhook:', error);
      throw error;
    }
  }

  async handleSubscriptionCreated(subscription) {
    const tenantId = subscription.metadata.tenant_id;
    const planId = subscription.metadata.plan_id;

    await dbPool.query(
      'UPDATE tenants SET status = $1, plan = $2 WHERE id = $3',
      ['active', planId, tenantId]
    );
  }

  async handleSubscriptionUpdated(subscription) {
    const tenantId = subscription.metadata.tenant_id;
    
    await dbPool.query(
      `UPDATE subscriptions 
       SET status = $1, current_period_start = $2, current_period_end = $3, updated_at = NOW()
       WHERE stripe_subscription_id = $4`,
      [
        subscription.status,
        new Date(subscription.current_period_start * 1000),
        new Date(subscription.current_period_end * 1000),
        subscription.id
      ]
    );

    // Update tenant status based on subscription status
    let tenantStatus = 'active';
    if (subscription.status === 'past_due') {
      tenantStatus = 'past_due';
    } else if (subscription.status === 'canceled') {
      tenantStatus = 'suspended';
    }

    await dbPool.query(
      'UPDATE tenants SET status = $1 WHERE id = $2',
      [tenantStatus, tenantId]
    );
  }

  async handleSubscriptionDeleted(subscription) {
    const tenantId = subscription.metadata.tenant_id;

    await dbPool.query(
      'UPDATE tenants SET status = $1, plan = $2 WHERE id = $3',
      ['suspended', 'free', tenantId]
    );

    await dbPool.query(
      `UPDATE subscriptions 
       SET status = 'canceled', canceled_at = NOW(), updated_at = NOW()
       WHERE stripe_subscription_id = $1`,
      [subscription.id]
    );
  }

  async handlePaymentSucceeded(invoice) {
    const subscriptionId = invoice.subscription;
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    const tenantId = subscription.metadata.tenant_id;

    // Reactivate tenant if payment succeeded
    await dbPool.query(
      'UPDATE tenants SET status = $1 WHERE id = $2',
      ['active', tenantId]
    );
  }

  async handlePaymentFailed(invoice) {
    const subscriptionId = invoice.subscription;
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    const tenantId = subscription.metadata.tenant_id;

    // Mark tenant as past due
    await dbPool.query(
      'UPDATE tenants SET status = $1 WHERE id = $2',
      ['past_due', tenantId]
    );
  }

  /**
   * Get available plans
   */
  getPlans() {
    return this.plans;
  }

  /**
   * Calculate monthly recurring revenue
   */
  async calculateMRR() {
    try {
      const query = `
        SELECT 
          s.plan_id,
          COUNT(*) as subscribers,
          SUM(CASE 
            WHEN s.plan_id = 'starter' THEN 499
            WHEN s.plan_id = 'professional' THEN 1999
            ELSE 0
          END) as mrr
        FROM subscriptions s
        WHERE s.status IN ('active', 'trialing')
        GROUP BY s.plan_id
      `;

      const result = await dbPool.query(query);
      
      let totalMRR = 0;
      let totalSubscribers = 0;
      
      result.rows.forEach(row => {
        totalMRR += parseFloat(row.mrr);
        totalSubscribers += parseInt(row.subscribers);
      });

      return {
        total_mrr: totalMRR,
        total_subscribers: totalSubscribers,
        by_plan: result.rows
      };

    } catch (error) {
      console.error('Error calculating MRR:', error);
      throw error;
    }
  }
}

module.exports = new SubscriptionService(); 