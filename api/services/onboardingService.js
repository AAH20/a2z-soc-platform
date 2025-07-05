const { v4: uuidv4 } = require('uuid');

class OnboardingService {
  constructor(db) {
    this.db = db;
  }

  // Start Onboarding Process
  async startOnboarding(tenantId, userId) {
    try {
      const onboardingId = uuidv4();
      
      // Create onboarding record
      const result = await this.db.query(
        `INSERT INTO onboarding_progress (id, tenant_id, user_id, status, current_step, steps_completed, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *`,
        [onboardingId, tenantId, userId, 'in_progress', 1, []]
      );

      // Initialize onboarding steps
      const steps = this.getOnboardingSteps();
      await this.initializeSteps(onboardingId, steps);

      return {
        onboarding: result.rows[0],
        steps: steps,
        message: 'Onboarding process started successfully'
      };
    } catch (error) {
      throw new Error(`Failed to start onboarding: ${error.message}`);
    }
  }

  // Get Onboarding Progress
  async getOnboardingProgress(tenantId) {
    try {
      const result = await this.db.query(
        `SELECT op.*, os.step_number, os.title, os.description, os.status as step_status, os.completed_at
         FROM onboarding_progress op
         LEFT JOIN onboarding_steps os ON op.id = os.onboarding_id
         WHERE op.tenant_id = $1
         ORDER BY os.step_number`,
        [tenantId]
      );

      if (result.rows.length === 0) {
        return null;
      }

      const onboarding = {
        id: result.rows[0].id,
        tenant_id: result.rows[0].tenant_id,
        user_id: result.rows[0].user_id,
        status: result.rows[0].status,
        current_step: result.rows[0].current_step,
        steps_completed: result.rows[0].steps_completed,
        created_at: result.rows[0].created_at,
        updated_at: result.rows[0].updated_at,
        steps: []
      };

      // Group steps
      result.rows.forEach(row => {
        if (row.step_number) {
          onboarding.steps.push({
            step_number: row.step_number,
            title: row.title,
            description: row.description,
            status: row.step_status,
            completed_at: row.completed_at
          });
        }
      });

      return onboarding;
    } catch (error) {
      throw new Error(`Failed to get onboarding progress: ${error.message}`);
    }
  }

  // Complete Onboarding Step
  async completeStep(tenantId, stepNumber, stepData = {}) {
    try {
      const onboarding = await this.getOnboardingProgress(tenantId);
      if (!onboarding) {
        throw new Error('Onboarding not found');
      }

      // Mark step as completed
      await this.db.query(
        `UPDATE onboarding_steps 
         SET status = 'completed', completed_at = NOW(), data = $1
         WHERE onboarding_id = $2 AND step_number = $3`,
        [JSON.stringify(stepData), onboarding.id, stepNumber]
      );

      // Update overall progress
      const completedSteps = [...onboarding.steps_completed, stepNumber];
      const nextStep = stepNumber + 1;
      const totalSteps = this.getOnboardingSteps().length;
      
      let status = 'in_progress';
      if (completedSteps.length === totalSteps) {
        status = 'completed';
      }

      await this.db.query(
        `UPDATE onboarding_progress 
         SET current_step = $1, steps_completed = $2, status = $3, updated_at = NOW()
         WHERE id = $4`,
        [nextStep <= totalSteps ? nextStep : totalSteps, JSON.stringify(completedSteps), status, onboarding.id]
      );

      // Process step-specific actions
      await this.processStepCompletion(tenantId, stepNumber, stepData);

      // Check if onboarding is completed
      if (status === 'completed') {
        await this.completeOnboarding(tenantId);
      }

      return {
        step_completed: stepNumber,
        status: status,
        next_step: nextStep <= totalSteps ? nextStep : null,
        progress_percentage: Math.round((completedSteps.length / totalSteps) * 100)
      };
    } catch (error) {
      throw new Error(`Failed to complete step: ${error.message}`);
    }
  }

  // Process Step-Specific Actions
  async processStepCompletion(tenantId, stepNumber, stepData) {
    try {
      switch (stepNumber) {
        case 1: // Profile Setup
          await this.processProfileSetup(tenantId, stepData);
          break;
        case 2: // Security Configuration
          await this.processSecurityConfiguration(tenantId, stepData);
          break;
        case 3: // Integration Setup
          await this.processIntegrationSetup(tenantId, stepData);
          break;
        case 4: // Team Invitation
          await this.processTeamInvitation(tenantId, stepData);
          break;
        case 5: // Trial Configuration
          await this.processTrialConfiguration(tenantId, stepData);
          break;
        case 6: // First Security Scan
          await this.processFirstSecurityScan(tenantId, stepData);
          break;
        case 7: // Dashboard Tour
          await this.processDashboardTour(tenantId, stepData);
          break;
      }
    } catch (error) {
      console.error(`Failed to process step ${stepNumber}:`, error.message);
    }
  }

  // Step 1: Profile Setup
  async processProfileSetup(tenantId, stepData) {
    const { organizationName, industry, companySize, timezone } = stepData;
    
    await this.db.query(
      `UPDATE tenants 
       SET name = $1, industry = $2, company_size = $3, timezone = $4, updated_at = NOW()
       WHERE id = $5`,
      [organizationName, industry, companySize, timezone, tenantId]
    );
  }

  // Step 2: Security Configuration
  async processSecurityConfiguration(tenantId, stepData) {
    const { passwordPolicy, twoFactorRequired, sessionTimeout } = stepData;
    
    const settings = {
      security: {
        password_policy: passwordPolicy,
        two_factor_required: twoFactorRequired,
        session_timeout: sessionTimeout
      }
    };

    await this.db.query(
      `UPDATE tenant_settings 
       SET settings = jsonb_deep_merge(settings, $1::jsonb)
       WHERE tenant_id = $2`,
      [JSON.stringify(settings), tenantId]
    );
  }

  // Step 3: Integration Setup
  async processIntegrationSetup(tenantId, stepData) {
    const { selectedIntegrations } = stepData;
    
    for (const integration of selectedIntegrations) {
      await this.db.query(
        `INSERT INTO tenant_integrations (tenant_id, type, status, config, created_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (tenant_id, type) DO UPDATE SET
         status = $3, config = $4, updated_at = NOW()`,
        [tenantId, integration.type, 'configured', JSON.stringify(integration.config || {})]
      );
    }
  }

  // Step 4: Team Invitation
  async processTeamInvitation(tenantId, stepData) {
    const { teamMembers } = stepData;
    const UserService = require('./userService');
    const userService = new UserService(this.db);
    
    if (teamMembers && teamMembers.length > 0) {
      for (const member of teamMembers) {
        try {
          await userService.inviteTeamMember(tenantId, stepData.inviterUserId, member);
        } catch (error) {
          console.error(`Failed to invite ${member.email}:`, error.message);
        }
      }
    }
  }

  // Step 5: Trial Configuration
  async processTrialConfiguration(tenantId, stepData) {
    const { trialDuration = 14 } = stepData;
    
    const trialEndDate = new Date();
    trialEndDate.setDate(trialEndDate.getDate() + trialDuration);
    
    await this.db.query(
      `UPDATE tenants 
       SET trial_ends_at = $1, updated_at = NOW()
       WHERE id = $2`,
      [trialEndDate, tenantId]
    );
  }

  // Step 6: First Security Scan
  async processFirstSecurityScan(tenantId, stepData) {
    // Schedule or trigger first security scan
    await this.db.query(
      `INSERT INTO tenant_alerts (id, tenant_id, type, severity, title, message, metadata, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
      [
        uuidv4(),
        tenantId,
        'onboarding',
        'info',
        'First Security Scan Completed',
        'Your initial security assessment has been completed. Review the results in your dashboard.',
        JSON.stringify({ scan_type: 'initial', step: 'onboarding' })
      ]
    );
  }

  // Step 7: Dashboard Tour
  async processDashboardTour(tenantId, stepData) {
    // Mark tour as completed
    await this.db.query(
      `UPDATE tenant_settings 
       SET settings = jsonb_set(settings, '{ui,dashboard_tour_completed}', 'true'::jsonb)
       WHERE tenant_id = $1`,
      [tenantId]
    );
  }

  // Complete Onboarding
  async completeOnboarding(tenantId) {
    try {
      // Send completion email
      const EmailService = require('./emailService');
      const emailService = new EmailService();
      
      // Get user details
      const userResult = await this.db.query(
        `SELECT u.*, t.name as tenant_name 
         FROM users u 
         JOIN tenants t ON u.tenant_id = t.id 
         WHERE u.tenant_id = $1 AND u.role = 'admin' 
         LIMIT 1`,
        [tenantId]
      );

      if (userResult.rows.length > 0) {
        const user = userResult.rows[0];
        await emailService.sendOnboardingCompletionEmail(user);
      }

      // Create completion alert
      await this.db.query(
        `INSERT INTO tenant_alerts (id, tenant_id, type, severity, title, message, metadata, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
        [
          uuidv4(),
          tenantId,
          'onboarding',
          'success',
          'Onboarding Completed!',
          'Welcome to A2Z SOC! Your account is now fully set up and ready to use.',
          JSON.stringify({ onboarding_completed: true })
        ]
      );

      // Update tenant status
      await this.db.query(
        'UPDATE tenants SET onboarding_completed_at = NOW() WHERE id = $1',
        [tenantId]
      );

    } catch (error) {
      console.error('Failed to complete onboarding:', error.message);
    }
  }

  // Skip Onboarding Step
  async skipStep(tenantId, stepNumber) {
    try {
      const onboarding = await this.getOnboardingProgress(tenantId);
      if (!onboarding) {
        throw new Error('Onboarding not found');
      }

      // Mark step as skipped
      await this.db.query(
        `UPDATE onboarding_steps 
         SET status = 'skipped', completed_at = NOW()
         WHERE onboarding_id = $1 AND step_number = $2`,
        [onboarding.id, stepNumber]
      );

      // Continue to next step
      return await this.completeStep(tenantId, stepNumber, { skipped: true });
    } catch (error) {
      throw new Error(`Failed to skip step: ${error.message}`);
    }
  }

  // Reset Onboarding
  async resetOnboarding(tenantId) {
    try {
      const onboarding = await this.getOnboardingProgress(tenantId);
      if (!onboarding) {
        throw new Error('Onboarding not found');
      }

      // Reset all steps
      await this.db.query(
        `UPDATE onboarding_steps 
         SET status = 'pending', completed_at = NULL, data = NULL
         WHERE onboarding_id = $1`,
        [onboarding.id]
      );

      // Reset progress
      await this.db.query(
        `UPDATE onboarding_progress 
         SET current_step = 1, steps_completed = '[]'::jsonb, status = 'in_progress', updated_at = NOW()
         WHERE id = $1`,
        [onboarding.id]
      );

      return { message: 'Onboarding reset successfully' };
    } catch (error) {
      throw new Error(`Failed to reset onboarding: ${error.message}`);
    }
  }

  // Get Onboarding Analytics
  async getOnboardingAnalytics() {
    try {
      const result = await this.db.query(`
        SELECT 
          COUNT(*) as total_onboardings,
          COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_onboardings,
          COUNT(CASE WHEN status = 'in_progress' THEN 1 END) as in_progress_onboardings,
          COUNT(CASE WHEN status = 'abandoned' THEN 1 END) as abandoned_onboardings,
          AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/3600) as avg_completion_hours,
          AVG(array_length(steps_completed, 1)) as avg_steps_completed
        FROM onboarding_progress
        WHERE created_at >= NOW() - INTERVAL '30 days'
      `);

      const stepAnalytics = await this.db.query(`
        SELECT 
          step_number,
          COUNT(*) as total_attempts,
          COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
          COUNT(CASE WHEN status = 'skipped' THEN 1 END) as skipped,
          AVG(EXTRACT(EPOCH FROM (completed_at - created_at))/60) as avg_completion_minutes
        FROM onboarding_steps os
        JOIN onboarding_progress op ON os.onboarding_id = op.id
        WHERE op.created_at >= NOW() - INTERVAL '30 days'
        GROUP BY step_number
        ORDER BY step_number
      `);

      return {
        overall: result.rows[0],
        by_step: stepAnalytics.rows,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get onboarding analytics: ${error.message}`);
    }
  }

  // Helper Methods
  getOnboardingSteps() {
    return [
      {
        step_number: 1,
        title: 'Complete Your Profile',
        description: 'Set up your organization details and preferences',
        estimated_time: 5
      },
      {
        step_number: 2,
        title: 'Configure Security Settings',
        description: 'Set up password policies and security preferences',
        estimated_time: 10
      },
      {
        step_number: 3,
        title: 'Connect Your Security Tools',
        description: 'Integrate with your existing security infrastructure',
        estimated_time: 15
      },
      {
        step_number: 4,
        title: 'Invite Your Team',
        description: 'Add team members and assign roles',
        estimated_time: 5
      },
      {
        step_number: 5,
        title: 'Configure Trial Settings',
        description: 'Set up your trial period and preferences',
        estimated_time: 3
      },
      {
        step_number: 6,
        title: 'Run First Security Scan',
        description: 'Perform an initial assessment of your security posture',
        estimated_time: 10
      },
      {
        step_number: 7,
        title: 'Take Dashboard Tour',
        description: 'Get familiar with the platform features and navigation',
        estimated_time: 8
      }
    ];
  }

  async initializeSteps(onboardingId, steps) {
    for (const step of steps) {
      await this.db.query(
        `INSERT INTO onboarding_steps (onboarding_id, step_number, title, description, status, estimated_time)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [onboardingId, step.step_number, step.title, step.description, 'pending', step.estimated_time]
      );
    }
  }
}

module.exports = OnboardingService; 