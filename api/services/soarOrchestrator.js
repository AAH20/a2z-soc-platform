const { Pool } = require('pg');
const EventEmitter = require('events');

class SOAROrchestrator extends EventEmitter {
  constructor() {
    super();
    this.pool = new Pool({
      user: process.env.DB_USER || 'postgres',
      host: process.env.DB_HOST || 'localhost',
      database: process.env.DB_NAME || 'a2z_soc',
      password: process.env.DB_PASSWORD || 'postgres',
      port: process.env.DB_PORT || 5432,
    });
    
    this.runningExecutions = new Map();
    this.integrations = new Map();
    
    this.initializeIntegrations();
  }

  initializeIntegrations() {
    // Slack Integration
    this.integrations.set('slack', {
      name: 'Slack',
      type: 'notification',
      actions: {
        send_notification: async (params) => {
          console.log(`Slack notification: ${params.message} to ${params.channel}`);
          // In production, this would use the Slack API
          return { success: true, message: 'Notification sent' };
        }
      }
    });

    // VirusTotal Integration
    this.integrations.set('virustotal', {
      name: 'VirusTotal',
      type: 'threat_intel',
      actions: {
        analyze_ip: async (params) => {
          console.log(`VirusTotal IP analysis: ${params.ip_address}`);
          // Mock response
          return {
            success: true,
            result: {
              ip: params.ip_address,
              reputation: 'clean',
              detections: 0,
              country: 'US'
            }
          };
        },
        analyze_hash: async (params) => {
          console.log(`VirusTotal hash analysis: ${params.hash}`);
          return {
            success: true,
            result: {
              hash: params.hash,
              detections: 5,
              total_engines: 70,
              verdict: 'malicious'
            }
          };
        }
      }
    });

    // Shodan Integration
    this.integrations.set('shodan', {
      name: 'Shodan',
      type: 'reconnaissance',
      actions: {
        lookup_ip: async (params) => {
          console.log(`Shodan IP lookup: ${params.ip_address}`);
          return {
            success: true,
            result: {
              ip: params.ip_address,
              ports: [22, 80, 443],
              services: ['ssh', 'http', 'https'],
              location: 'US'
            }
          };
        }
      }
    });

    // MISP Integration
    this.integrations.set('misp', {
      name: 'MISP',
      type: 'threat_intel',
      actions: {
        create_event: async (params) => {
          console.log(`MISP event creation: ${params.title}`);
          return {
            success: true,
            event_id: `misp_${Date.now()}`
          };
        }
      }
    });

    // Email Integration
    this.integrations.set('email', {
      name: 'Email',
      type: 'notification',
      actions: {
        send_alert: async (params) => {
          console.log(`Email alert: ${params.subject} to ${params.recipients}`);
          return { success: true, message: 'Email sent' };
        }
      }
    });

    console.log(`Initialized ${this.integrations.size} integrations`);
  }

  async getPlaybooks(tenantId = 'default') {
    try {
      const query = `
        SELECT 
          playbook_id as id,
          name,
          description,
          trigger_conditions,
          steps,
          enabled,
          execution_count,
          success_count,
          failure_count,
          last_executed,
          created_at
        FROM soar_playbooks 
        WHERE tenant_id = $1
        ORDER BY name
      `;
      
      const result = await this.pool.query(query, [tenantId]);
      
      return result.rows.map(row => ({
        ...row,
        step_count: Array.isArray(row.steps) ? row.steps.length : 0,
        success_rate: row.execution_count > 0 ? 
          Math.round((row.success_count / row.execution_count) * 100) : 0
      }));
      
    } catch (error) {
      console.error('Failed to get playbooks:', error);
      throw error;
    }
  }

  async getPlaybook(playbookId, tenantId = 'default') {
    try {
      const query = `
        SELECT * FROM soar_playbooks 
        WHERE playbook_id = $1 AND tenant_id = $2
      `;
      
      const result = await this.pool.query(query, [playbookId, tenantId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return result.rows[0];
      
    } catch (error) {
      console.error('Failed to get playbook:', error);
      throw error;
    }
  }

  async addPlaybook(playbookData) {
    try {
      const query = `
        INSERT INTO soar_playbooks (
          tenant_id, playbook_id, name, description, trigger_conditions,
          steps, enabled, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
      `;
      
      const values = [
        playbookData.tenant_id,
        playbookData.id,
        playbookData.name,
        playbookData.description,
        playbookData.trigger_conditions,
        playbookData.steps,
        true,
        playbookData.created_by,
        playbookData.created_at,
        playbookData.created_at
      ];
      
      const result = await this.pool.query(query, values);
      
      console.log(`Playbook added: ${playbookData.name}`);
      return result.rows[0];
      
    } catch (error) {
      console.error('Failed to add playbook:', error);
      throw error;
    }
  }

  async executePlaybook(playbookId, incidentData, options = {}) {
    try {
      const playbook = await this.getPlaybook(playbookId, incidentData.tenant_id);
      
      if (!playbook) {
        throw new Error(`Playbook not found: ${playbookId}`);
      }

      const executionId = `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const now = new Date();
      
      // Create execution record
      const executionQuery = `
        INSERT INTO soar_executions (
          tenant_id, execution_id, playbook_id, incident_id, status,
          total_steps, input_data, started_at, created_by, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
      `;
      
      const executionValues = [
        incidentData.tenant_id,
        executionId,
        playbookId,
        incidentData.id || null,
        'RUNNING',
        playbook.steps.length,
        incidentData,
        now,
        incidentData.executed_by,
        now,
        now
      ];
      
      const executionResult = await this.pool.query(executionQuery, executionValues);
      const execution = executionResult.rows[0];
      
      // Update playbook execution count
      await this.pool.query(
        'UPDATE soar_playbooks SET execution_count = execution_count + 1, last_executed = $1 WHERE playbook_id = $2',
        [now, playbookId]
      );
      
      // Start async execution
      this.runPlaybookSteps(execution, playbook, incidentData);
      
      return {
        id: executionId,
        status: 'STARTED',
        playbook_id: playbookId,
        incident_id: incidentData.id
      };
      
    } catch (error) {
      console.error('Failed to execute playbook:', error);
      throw error;
    }
  }

  async runPlaybookSteps(execution, playbook, incidentData) {
    const executionId = execution.execution_id;
    const steps = playbook.steps;
    let currentStepIndex = 0;
    let success = true;
    const executionLog = [];
    
    try {
      this.runningExecutions.set(executionId, {
        execution,
        playbook,
        incidentData,
        startTime: new Date(),
        status: 'RUNNING'
      });
      
      for (const step of steps) {
        currentStepIndex++;
        const stepStartTime = new Date();
        
        // Update execution progress
        const progress = Math.round((currentStepIndex / steps.length) * 100);
        await this.updateExecutionProgress(executionId, progress, step.action, currentStepIndex);
        
        try {
          console.log(`Executing step ${currentStepIndex}/${steps.length}: ${step.action}`);
          
          // Execute the step
          const stepResult = await this.executeStep(step, incidentData);
          
          const stepEndTime = new Date();
          const stepDuration = stepEndTime - stepStartTime;
          
          executionLog.push({
            step_index: currentStepIndex,
            action: step.action,
            status: 'SUCCESS',
            duration: stepDuration,
            result: stepResult,
            timestamp: stepEndTime
          });
          
          // Emit step completion event
          this.emit('step_completed', {
            execution_id: executionId,
            step_index: currentStepIndex,
            action: step.action,
            result: stepResult
          });
          
        } catch (stepError) {
          console.error(`Step ${currentStepIndex} failed:`, stepError);
          
          executionLog.push({
            step_index: currentStepIndex,
            action: step.action,
            status: 'FAILED',
            error: stepError.message,
            timestamp: new Date()
          });
          
          success = false;
          
          // Check if we should continue on error
          if (!step.continue_on_error) {
            break;
          }
        }
        
        // Add delay between steps if specified
        if (step.delay) {
          await this.sleep(step.delay * 1000);
        }
      }
      
      // Complete execution
      const completedAt = new Date();
      const finalStatus = success ? 'COMPLETED' : 'FAILED';
      
      await this.completeExecution(executionId, finalStatus, executionLog, completedAt);
      
      // Update playbook success/failure count
      const countField = success ? 'success_count' : 'failure_count';
      await this.pool.query(
        `UPDATE soar_playbooks SET ${countField} = ${countField} + 1 WHERE playbook_id = $1`,
        [playbook.playbook_id]
      );
      
      // Remove from running executions
      this.runningExecutions.delete(executionId);
      
      // Emit completion event
      this.emit('execution_completed', {
        execution_id: executionId,
        status: finalStatus,
        playbook_id: playbook.playbook_id,
        duration: completedAt - execution.started_at
      });
      
      console.log(`Playbook execution ${finalStatus}: ${executionId}`);
      
    } catch (error) {
      console.error('Playbook execution failed:', error);
      
      await this.completeExecution(executionId, 'FAILED', executionLog, new Date(), error.message);
      
      this.runningExecutions.delete(executionId);
      
      this.emit('execution_failed', {
        execution_id: executionId,
        error: error.message,
        playbook_id: playbook.playbook_id
      });
    }
  }

  async executeStep(step, incidentData) {
    const { action, parameters = {}, timeout = 30000 } = step;
    
    // Replace template variables in parameters
    const resolvedParameters = this.resolveParameters(parameters, incidentData);
    
    return new Promise(async (resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Step timeout: ${action}`));
      }, timeout);
      
      try {
        let result;
        
        switch (action) {
          case 'isolate_host':
            result = await this.isolateHost(resolvedParameters);
            break;
          case 'block_ip':
            result = await this.blockIP(resolvedParameters);
            break;
          case 'scan_system':
            result = await this.scanSystem(resolvedParameters);
            break;
          case 'notify_team':
            result = await this.notifyTeam(resolvedParameters);
            break;
          case 'create_ticket':
            result = await this.createTicket(resolvedParameters);
            break;
          case 'analyze_ip':
            result = await this.analyzeIP(resolvedParameters);
            break;
          case 'quarantine_email':
            result = await this.quarantineEmail(resolvedParameters);
            break;
          case 'update_firewall':
            result = await this.updateFirewall(resolvedParameters);
            break;
          default:
            throw new Error(`Unknown action: ${action}`);
        }
        
        clearTimeout(timer);
        resolve(result);
        
      } catch (error) {
        clearTimeout(timer);
        reject(error);
      }
    });
  }

  resolveParameters(parameters, incidentData) {
    const resolved = {};
    
    for (const [key, value] of Object.entries(parameters)) {
      if (typeof value === 'string') {
        // Replace template variables like {{variable}}
        resolved[key] = value.replace(/\{\{([^}]+)\}\}/g, (match, varName) => {
          return incidentData[varName] || match;
        });
      } else {
        resolved[key] = value;
      }
    }
    
    return resolved;
  }

  // Action implementations
  async isolateHost(params) {
    console.log(`Isolating host: ${params.host}`);
    // In production, this would interact with network management systems
    await this.sleep(2000); // Simulate network operation
    return { success: true, message: `Host ${params.host} isolated` };
  }

  async blockIP(params) {
    console.log(`Blocking IP: ${params.ip} for ${params.duration} seconds`);
    // In production, this would update firewall rules
    await this.sleep(1000);
    return { success: true, message: `IP ${params.ip} blocked` };
  }

  async scanSystem(params) {
    console.log(`Scanning system: ${params.host} (${params.scan_type})`);
    // In production, this would trigger antivirus/vulnerability scans
    await this.sleep(5000); // Simulate scan time
    return { 
      success: true, 
      message: `${params.scan_type} scan completed`,
      threats_found: 0
    };
  }

  async notifyTeam(params) {
    const slack = this.integrations.get('slack');
    if (slack) {
      return await slack.actions.send_notification({
        message: params.message,
        channel: params.channel || '#security'
      });
    }
    
    console.log(`Team notification: ${params.message}`);
    return { success: true, message: 'Team notified' };
  }

  async createTicket(params) {
    console.log(`Creating ticket: ${params.title} (${params.priority})`);
    // In production, this would integrate with ticketing systems
    await this.sleep(1000);
    return { 
      success: true, 
      ticket_id: `TKT-${Date.now()}`,
      message: 'Ticket created'
    };
  }

  async analyzeIP(params) {
    const virustotal = this.integrations.get('virustotal');
    if (virustotal) {
      return await virustotal.actions.analyze_ip({
        ip_address: params.ip
      });
    }
    
    console.log(`Analyzing IP: ${params.ip}`);
    return { 
      success: true, 
      result: { ip: params.ip, reputation: 'unknown' }
    };
  }

  async quarantineEmail(params) {
    console.log(`Quarantining email: ${params.email_id}`);
    // In production, this would interact with email security systems
    await this.sleep(1000);
    return { success: true, message: 'Email quarantined' };
  }

  async updateFirewall(params) {
    console.log(`Updating firewall: ${params.action} ${params.source}`);
    // In production, this would update firewall rules
    await this.sleep(2000);
    return { success: true, message: 'Firewall updated' };
  }

  async updateExecutionProgress(executionId, progress, currentStep, stepIndex) {
    try {
      const query = `
        UPDATE soar_executions 
        SET progress = $1, current_step = $2, current_step_index = $3, updated_at = CURRENT_TIMESTAMP
        WHERE execution_id = $4
      `;
      
      await this.pool.query(query, [progress, currentStep, stepIndex, executionId]);
      
    } catch (error) {
      console.error('Failed to update execution progress:', error);
    }
  }

  async completeExecution(executionId, status, executionLog, completedAt, errorMessage = null) {
    try {
      const query = `
        UPDATE soar_executions 
        SET status = $1, progress = $2, execution_log = $3, completed_at = $4, 
            error_message = $5, updated_at = CURRENT_TIMESTAMP
        WHERE execution_id = $6
      `;
      
      const progress = status === 'COMPLETED' ? 100 : 0;
      
      await this.pool.query(query, [
        status, progress, executionLog, completedAt, errorMessage, executionId
      ]);
      
    } catch (error) {
      console.error('Failed to complete execution:', error);
    }
  }

  async getExecutionStatus(executionId, tenantId = 'default') {
    try {
      const query = `
        SELECT e.*, p.name as playbook_name
        FROM soar_executions e
        JOIN soar_playbooks p ON e.playbook_id = p.playbook_id
        WHERE e.execution_id = $1 AND e.tenant_id = $2
      `;
      
      const result = await this.pool.query(query, [executionId, tenantId]);
      
      if (result.rows.length === 0) {
        return null;
      }
      
      return result.rows[0];
      
    } catch (error) {
      console.error('Failed to get execution status:', error);
      throw error;
    }
  }

  async stopExecution(executionId) {
    try {
      const runningExecution = this.runningExecutions.get(executionId);
      
      if (runningExecution) {
        runningExecution.status = 'STOPPED';
        this.runningExecutions.delete(executionId);
      }
      
      const query = `
        UPDATE soar_executions 
        SET status = 'STOPPED', completed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
        WHERE execution_id = $1 AND status = 'RUNNING'
      `;
      
      await this.pool.query(query, [executionId]);
      
      return { success: true, message: 'Execution stopped' };
      
    } catch (error) {
      console.error('Failed to stop execution:', error);
      throw error;
    }
  }

  async getMetrics(timeRange = '24h', tenantId = 'default') {
    try {
      const timeRangeMs = this.getTimeRangeMs(timeRange);
      const startTime = new Date(Date.now() - timeRangeMs);
      
      // Get playbook metrics
      const playbookMetrics = await this.pool.query(`
        SELECT COUNT(*) as total_playbooks
        FROM soar_playbooks 
        WHERE tenant_id = $1 AND enabled = true
      `, [tenantId]);
      
      // Get execution metrics
      const executionMetrics = await this.pool.query(`
        SELECT 
          COUNT(*) as total_executions,
          COUNT(CASE WHEN status = 'RUNNING' THEN 1 END) as active_executions,
          COUNT(CASE WHEN status = 'COMPLETED' THEN 1 END) as successful_executions,
          COUNT(CASE WHEN status = 'FAILED' THEN 1 END) as failed_executions
        FROM soar_executions 
        WHERE tenant_id = $1 AND started_at >= $2
      `, [tenantId, startTime]);
      
      // Get incident metrics
      const incidentMetrics = await this.pool.query(`
        SELECT 
          COUNT(*) as total_incidents,
          COUNT(CASE WHEN DATE(created_at) = CURRENT_DATE THEN 1 END) as incidents_today,
          COUNT(CASE WHEN status = 'RESOLVED' THEN 1 END) as resolved_incidents,
          AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/60) as avg_resolution_time
        FROM soar_incidents 
        WHERE tenant_id = $1 AND created_at >= $2
      `, [tenantId, startTime]);
      
      const execData = executionMetrics.rows[0];
      const incidentData = incidentMetrics.rows[0];
      
      const totalExec = parseInt(execData.total_executions) || 0;
      const successfulExec = parseInt(execData.successful_executions) || 0;
      const successRate = totalExec > 0 ? Math.round((successfulExec / totalExec) * 100) : 0;
      
      const totalIncidents = parseInt(incidentData.total_incidents) || 0;
      const resolvedIncidents = parseInt(incidentData.resolved_incidents) || 0;
      const automationRate = totalIncidents > 0 ? Math.round((resolvedIncidents / totalIncidents) * 100) : 0;
      
      return {
        total_playbooks: parseInt(playbookMetrics.rows[0].total_playbooks) || 0,
        active_executions: parseInt(execData.active_executions) || 0,
        incidents_today: parseInt(incidentData.incidents_today) || 0,
        automation_rate: automationRate,
        avg_response_time: Math.round(parseFloat(incidentData.avg_resolution_time) || 0),
        success_rate: successRate,
        executions_over_time: [], // Would need more complex query
        playbook_usage: [], // Would need more complex query
        incident_trends: [] // Would need more complex query
      };
      
    } catch (error) {
      console.error('Failed to get SOAR metrics:', error);
      throw error;
    }
  }

  getTimeRangeMs(range) {
    const ranges = {
      '1h': 3600000,
      '24h': 86400000,
      '7d': 604800000,
      '30d': 2592000000
    };
    return ranges[range] || ranges['24h'];
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async close() {
    await this.pool.end();
  }
}

module.exports = SOAROrchestrator; 