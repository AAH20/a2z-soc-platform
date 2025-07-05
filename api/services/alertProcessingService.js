class AlertProcessingService {
  constructor() {
    this.alertQueue = [];
    this.processingRules = [];
    this.isProcessing = false;
  }

  async processAlert(tenantId, agentId, alert) {
    try {
      console.log(`Processing alert ${alert.id} from agent ${agentId}`);
      
      // Enrich alert with additional metadata
      const enrichedAlert = {
        ...alert,
        tenantId,
        agentId,
        processedAt: new Date(),
        enrichment: {
          agentInfo: await this.getAgentInfo(agentId),
          riskScore: this.calculateRiskScore(alert),
          category: this.categorizeAlert(alert),
          mitreTactics: this.mapToMitre(alert)
        }
      };

      // Apply processing rules
      const processedAlert = await this.applyProcessingRules(enrichedAlert);
      
      // Determine if escalation is needed
      if (this.shouldEscalate(processedAlert)) {
        await this.escalateAlert(processedAlert);
      }

      // Store the processed alert
      await this.storeAlert(processedAlert);

      return {
        success: true,
        alertId: processedAlert.id,
        status: processedAlert.status,
        riskScore: processedAlert.enrichment.riskScore
      };
    } catch (error) {
      console.error('Alert processing error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async processBatchAlerts(tenantId, agentId, alerts) {
    try {
      console.log(`Processing batch of ${alerts.length} alerts from agent ${agentId}`);
      
      const results = [];
      for (const alert of alerts) {
        const result = await this.processAlert(tenantId, agentId, alert);
        results.push(result);
      }

      return {
        success: true,
        processed: results.filter(r => r.success).length,
        failed: results.filter(r => !r.success).length,
        results
      };
    } catch (error) {
      console.error('Batch alert processing error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  calculateRiskScore(alert) {
    let score = 0;
    
    // Base score from severity
    const severityScores = {
      low: 1,
      medium: 3,
      high: 7,
      critical: 9
    };
    score += severityScores[alert.severity] || 1;

    // Additional factors
    if (alert.source === 'external') score += 2;
    if (alert.type === 'malware') score += 3;
    if (alert.type === 'intrusion') score += 4;
    if (alert.type === 'data_exfiltration') score += 5;

    return Math.min(score, 10); // Cap at 10
  }

  categorizeAlert(alert) {
    const categories = {
      malware: ['trojan', 'virus', 'worm', 'backdoor'],
      network: ['intrusion', 'port_scan', 'ddos', 'brute_force'],
      data: ['data_exfiltration', 'unauthorized_access', 'data_leak'],
      system: ['system_compromise', 'privilege_escalation', 'persistence']
    };

    for (const [category, types] of Object.entries(categories)) {
      if (types.some(type => alert.type?.includes(type) || alert.description?.toLowerCase().includes(type))) {
        return category;
      }
    }

    return 'other';
  }

  mapToMitre(alert) {
    // Simple MITRE ATT&CK mapping based on alert characteristics
    const mitreMap = {
      'brute_force': ['T1110'],
      'port_scan': ['T1046'],
      'malware': ['T1055', 'T1059'],
      'data_exfiltration': ['T1041', 'T1048'],
      'privilege_escalation': ['T1068', 'T1134'],
      'persistence': ['T1053', 'T1078']
    };

    const tactics = [];
    for (const [key, ids] of Object.entries(mitreMap)) {
      if (alert.type?.includes(key) || alert.description?.toLowerCase().includes(key)) {
        tactics.push(...ids);
      }
    }

    return [...new Set(tactics)]; // Remove duplicates
  }

  async applyProcessingRules(alert) {
    let processedAlert = { ...alert };
    
    // Apply each processing rule
    for (const rule of this.processingRules) {
      if (this.ruleMatches(rule, processedAlert)) {
        processedAlert = await this.applyRule(rule, processedAlert);
      }
    }

    return processedAlert;
  }

  ruleMatches(rule, alert) {
    // Simple rule matching logic
    if (rule.conditions.severity && rule.conditions.severity !== alert.severity) {
      return false;
    }
    if (rule.conditions.type && !alert.type?.includes(rule.conditions.type)) {
      return false;
    }
    return true;
  }

  async applyRule(rule, alert) {
    const modifiedAlert = { ...alert };
    
    // Apply rule actions
    if (rule.actions.setSeverity) {
      modifiedAlert.severity = rule.actions.setSeverity;
    }
    if (rule.actions.addTag) {
      modifiedAlert.tags = [...(modifiedAlert.tags || []), rule.actions.addTag];
    }
    if (rule.actions.setStatus) {
      modifiedAlert.status = rule.actions.setStatus;
    }

    return modifiedAlert;
  }

  shouldEscalate(alert) {
    return alert.enrichment.riskScore >= 8 || 
           alert.severity === 'critical' ||
           alert.enrichment.category === 'data';
  }

  async escalateAlert(alert) {
    console.log(`Escalating high-risk alert ${alert.id} (Risk Score: ${alert.enrichment.riskScore})`);
    
    // In a real implementation, this would:
    // - Send notifications
    // - Create incidents
    // - Trigger automated responses
    
    alert.escalated = true;
    alert.escalatedAt = new Date();
    
    return { success: true };
  }

  async getAgentInfo(agentId) {
    // Placeholder - would normally fetch from database
    return {
      id: agentId,
      type: 'unknown',
      version: '1.0.0',
      lastSeen: new Date()
    };
  }

  async storeAlert(alert) {
    // Placeholder - would normally store in database/elasticsearch
    console.log(`Storing processed alert ${alert.id}`);
    return { success: true };
  }

  addProcessingRule(rule) {
    this.processingRules.push({
      id: `rule_${Date.now()}`,
      ...rule,
      createdAt: new Date()
    });
  }

  async getProcessingStats(tenantId) {
    return {
      success: true,
      stats: {
        queueLength: this.alertQueue.filter(a => a.tenantId === tenantId).length,
        rulesCount: this.processingRules.length,
        isProcessing: this.isProcessing,
        lastProcessed: new Date()
      }
    };
  }
}

module.exports = AlertProcessingService; 