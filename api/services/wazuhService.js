const axios = require('axios');
const https = require('https');

class WazuhService {
  constructor() {
    this.baseUrl = process.env.WAZUH_API_URL || 'https://localhost:55000';
    this.username = process.env.WAZUH_USERNAME || 'wazuh-wui';
    this.password = process.env.WAZUH_PASSWORD || 'wazuh-wui';
    this.token = null;
    this.tokenExpiry = null;
    
    // Allow self-signed certificates for development
    this.axiosInstance = axios.create({
      httpsAgent: new https.Agent({
        rejectUnauthorized: false
      }),
      timeout: 30000
    });
  }

  async authenticate() {
    try {
      const response = await this.axiosInstance.post(`${this.baseUrl}/security/user/authenticate`, {}, {
        auth: {
          username: this.username,
          password: this.password
        }
      });

      this.token = response.data.data.token;
      this.tokenExpiry = Date.now() + (15 * 60 * 1000); // 15 minutes

      return {
        success: true,
        token: this.token,
        expires_at: new Date(this.tokenExpiry).toISOString()
      };
    } catch (error) {
      throw new Error(`Wazuh authentication failed: ${error.message}`);
    }
  }

  async ensureAuth() {
    if (!this.token || Date.now() >= this.tokenExpiry) {
      await this.authenticate();
    }
  }

  async makeRequest(endpoint, method = 'GET', data = null, params = {}) {
    try {
      await this.ensureAuth();

      const config = {
        method,
        url: `${this.baseUrl}${endpoint}`,
        headers: {
          'Authorization': `Bearer ${this.token}`,
          'Content-Type': 'application/json'
        },
        params
      };

      if (data) {
        config.data = data;
      }

      const response = await this.axiosInstance(config);
      return response.data;
    } catch (error) {
      if (error.response?.status === 401) {
        // Token expired, re-authenticate
        this.token = null;
        await this.ensureAuth();
        return this.makeRequest(endpoint, method, data, params);
      }
      throw new Error(`Wazuh API request failed: ${error.message}`);
    }
  }

  // Connection Testing
  async testConnection() {
    try {
      await this.authenticate();
      const managerInfo = await this.getManagerInfo();
      
      return {
        status: 'connected',
        version: managerInfo.data.affected_items[0].version,
        timestamp: new Date().toISOString(),
        message: 'Successfully connected to Wazuh Manager'
      };
    } catch (error) {
      return {
        status: 'error',
        timestamp: new Date().toISOString(),
        message: error.message
      };
    }
  }

  // Manager Information
  async getManagerInfo() {
    return await this.makeRequest('/manager/info');
  }

  async getManagerStatus() {
    return await this.makeRequest('/manager/status');
  }

  async getManagerConfiguration() {
    return await this.makeRequest('/manager/configuration');
  }

  async getManagerStats() {
    return await this.makeRequest('/manager/stats');
  }

  // Agent Management
  async getAgents(params = {}) {
    return await this.makeRequest('/agents', 'GET', null, params);
  }

  async getAgent(agentId) {
    return await this.makeRequest(`/agents/${agentId}`);
  }

  async getAgentStatus(agentId) {
    return await this.makeRequest(`/agents/${agentId}/stats/logcollector`);
  }

  async addAgent(agentData) {
    return await this.makeRequest('/agents', 'POST', agentData);
  }

  async deleteAgent(agentId) {
    return await this.makeRequest(`/agents/${agentId}`, 'DELETE');
  }

  async restartAgent(agentId) {
    return await this.makeRequest(`/agents/${agentId}/restart`, 'PUT');
  }

  async getAgentKey(agentId) {
    return await this.makeRequest(`/agents/${agentId}/key`);
  }

  async upgradeAgent(agentId) {
    return await this.makeRequest(`/agents/${agentId}/upgrade`, 'PUT');
  }

  async getAgentGroups() {
    return await this.makeRequest('/groups');
  }

  async getAgentGroup(groupId) {
    return await this.makeRequest(`/groups/${groupId}`);
  }

  async addAgentToGroup(agentId, groupId) {
    return await this.makeRequest(`/agents/${agentId}/group/${groupId}`, 'PUT');
  }

  // Rules Management
  async getRules(params = {}) {
    return await this.makeRequest('/rules', 'GET', null, params);
  }

  async getRule(ruleId) {
    return await this.makeRequest(`/rules/${ruleId}`);
  }

  async getRuleGroups() {
    return await this.makeRequest('/rules/groups');
  }

  async getRuleFiles() {
    return await this.makeRequest('/rules/files');
  }

  async getRuleFile(filename) {
    return await this.makeRequest(`/rules/files/${filename}`);
  }

  async updateRuleFile(filename, content) {
    return await this.makeRequest(`/rules/files/${filename}`, 'PUT', { content });
  }

  // Decoders Management
  async getDecoders(params = {}) {
    return await this.makeRequest('/decoders', 'GET', null, params);
  }

  async getDecoder(decoderId) {
    return await this.makeRequest(`/decoders/${decoderId}`);
  }

  async getDecoderFiles() {
    return await this.makeRequest('/decoders/files');
  }

  // Lists Management
  async getLists() {
    return await this.makeRequest('/lists');
  }

  async getList(listName) {
    return await this.makeRequest(`/lists/${listName}`);
  }

  async addListItem(listName, value) {
    return await this.makeRequest(`/lists/${listName}`, 'PUT', { value });
  }

  async deleteListItem(listName, value) {
    return await this.makeRequest(`/lists/${listName}`, 'DELETE', null, { value });
  }

  // Security Events and Alerts
  async getAlerts(params = {}) {
    const defaultParams = {
      limit: 500,
      sort: '-timestamp',
      ...params
    };
    return await this.makeRequest('/alerts', 'GET', null, defaultParams);
  }

  async getAlert(alertId) {
    return await this.makeRequest(`/alerts/${alertId}`);
  }

  async getAlertsSummary(timeRange = '24h') {
    const params = {
      timeframe: timeRange,
      summary: true
    };
    return await this.makeRequest('/alerts/summary', 'GET', null, params);
  }

  // Vulnerability Detection
  async getVulnerabilities(params = {}) {
    return await this.makeRequest('/vulnerability', 'GET', null, params);
  }

  async getAgentVulnerabilities(agentId, params = {}) {
    return await this.makeRequest(`/vulnerability/${agentId}`, 'GET', null, params);
  }

  // Compliance
  async getComplianceResults(params = {}) {
    return await this.makeRequest('/compliance', 'GET', null, params);
  }

  async getAgentCompliance(agentId, params = {}) {
    return await this.makeRequest(`/compliance/${agentId}`, 'GET', null, params);
  }

  // System Check (SCA)
  async getSCAResults(params = {}) {
    return await this.makeRequest('/sca', 'GET', null, params);
  }

  async getAgentSCA(agentId, params = {}) {
    return await this.makeRequest(`/sca/${agentId}`, 'GET', null, params);
  }

  // File Integrity Monitoring (FIM)
  async getFIMEvents(params = {}) {
    return await this.makeRequest('/syscheck', 'GET', null, params);
  }

  async getAgentFIM(agentId, params = {}) {
    return await this.makeRequest(`/syscheck/${agentId}`, 'GET', null, params);
  }

  // Rootcheck
  async getRootcheckResults(params = {}) {
    return await this.makeRequest('/rootcheck', 'GET', null, params);
  }

  async getAgentRootcheck(agentId, params = {}) {
    return await this.makeRequest(`/rootcheck/${agentId}`, 'GET', null, params);
  }

  // Cluster Management
  async getClusterStatus() {
    return await this.makeRequest('/cluster/status');
  }

  async getClusterNodes() {
    return await this.makeRequest('/cluster/nodes');
  }

  async getClusterConfig() {
    return await this.makeRequest('/cluster/configuration');
  }

  // Statistics and Analytics
  async getStatistics(component = 'logcollector') {
    return await this.makeRequest(`/stats/${component}`);
  }

  async getHourlyStats() {
    return await this.makeRequest('/stats/hourly');
  }

  async getWeeklyStats() {
    return await this.makeRequest('/stats/weekly');
  }

  // MITRE ATT&CK Framework
  async getMitreAttacks(params = {}) {
    return await this.makeRequest('/mitre', 'GET', null, params);
  }

  async getMitreAttack(attackId) {
    return await this.makeRequest(`/mitre/${attackId}`);
  }

  // Active Response
  async getActiveResponses() {
    return await this.makeRequest('/active-response');
  }

  async runActiveResponse(command, agentIds = []) {
    return await this.makeRequest('/active-response', 'PUT', {
      command,
      agents: agentIds
    });
  }

  // Log Analysis
  async analyzeLogFormat(sample) {
    return await this.makeRequest('/logtest', 'PUT', { log_format: sample });
  }

  async testRule(ruleText, logSample) {
    return await this.makeRequest('/logtest', 'PUT', {
      rule: ruleText,
      log: logSample
    });
  }

  // Custom Analytics Methods
  async getAgentSummary() {
    try {
      const agents = await this.getAgents();
      const summary = {
        total: agents.data.total_affected_items,
        active: 0,
        inactive: 0,
        never_connected: 0,
        pending: 0,
        by_os: {},
        by_version: {},
        timestamp: new Date().toISOString()
      };

      agents.data.affected_items.forEach(agent => {
        // Count by status
        summary[agent.status]++;

        // Count by OS
        if (agent.os?.name) {
          summary.by_os[agent.os.name] = (summary.by_os[agent.os.name] || 0) + 1;
        }

        // Count by version
        if (agent.version) {
          summary.by_version[agent.version] = (summary.by_version[agent.version] || 0) + 1;
        }
      });

      return summary;
    } catch (error) {
      throw new Error(`Failed to get agent summary: ${error.message}`);
    }
  }

  async getSecurityOverview(timeRange = '24h') {
    try {
      const [alerts, agentSummary, managerStats] = await Promise.all([
        this.getAlertsSummary(timeRange),
        this.getAgentSummary(),
        this.getManagerStats()
      ]);

      return {
        alerts: alerts.data,
        agents: agentSummary,
        manager: managerStats.data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get security overview: ${error.message}`);
    }
  }

  async getTopAlerts(limit = 10, timeRange = '24h') {
    try {
      const params = {
        timeframe: timeRange,
        limit,
        sort: '-count'
      };
      
      const alerts = await this.getAlerts(params);
      
      // Group alerts by rule ID and count occurrences
      const groupedAlerts = {};
      alerts.data.affected_items.forEach(alert => {
        const ruleId = alert.rule.id;
        if (!groupedAlerts[ruleId]) {
          groupedAlerts[ruleId] = {
            rule: alert.rule,
            count: 0,
            latest_timestamp: alert.timestamp
          };
        }
        groupedAlerts[ruleId].count++;
        if (alert.timestamp > groupedAlerts[ruleId].latest_timestamp) {
          groupedAlerts[ruleId].latest_timestamp = alert.timestamp;
        }
      });

      // Sort by count and return top results
      return Object.values(groupedAlerts)
        .sort((a, b) => b.count - a.count)
        .slice(0, limit);
    } catch (error) {
      throw new Error(`Failed to get top alerts: ${error.message}`);
    }
  }

  async getComplianceStatus() {
    try {
      const compliance = await this.getComplianceResults();
      
      const status = {
        total_checks: 0,
        passed: 0,
        failed: 0,
        by_standard: {},
        by_agent: {},
        timestamp: new Date().toISOString()
      };

      compliance.data.affected_items.forEach(item => {
        status.total_checks++;
        if (item.result === 'passed') {
          status.passed++;
        } else {
          status.failed++;
        }

        // Group by standard
        const standard = item.compliance?.standard || 'unknown';
        if (!status.by_standard[standard]) {
          status.by_standard[standard] = { passed: 0, failed: 0 };
        }
        status.by_standard[standard][item.result]++;

        // Group by agent
        const agentId = item.agent.id;
        if (!status.by_agent[agentId]) {
          status.by_agent[agentId] = { 
            name: item.agent.name,
            passed: 0, 
            failed: 0 
          };
        }
        status.by_agent[agentId][item.result]++;
      });

      return status;
    } catch (error) {
      throw new Error(`Failed to get compliance status: ${error.message}`);
    }
  }

  // Health Check
  async getServiceHealth() {
    try {
      const [managerInfo, managerStatus, agentSummary] = await Promise.all([
        this.getManagerInfo(),
        this.getManagerStatus(),
        this.getAgentSummary()
      ]);

      return {
        status: 'healthy',
        version: managerInfo.data.affected_items[0].version,
        manager_status: managerStatus.data.affected_items[0],
        agents: {
          total: agentSummary.total,
          active: agentSummary.active,
          inactive: agentSummary.inactive
        },
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'error',
        message: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  // Event Streaming (mock implementation)
  async streamEvents(callback, filters = {}) {
    try {
      // Mock real-time event streaming
      const interval = setInterval(async () => {
        try {
          const alerts = await this.getAlerts({
            limit: 10,
            sort: '-timestamp',
            ...filters
          });

          if (alerts.data.affected_items.length > 0) {
            callback(null, alerts.data.affected_items);
          }
        } catch (error) {
          callback(error, null);
        }
      }, 5000); // Poll every 5 seconds

      return {
        stop: () => clearInterval(interval),
        interval_id: interval
      };
    } catch (error) {
      throw new Error(`Failed to start event streaming: ${error.message}`);
    }
  }
}

module.exports = WazuhService; 