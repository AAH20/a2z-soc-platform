const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');

// Import all integration services
const WazuhService = require('../services/wazuhService');
const ElasticsearchService = require('../services/elasticsearchService');
const OpenSearchService = require('../services/opensearchService');
const SnortService = require('../services/snortService');
const SuricataService = require('../services/suricataService');

// Initialize services
const wazuhService = new WazuhService();
const elasticsearchService = new ElasticsearchService();
const opensearchService = new OpenSearchService();
const snortService = new SnortService();
const suricataService = new SuricataService();

// =============================================================================
// WAZUH ROUTES
// =============================================================================

// Wazuh Health Check
router.get('/wazuh/health', async (req, res) => {
  try {
    const health = await wazuhService.testConnection();
    res.json(health);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Wazuh Manager Info
router.get('/wazuh/manager/info', async (req, res) => {
  try {
    const info = await wazuhService.getManagerInfo();
    res.json(info);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/wazuh/manager/status', async (req, res) => {
  try {
    const status = await wazuhService.getManagerStatus();
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/wazuh/manager/stats', async (req, res) => {
  try {
    const stats = await wazuhService.getManagerStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Wazuh Agents
router.get('/wazuh/agents', async (req, res) => {
  try {
    const agents = await wazuhService.getAgents(req.query);
    res.json(agents);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/wazuh/agents/summary', async (req, res) => {
  try {
    const summary = await wazuhService.getAgentSummary();
    res.json(summary);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/wazuh/agents/:id', async (req, res) => {
  try {
    const agent = await wazuhService.getAgent(req.params.id);
    res.json(agent);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.put('/wazuh/agents/:id/restart', async (req, res) => {
  try {
    const result = await wazuhService.restartAgent(req.params.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Wazuh Alerts
router.get('/wazuh/alerts', async (req, res) => {
  try {
    const alerts = await wazuhService.getAlerts(req.query);
    res.json(alerts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/wazuh/alerts/summary', async (req, res) => {
  try {
    const timeRange = req.query.timeRange || '24h';
    const summary = await wazuhService.getAlertsSummary(timeRange);
    res.json(summary);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/wazuh/alerts/top', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const timeRange = req.query.timeRange || '24h';
    const topAlerts = await wazuhService.getTopAlerts(limit, timeRange);
    res.json(topAlerts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Wazuh Rules
router.get('/wazuh/rules', async (req, res) => {
  try {
    const rules = await wazuhService.getRules(req.query);
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/wazuh/rules/:id', async (req, res) => {
  try {
    const rule = await wazuhService.getRule(req.params.id);
    res.json(rule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Wazuh Security Overview
router.get('/wazuh/overview', async (req, res) => {
  try {
    const timeRange = req.query.timeRange || '24h';
    const overview = await wazuhService.getSecurityOverview(timeRange);
    res.json(overview);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// ELASTICSEARCH ROUTES
// =============================================================================

// Elasticsearch Health Check
router.get('/elasticsearch/health', async (req, res) => {
  try {
    const health = await elasticsearchService.testConnection();
    res.json(health);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Elasticsearch Cluster Info
router.get('/elasticsearch/cluster/health', async (req, res) => {
  try {
    const health = await elasticsearchService.getClusterHealth();
    res.json(health);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/elasticsearch/cluster/status', async (req, res) => {
  try {
    const status = await elasticsearchService.getClusterStatus();
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Elasticsearch Indices
router.get('/elasticsearch/indices', async (req, res) => {
  try {
    const pattern = req.query.pattern || '*';
    const indices = await elasticsearchService.getIndices(pattern);
    res.json(indices);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/elasticsearch/indices/:name/stats', async (req, res) => {
  try {
    const stats = await elasticsearchService.getIndexStats(req.params.name);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Elasticsearch Search
router.post('/elasticsearch/search', async (req, res) => {
  try {
    const results = await elasticsearchService.searchDocuments(req.body);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Elasticsearch Security Events
router.get('/elasticsearch/security/events', async (req, res) => {
  try {
    const events = await elasticsearchService.getSecurityEvents(req.query);
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/elasticsearch/security/statistics', async (req, res) => {
  try {
    const timeRange = req.query.timeRange || '24h';
    const stats = await elasticsearchService.getAlertStatistics(timeRange);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Elasticsearch Logs
router.get('/elasticsearch/logs', async (req, res) => {
  try {
    const logs = await elasticsearchService.getLogs(req.query);
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// OPENSEARCH ROUTES
// =============================================================================

// OpenSearch Health Check
router.get('/opensearch/health', async (req, res) => {
  try {
    const health = await opensearchService.testConnection();
    res.json(health);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OpenSearch Cluster Info
router.get('/opensearch/cluster/health', async (req, res) => {
  try {
    const health = await opensearchService.getClusterHealth();
    res.json(health);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/opensearch/cluster/status', async (req, res) => {
  try {
    const status = await opensearchService.getClusterStatus();
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OpenSearch Indices
router.get('/opensearch/indices', async (req, res) => {
  try {
    const pattern = req.query.pattern || '*';
    const indices = await opensearchService.getIndices(pattern);
    res.json(indices);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OpenSearch Search
router.post('/opensearch/search', async (req, res) => {
  try {
    const results = await opensearchService.searchDocuments(req.body);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OpenSearch Security
router.get('/opensearch/security/config', async (req, res) => {
  try {
    const config = await opensearchService.getSecurityConfig();
    res.json(config);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/opensearch/security/events', async (req, res) => {
  try {
    const events = await opensearchService.getSecurityEvents(req.query);
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OpenSearch Anomaly Detection
router.get('/opensearch/anomaly/detectors', async (req, res) => {
  try {
    const detectors = await opensearchService.getAnomalyDetectors();
    res.json(detectors);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// OpenSearch Dashboards
router.get('/opensearch/dashboards/info', async (req, res) => {
  try {
    const info = await opensearchService.getDashboardsInfo();
    res.json(info);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// SNORT ROUTES
// =============================================================================

// Snort Health Check
router.get('/snort/health', async (req, res) => {
  try {
    const health = await snortService.testConnection();
    res.json(health);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Snort Service Management
router.get('/snort/status', async (req, res) => {
  try {
    const status = await snortService.getServiceStatus();
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start Snort IDS
router.post('/snort/start', [
  body('networkInterface').optional().isString(),
  body('options').optional().isObject()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { networkInterface = 'eth0', options = {} } = req.body;
    const result = await snortService.startSnort(networkInterface, options);

    res.json({
      message: 'Snort IDS started successfully',
      data: result
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to start Snort IDS',
      message: error.message
    });
  }
});

router.post('/snort/stop', async (req, res) => {
  try {
    const result = await snortService.stopSnort();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Restart Snort IDS
router.post('/snort/restart', [
  body('networkInterface').optional().isString(),
  body('options').optional().isObject()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { networkInterface = 'eth0', options = {} } = req.body;
    const result = await snortService.restartSnort(networkInterface, options);

    res.json({
      message: 'Snort IDS restarted successfully',
      data: result
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to restart Snort IDS',
      message: error.message
    });
  }
});

// Snort Rules
router.get('/snort/rules', async (req, res) => {
  try {
    const category = req.query.category || null;
    const rules = await snortService.getRules(category);
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/snort/rules/categories', async (req, res) => {
  try {
    const categories = await snortService.getRuleCategories();
    res.json(categories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/snort/rules/update', async (req, res) => {
  try {
    const result = await snortService.updateRulesFromCache();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Snort Alerts
router.get('/snort/alerts', async (req, res) => {
  try {
    const alerts = await snortService.getAlerts(req.query);
    res.json(alerts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/snort/alerts/statistics', async (req, res) => {
  try {
    const timeRange = req.query.timeRange || '24h';
    const stats = await snortService.getAlertStatistics(timeRange);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Snort Performance
router.get('/snort/performance', async (req, res) => {
  try {
    const stats = await snortService.getPerformanceStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Snort Configuration
router.get('/snort/config', async (req, res) => {
  try {
    const config = await snortService.getConfiguration();
    res.json(config);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/snort/config/validate', async (req, res) => {
  try {
    const validation = await snortService.validateConfiguration();
    res.json(validation);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// SURICATA ROUTES
// =============================================================================

// Suricata Health Check
router.get('/suricata/health', async (req, res) => {
  try {
    const health = await suricataService.testConnection();
    res.json(health);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Suricata Service Management
router.get('/suricata/status', async (req, res) => {
  try {
    const status = await suricataService.getServiceStatus();
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start Suricata IDS
router.post('/suricata/start', [
  body('networkInterface').optional().isString(),
  body('options').optional().isObject()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { networkInterface = 'eth0', options = {} } = req.body;
    const result = await suricataService.startSuricata(networkInterface, options);

    res.json({
      message: 'Suricata IDS started successfully',
      data: result
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to start Suricata IDS',
      message: error.message
    });
  }
});

router.post('/suricata/stop', async (req, res) => {
  try {
    const result = await suricataService.stopSuricata();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Restart Suricata IDS
router.post('/suricata/restart', [
  body('networkInterface').optional().isString(),
  body('options').optional().isObject()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array()
      });
    }

    const { networkInterface = 'eth0', options = {} } = req.body;
    const result = await suricataService.restartSuricata(networkInterface, options);

    res.json({
      message: 'Suricata IDS restarted successfully',
      data: result
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to restart Suricata IDS',
      message: error.message
    });
  }
});

router.post('/suricata/rules/reload', async (req, res) => {
  try {
    const result = await suricataService.reloadRules();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Suricata Rules
router.get('/suricata/rules', async (req, res) => {
  try {
    const source = req.query.source || null;
    const rules = await suricataService.getRules(source);
    res.json(rules);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/suricata/rules/sources', async (req, res) => {
  try {
    const sources = await suricataService.getRuleSources();
    res.json(sources);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/suricata/rules/update', async (req, res) => {
  try {
    const result = await suricataService.updateRulesFromSources();
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Suricata Alerts
router.get('/suricata/alerts', async (req, res) => {
  try {
    const alerts = await suricataService.getAlerts(req.query);
    res.json(alerts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/suricata/alerts/statistics', async (req, res) => {
  try {
    const timeRange = req.query.timeRange || '24h';
    const stats = await suricataService.getAlertStatistics(timeRange);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Suricata Eve JSON Logs
router.get('/suricata/flows', async (req, res) => {
  try {
    const flows = await suricataService.getFlowData(req.query);
    res.json(flows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/suricata/http', async (req, res) => {
  try {
    const logs = await suricataService.getHttpLogs(req.query);
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/suricata/dns', async (req, res) => {
  try {
    const logs = await suricataService.getDnsLogs(req.query);
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/suricata/tls', async (req, res) => {
  try {
    const events = await suricataService.getTlsEvents(req.query);
    res.json(events);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.get('/suricata/files', async (req, res) => {
  try {
    const files = await suricataService.getFileExtractions(req.query);
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Suricata Performance
router.get('/suricata/performance', async (req, res) => {
  try {
    const stats = await suricataService.getPerformanceStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Suricata Configuration
router.get('/suricata/config', async (req, res) => {
  try {
    const config = await suricataService.getConfiguration();
    res.json(config);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/suricata/config/validate', async (req, res) => {
  try {
    const validation = await suricataService.validateConfiguration();
    res.json(validation);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// COMBINED INTEGRATION STATUS
// =============================================================================

router.get('/status/all', async (req, res) => {
  try {
    const [wazuhHealth, elasticsearchHealth, opensearchHealth, snortHealth, suricataHealth] = await Promise.allSettled([
      wazuhService.getServiceHealth(),
      elasticsearchService.getServiceHealth(),
      opensearchService.getServiceHealth(),
      snortService.testConnection(),
      suricataService.testConnection()
    ]);

    const status = {
      wazuh: wazuhHealth.status === 'fulfilled' ? wazuhHealth.value : { status: 'error', message: wazuhHealth.reason?.message },
      elasticsearch: elasticsearchHealth.status === 'fulfilled' ? elasticsearchHealth.value : { status: 'error', message: elasticsearchHealth.reason?.message },
      opensearch: opensearchHealth.status === 'fulfilled' ? opensearchHealth.value : { status: 'error', message: opensearchHealth.reason?.message },
      snort: snortHealth.status === 'fulfilled' ? snortHealth.value : { status: 'error', message: snortHealth.reason?.message },
      suricata: suricataHealth.status === 'fulfilled' ? suricataHealth.value : { status: 'error', message: suricataHealth.reason?.message },
      timestamp: new Date().toISOString()
    };

    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// INTEGRATION OVERVIEW DASHBOARD
// =============================================================================

router.get('/overview', async (req, res) => {
  try {
    const timeRange = req.query.timeRange || '24h';
    
    const [
      wazuhOverview,
      elasticsearchStats,
      snortAlerts,
      suricataAlerts
    ] = await Promise.allSettled([
      wazuhService.getSecurityOverview(timeRange),
      elasticsearchService.getAlertStatistics(timeRange),
      snortService.getAlertStatistics(timeRange),
      suricataService.getAlertStatistics(timeRange)
    ]);

    const overview = {
      wazuh: wazuhOverview.status === 'fulfilled' ? wazuhOverview.value : null,
      elasticsearch: elasticsearchStats.status === 'fulfilled' ? elasticsearchStats.value : null,
      snort: snortAlerts.status === 'fulfilled' ? snortAlerts.value : null,
      suricata: suricataAlerts.status === 'fulfilled' ? suricataAlerts.value : null,
      timestamp: new Date().toISOString()
    };

    res.json(overview);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router; 