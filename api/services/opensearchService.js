const { Client } = require('@opensearch-project/opensearch');

class OpenSearchService {
  constructor() {
    this.client = null;
    this.isConnected = false;
    this.connectionConfig = {
      node: process.env.OPENSEARCH_URL || 'https://localhost:9200',
      auth: {
        username: process.env.OPENSEARCH_USERNAME || 'admin',
        password: process.env.OPENSEARCH_PASSWORD || 'admin'
      },
      ssl: {
        rejectUnauthorized: false // Allow self-signed certificates for development
      },
      requestTimeout: 30000,
      pingTimeout: 3000,
      sniffOnStart: false
    };
    
    this.initialize();
  }

  async initialize() {
    try {
      this.client = new Client(this.connectionConfig);
      await this.testConnection();
      this.isConnected = true;
      console.log('OpenSearch service initialized successfully');
    } catch (error) {
      console.error('Failed to initialize OpenSearch service:', error.message);
      this.isConnected = false;
    }
  }

  async ensureConnection() {
    if (!this.isConnected || !this.client) {
      await this.initialize();
    }
  }

  // Connection and Health
  async testConnection() {
    try {
      const response = await this.client.ping();
      return {
        status: 'connected',
        timestamp: new Date().toISOString(),
        message: 'Successfully connected to OpenSearch'
      };
    } catch (error) {
      throw new Error(`OpenSearch connection failed: ${error.message}`);
    }
  }

  async getClusterHealth() {
    try {
      await this.ensureConnection();
      
      const [health, stats, nodes] = await Promise.all([
        this.client.cluster.health(),
        this.client.cluster.stats(),
        this.client.nodes.info()
      ]);

      return {
        health: health.body,
        stats: stats.body,
        nodes: nodes.body,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get cluster health: ${error.message}`);
    }
  }

  async getClusterStatus() {
    try {
      await this.ensureConnection();
      
      const health = await this.client.cluster.health();
      const stats = await this.client.cluster.stats();
      
      return {
        status: health.body.status,
        cluster_name: health.body.cluster_name,
        number_of_nodes: health.body.number_of_nodes,
        number_of_data_nodes: health.body.number_of_data_nodes,
        active_primary_shards: health.body.active_primary_shards,
        active_shards: health.body.active_shards,
        relocating_shards: health.body.relocating_shards,
        initializing_shards: health.body.initializing_shards,
        unassigned_shards: health.body.unassigned_shards,
        delayed_unassigned_shards: health.body.delayed_unassigned_shards,
        number_of_pending_tasks: health.body.number_of_pending_tasks,
        task_max_waiting_in_queue_millis: health.body.task_max_waiting_in_queue_millis,
        timed_out: health.body.timed_out,
        indices_count: stats.body.indices.count,
        docs_count: stats.body.indices.docs.count,
        store_size: stats.body.indices.store.size_in_bytes,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get cluster status: ${error.message}`);
    }
  }

  // Index Management
  async getIndices(pattern = '*') {
    try {
      await this.ensureConnection();
      
      const response = await this.client.cat.indices({
        index: pattern,
        format: 'json',
        bytes: 'b',
        h: 'index,health,status,pri,rep,docs.count,docs.deleted,store.size,pri.store.size'
      });

      return response.body.map(index => ({
        name: index.index,
        health: index.health,
        status: index.status,
        primary_shards: parseInt(index.pri),
        replica_shards: parseInt(index.rep),
        docs_count: parseInt(index['docs.count']) || 0,
        docs_deleted: parseInt(index['docs.deleted']) || 0,
        store_size: parseInt(index['store.size']) || 0,
        primary_store_size: parseInt(index['pri.store.size']) || 0
      }));
    } catch (error) {
      throw new Error(`Failed to get indices: ${error.message}`);
    }
  }

  async getIndexStats(indexName) {
    try {
      await this.ensureConnection();
      
      const response = await this.client.indices.stats({
        index: indexName,
        human: true
      });

      return response.body;
    } catch (error) {
      throw new Error(`Failed to get index stats for ${indexName}: ${error.message}`);
    }
  }

  async createIndex(indexName, settings = {}, mappings = {}) {
    try {
      await this.ensureConnection();
      
      const body = {};
      if (Object.keys(settings).length > 0) body.settings = settings;
      if (Object.keys(mappings).length > 0) body.mappings = mappings;

      const response = await this.client.indices.create({
        index: indexName,
        body
      });

      return response.body;
    } catch (error) {
      throw new Error(`Failed to create index ${indexName}: ${error.message}`);
    }
  }

  async deleteIndex(indexName) {
    try {
      await this.ensureConnection();
      
      const response = await this.client.indices.delete({
        index: indexName
      });

      return response.body;
    } catch (error) {
      throw new Error(`Failed to delete index ${indexName}: ${error.message}`);
    }
  }

  // Document Operations
  async searchDocuments(params = {}) {
    try {
      await this.ensureConnection();
      
      const searchParams = {
        index: params.index || '_all',
        body: {
          query: params.query || { match_all: {} },
          sort: params.sort || [{ '@timestamp': { order: 'desc' } }],
          size: params.size || 100,
          from: params.from || 0
        }
      };

      if (params.aggregations) {
        searchParams.body.aggs = params.aggregations;
      }

      const response = await this.client.search(searchParams);
      
      return {
        total: response.body.hits.total.value,
        documents: response.body.hits.hits,
        aggregations: response.body.aggregations || {},
        took: response.body.took,
        timed_out: response.body.timed_out
      };
    } catch (error) {
      throw new Error(`Search failed: ${error.message}`);
    }
  }

  async getDocument(indexName, documentId) {
    try {
      await this.ensureConnection();
      
      const response = await this.client.get({
        index: indexName,
        id: documentId
      });

      return response.body;
    } catch (error) {
      throw new Error(`Failed to get document ${documentId} from ${indexName}: ${error.message}`);
    }
  }

  async indexDocument(indexName, document, documentId = null) {
    try {
      await this.ensureConnection();
      
      const params = {
        index: indexName,
        body: document
      };

      if (documentId) {
        params.id = documentId;
      }

      const response = await this.client.index(params);
      return response.body;
    } catch (error) {
      throw new Error(`Failed to index document: ${error.message}`);
    }
  }

  // Security Event Queries
  async getSecurityEvents(params = {}) {
    try {
      const query = {
        bool: {
          must: []
        }
      };

      // Time range filter
      if (params.timeRange) {
        query.bool.must.push({
          range: {
            '@timestamp': {
              gte: params.timeRange.from,
              lte: params.timeRange.to
            }
          }
        });
      }

      // Severity filter
      if (params.severity) {
        query.bool.must.push({
          term: { 'rule.level': params.severity }
        });
      }

      // Agent filter
      if (params.agent) {
        query.bool.must.push({
          term: { 'agent.name': params.agent }
        });
      }

      // Rule ID filter
      if (params.ruleId) {
        query.bool.must.push({
          term: { 'rule.id': params.ruleId }
        });
      }

      // Search text
      if (params.search) {
        query.bool.must.push({
          multi_match: {
            query: params.search,
            fields: ['rule.description', 'full_log', 'data']
          }
        });
      }

      const searchParams = {
        index: params.index || 'opensearch-security-*',
        body: {
          query,
          sort: [{ '@timestamp': { order: 'desc' } }],
          size: params.size || 50,
          from: params.from || 0
        }
      };

      return await this.searchDocuments(searchParams);
    } catch (error) {
      throw new Error(`Failed to get security events: ${error.message}`);
    }
  }

  // Alert Analytics
  async getAlertStatistics(timeRange = '24h') {
    try {
      const query = {
        bool: {
          must: [
            {
              range: {
                '@timestamp': {
                  gte: `now-${timeRange}`
                }
              }
            }
          ]
        }
      };

      const aggregations = {
        severity_breakdown: {
          terms: {
            field: 'rule.level',
            size: 10
          }
        },
        top_rules: {
          terms: {
            field: 'rule.id',
            size: 10
          }
        },
        agent_breakdown: {
          terms: {
            field: 'agent.name',
            size: 10
          }
        },
        timeline: {
          date_histogram: {
            field: '@timestamp',
            calendar_interval: '1h'
          }
        }
      };

      const result = await this.searchDocuments({
        index: 'opensearch-security-*',
        query,
        aggregations,
        size: 0
      });

      return {
        total_alerts: result.total,
        severity_breakdown: result.aggregations.severity_breakdown.buckets,
        top_rules: result.aggregations.top_rules.buckets,
        agent_breakdown: result.aggregations.agent_breakdown.buckets,
        timeline: result.aggregations.timeline.buckets,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get alert statistics: ${error.message}`);
    }
  }

  // Log Management
  async getLogs(params = {}) {
    try {
      const query = {
        bool: {
          must: []
        }
      };

      if (params.timeRange) {
        query.bool.must.push({
          range: {
            '@timestamp': {
              gte: params.timeRange.from,
              lte: params.timeRange.to
            }
          }
        });
      }

      if (params.level) {
        query.bool.must.push({
          term: { 'level': params.level }
        });
      }

      if (params.component) {
        query.bool.must.push({
          term: { 'component': params.component }
        });
      }

      return await this.searchDocuments({
        index: params.index || 'opensearch-logs-*',
        query,
        sort: [{ '@timestamp': { order: 'desc' } }],
        size: params.size || 100,
        from: params.from || 0
      });
    } catch (error) {
      throw new Error(`Failed to get logs: ${error.message}`);
    }
  }

  // Index Templates
  async getIndexTemplates() {
    try {
      await this.ensureConnection();
      
      const response = await this.client.indices.getTemplate();
      return response.body;
    } catch (error) {
      throw new Error(`Failed to get index templates: ${error.message}`);
    }
  }

  async createIndexTemplate(name, template) {
    try {
      await this.ensureConnection();
      
      const response = await this.client.indices.putTemplate({
        name,
        body: template
      });

      return response.body;
    } catch (error) {
      throw new Error(`Failed to create index template ${name}: ${error.message}`);
    }
  }

  // Bulk Operations
  async bulkIndex(operations) {
    try {
      await this.ensureConnection();
      
      const response = await this.client.bulk({
        body: operations,
        refresh: true
      });

      return {
        took: response.body.took,
        errors: response.body.errors,
        items: response.body.items
      };
    } catch (error) {
      throw new Error(`Bulk operation failed: ${error.message}`);
    }
  }

  // OpenSearch Security Plugin
  async getSecurityConfig() {
    try {
      await this.ensureConnection();
      
      // OpenSearch Security plugin API endpoints
      const [users, roles, roleMappings] = await Promise.all([
        this.client.transport.request({
          method: 'GET',
          path: '/_plugins/_security/api/internalusers'
        }).catch(() => ({ body: {} })),
        this.client.transport.request({
          method: 'GET',
          path: '/_plugins/_security/api/roles'
        }).catch(() => ({ body: {} })),
        this.client.transport.request({
          method: 'GET',
          path: '/_plugins/_security/api/rolesmapping'
        }).catch(() => ({ body: {} }))
      ]);

      return {
        users: users.body,
        roles: roles.body,
        role_mappings: roleMappings.body,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.warn('Security plugin not available or not accessible:', error.message);
      return {
        users: {},
        roles: {},
        role_mappings: {},
        error: 'Security plugin not accessible',
        timestamp: new Date().toISOString()
      };
    }
  }

  // OpenSearch Dashboards Integration
  async getDashboardsInfo() {
    try {
      // Mock implementation - would connect to OpenSearch Dashboards API
      return {
        version: '2.11.0',
        status: 'available',
        url: process.env.OPENSEARCH_DASHBOARDS_URL || 'http://localhost:5601',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unavailable',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  // Query DSL Helper
  buildSecurityQuery(filters = {}) {
    const query = {
      bool: {
        must: [],
        filter: []
      }
    };

    if (filters.timeRange) {
      query.bool.filter.push({
        range: {
          '@timestamp': filters.timeRange
        }
      });
    }

    if (filters.severity) {
      query.bool.filter.push({
        terms: { 'rule.level': Array.isArray(filters.severity) ? filters.severity : [filters.severity] }
      });
    }

    if (filters.agents) {
      query.bool.filter.push({
        terms: { 'agent.name': Array.isArray(filters.agents) ? filters.agents : [filters.agents] }
      });
    }

    if (filters.ruleGroups) {
      query.bool.filter.push({
        terms: { 'rule.groups': Array.isArray(filters.ruleGroups) ? filters.ruleGroups : [filters.ruleGroups] }
      });
    }

    if (filters.searchText) {
      query.bool.must.push({
        multi_match: {
          query: filters.searchText,
          fields: ['rule.description^2', 'full_log', 'data', 'location'],
          type: 'best_fields',
          fuzziness: 'AUTO'
        }
      });
    }

    return query;
  }

  // Performance Analyzer (OpenSearch specific)
  async getPerformanceMetrics() {
    try {
      await this.ensureConnection();
      
      // Performance Analyzer API
      const response = await this.client.transport.request({
        method: 'GET',
        path: '/_plugins/_performanceanalyzer/metrics'
      }).catch(() => ({ body: {} }));

      return {
        metrics: response.body,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.warn('Performance Analyzer not available:', error.message);
      return {
        metrics: {},
        error: 'Performance Analyzer not available',
        timestamp: new Date().toISOString()
      };
    }
  }

  // Anomaly Detection (OpenSearch specific)
  async getAnomalyDetectors() {
    try {
      await this.ensureConnection();
      
      const response = await this.client.transport.request({
        method: 'GET',
        path: '/_plugins/_anomaly_detection/detectors'
      }).catch(() => ({ body: { detectors: [] } }));

      return {
        detectors: response.body.detectors || [],
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.warn('Anomaly Detection plugin not available:', error.message);
      return {
        detectors: [],
        error: 'Anomaly Detection plugin not available',
        timestamp: new Date().toISOString()
      };
    }
  }

  async createAnomalyDetector(config) {
    try {
      await this.ensureConnection();
      
      const response = await this.client.transport.request({
        method: 'POST',
        path: '/_plugins/_anomaly_detection/detectors',
        body: config
      });

      return response.body;
    } catch (error) {
      throw new Error(`Failed to create anomaly detector: ${error.message}`);
    }
  }

  // Monitoring
  async getServiceHealth() {
    try {
      const health = await this.getClusterHealth();
      const indices = await this.getIndices();
      const securityConfig = await this.getSecurityConfig();
      
      return {
        status: health.health.status,
        cluster_name: health.health.cluster_name,
        nodes: health.health.number_of_nodes,
        indices_count: indices.length,
        total_documents: indices.reduce((sum, idx) => sum + idx.docs_count, 0),
        total_size_bytes: indices.reduce((sum, idx) => sum + idx.store_size, 0),
        security_enabled: !securityConfig.error,
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

  // Saved Objects (similar to Elasticsearch/Kibana)
  async getSavedObjects(type = null) {
    try {
      // Mock implementation - would integrate with OpenSearch Dashboards
      const savedObjects = {
        dashboards: [
          { id: 'security-overview', title: 'Security Overview Dashboard' },
          { id: 'threat-hunting', title: 'Threat Hunting Dashboard' }
        ],
        visualizations: [
          { id: 'alerts-timeline', title: 'Alerts Timeline' },
          { id: 'top-threats', title: 'Top Threats' }
        ],
        searches: [
          { id: 'failed-logins', title: 'Failed Login Attempts' },
          { id: 'suspicious-traffic', title: 'Suspicious Network Traffic' }
        ]
      };

      if (type) {
        return savedObjects[type] || [];
      }

      return savedObjects;
    } catch (error) {
      throw new Error(`Failed to get saved objects: ${error.message}`);
    }
  }

  // Index State Management (OpenSearch specific)
  async getISMPolicies() {
    try {
      await this.ensureConnection();
      
      const response = await this.client.transport.request({
        method: 'GET',
        path: '/_plugins/_ism/policies'
      }).catch(() => ({ body: { policies: [] } }));

      return {
        policies: response.body.policies || [],
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.warn('ISM plugin not available:', error.message);
      return {
        policies: [],
        error: 'ISM plugin not available',
        timestamp: new Date().toISOString()
      };
    }
  }

  async createISMPolicy(name, policy) {
    try {
      await this.ensureConnection();
      
      const response = await this.client.transport.request({
        method: 'PUT',
        path: `/_plugins/_ism/policies/${name}`,
        body: { policy }
      });

      return response.body;
    } catch (error) {
      throw new Error(`Failed to create ISM policy ${name}: ${error.message}`);
    }
  }
}

module.exports = OpenSearchService; 