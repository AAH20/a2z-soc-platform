const { Pool } = require('pg');
const EventEmitter = require('events');

class SIEMIngestionService extends EventEmitter {
  constructor() {
    super();
    this.pool = new Pool({
      user: process.env.DB_USER || 'postgres',
      host: process.env.DB_HOST || 'localhost',
      database: process.env.DB_NAME || 'a2z_soc',
      password: process.env.DB_PASSWORD || 'postgres',
      port: process.env.DB_PORT || 5432,
    });
    
    this.isRunning = false;
    this.eventsPerSecond = 0;
    this.totalEvents = 0;
    this.correlationEngine = null;
    this.eventBuffer = [];
    this.bufferSize = 1000;
    this.flushInterval = 5000; // 5 seconds
    
    this.initializeCorrelationEngine();
    this.startBufferFlush();
  }

  async initializeCorrelationEngine() {
    try {
      const SIEMCorrelationEngine = require('./siemCorrelationEngine');
      this.correlationEngine = new SIEMCorrelationEngine();
      await this.correlationEngine.initialize();
      
      // Load correlation rules from database
      await this.loadCorrelationRules();
      
      console.log('SIEM Correlation Engine initialized');
    } catch (error) {
      console.error('Failed to initialize correlation engine:', error);
    }
  }

  async loadCorrelationRules() {
    try {
      const query = `
        SELECT rule_id, name, description, query, conditions, severity, time_window, threshold
        FROM siem_correlation_rules 
        WHERE enabled = true
      `;
      const result = await this.pool.query(query);
      
      for (const rule of result.rows) {
        if (this.correlationEngine) {
          this.correlationEngine.addRule({
            id: rule.rule_id,
            name: rule.name,
            description: rule.description,
            query: rule.query,
            conditions: rule.conditions,
            severity: rule.severity,
            timeWindow: rule.time_window,
            threshold: rule.threshold
          });
        }
      }
      
      console.log(`Loaded ${result.rows.length} correlation rules`);
    } catch (error) {
      console.error('Failed to load correlation rules:', error);
    }
  }

  async ingestEvent(eventData, tenantId = 'default') {
    try {
      // Validate and normalize event data
      const normalizedEvent = this.normalizeEvent(eventData, tenantId);
      
      // Add to buffer for batch processing
      this.eventBuffer.push(normalizedEvent);
      
      // Process correlation immediately for critical events
      if (normalizedEvent.severity === 'CRITICAL' || normalizedEvent.severity === 'HIGH') {
        await this.processCorrelation(normalizedEvent);
      }
      
      // Flush buffer if it's full
      if (this.eventBuffer.length >= this.bufferSize) {
        await this.flushEventBuffer();
      }
      
      // Update metrics
      this.totalEvents++;
      this.eventsPerSecond++;
      
      // Emit event for real-time processing
      this.emit('event', normalizedEvent);
      
      return {
        success: true,
        event_id: normalizedEvent.event_id,
        message: 'Event ingested successfully'
      };
      
    } catch (error) {
      console.error('Event ingestion failed:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  normalizeEvent(eventData, tenantId) {
    const now = new Date();
    const eventId = `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Parse source and destination IPs
    const sourceIp = this.extractIP(eventData.source_ip || eventData.src_ip);
    const destinationIp = this.extractIP(eventData.destination_ip || eventData.dst_ip);
    
    // Determine severity based on content
    let severity = eventData.severity || 'LOW';
    if (eventData.message) {
      const message = eventData.message.toLowerCase();
      if (message.includes('critical') || message.includes('malware') || message.includes('virus')) {
        severity = 'CRITICAL';
      } else if (message.includes('failed') || message.includes('error') || message.includes('denied')) {
        severity = 'HIGH';
      } else if (message.includes('warning') || message.includes('suspicious')) {
        severity = 'MEDIUM';
      }
    }
    
    return {
      tenant_id: tenantId,
      event_id: eventId,
      timestamp: eventData.timestamp || now,
      source_type: eventData.source_type || 'unknown',
      source_ip: sourceIp,
      destination_ip: destinationIp,
      source_port: eventData.source_port || null,
      destination_port: eventData.destination_port || null,
      protocol: eventData.protocol || null,
      severity: severity,
      message: eventData.message || '',
      raw_log: eventData.raw_log || JSON.stringify(eventData),
      parsed_data: eventData.parsed_data || eventData,
      tags: eventData.tags || [],
      created_at: now,
      updated_at: now
    };
  }

  extractIP(ipString) {
    if (!ipString) return null;
    
    // Simple IP validation regex
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    
    if (ipRegex.test(ipString)) {
      return ipString;
    }
    
    return null;
  }

  async processCorrelation(event) {
    if (!this.correlationEngine) return;
    
    try {
      const correlationResult = await this.correlationEngine.processEvent(event);
      
      if (correlationResult.alert) {
        await this.createAlert(correlationResult.alert, event.tenant_id);
      }
      
      if (correlationResult.correlation_id) {
        // Update event with correlation ID
        await this.updateEventCorrelation(event.event_id, correlationResult.correlation_id);
      }
      
    } catch (error) {
      console.error('Correlation processing failed:', error);
    }
  }

  async createAlert(alertData, tenantId) {
    try {
      const alertId = `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const now = new Date();
      
      const query = `
        INSERT INTO siem_alerts (
          tenant_id, alert_id, title, description, severity, status,
          source_ip, destination_ip, affected_assets, indicators,
          correlation_rule_id, event_count, first_seen, last_seen,
          created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        RETURNING *
      `;
      
      const values = [
        tenantId,
        alertId,
        alertData.title,
        alertData.description,
        alertData.severity,
        'OPEN',
        alertData.source_ip,
        alertData.destination_ip,
        alertData.affected_assets || [],
        alertData.indicators || {},
        alertData.rule_id,
        alertData.event_count || 1,
        now,
        now,
        now,
        now
      ];
      
      const result = await this.pool.query(query, values);
      
      // Emit alert for real-time notifications
      this.emit('alert', result.rows[0]);
      
      console.log(`Alert created: ${alertId}`);
      return result.rows[0];
      
    } catch (error) {
      console.error('Failed to create alert:', error);
      throw error;
    }
  }

  async updateEventCorrelation(eventId, correlationId) {
    try {
      const query = `
        UPDATE siem_events 
        SET correlation_id = $1, updated_at = CURRENT_TIMESTAMP
        WHERE event_id = $2
      `;
      
      await this.pool.query(query, [correlationId, eventId]);
    } catch (error) {
      console.error('Failed to update event correlation:', error);
    }
  }

  async flushEventBuffer() {
    if (this.eventBuffer.length === 0) return;
    
    try {
      const client = await this.pool.connect();
      
      try {
        await client.query('BEGIN');
        
        // Batch insert events
        const query = `
          INSERT INTO siem_events (
            tenant_id, event_id, timestamp, source_type, source_ip, destination_ip,
            source_port, destination_port, protocol, severity, message, raw_log,
            parsed_data, tags, created_at, updated_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        `;
        
        for (const event of this.eventBuffer) {
          const values = [
            event.tenant_id,
            event.event_id,
            event.timestamp,
            event.source_type,
            event.source_ip,
            event.destination_ip,
            event.source_port,
            event.destination_port,
            event.protocol,
            event.severity,
            event.message,
            event.raw_log,
            event.parsed_data,
            event.tags,
            event.created_at,
            event.updated_at
          ];
          
          await client.query(query, values);
        }
        
        await client.query('COMMIT');
        
        console.log(`Flushed ${this.eventBuffer.length} events to database`);
        this.eventBuffer = [];
        
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      
    } catch (error) {
      console.error('Failed to flush event buffer:', error);
    }
  }

  startBufferFlush() {
    setInterval(async () => {
      if (this.eventBuffer.length > 0) {
        await this.flushEventBuffer();
      }
    }, this.flushInterval);
  }

  async searchEvents(searchParams, tenantId = 'default') {
    try {
      let query = `
        SELECT * FROM siem_events 
        WHERE tenant_id = $1
      `;
      const values = [tenantId];
      let paramIndex = 2;
      
      // Add time range filter
      if (searchParams.filters?.time_range) {
        const { start, end } = searchParams.filters.time_range;
        query += ` AND timestamp BETWEEN $${paramIndex} AND $${paramIndex + 1}`;
        values.push(start, end);
        paramIndex += 2;
      }
      
      // Add source type filter
      if (searchParams.filters?.source_type?.length > 0) {
        query += ` AND source_type = ANY($${paramIndex})`;
        values.push(searchParams.filters.source_type);
        paramIndex++;
      }
      
      // Add severity filter
      if (searchParams.filters?.severity?.length > 0) {
        query += ` AND severity = ANY($${paramIndex})`;
        values.push(searchParams.filters.severity);
        paramIndex++;
      }
      
      // Add text search
      if (searchParams.query) {
        query += ` AND (message ILIKE $${paramIndex} OR raw_log ILIKE $${paramIndex})`;
        values.push(`%${searchParams.query}%`);
        paramIndex++;
      }
      
      // Add ordering and limit
      query += ` ORDER BY timestamp DESC LIMIT $${paramIndex}`;
      values.push(searchParams.size || 100);
      
      const result = await this.pool.query(query, values);
      
      return {
        events: result.rows,
        total: result.rowCount
      };
      
    } catch (error) {
      console.error('Search failed:', error);
      throw error;
    }
  }

  async getMetrics(timeRange = '24h', tenantId = 'default') {
    try {
      const timeRangeMs = this.getTimeRangeMs(timeRange);
      const startTime = new Date(Date.now() - timeRangeMs);
      
      // Get basic metrics
      const metricsQuery = `
        SELECT 
          COUNT(*) as total_events,
          COUNT(DISTINCT source_ip) as unique_sources,
          AVG(CASE WHEN severity = 'CRITICAL' THEN 4 WHEN severity = 'HIGH' THEN 3 WHEN severity = 'MEDIUM' THEN 2 ELSE 1 END) as avg_severity
        FROM siem_events 
        WHERE tenant_id = $1 AND timestamp >= $2
      `;
      
      const metricsResult = await this.pool.query(metricsQuery, [tenantId, startTime]);
      
      // Get active alerts
      const alertsQuery = `
        SELECT COUNT(*) as active_alerts
        FROM siem_alerts 
        WHERE tenant_id = $1 AND status IN ('OPEN', 'IN_PROGRESS')
      `;
      
      const alertsResult = await this.pool.query(alertsQuery, [tenantId]);
      
      // Get events over time
      const eventsOverTimeQuery = `
        SELECT 
          DATE_TRUNC('hour', timestamp) as hour,
          COUNT(*) as count
        FROM siem_events 
        WHERE tenant_id = $1 AND timestamp >= $2
        GROUP BY hour
        ORDER BY hour
      `;
      
      const eventsOverTimeResult = await this.pool.query(eventsOverTimeQuery, [tenantId, startTime]);
      
      // Get events by source type
      const eventsBySourceQuery = `
        SELECT 
          source_type,
          COUNT(*) as count
        FROM siem_events 
        WHERE tenant_id = $1 AND timestamp >= $2
        GROUP BY source_type
        ORDER BY count DESC
      `;
      
      const eventsBySourceResult = await this.pool.query(eventsBySourceQuery, [tenantId, startTime]);
      
      // Get alerts by severity
      const alertsBySeverityQuery = `
        SELECT 
          severity,
          COUNT(*) as count
        FROM siem_alerts 
        WHERE tenant_id = $1 AND created_at >= $2
        GROUP BY severity
        ORDER BY count DESC
      `;
      
      const alertsBySeverityResult = await this.pool.query(alertsBySeverityQuery, [tenantId, startTime]);
      
      const metrics = metricsResult.rows[0];
      const securityScore = Math.max(0, Math.min(100, 100 - (metrics.avg_severity * 20)));
      
      return {
        eventsPerSecond: this.eventsPerSecond,
        totalEvents: parseInt(metrics.total_events),
        activeAlerts: parseInt(alertsResult.rows[0].active_alerts),
        securityScore: Math.round(securityScore),
        riskLevel: securityScore > 80 ? 'LOW' : securityScore > 60 ? 'MEDIUM' : securityScore > 40 ? 'HIGH' : 'CRITICAL',
        eventsOverTime: eventsOverTimeResult.rows.map(row => ({
          timestamp: row.hour,
          count: parseInt(row.count)
        })),
        eventsBySourceType: eventsBySourceResult.rows.map(row => ({
          source_type: row.source_type,
          count: parseInt(row.count)
        })),
        alertsBySeverity: alertsBySeverityResult.rows.map(row => ({
          severity: row.severity,
          count: parseInt(row.count)
        })),
        alertsByStatus: [
          { status: 'OPEN', count: parseInt(alertsResult.rows[0].active_alerts) },
          { status: 'RESOLVED', count: 0 }
        ]
      };
      
    } catch (error) {
      console.error('Failed to get metrics:', error);
      throw error;
    }
  }

  async getAlerts(filters = {}, tenantId = 'default') {
    try {
      let query = `
        SELECT * FROM siem_alerts 
        WHERE tenant_id = $1
      `;
      const values = [tenantId];
      let paramIndex = 2;
      
      // Add status filter
      if (filters.status) {
        query += ` AND status = $${paramIndex}`;
        values.push(filters.status);
        paramIndex++;
      }
      
      // Add severity filter
      if (filters.severity) {
        query += ` AND severity = $${paramIndex}`;
        values.push(filters.severity);
        paramIndex++;
      }
      
      // Add assignee filter
      if (filters.assignee) {
        query += ` AND assigned_to = $${paramIndex}`;
        values.push(filters.assignee);
        paramIndex++;
      }
      
      // Add ordering and limit
      query += ` ORDER BY created_at DESC LIMIT $${paramIndex}`;
      values.push(filters.limit || 50);
      
      const result = await this.pool.query(query, values);
      
      return {
        alerts: result.rows,
        total: result.rowCount
      };
      
    } catch (error) {
      console.error('Failed to get alerts:', error);
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

  start() {
    this.isRunning = true;
    
    // Reset events per second counter every second
    setInterval(() => {
      this.eventsPerSecond = 0;
    }, 1000);
    
    console.log('SIEM Ingestion Service started');
  }

  stop() {
    this.isRunning = false;
    console.log('SIEM Ingestion Service stopped');
  }

  async close() {
    await this.pool.end();
  }
}

module.exports = SIEMIngestionService; 