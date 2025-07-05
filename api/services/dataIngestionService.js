class DataIngestionService {
  constructor() {
    this.eventBuffer = [];
    this.alertBuffer = [];
  }

  async ingestEvents(tenantId, agentId, events) {
    try {
      console.log(`Ingesting ${events.length} events from agent ${agentId}`);
      
      // Process and store events
      const processedEvents = events.map(event => ({
        ...event,
        tenantId,
        agentId,
        timestamp: new Date(),
        id: this.generateEventId()
      }));

      // Add to buffer for batch processing
      this.eventBuffer.push(...processedEvents);

      // If buffer is large enough, process batch
      if (this.eventBuffer.length >= 100) {
        await this.processBatch();
      }

      return {
        success: true,
        processed: processedEvents.length,
        message: 'Events ingested successfully'
      };
    } catch (error) {
      console.error('Event ingestion error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async ingestAlerts(tenantId, agentId, alerts) {
    try {
      console.log(`Ingesting ${alerts.length} alerts from agent ${agentId}`);
      
      // Process and store alerts
      const processedAlerts = alerts.map(alert => ({
        ...alert,
        tenantId,
        agentId,
        timestamp: new Date(),
        id: this.generateAlertId(),
        severity: alert.severity || 'medium',
        status: 'new'
      }));

      // Add to buffer
      this.alertBuffer.push(...processedAlerts);

      return {
        success: true,
        processed: processedAlerts.length,
        message: 'Alerts ingested successfully'
      };
    } catch (error) {
      console.error('Alert ingestion error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async ingestData(tenantId, agentId, data) {
    try {
      const { type, payload } = data;
      
      switch (type) {
        case 'events':
          return await this.ingestEvents(tenantId, agentId, payload);
        case 'alerts':
          return await this.ingestAlerts(tenantId, agentId, payload);
        case 'metrics':
          return await this.ingestMetrics(tenantId, agentId, payload);
        default:
          return {
            success: false,
            error: `Unknown data type: ${type}`
          };
      }
    } catch (error) {
      console.error('Data ingestion error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async ingestMetrics(tenantId, agentId, metrics) {
    try {
      console.log(`Ingesting metrics from agent ${agentId}`);
      
      // Store metrics (placeholder implementation)
      const processedMetrics = {
        ...metrics,
        tenantId,
        agentId,
        timestamp: new Date()
      };

      return {
        success: true,
        message: 'Metrics ingested successfully'
      };
    } catch (error) {
      console.error('Metrics ingestion error:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async processBatch() {
    try {
      console.log(`Processing batch of ${this.eventBuffer.length} events`);
      
      // Placeholder batch processing
      // In real implementation, this would write to database/elasticsearch
      
      // Clear buffer
      this.eventBuffer = [];
      
      return { success: true };
    } catch (error) {
      console.error('Batch processing error:', error);
      return { success: false, error: error.message };
    }
  }

  generateEventId() {
    return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  generateAlertId() {
    return `alt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  async getIngestionStats(tenantId) {
    return {
      success: true,
      stats: {
        eventsInBuffer: this.eventBuffer.filter(e => e.tenantId === tenantId).length,
        alertsInBuffer: this.alertBuffer.filter(a => a.tenantId === tenantId).length,
        lastProcessed: new Date()
      }
    };
  }
}

module.exports = DataIngestionService; 