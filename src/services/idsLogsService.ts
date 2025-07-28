import { apiService } from './api';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000/api';

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
  source: 'ids-core' | 'network-agent' | 'detection-engine' | 'packet-capture' | 'active-protection' | 'threat-monitor' | 'real-time-protection';
  agentId: string;
  agentName: string;
  category: 'detection' | 'network' | 'system' | 'security' | 'performance' | 'rule-processing';
  message: string;
  metadata?: {
    sourceIp?: string;
    destinationIp?: string;
    sourcePort?: number;
    destinationPort?: number;
    protocol?: string;
    port?: number;
    ruleId?: string;
    ruleName?: string;
    threatType?: string;
    severity?: string;
    confidence?: number;
    mitreId?: string;
    action?: string;
    packetsProcessed?: number;
    cpuUsage?: number;
    memoryUsage?: number;
    processingTime?: number;
    activeProtection?: string;
    protectionAction?: string;
    isRealTimeProtection?: boolean;
    threatCount?: number;
    threats?: Array<{
      type: string;
      severity: string;
      confidence: number;
      mitreId: string;
      action: string;
    }>;
    analysisEngine?: string;
    interface?: string;
    networkInterface?: string;
    [key: string]: any;
  };
  rawData?: string;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: 'threat-detected' | 'packet-blocked' | 'rule-triggered' | 'anomaly-detected' | 'system-alert';
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  destination: string;
  description: string;
  ruleId?: string;
  ruleName?: string;
  action: 'alert' | 'block' | 'drop' | 'pass';
  confidence: number;
  mitreTactics?: string[];
  mitreId?: string;
  packetInfo?: {
    protocol: string;
    size: number;
    flags: string[];
    payload?: string;
  };
  geoLocation?: {
    sourceCountry?: string;
    sourceCity?: string;
    destCountry?: string;
    destCity?: string;
  };
}

export interface AgentLog {
  agentId: string;
  agentName: string;
  agentType: 'ids-core' | 'network-agent';
  status: 'online' | 'offline' | 'error';
  logs: LogEntry[];
  totalLogs: number;
  logLevels: Record<string, number>;
  lastActivity: string;
}

export interface LogsFilter {
  agentId?: string;
  level?: string | string[];
  source?: string;
  category?: string;
  startDate?: string;
  endDate?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface LogsStatistics {
  totalLogs: number;
  logsPerLevel: Record<string, number>;
  logsPerSource: Record<string, number>;
  logsPerCategory: Record<string, number>;
  recentActivity: Array<{ timestamp: string; count: number }>;
  topAgents: Array<{ agentId: string; agentName: string; logCount: number }>;
}

class IDSLogsService {
  private baseUrl: string = '/api';

  async getLogs(filter: LogsFilter = {}): Promise<{
    logs: LogEntry[];
    total: number;
    hasMore: boolean;
  }> {
    try {
      const params = new URLSearchParams();
      
      if (filter.agentId) params.append('agent_id', filter.agentId);
      if (filter.level) {
        const levels = Array.isArray(filter.level) ? filter.level : [filter.level];
        levels.forEach(level => params.append('level', level));
      }
      if (filter.source) params.append('source', filter.source);
      if (filter.category) params.append('category', filter.category);
      if (filter.startDate) params.append('start_date', filter.startDate);
      if (filter.endDate) params.append('end_date', filter.endDate);
      if (filter.search) params.append('search', filter.search);
      if (filter.limit) params.append('limit', filter.limit.toString());
      if (filter.offset) params.append('offset', filter.offset.toString());

      const response = await apiService.get(`/ids-logs?${params.toString()}`);
      
      if (response.data.success) {
        return {
          logs: response.data.data || [],
          total: response.data.total || 0,
          hasMore: response.data.has_more || false
        };
      }

      throw new Error('Failed to fetch logs');
    } catch (error) {
      console.error('Error fetching logs:', error);
      return {
        logs: [],
        total: 0,
        hasMore: false
      };
    }
  }

  async getSecurityEvents(): Promise<{ events: SecurityEvent[]; total: number }> {
    try {
      const response = await apiService.get('/api/security-events?limit=100');
      
      if (response.data.success) {
        const events = response.data.data.data || [];
        return {
          events: events.map((event: any) => ({
            id: event.id,
            timestamp: event.created_at,
            type: event.event_type,
            severity: event.severity,
            source: event.source_ip || 'Unknown',
            destination: event.destination_ip || 'Unknown',
            description: event.description,
            ruleId: event.rule_id,
            ruleName: event.rule_name,
            action: 'alert',
            confidence: event.confidence_score || 0.8,
            mitreTactics: event.mitre_technique ? [event.mitre_technique] : [],
            mitreId: event.mitre_technique,
            packetInfo: {
              protocol: event.protocol || 'Unknown',
              size: 0,
              flags: []
            }
          })),
          total: response.data.data.total || events.length
        };
      }

      throw new Error('Failed to fetch security events');
    } catch (error) {
      console.error('Error fetching security events:', error);
      return { events: [], total: 0 };
    }
  }

  async getAgentLogs(agentId: string): Promise<AgentLog> {
    try {
      const response = await apiService.get(`/ids-logs?agent_id=${agentId}&limit=1000`);
      
      if (response.data.success) {
        const logs = response.data.data || [];
        
        // Calculate log level distribution
        const logLevels: Record<string, number> = {};
        logs.forEach((log: LogEntry) => {
          logLevels[log.level] = (logLevels[log.level] || 0) + 1;
        });

        // Get agent info
        const agentResponse = await apiService.get(`/api/network-agents/${agentId}`);
        const agentName = agentResponse.data.data?.name || `Agent ${agentId}`;

        return {
          agentId,
          agentName,
          logs,
          totalLogs: response.data.total || logs.length,
          logLevels,
          lastActivity: logs.length > 0 ? logs[0].timestamp : new Date().toISOString()
        };
      }

      throw new Error('Failed to fetch agent logs');
    } catch (error) {
      console.error('Error fetching agent logs:', error);
      return {
        agentId,
        agentName: `Agent ${agentId}`,
        logs: [],
        totalLogs: 0,
        logLevels: {},
        lastActivity: new Date().toISOString()
      };
    }
  }

  async getStatistics(): Promise<LogsStatistics> {
    try {
      const response = await apiService.get('/ids-logs/statistics');
      
      if (response.data.success) {
        return response.data.data;
      }

      throw new Error('Failed to fetch statistics');
    } catch (error) {
      console.error('Error fetching statistics:', error);
      return {
        totalLogs: 0,
        logsPerLevel: {},
        logsPerSource: {},
        logsPerCategory: {},
        recentActivity: [],
        topAgents: []
      };
    }
  }

  async exportLogs(filter: LogsFilter = {}, format: 'json' | 'csv' = 'json'): Promise<Blob> {
    try {
      const params = new URLSearchParams();
      
      if (filter.agentId) params.append('agent_id', filter.agentId);
      if (filter.level) {
        const levels = Array.isArray(filter.level) ? filter.level : [filter.level];
        levels.forEach(level => params.append('level', level));
      }
      if (filter.source) params.append('source', filter.source);
      if (filter.category) params.append('category', filter.category);
      if (filter.startDate) params.append('start_date', filter.startDate);
      if (filter.endDate) params.append('end_date', filter.endDate);
      if (filter.search) params.append('search', filter.search);
      params.append('format', format);

      const response = await fetch(`${this.baseUrl}/ids-logs/export?${params.toString()}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });

      if (!response.ok) {
        throw new Error('Export failed');
      }

      return await response.blob();
    } catch (error) {
      console.error('Error exporting logs:', error);
      throw error;
    }
  }

  async clearLogs(agentId?: string, beforeDate?: string): Promise<boolean> {
    try {
      const body: any = {};
      if (agentId) body.agent_id = agentId;
      if (beforeDate) body.before_date = beforeDate;

      const response = await apiService.delete('/ids-logs', { data: body });
      return response.data.success;
    } catch (error) {
      console.error('Error clearing logs:', error);
      return false;
    }
  }

  async updateEventStatus(eventId: string, status: string, notes?: string): Promise<boolean> {
    try {
      const response = await apiService.put(`/api/security-events/${eventId}`, {
        status,
        notes
      });
      return response.data.success;
    } catch (error) {
      console.error('Error updating event status:', error);
      return false;
    }
  }

  async acknowledgeEvent(eventId: string, userId: string, notes?: string): Promise<boolean> {
    try {
      const response = await apiService.post(`/api/security-events/${eventId}/acknowledge`, {
        user_id: userId,
        notes
      });
      return response.data.success;
    } catch (error) {
      console.error('Error acknowledging event:', error);
      return false;
    }
  }

  async getEventDetails(eventId: string): Promise<SecurityEvent | null> {
    try {
      const response = await apiService.get(`/api/security-events/${eventId}`);
      
      if (response.data.success) {
        const event = response.data.data;
        return {
          id: event.id,
          timestamp: event.created_at,
          type: event.event_type,
          severity: event.severity,
          source: event.source_ip || 'Unknown',
          destination: event.destination_ip || 'Unknown',
          description: event.description,
          ruleId: event.rule_id,
          ruleName: event.rule_name,
          action: 'alert',
          confidence: event.confidence_score || 0.8,
          mitreTactics: event.mitre_technique ? [event.mitre_technique] : [],
          mitreId: event.mitre_technique,
          packetInfo: {
            protocol: event.protocol || 'Unknown',
            size: 0,
            flags: []
          }
        };
      }

      return null;
    } catch (error) {
      console.error('Error fetching event details:', error);
      return null;
    }
  }
}

export { IDSLogsService };
export default new IDSLogsService(); 