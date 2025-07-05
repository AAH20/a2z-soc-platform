import axios, { AxiosInstance } from 'axios';
import { AgentStatus, SystemMetrics, NetworkMetrics, ThreatAlert, ThreatRule, LogEntry, AgentConfig } from '@/types';

interface SystemInfo {
  platform: string;
  arch: string;
  nodeVersion: string;
  networkInterfaces: NetworkInterface[];
}

interface NetworkInterface {
  name: string;
  addresses: string[];
  type: string;
  active: boolean;
}

interface AgentStatus {
  agentId: string;
  status: string;
  uptime: number;
  version: string;
  lastHeartbeat: string;
  systemInfo: SystemInfo;
}

interface SystemMetrics {
  timestamp: string;
  cpu: {
    usage: number;
    user: number;
    system: number;
    cores: number;
    model: string;
  };
  memory: {
    used: number;
    free: number;
    total: number;
    percentage: number;
  };
}

interface NetworkMetrics {
  timestamp: string;
  totalPackets: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  protocolDistribution: {
    TCP: number;
    UDP: number;
    ICMP: number;
  };
  topSources: Array<{ ip: string; packets: number; bytes: number }>;
  topDestinations: Array<{ ip: string; packets: number; bytes: number }>;
}

interface AgentConfig {
  agentName: string;
  serverEndpoint: string;
  reportingInterval: number;
  logLevel: string;
  autoStart: boolean;
  monitoredInterfaces: string[];
  connectionTimeout: number;
  enableThreatDetection: boolean;
  enableDeepPacketInspection: boolean;
  alertThreshold: string;
  dataRetentionDays: number;
  metricsInterval: number;
  enablePerformanceMonitoring: boolean;
  enableNetworkCapture: boolean;
  maxLogSize: number;
  lastUpdated: string;
}

// Network Agent API Service
class NetworkAgentAPI {
  private api: AxiosInstance;
  private baseURL: string;

  constructor(baseURL: string = '/api') {
    this.baseURL = baseURL;
    this.api = axios.create({
      baseURL,
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add request interceptor for authentication
    this.api.interceptors.request.use((config) => {
      const token = localStorage.getItem('auth_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Add response interceptor for error handling
    this.api.interceptors.response.use(
      (response) => response,
      (error) => {
        console.error('Network Agent API Error:', error);
        throw error;
      }
    );
  }

  async getStatus(): Promise<AgentStatus> {
    const response = await this.api.get('/network-agent/status');
    return response.data.data;
  }

  async getSystemMetrics(): Promise<SystemMetrics> {
    const response = await this.api.get('/network-agent/metrics/system');
    return response.data.data;
  }

  async getNetworkMetrics(): Promise<NetworkMetrics> {
    const response = await this.api.get('/network-agent/metrics/network');
    return response.data.data;
  }

  async getThreats(): Promise<any[]> {
    const response = await this.api.get('/network-agent/threats');
    return response.data.data;
  }

  async getConfig(): Promise<AgentConfig> {
    const response = await this.api.get('/network-agent/config');
    return response.data.data;
  }

  async updateConfig(config: Partial<AgentConfig>): Promise<AgentConfig> {
    const response = await this.api.put('/network-agent/config', config);
    return response.data.data;
  }

  async startAgent(): Promise<void> {
    await this.api.post('/network-agent/start');
  }

  async stopAgent(): Promise<void> {
    await this.api.post('/network-agent/stop');
  }

  async restartAgent(): Promise<void> {
    await this.api.post('/network-agent/restart');
  }

  // Health check
  async healthCheck() {
    const response = await this.api.get('/health');
    return response.data;
  }

  // Agent status
  async getAgentStatus(): Promise<AgentStatus> {
    const response = await this.api.get('/network-agent/status');
    return response.data.data;
  }

  // Protocol distribution
  async getProtocolDistribution(): Promise<Record<string, number>> {
    const response = await this.api.get('/network-agent/metrics/protocols');
    return response.data.data;
  }

  // Threat management
  async getThreatRules(): Promise<ThreatRule[]> {
    const response = await this.api.get('/network-agent/threats/rules');
    return response.data.data || [];
  }

  async updateThreatRule(ruleId: string, rule: Partial<ThreatRule>) {
    const response = await this.api.put(`/network-agent/threats/rules/${ruleId}`, rule);
    return response.data;
  }

  async createThreatRule(rule: Omit<ThreatRule, 'id'>) {
    const response = await this.api.post('/network-agent/threats/rules', rule);
    return response.data;
  }

  async deleteThreatRule(ruleId: string) {
    const response = await this.api.delete(`/network-agent/threats/rules/${ruleId}`);
    return response.data;
  }

  // Logs management
  async getLogs(params?: { 
    level?: string; 
    component?: string; 
    timeRange?: string;
    search?: string;
    limit?: number;
  }): Promise<LogEntry[]> {
    const response = await this.api.get('/network-agent/logs', { params });
    return response.data.data || [];
  }

  async clearLogs() {
    const response = await this.api.delete('/network-agent/logs');
    return response.data;
  }

  async exportLogs(format: 'json' | 'csv' | 'txt' = 'txt') {
    const response = await this.api.get(`/network-agent/logs/export`, {
      params: { format },
      responseType: 'blob'
    });
    return response.data;
  }

  // Network operations
  async getNetworkInterfaces() {
    const response = await this.api.get('/network-agent/network/interfaces');
    return response.data.data;
  }

  async testConnectivity(host: string, port?: number) {
    const response = await this.api.post('/network-agent/network/test', { host, port });
    return response.data;
  }

  // Statistics and reporting
  async getStatistics(timeRange: string = '24h') {
    const response = await this.api.get('/network-agent/statistics', { 
      params: { timeRange } 
    });
    return response.data.data;
  }

  async generateReport(type: 'security' | 'network' | 'performance', timeRange: string = '24h') {
    const response = await this.api.post('/network-agent/reports/generate', {
      type,
      timeRange
    });
    return response.data;
  }

  // Real-time updates
  createWebSocket(path: string = '/ws'): WebSocket | null {
    try {
      const wsUrl = this.api.defaults.baseURL?.replace('http', 'ws') + path;
      return new WebSocket(wsUrl);
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      return null;
    }
  }
}

// Create singleton instance
const networkAgentAPI = new NetworkAgentAPI();

// Export both class and instance
export { NetworkAgentAPI, networkAgentAPI };
export default NetworkAgentAPI; 