import axios, { AxiosInstance, AxiosResponse } from 'axios';
import {
  AgentStatus,
  SystemMetrics,
  NetworkMetrics,
  ThreatAlert,
  ThreatRule,
  AgentConfiguration,
  ApiResponse,
  PaginatedResponse,
  SearchParams,
} from '@/types';

// Enhanced types for log collection
export interface LogCollectionStatus {
  isRunning: boolean;
  organizationId: string;
  metrics: {
    totalLogsCollected: number;
    lastCollectionTime: string | null;
    errors: Array<{ source: string; error: string; timestamp: string }>;
    sourceStats: Record<string, { totalLogs: number; lastCollection: string; errors: number }>;
  };
  sources: Record<string, {
    name: string;
    description: string;
    logTypes: string[];
    enabled: boolean;
    collectionInterval: number;
    lastCollection: string | null;
  }>;
  timestamp: string;
}

export interface LogStatistics {
  ids_logs: Array<{
    source: string;
    total_logs: string;
    error_logs: string;
    warning_logs: string;
    high_severity: string;
    logs_1h: string;
    logs_24h: string;
  }>;
  system_logs: Array<{
    facility: string;
    total_logs: string;
    error_logs: string;
    warning_logs: string;
    logs_1h: string;
    logs_24h: string;
  }>;
  recent_activity: Array<{
    table_name: string;
    source: string;
    count: string;
    last_activity: string;
  }>;
  collection_metrics: {
    totalLogsCollected: number;
    lastCollectionTime: string;
    errors: Array<{ source: string; error: string; timestamp: string }>;
    sourceStats: Record<string, { totalLogs: number; lastCollection: string; errors: number }>;
  };
  timestamp: string;
}

export interface IdsLog {
  id: string;
  organization_id: string;
  agent_id: string | null;
  log_level: string;
  source: string;
  category: string;
  message: string;
  severity: string;
  source_ip: string | null;
  dest_ip: string | null;
  rule_id: string | null;
  metadata: any;
  created_at: string;
}

export interface SystemLog {
  id: string;
  organization_id: string;
  agent_id: string | null;
  facility: string;
  priority: string;
  message: string;
  hostname: string;
  timestamp: string;
  created_at: string;
}

export interface NetworkAgent {
  id: string;
  organization_id: string;
  name: string;
  agent_type: string;
  ip_address: string;
  hostname: string;
  operating_system: string;
  version: string;
  status: string;
  last_heartbeat: string;
  configuration: any;
  created_at: string;
  updated_at: string;
}

export interface SecurityEvent {
  id: string;
  organization_id: string;
  agent_id: string | null;
  event_type: string;
  severity: string;
  status: string;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  rule_id: string | null;
  rule_name: string | null;
  description: string;
  mitre_technique: string | null;
  confidence_score: number | null;
  raw_data: any;
  created_at: string;
  updated_at: string;
}

class ApiService {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
        return config;
      },
      (error) => {
        console.error('API Request Error:', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        console.log(`API Response: ${response.status} ${response.config.url}`);
        return response;
      },
      (error) => {
        console.error('API Response Error:', error);
        if (error.response?.status === 401) {
          // Handle unauthorized access
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // ==============================================
  // ENHANCED LOG COLLECTION ENDPOINTS
  // ==============================================

  // Start real-time log collection
  async startLogCollection(organizationId?: string): Promise<{ success: boolean; message: string }> {
    const response = await this.client.post('/api/log-collection/start', { organizationId });
    return response.data;
  }

  // Stop log collection
  async stopLogCollection(): Promise<{ success: boolean; message: string }> {
    const response = await this.client.post('/api/log-collection/stop');
    return response.data;
  }

  // Get log collection status
  async getLogCollectionStatus(): Promise<LogCollectionStatus> {
    const response = await this.client.get<ApiResponse<LogCollectionStatus>>('/api/log-collection/status');
    return response.data.data!;
  }

  // Get log statistics
  async getLogStatistics(organizationId?: string): Promise<LogStatistics> {
    const params = organizationId ? { organizationId } : {};
    const response = await this.client.get<ApiResponse<LogStatistics>>('/api/log-collection/statistics', { params });
    return response.data.data!;
  }

  // Get recent logs from all sources
  async getRecentLogs(organizationId?: string, limit?: number): Promise<{
    ids_logs: IdsLog[];
    system_logs: SystemLog[];
    total_ids_logs: number;
    total_system_logs: number;
    timestamp: string;
  }> {
    const params: any = {};
    if (organizationId) params.organizationId = organizationId;
    if (limit) params.limit = limit;
    
    const response = await this.client.get<ApiResponse<any>>('/api/log-collection/recent-logs', { params });
    return response.data.data!;
  }

  // Get logs by source
  async getLogsBySource(source: string, organizationId?: string, limit?: number): Promise<{
    source: string;
    logs: IdsLog[] | SystemLog[];
    total: number;
    timestamp: string;
  }> {
    const params: any = {};
    if (organizationId) params.organizationId = organizationId;
    if (limit) params.limit = limit;
    
    const response = await this.client.get<ApiResponse<any>>(`/api/log-collection/logs/${source}`, { params });
    return response.data.data!;
  }

  // Get logs by severity
  async getLogsBySeverity(level: string, organizationId?: string, limit?: number): Promise<{
    severity: string;
    ids_logs: IdsLog[];
    system_logs: SystemLog[];
    total_ids_logs: number;
    total_system_logs: number;
  }> {
    const params: any = {};
    if (organizationId) params.organizationId = organizationId;
    if (limit) params.limit = limit;
    
    const response = await this.client.get<ApiResponse<any>>(`/api/log-collection/logs/severity/${level}`, { params });
    return response.data.data!;
  }

  // Search logs
  async searchLogs(query: string, source?: string, severity?: string, organizationId?: string, limit?: number): Promise<{
    query: string;
    ids_logs: IdsLog[];
    system_logs: SystemLog[];
    total_results: number;
    timestamp: string;
  }> {
    const params: any = { query };
    if (source) params.source = source;
    if (severity) params.severity = severity;
    if (organizationId) params.organizationId = organizationId;
    if (limit) params.limit = limit;
    
    const response = await this.client.get<ApiResponse<any>>('/api/log-collection/search', { params });
    return response.data.data!;
  }

  // Generate sample logs
  async generateSampleLogs(organizationId?: string, count?: number): Promise<{
    total_logs: number;
    summary: Array<{
      source: string;
      success: boolean;
      count: number;
      error: string | null;
    }>;
    timestamp: string;
  }> {
    const body: any = {};
    if (organizationId) body.organizationId = organizationId;
    if (count) body.count = count;
    
    const response = await this.client.post<ApiResponse<any>>('/api/log-collection/generate-sample', body);
    return response.data.data!;
  }

  // ==============================================
  // UNIFIED API ENDPOINTS
  // ==============================================

  // Get network agents
  async getNetworkAgents(organizationId?: string): Promise<{
    data: NetworkAgent[];
    total: number;
  }> {
    const response = await this.client.get<ApiResponse<any>>('/api/network-agents');
    return response.data.data!;
  }

  // Get security events
  async getSecurityEvents(organizationId?: string, limit?: number): Promise<{
    data: SecurityEvent[];
    total: number;
    page: number;
    limit: number;
  }> {
    const params: any = {};
    if (limit) params.limit = limit;
    
    const response = await this.client.get<ApiResponse<any>>('/api/security-events', { params });
    return response.data.data!;
  }

  // Get IDS logs
  async getIdsLogs(organizationId?: string, limit?: number): Promise<{
    data: IdsLog[];
    total: number;
    page: number;
    limit: number;
  }> {
    const params: any = {};
    if (limit) params.limit = limit;
    
    const response = await this.client.get<ApiResponse<any>>('/api/ids-logs', { params });
    return response.data.data!;
  }

  // Get system logs
  async getSystemLogs(organizationId?: string, limit?: number): Promise<{
    data: SystemLog[];
    total: number;
    page: number;
    limit: number;
  }> {
    const params: any = {};
    if (limit) params.limit = limit;
    
    const response = await this.client.get<ApiResponse<any>>('/api/system-logs', { params });
    return response.data.data!;
  }

  // Initialize sample data
  async initSampleData(organizationId?: string): Promise<{ success: boolean; message: string }> {
    const response = await this.client.post('/api/init-sample-data');
    return response.data;
  }

  // ==============================================
  // LEGACY ENDPOINTS (for backward compatibility)
  // ==============================================

  // Agent Status
  async getAgentStatus(): Promise<AgentStatus> {
    const response = await this.client.get<ApiResponse<AgentStatus>>('/api/v1/status');
    return response.data.data!;
  }

  async startAgent(): Promise<void> {
    await this.client.post<ApiResponse>('/api/v1/agent/start');
  }

  async stopAgent(): Promise<void> {
    await this.client.post<ApiResponse>('/api/v1/agent/stop');
  }

  async restartAgent(): Promise<void> {
    await this.client.post<ApiResponse>('/api/v1/agent/restart');
  }

  // System Metrics
  async getSystemMetrics(timeRange?: { start: string; end: string }): Promise<SystemMetrics[]> {
    const params = timeRange ? { ...timeRange } : {};
    const response = await this.client.get<ApiResponse<SystemMetrics[]>>('/api/v1/metrics/system', { params });
    return response.data.data!;
  }

  async getLatestSystemMetrics(): Promise<SystemMetrics> {
    const response = await this.client.get<ApiResponse<SystemMetrics>>('/api/v1/metrics/system/latest');
    return response.data.data!;
  }

  // Network Metrics
  async getNetworkMetrics(timeRange?: { start: string; end: string }): Promise<NetworkMetrics[]> {
    const params = timeRange ? { ...timeRange } : {};
    const response = await this.client.get<ApiResponse<NetworkMetrics[]>>('/api/v1/metrics/network', { params });
    return response.data.data!;
  }

  async getLatestNetworkMetrics(): Promise<NetworkMetrics> {
    const response = await this.client.get<ApiResponse<NetworkMetrics>>('/api/v1/metrics/network/latest');
    return response.data.data!;
  }

  async getProtocolDistribution(): Promise<Record<string, number>> {
    const response = await this.client.get<ApiResponse<Record<string, number>>>('/api/v1/metrics/protocols');
    return response.data.data!;
  }

  // Threat Alerts
  async getThreatAlerts(params?: SearchParams): Promise<PaginatedResponse<ThreatAlert>> {
    const searchParams = this.formatSearchParams(params || {});
    const response = await this.client.get<ApiResponse<PaginatedResponse<ThreatAlert>>>('/api/v1/threat-alerts', {
      params: searchParams,
    });
    return response.data.data!;
  }

  async getThreatAlert(id: string): Promise<ThreatAlert> {
    const response = await this.client.get<ApiResponse<ThreatAlert>>(`/api/v1/threat-alerts/${id}`);
    return response.data.data!;
  }

  async updateThreatAlert(id: string, updates: Partial<ThreatAlert>): Promise<ThreatAlert> {
    const response = await this.client.put<ApiResponse<ThreatAlert>>(`/api/v1/threat-alerts/${id}`, updates);
    return response.data.data!;
  }

  // Threat Rules
  async getThreatRules(): Promise<ThreatRule[]> {
    const response = await this.client.get<ApiResponse<ThreatRule[]>>('/api/v1/threat-rules');
    return response.data.data!;
  }

  async updateThreatRule(id: string, updates: Partial<ThreatRule>): Promise<ThreatRule> {
    const response = await this.client.put<ApiResponse<ThreatRule>>(`/api/v1/threat-rules/${id}`, updates);
    return response.data.data!;
  }

  async createThreatRule(rule: Omit<ThreatRule, 'id' | 'triggerCount' | 'lastTriggered'>): Promise<ThreatRule> {
    const response = await this.client.post<ApiResponse<ThreatRule>>('/api/v1/threat-rules', rule);
    return response.data.data!;
  }

  async deleteThreatRule(id: string): Promise<void> {
    await this.client.delete(`/api/v1/threat-rules/${id}`);
  }

  // Configuration
  async getConfiguration(): Promise<AgentConfiguration> {
    const response = await this.client.get<ApiResponse<AgentConfiguration>>('/api/v1/configuration');
    return response.data.data!;
  }

  async updateConfiguration(config: Partial<AgentConfiguration>): Promise<AgentConfiguration> {
    const response = await this.client.put<ApiResponse<AgentConfiguration>>('/api/v1/configuration', config);
    return response.data.data!;
  }

  async resetConfiguration(): Promise<AgentConfiguration> {
    const response = await this.client.post<ApiResponse<AgentConfiguration>>('/api/v1/configuration/reset');
    return response.data.data!;
  }

  async exportConfiguration(): Promise<Blob> {
    const response = await this.client.get('/api/v1/configuration/export', {
      responseType: 'blob',
    });
    return response.data;
  }

  async importConfiguration(file: File): Promise<AgentConfiguration> {
    const formData = new FormData();
    formData.append('config', file);
    const response = await this.client.post<ApiResponse<AgentConfiguration>>('/api/v1/configuration/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data.data!;
  }

  // Logs
  async getLogs(params?: { level?: string; limit?: number; start?: string; end?: string }): Promise<string[]> {
    const response = await this.client.get<ApiResponse<string[]>>('/api/v1/logs', { params });
    return response.data.data!;
  }

  async downloadLogs(): Promise<Blob> {
    const response = await this.client.get('/api/v1/logs/download', {
      responseType: 'blob',
    });
    return response.data;
  }

  // Health Check
  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    const response = await this.client.get<ApiResponse<{ status: string; timestamp: string }>>('/health');
    return response.data.data!;
  }

  // Generic HTTP methods
  async get(url: string, config?: any): Promise<any> {
    const response = await this.client.get(url, config);
    return response.data;
  }

  async post(url: string, data?: any, config?: any): Promise<any> {
    const response = await this.client.post(url, data, config);
    return response.data;
  }

  async put(url: string, data?: any, config?: any): Promise<any> {
    const response = await this.client.put(url, data, config);
    return response.data;
  }

  async patch(url: string, data?: any, config?: any): Promise<any> {
    const response = await this.client.patch(url, data, config);
    return response.data;
  }

  async delete(url: string, config?: any): Promise<any> {
    const response = await this.client.delete(url, config);
    return response.data;
  }

  private formatSearchParams(params: SearchParams): Record<string, any> {
    const formatted: Record<string, any> = {};
    
    if (params.page) formatted.page = params.page;
    if (params.limit) formatted.limit = params.limit;
    if (params.search) formatted.search = params.search;
    if (params.sortBy) formatted.sortBy = params.sortBy;
    if (params.sortOrder) formatted.sortOrder = params.sortOrder;
    if (params.filters) {
      Object.entries(params.filters).forEach(([key, value]) => {
        formatted[`filter_${key}`] = value;
      });
    }
    
    return formatted;
  }
}

// WebSocket Service for real-time updates
export class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private listeners: Map<string, ((data: any) => void)[]> = new Map();

  constructor(private url: string) {}

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.url);
        
        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.reconnectAttempts = 0;
          resolve();
        };
        
        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
          } catch (error) {
            console.error('Error parsing WebSocket message:', error);
          }
        };
        
        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          reject(error);
        };
        
        this.ws.onclose = () => {
          console.log('WebSocket disconnected');
          if (this.reconnectAttempts < this.maxReconnectAttempts) {
            setTimeout(() => this.reconnect(), this.reconnectDelay);
          }
        };
      } catch (error) {
        reject(error);
      }
    });
  }

  private handleMessage(message: any): void {
    const { type, data } = message;
    const callbacks = this.listeners.get(type);
    if (callbacks) {
      callbacks.forEach(callback => callback(data));
    }
  }

  subscribe(type: string, callback: (data: any) => void): () => void {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, []);
    }
    this.listeners.get(type)!.push(callback);
    
    return () => {
      const callbacks = this.listeners.get(type);
      if (callbacks) {
        const index = callbacks.indexOf(callback);
        if (index > -1) {
          callbacks.splice(index, 1);
        }
      }
    };
  }

  private reconnect(): void {
    this.reconnectAttempts++;
    console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
    this.connect().catch(error => {
      console.error('Reconnection failed:', error);
    });
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.listeners.clear();
  }
}

export const createWebSocketService = (path: string = '/ws') => {
  const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';
  const wsUrl = baseUrl.replace('http', 'ws') + path;
  return new WebSocketService(wsUrl);
};

export const apiService = new ApiService(); 