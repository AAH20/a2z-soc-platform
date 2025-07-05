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

  // Threat Detection
  async getThreatAlerts(params?: SearchParams): Promise<PaginatedResponse<ThreatAlert>> {
    const response = await this.client.get<ApiResponse<PaginatedResponse<ThreatAlert>>>('/api/v1/threats/alerts', { 
      params: params ? this.formatSearchParams(params) : undefined 
    });
    return response.data.data!;
  }

  async getThreatAlert(id: string): Promise<ThreatAlert> {
    const response = await this.client.get<ApiResponse<ThreatAlert>>(`/api/v1/threats/alerts/${id}`);
    return response.data.data!;
  }

  async updateThreatAlert(id: string, updates: Partial<ThreatAlert>): Promise<ThreatAlert> {
    const response = await this.client.patch<ApiResponse<ThreatAlert>>(`/api/v1/threats/alerts/${id}`, updates);
    return response.data.data!;
  }

  async getThreatRules(): Promise<ThreatRule[]> {
    const response = await this.client.get<ApiResponse<ThreatRule[]>>('/api/v1/threats/rules');
    return response.data.data!;
  }

  async updateThreatRule(id: string, updates: Partial<ThreatRule>): Promise<ThreatRule> {
    const response = await this.client.patch<ApiResponse<ThreatRule>>(`/api/v1/threats/rules/${id}`, updates);
    return response.data.data!;
  }

  async createThreatRule(rule: Omit<ThreatRule, 'id' | 'triggerCount' | 'lastTriggered'>): Promise<ThreatRule> {
    const response = await this.client.post<ApiResponse<ThreatRule>>('/api/v1/threats/rules', rule);
    return response.data.data!;
  }

  async deleteThreatRule(id: string): Promise<void> {
    await this.client.delete<ApiResponse>(`/api/v1/threats/rules/${id}`);
  }

  // Configuration
  async getConfiguration(): Promise<AgentConfiguration> {
    const response = await this.client.get<ApiResponse<AgentConfiguration>>('/api/v1/config');
    return response.data.data!;
  }

  async updateConfiguration(config: Partial<AgentConfiguration>): Promise<AgentConfiguration> {
    const response = await this.client.patch<ApiResponse<AgentConfiguration>>('/api/v1/config', config);
    return response.data.data!;
  }

  async resetConfiguration(): Promise<AgentConfiguration> {
    const response = await this.client.post<ApiResponse<AgentConfiguration>>('/api/v1/config/reset');
    return response.data.data!;
  }

  async exportConfiguration(): Promise<Blob> {
    const response = await this.client.get('/api/v1/config/export', {
      responseType: 'blob',
    });
    return response.data;
  }

  async importConfiguration(file: File): Promise<AgentConfiguration> {
    const formData = new FormData();
    formData.append('config', file);
    
    const response = await this.client.post<ApiResponse<AgentConfiguration>>('/api/v1/config/import', formData, {
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
    const response = await this.client.get<{ status: string; timestamp: string }>('/health');
    return response.data;
  }

  // Generic API methods for database-driven endpoints
  async get(url: string, config?: any): Promise<any> {
    const response = await this.client.get(url, config);
    return response;
  }

  async post(url: string, data?: any, config?: any): Promise<any> {
    const response = await this.client.post(url, data, config);
    return response;
  }

  async put(url: string, data?: any, config?: any): Promise<any> {
    const response = await this.client.put(url, data, config);
    return response;
  }

  async patch(url: string, data?: any, config?: any): Promise<any> {
    const response = await this.client.patch(url, data, config);
    return response;
  }

  async delete(url: string, config?: any): Promise<any> {
    const response = await this.client.delete(url, config);
    return response;
  }

  // Utilities
  private formatSearchParams(params: SearchParams): Record<string, any> {
    const formatted: Record<string, any> = {
      query: params.query,
      sortBy: params.sortBy,
      sortOrder: params.sortOrder,
      page: params.page,
      limit: params.limit,
    };

    if (params.filters) {
      Object.entries(params.filters).forEach(([key, value]) => {
        formatted[`filter_${key}`] = value;
      });
    }

    return formatted;
  }
}

// WebSocket Service
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
            const message = JSON.parse(event.data);
            this.handleMessage(message);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onclose = () => {
          console.log('WebSocket disconnected');
          this.reconnect();
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          reject(error);
        };
      } catch (error) {
        reject(error);
      }
    });
  }

  private handleMessage(message: any): void {
    const { type, payload } = message;
    const listeners = this.listeners.get(type) || [];
    listeners.forEach(listener => listener(payload));
  }

  subscribe(type: string, callback: (data: any) => void): () => void {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, []);
    }
    this.listeners.get(type)!.push(callback);

    // Return unsubscribe function
    return () => {
      const listeners = this.listeners.get(type) || [];
      const index = listeners.indexOf(callback);
      if (index > -1) {
        listeners.splice(index, 1);
      }
    };
  }

  private reconnect(): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }

    setTimeout(() => {
      this.reconnectAttempts++;
      console.log(`Reconnecting... Attempt ${this.reconnectAttempts}`);
      this.connect().catch(console.error);
    }, this.reconnectDelay * this.reconnectAttempts);
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

// Export singleton instance
export const apiService = new ApiService();

// Export class for custom instances
export default ApiService;

export const createWebSocketService = (path: string = '/ws') => {
  const baseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';
  const wsUrl = baseUrl.replace(/^https?/, 'ws') + path;
  return new WebSocketService(wsUrl);
}; 