// Agent Status Types
export interface AgentStatus {
  agentId: string;
  tenantId: string;
  status: 'online' | 'offline' | 'connecting' | 'error';
  uptime: number;
  version: string;
  lastHeartbeat: string;
  systemInfo: {
    platform: string;
    arch: string;
    nodeVersion: string;
    memory: MemoryUsage;
    cpu: CPUUsage;
    networkInterfaces: NetworkInterface[];
  };
}

export interface MemoryUsage {
  rss: number;
  heapUsed: number;
  heapTotal: number;
  external: number;
}

export interface CPUUsage {
  user: number;
  system: number;
}

export interface NetworkInterface {
  name: string;
  addresses: string[];
  type: string;
  active: boolean;
}

// Metrics Types
export interface SystemMetrics {
  timestamp: string;
  cpu: {
    usage: number;
    user: number;
    system: number;
  };
  memory: {
    used: number;
    total: number;
    percentage: number;
  };
  network: {
    packetsReceived: number;
    packetsSent: number;
    bytesReceived: number;
    bytesSent: number;
    errorsReceived: number;
    errorsSent: number;
  };
  disk: {
    used: number;
    total: number;
    percentage: number;
  };
}

export interface NetworkMetrics {
  timestamp: string;
  totalPackets: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  protocolDistribution: Record<string, number>;
  topSources: Array<{
    ip: string;
    packets: number;
    bytes: number;
  }>;
  topDestinations: Array<{
    ip: string;
    packets: number;
    bytes: number;
  }>;
}

// Threat Detection Types
export interface ThreatAlert {
  id: string;
  timestamp: string;
  type: 'signature' | 'anomaly' | 'behavioral' | 'volumetric';
  severity: 'low' | 'medium' | 'high' | 'critical';
  name: string;
  description: string;
  technique: string;
  tactics: string[];
  confidence: number;
  indicators: string[];
  metadata: Record<string, any>;
  status: 'active' | 'investigating' | 'resolved' | 'false_positive';
  assignedTo?: string;
  notes?: string;
}

export interface ThreatRule {
  id: string;
  name: string;
  type: 'signature' | 'anomaly' | 'behavioral' | 'volumetric';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  technique: string;
  tactics: string[];
  enabled: boolean;
  lastTriggered?: string;
  triggerCount: number;
}

// Configuration Types
export interface AgentConfiguration {
  agentId: string;
  tenantId: string;
  networkInterface: string;
  pcapFilter: string;
  bufferSize: number;
  bufferTimeout: number;
  maxBufferSize: number;
  flushInterval: number;
  alertFlushInterval: number;
  heartbeatInterval: number;
  encryption: boolean;
  validateCerts: boolean;
  maxCpuUsage: number;
  maxMemoryUsage: number;
  compressionLevel: number;
  enableThreatDetection: boolean;
  threatSensitivity: 'low' | 'medium' | 'high';
  logLevel: 'error' | 'warn' | 'info' | 'debug' | 'trace';
  platform: PlatformConfig;
}

export interface PlatformConfig {
  windows: {
    serviceMode: boolean;
    autostart: boolean;
  };
  linux: {
    daemonMode: boolean;
    systemdService: boolean;
  };
  darwin: {
    launchdService: boolean;
    autostart: boolean;
  };
}

// API Response Types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  hasMore: boolean;
}

// UI State Types
export interface NotificationState {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  duration?: number;
  actions?: NotificationAction[];
}

export interface NotificationAction {
  label: string;
  action: () => void;
  style?: 'primary' | 'secondary' | 'danger';
}

export interface LoadingState {
  isLoading: boolean;
  message?: string;
}

export interface ErrorState {
  hasError: boolean;
  error?: Error;
  errorId?: string;
}

// Chart Data Types
export interface ChartDataPoint {
  timestamp: string;
  value: number;
  label?: string;
}

export interface TimeSeriesData {
  name: string;
  data: ChartDataPoint[];
  color?: string;
}

// WebSocket Message Types
export interface WebSocketMessage {
  type: 'metrics' | 'alert' | 'status' | 'config' | 'command';
  payload: any;
  timestamp: string;
}

export interface AgentCommand {
  id: string;
  command: string;
  parameters?: Record<string, any>;
  timestamp: string;
}

// Filter and Search Types
export interface FilterOptions {
  timeRange: {
    start: string;
    end: string;
  };
  severity?: ('low' | 'medium' | 'high' | 'critical')[];
  protocols?: string[];
  sources?: string[];
  destinations?: string[];
  alertTypes?: string[];
}

export interface SearchParams {
  query: string;
  filters: FilterOptions;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
  page?: number;
  limit?: number;
}

// Export utility types
export type StatusColor = 'green' | 'yellow' | 'red' | 'gray';
export type SeverityColor = 'blue' | 'yellow' | 'orange' | 'red';
export type ComponentSize = 'sm' | 'md' | 'lg' | 'xl'; 