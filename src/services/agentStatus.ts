interface AgentInfo {
  id: string;
  name: string;
  platform: string;
  version: string;
  status: 'online' | 'offline' | 'unknown' | 'checking';
  lastSeen: string;
  uptime?: number;
  ipAddress?: string;
  hostname?: string;
  apiEndpoint?: string;
}

interface AgentMetrics {
  packetsProcessed: number;
  threatsDetected: number;
  alertsGenerated: number;
  logsCollected: number;
  memoryUsage: {
    rss: number;
    heapTotal: number;
    heapUsed: number;
    external: number;
  };
  cpuUsage: number;
  networkInterfaces: string[];
}

interface LogEntry {
  timestamp: string;
  source: string;
  level: string;
  message: string;
  hostname: string;
  platform: string;
  agentId: string;
}

interface SecurityAlert {
  id: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  threat: string;
  pattern: string;
  source: string;
  message: string;
  agentId: string;
  hostname: string;
}

class AgentStatusService {
  private agents: Map<string, AgentInfo> = new Map();
  private agentMetrics: Map<string, AgentMetrics> = new Map();
  private agentLogs: Map<string, LogEntry[]> = new Map();
  private agentAlerts: Map<string, SecurityAlert[]> = new Map();
  private subscribers: Array<(agents: AgentInfo[]) => void> = [];
  private checkInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.startStatusMonitoring();
  }

  // Subscribe to agent status updates
  subscribe(callback: (agents: AgentInfo[]) => void): () => void {
    this.subscribers.push(callback);
    
    // Immediately notify with current state
    callback(Array.from(this.agents.values()));
    
    // Return unsubscribe function
    return () => {
      const index = this.subscribers.indexOf(callback);
      if (index > -1) {
        this.subscribers.splice(index, 1);
      }
    };
  }

  // Notify all subscribers of status changes
  private notifySubscribers(): void {
    const agentList = Array.from(this.agents.values());
    this.subscribers.forEach(callback => callback(agentList));
  }

  // Register a new agent
  registerAgent(agent: Omit<AgentInfo, 'status' | 'lastSeen'>): void {
    const agentInfo: AgentInfo = {
      ...agent,
      status: 'unknown',
      lastSeen: new Date().toISOString()
    };
    
    this.agents.set(agent.id, agentInfo);
    this.notifySubscribers();
  }

  // Update agent status
  updateAgentStatus(agentId: string, status: AgentInfo['status'], additionalData?: Partial<AgentInfo>): void {
    const agent = this.agents.get(agentId);
    if (agent) {
      this.agents.set(agentId, {
        ...agent,
        ...additionalData,
        status,
        lastSeen: new Date().toISOString()
      });
      this.notifySubscribers();
    }
  }

  // Remove an agent
  removeAgent(agentId: string): void {
    this.agents.delete(agentId);
    this.agentMetrics.delete(agentId);
    this.agentLogs.delete(agentId);
    this.agentAlerts.delete(agentId);
    this.notifySubscribers();
  }

  // Get all agents
  getAllAgents(): AgentInfo[] {
    return Array.from(this.agents.values());
  }

  // Get specific agent
  getAgent(agentId: string): AgentInfo | undefined {
    return this.agents.get(agentId);
  }

  // Check agent status via API
  async checkAgentStatus(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent || !agent.apiEndpoint) return;

    this.updateAgentStatus(agentId, 'checking');

    try {
      const response = await fetch(`${agent.apiEndpoint}/status`, {
        method: 'GET',
        timeout: 5000
      });

      if (response.ok) {
        const statusData = await response.json();
        
        // Update agent with latest status information
        this.updateAgentStatus(agentId, 'online', {
          uptime: statusData.uptime,
          hostname: statusData.hostname,
          version: statusData.version
        });

        // Update metrics if available
        if (statusData.memory || statusData.performance) {
          this.updateAgentMetrics(agentId, {
            packetsProcessed: statusData.performance?.packetsProcessed || 0,
            threatsDetected: statusData.performance?.threatsDetected || 0,
            alertsGenerated: statusData.performance?.alertsGenerated || 0,
            logsCollected: statusData.performance?.logsCollected || 0,
            memoryUsage: statusData.memory || { rss: 0, heapTotal: 0, heapUsed: 0, external: 0 },
            cpuUsage: statusData.cpuUsage || 0,
            networkInterfaces: statusData.networkInterfaces || []
          });
        }

      } else {
        this.updateAgentStatus(agentId, 'offline');
      }
    } catch (error) {
      console.warn(`Failed to check status for agent ${agentId}:`, error);
      this.updateAgentStatus(agentId, 'offline');
    }
  }

  // Check all agent statuses
  async checkAllAgentStatuses(): Promise<void> {
    const promises = Array.from(this.agents.keys()).map(agentId => 
      this.checkAgentStatus(agentId)
    );
    
    await Promise.allSettled(promises);
  }

  // Update agent metrics
  updateAgentMetrics(agentId: string, metrics: AgentMetrics): void {
    this.agentMetrics.set(agentId, metrics);
  }

  // Get agent metrics
  getAgentMetrics(agentId: string): AgentMetrics | undefined {
    return this.agentMetrics.get(agentId);
  }

  // Fetch agent logs
  async fetchAgentLogs(agentId: string): Promise<LogEntry[]> {
    const agent = this.agents.get(agentId);
    if (!agent || !agent.apiEndpoint) return [];

    try {
      const response = await fetch(`${agent.apiEndpoint}/logs`);
      if (response.ok) {
        const data = await response.json();
        const logs = data.logs || [];
        this.agentLogs.set(agentId, logs);
        return logs;
      }
    } catch (error) {
      console.warn(`Failed to fetch logs for agent ${agentId}:`, error);
    }

    return this.agentLogs.get(agentId) || [];
  }

  // Fetch agent alerts
  async fetchAgentAlerts(agentId: string): Promise<SecurityAlert[]> {
    const agent = this.agents.get(agentId);
    if (!agent || !agent.apiEndpoint) return [];

    try {
      const response = await fetch(`${agent.apiEndpoint}/alerts`);
      if (response.ok) {
        const data = await response.json();
        const alerts = data.alerts || [];
        this.agentAlerts.set(agentId, alerts);
        return alerts;
      }
    } catch (error) {
      console.warn(`Failed to fetch alerts for agent ${agentId}:`, error);
    }

    return this.agentAlerts.get(agentId) || [];
  }

  // Get agent logs
  getAgentLogs(agentId: string): LogEntry[] {
    return this.agentLogs.get(agentId) || [];
  }

  // Get agent alerts
  getAgentAlerts(agentId: string): SecurityAlert[] {
    return this.agentAlerts.get(agentId) || [];
  }

  // Get all alerts across all agents
  getAllAlerts(): SecurityAlert[] {
    const allAlerts: SecurityAlert[] = [];
    this.agentAlerts.forEach(alerts => allAlerts.push(...alerts));
    return allAlerts.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }

  // Get agents by status
  getAgentsByStatus(status: AgentInfo['status']): AgentInfo[] {
    return Array.from(this.agents.values()).filter(agent => agent.status === status);
  }

  // Get online agents count
  getOnlineAgentsCount(): number {
    return this.getAgentsByStatus('online').length;
  }

  // Get total agents count
  getTotalAgentsCount(): number {
    return this.agents.size;
  }

  // Start periodic status monitoring
  private startStatusMonitoring(): void {
    // Check status every 30 seconds
    this.checkInterval = setInterval(() => {
      this.checkAllAgentStatuses();
    }, 30000);
  }

  // Stop status monitoring
  stopStatusMonitoring(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  // Auto-discover agents (for development/demo purposes)
  async autoDiscoverAgents(): Promise<void> {
    // Check for locally running agents
    const commonPorts = [5200, 5201, 5202, 5203, 5204];
    const discoveryPromises = commonPorts.map(port => this.discoverAgent(`http://localhost:${port}`));
    
    await Promise.allSettled(discoveryPromises);
  }

  private async discoverAgent(endpoint: string): Promise<void> {
    try {
      const response = await fetch(`${endpoint}/status`, { 
        method: 'GET',
        timeout: 2000 
      });

      if (response.ok) {
        const statusData = await response.json();
        
        if (statusData.agentId) {
          const agent: Omit<AgentInfo, 'status' | 'lastSeen'> = {
            id: statusData.agentId,
            name: statusData.hostname || `Agent ${statusData.agentId.substring(0, 8)}`,
            platform: statusData.platform || 'unknown',
            version: statusData.version || '1.0.0',
            hostname: statusData.hostname,
            apiEndpoint: 'http://localhost:5200/status'
          };

          this.registerAgent(agent);
          console.log(`Discovered agent: ${agent.name} at ${endpoint}`);
        }
      }
    } catch (error) {
      // Agent not found at this endpoint, ignore
    }
  }

  // Initialize with some demo agents for development
  initializeDemoAgents(): void {
    const demoAgents = [
      {
        id: 'demo-macos-1',
        name: 'MacBook Pro (Development)',
        platform: 'darwin',
        version: '1.2.3',
        apiEndpoint: 'http://localhost:5200/status'
      },
      {
        id: 'demo-linux-1', 
        name: 'Ubuntu Server (Production)',
        platform: 'linux',
        version: '1.2.3',
        apiEndpoint: 'http://localhost:5200/status'
      },
      {
        id: 'demo-windows-1',
        name: 'Windows Server (Staging)',
        platform: 'win32',
        version: '1.2.3',
        apiEndpoint: 'http://localhost:5200/status'
      }
    ];

    demoAgents.forEach(agent => this.registerAgent(agent));
    
    // Simulate some of them being online
    setTimeout(() => {
      this.updateAgentStatus('demo-macos-1', 'online');
      this.updateAgentStatus('demo-linux-1', 'online');
      this.updateAgentStatus('demo-windows-1', 'offline');
    }, 1000);
  }
}

// Export singleton instance
export const agentStatusService = new AgentStatusService();

// Initialize demo agents in development
if (process.env.NODE_ENV === 'development') {
  agentStatusService.initializeDemoAgents();
  agentStatusService.autoDiscoverAgents();
}

export type { AgentInfo, AgentMetrics, LogEntry, SecurityAlert }; 