import React, { useState, useEffect } from 'react';
import {
  BarChart3,
  Cpu,
  HardDrive,
  Zap,
  Thermometer,
  Clock,
  Activity,
  Gauge,
  Server,
  Database,
  Wifi,
  TrendingUp,
  TrendingDown,
  AlertCircle,
  WifiOff,
  Monitor,
  PlayCircle,
  PauseCircle
} from 'lucide-react';

interface ConnectedAgent {
  id: string;
  name: string;
  ipAddress: string;
  status: 'online' | 'offline';
  lastSeen: string;
  systemInfo?: {
    platform: string;
    arch: string;
    nodeVersion: string;
    networkInterfaces?: Array<{
      name: string;
      addresses: string[];
      type: string;
      active: boolean;
    }>;
  };
  metrics?: {
    cpu: {
      usage: number;
      user: number;
      system: number;
      cores: number;
      model?: string;
    };
    memory: {
      used: number;
      free: number;
      total: number;
      percentage: number;
    };
    uptime: number;
  };
}

export function SystemMetrics() {
  const [selectedAgent, setSelectedAgent] = useState<string>('all');
  const [timeRange, setTimeRange] = useState('1h');
  const [isLiveMonitoring, setIsLiveMonitoring] = useState(true);

  // Mock connected agents
  const [connectedAgents, setConnectedAgents] = useState<ConnectedAgent[]>([
    {
      id: '1',
      name: 'Production Server',
      ipAddress: '192.168.1.100',
      status: 'online',
      lastSeen: new Date().toISOString(),
      systemInfo: {
        platform: 'linux',
        arch: 'x64',
        nodeVersion: 'v18.0.0',
        networkInterfaces: [
          { name: 'eth0', addresses: ['192.168.1.100'], type: 'ethernet', active: true },
          { name: 'lo', addresses: ['127.0.0.1'], type: 'loopback', active: true }
        ]
      },
      metrics: {
        cpu: {
          usage: 0.45,
          user: 35,
          system: 20,
          cores: 8,
          model: 'Intel Xeon E5-2680'
        },
        memory: {
          used: 8589934592,
          free: 8589934592,
          total: 17179869184,
          percentage: 50
        },
        uptime: 86400
      }
    },
    {
      id: '2',
      name: 'Development Machine',
      ipAddress: '192.168.1.101',
      status: 'offline',
      lastSeen: new Date(Date.now() - 3600000).toISOString(),
      systemInfo: {
        platform: 'darwin',
        arch: 'arm64',
        nodeVersion: 'v18.0.0'
      }
    }
  ]);

  // Simulate real-time updates
  useEffect(() => {
    if (!isLiveMonitoring) return;

    const interval = setInterval(() => {
      setConnectedAgents(prev => prev.map(agent => {
        if (agent.status === 'online' && agent.metrics) {
          return {
            ...agent,
            lastSeen: new Date().toISOString(),
            metrics: {
              ...agent.metrics,
              cpu: {
                ...agent.metrics.cpu,
                usage: Math.max(0.1, Math.min(0.95, agent.metrics.cpu.usage + (Math.random() - 0.5) * 0.1)),
                user: Math.max(10, Math.min(80, agent.metrics.cpu.user + (Math.random() - 0.5) * 10)),
                system: Math.max(5, Math.min(40, agent.metrics.cpu.system + (Math.random() - 0.5) * 5))
              },
              memory: {
                ...agent.metrics.memory,
                percentage: Math.max(20, Math.min(90, agent.metrics.memory.percentage + (Math.random() - 0.5) * 5))
              },
              uptime: agent.metrics.uptime + 2
            }
          };
        }
        return agent;
      }));
    }, 2000);

    return () => clearInterval(interval);
  }, [isLiveMonitoring]);

  const getSelectedAgentData = () => {
    if (selectedAgent === 'all') {
      return connectedAgents.filter(agent => agent.status === 'online');
    }
    return connectedAgents.filter(agent => agent.id === selectedAgent && agent.status === 'online');
  };

  const aggregateMetrics = () => {
    const agents = getSelectedAgentData();
    if (agents.length === 0) return null;

    const validAgents = agents.filter(agent => agent.metrics);
    if (validAgents.length === 0) return null;

    return validAgents.reduce((acc, agent, index) => {
      const metrics = agent.metrics!;
      
      if (index === 0) {
        return {
          cpu: { ...metrics.cpu },
          memory: { ...metrics.memory },
          uptime: metrics.uptime,
          agentCount: 1
        };
      }

      return {
        cpu: {
          usage: (acc.cpu.usage + metrics.cpu.usage) / 2,
          user: (acc.cpu.user + metrics.cpu.user) / 2,
          system: (acc.cpu.system + metrics.cpu.system) / 2,
          cores: acc.cpu.cores + metrics.cpu.cores,
          model: acc.cpu.model
        },
        memory: {
          used: acc.memory.used + metrics.memory.used,
          free: acc.memory.free + metrics.memory.free,
          total: acc.memory.total + metrics.memory.total,
          percentage: (acc.memory.percentage + metrics.memory.percentage) / 2
        },
        uptime: Math.max(acc.uptime, metrics.uptime),
        agentCount: acc.agentCount + 1
      };
    }, {} as any);
  };

  const formatBytes = (bytes: number) => {
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h ${minutes}m`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m ${seconds % 60}s`;
  };

  const getHealthStatus = (value: number, thresholds: { warning: number; critical: number }) => {
    if (value >= thresholds.critical) return { status: 'critical', color: 'text-red-600', bg: 'bg-red-100' };
    if (value >= thresholds.warning) return { status: 'warning', color: 'text-yellow-600', bg: 'bg-yellow-100' };
    return { status: 'healthy', color: 'text-green-600', bg: 'bg-green-100' };
  };

  const onlineAgents = connectedAgents.filter(agent => agent.status === 'online');
  const offlineAgents = connectedAgents.filter(agent => agent.status === 'offline');
  const metrics = aggregateMetrics();

  const cpuHealth = metrics ? getHealthStatus(metrics.cpu.usage * 100, { warning: 70, critical: 90 }) : null;
  const memoryHealth = metrics ? getHealthStatus(metrics.memory.percentage, { warning: 80, critical: 95 }) : null;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 flex items-center">
              <BarChart3 className="w-8 h-8 text-green-600 mr-3" />
              System Metrics
            </h1>
            <p className="text-gray-500 mt-1">Real-time system performance monitoring across connected agents</p>
          </div>
          <div className="flex items-center space-x-4">
            <select 
              value={selectedAgent} 
              onChange={(e) => setSelectedAgent(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md text-sm"
            >
              <option value="all">All Agents ({onlineAgents.length})</option>
              {connectedAgents.map(agent => (
                <option key={agent.id} value={agent.id}>
                  {agent.name} ({agent.status})
                </option>
              ))}
            </select>
            <select 
              value={timeRange} 
              onChange={(e) => setTimeRange(e.target.value)}
              className="px-3 py-2 border border-gray-300 rounded-md text-sm"
            >
              <option value="5m">Last 5 minutes</option>
              <option value="1h">Last hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
            <button
              onClick={() => setIsLiveMonitoring(!isLiveMonitoring)}
              className={`flex items-center space-x-2 px-3 py-2 rounded-md ${
                isLiveMonitoring ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
              }`}
            >
              {isLiveMonitoring ? <PlayCircle className="w-4 h-4" /> : <PauseCircle className="w-4 h-4" />}
              <span className="text-sm font-medium">
                {isLiveMonitoring ? 'Live Monitoring' : 'Paused'}
              </span>
            </button>
          </div>
        </div>
      </div>

      {/* Agent Status Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="flex items-center">
            <Wifi className="w-6 h-6 text-green-600 mr-3" />
            <div>
              <p className="text-sm font-medium text-gray-500">Online Agents</p>
              <p className="text-2xl font-semibold text-green-600">{onlineAgents.length}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="flex items-center">
            <WifiOff className="w-6 h-6 text-red-600 mr-3" />
            <div>
              <p className="text-sm font-medium text-gray-500">Offline Agents</p>
              <p className="text-2xl font-semibold text-red-600">{offlineAgents.length}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="flex items-center">
            <div className={`p-3 rounded-full ${cpuHealth?.bg || 'bg-gray-100'}`}>
              <Cpu className={`w-6 h-6 ${cpuHealth?.color || 'text-gray-600'}`} />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Avg CPU Usage</p>
              <p className="text-2xl font-semibold text-gray-900">
                {metrics ? Math.round(metrics.cpu.usage * 100) : 0}%
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="flex items-center">
            <div className={`p-3 rounded-full ${memoryHealth?.bg || 'bg-gray-100'}`}>
              <HardDrive className={`w-6 h-6 ${memoryHealth?.color || 'text-gray-600'}`} />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Avg Memory Usage</p>
              <p className="text-2xl font-semibold text-gray-900">
                {metrics ? Math.round(metrics.memory.percentage) : 0}%
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* No Data State */}
      {onlineAgents.length === 0 && (
        <div className="bg-white rounded-lg shadow-sm p-12 text-center">
          <WifiOff className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No Active Agents</h3>
          <p className="text-gray-500 mb-4">
            No system monitoring agents are currently online. Deploy agents to start monitoring system performance.
          </p>
          <button className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700">
            Configure Agents
          </button>
        </div>
      )}

      {/* Content when agents are online */}
      {onlineAgents.length > 0 && metrics && (
        <>
          {/* Detailed Performance Metrics */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* CPU Details */}
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <Cpu className="w-5 h-5 text-blue-600 mr-2" />
                CPU Performance
              </h3>
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-gray-600">Overall Usage</span>
                    <span className={`text-sm font-medium ${cpuHealth?.color}`}>
                      {Math.round(metrics.cpu.usage * 100)}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-3">
                    <div
                      className={`h-3 rounded-full transition-all duration-300 ${
                        cpuHealth?.status === 'critical' ? 'bg-red-500' :
                        cpuHealth?.status === 'warning' ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                      style={{ width: `${Math.round(metrics.cpu.usage * 100)}%` }}
                    />
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center p-3 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-gray-900">{metrics.cpu.cores}</div>
                    <div className="text-xs text-gray-500">Total Cores</div>
                  </div>
                  <div className="text-center p-3 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-gray-900">
                      {Math.round(metrics.cpu.user)}%
                    </div>
                    <div className="text-xs text-gray-500">User Usage</div>
                  </div>
                </div>

                {metrics.cpu.model && (
                  <div className="text-sm text-gray-600">
                    <strong>Model:</strong> {metrics.cpu.model}
                  </div>
                )}
              </div>
            </div>

            {/* Memory Details */}
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <HardDrive className="w-5 h-5 text-green-600 mr-2" />
                Memory Usage
              </h3>
              <div className="space-y-4">
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-sm text-gray-600">RAM Usage</span>
                    <span className={`text-sm font-medium ${memoryHealth?.color}`}>
                      {Math.round(metrics.memory.percentage)}%
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-3">
                    <div
                      className={`h-3 rounded-full transition-all duration-300 ${
                        memoryHealth?.status === 'critical' ? 'bg-red-500' :
                        memoryHealth?.status === 'warning' ? 'bg-yellow-500' : 'bg-green-500'
                      }`}
                      style={{ width: `${Math.round(metrics.memory.percentage)}%` }}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="text-center p-3 bg-gray-50 rounded-lg">
                    <div className="text-lg font-bold text-gray-900">
                      {formatBytes(metrics.memory.used)}
                    </div>
                    <div className="text-xs text-gray-500">Used Memory</div>
                  </div>
                  <div className="text-center p-3 bg-gray-50 rounded-lg">
                    <div className="text-lg font-bold text-gray-900">
                      {formatBytes(metrics.memory.free)}
                    </div>
                    <div className="text-xs text-gray-500">Free Memory</div>
                  </div>
                </div>

                <div className="text-sm text-gray-600">
                  <strong>Total RAM:</strong> {formatBytes(metrics.memory.total)}
                </div>
              </div>
            </div>
          </div>

          {/* Individual Agent Details */}
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Monitor className="w-5 h-5 text-purple-600 mr-2" />
              Agent Details ({onlineAgents.length})
            </h3>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {onlineAgents.map((agent) => (
                <div key={agent.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <h4 className="font-medium text-gray-900">{agent.name}</h4>
                      <p className="text-sm text-gray-500 font-mono">{agent.ipAddress}</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                      <span className="text-xs text-green-600 font-medium">Online</span>
                    </div>
                  </div>
                  
                  {agent.metrics && (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="text-gray-500">CPU:</span>
                          <span className="ml-2 font-medium">{Math.round(agent.metrics.cpu.usage * 100)}%</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Memory:</span>
                          <span className="ml-2 font-medium">{Math.round(agent.metrics.memory.percentage)}%</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Cores:</span>
                          <span className="ml-2 font-medium">{agent.metrics.cpu.cores}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Uptime:</span>
                          <span className="ml-2 font-medium">{formatUptime(agent.metrics.uptime)}</span>
                        </div>
                      </div>
                      
                      {agent.systemInfo && (
                        <div className="text-xs text-gray-500 pt-2 border-t border-gray-100">
                          <div>{agent.systemInfo.platform} ({agent.systemInfo.arch})</div>
                          <div>Node.js {agent.systemInfo.nodeVersion}</div>
                          <div>Interfaces: {agent.systemInfo.networkInterfaces?.length || 0}</div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Health Alerts */}
          {(cpuHealth?.status !== 'healthy' || memoryHealth?.status !== 'healthy') && (
            <div className="bg-white rounded-lg shadow-sm p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                <AlertCircle className="w-5 h-5 text-orange-600 mr-2" />
                Health Alerts
              </h3>
              <div className="space-y-3">
                {cpuHealth?.status !== 'healthy' && (
                  <div className={`p-4 rounded-lg border ${
                    cpuHealth.status === 'critical' ? 'border-red-200 bg-red-50' : 'border-yellow-200 bg-yellow-50'
                  }`}>
                    <div className="flex items-center">
                      <Cpu className={`w-5 h-5 mr-3 ${cpuHealth.color}`} />
                      <div>
                        <div className={`font-medium ${cpuHealth.color}`}>
                          {cpuHealth.status === 'critical' ? 'Critical CPU Usage' : 'High CPU Usage'}
                        </div>
                        <div className="text-sm text-gray-600">
                          CPU usage is at {metrics ? Math.round(metrics.cpu.usage * 100) : 0}%. 
                          Consider investigating resource-intensive processes.
                        </div>
                      </div>
                    </div>
                  </div>
                )}
                
                {memoryHealth?.status !== 'healthy' && (
                  <div className={`p-4 rounded-lg border ${
                    memoryHealth.status === 'critical' ? 'border-red-200 bg-red-50' : 'border-yellow-200 bg-yellow-50'
                  }`}>
                    <div className="flex items-center">
                      <HardDrive className={`w-5 h-5 mr-3 ${memoryHealth.color}`} />
                      <div>
                        <div className={`font-medium ${memoryHealth.color}`}>
                          {memoryHealth.status === 'critical' ? 'Critical Memory Usage' : 'High Memory Usage'}
                        </div>
                        <div className="text-sm text-gray-600">
                          Memory usage is at {Math.round(metrics.memory.percentage) || 0}%. 
                          Consider freeing up memory or adding more RAM.
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Quick Actions */}
          <div className="bg-white rounded-lg shadow-sm p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Zap className="w-5 h-5 text-yellow-600 mr-2" />
              Quick Actions
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <button className="flex items-center justify-center space-x-3 p-4 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
                <TrendingUp className="w-5 h-5 text-blue-600" />
                <span className="font-medium">Performance Report</span>
              </button>
              <button className="flex items-center justify-center space-x-3 p-4 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
                <Gauge className="w-5 h-5 text-green-600" />
                <span className="font-medium">Set Thresholds</span>
              </button>
              <button className="flex items-center justify-center space-x-3 p-4 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
                <AlertCircle className="w-5 h-5 text-orange-600" />
                <span className="font-medium">Configure Alerts</span>
              </button>
              <button className="flex items-center justify-center space-x-3 p-4 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
                <Database className="w-5 h-5 text-purple-600" />
                <span className="font-medium">Export Metrics</span>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
} 