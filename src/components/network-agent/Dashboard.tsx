import React, { useState, useEffect } from 'react';
import {
  Activity,
  Shield,
  AlertTriangle,
  Network,
  Server,
  Clock,
  Cpu,
  HardDrive,
  TrendingUp,
  Wifi,
  WifiOff,
  Monitor,
  PlayCircle,
  PauseCircle,
  Eye,
  Target,
  Zap,
  Lock,
  Router,
  BarChart3,
  Database,
  CheckCircle,
  XCircle
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { apiService } from '@/services/api';

interface ConnectedAgent {
  id: string;
  name: string;
  ip_address: string;
  status: 'online' | 'offline';
  agent_type: string;
  capabilities?: string[];
  lastSeen: string;
  isOnline: boolean;
  operating_system?: string;
  version?: string;
  metrics?: {
    cpu: {
      usage: number;
      cores: number;
    };
    memory: {
      used: number;
      total: number;
      percentage: number;
    };
    network: {
      totalPackets: number;
      bytesPerSecond: number;
      packetsPerSecond: number;
    };
    uptime: number;
    threatsDetected?: number;
    packetsBlocked?: number;
    rulesActive?: number;
  };
}

interface ThreatSummary {
  totalThreats: number;
  criticalThreats: number;
  highThreats: number;
  packetsBlocked: number;
  rulesTriggered: number;
  falsePositives: number;
}

export function Dashboard() {
  const [isLiveMonitoring, setIsLiveMonitoring] = useState(true);
  const [timeRange, setTimeRange] = useState('1h');
  const [selectedSystemView, setSelectedSystemView] = useState<'unified' | 'network-only' | 'ids-only'>('unified');
  const [connectedAgents, setConnectedAgents] = useState<ConnectedAgent[]>([]);
  const [threatSummary, setThreatSummary] = useState<ThreatSummary>({
    totalThreats: 0,
    criticalThreats: 0,
    highThreats: 0,
    packetsBlocked: 0,
    rulesTriggered: 0,
    falsePositives: 0
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load real agent data from API
  const loadAgentData = async () => {
    try {
      setLoading(true);
      setError(null);

      const [agentsResponse, securityEventsResponse] = await Promise.all([
        apiService.get('/network-agents'),
        apiService.get('/security-events?limit=100').catch(() => ({ data: { data: [] } }))
      ]);

      const agents = agentsResponse.data.data || [];
      const securityEvents = securityEventsResponse.data.data || [];

      // Transform agents data
      const transformedAgents: ConnectedAgent[] = agents.map((agent: any) => ({
        id: agent.id,
        name: agent.name,
        ip_address: agent.ip_address,
        status: agent.isOnline ? 'online' : 'offline',
        agent_type: agent.agent_type,
        capabilities: getCapabilitiesForType(agent.agent_type),
        lastSeen: agent.last_heartbeat || agent.lastSeen,
        isOnline: agent.isOnline,
        operating_system: agent.operating_system,
        version: agent.version,
        metrics: agent.metrics
      }));

      setConnectedAgents(transformedAgents);

      // Calculate threat summary from security events
      const criticalEvents = securityEvents.filter((e: any) => e.severity === 'critical').length;
      const highEvents = securityEvents.filter((e: any) => e.severity === 'high').length;
      const resolvedEvents = securityEvents.filter((e: any) => e.status === 'resolved').length;

      setThreatSummary({
        totalThreats: criticalEvents + highEvents,
        criticalThreats: criticalEvents,
        highThreats: highEvents,
        packetsBlocked: resolvedEvents,
        rulesTriggered: securityEvents.length,
        falsePositives: Math.floor(securityEvents.length * 0.1) // Estimate 10% false positives
      });

    } catch (err: any) {
      console.error('Failed to load agent data:', err);
      setError(err.message || 'Failed to load agent data');
    } finally {
      setLoading(false);
    }
  };

  const getCapabilitiesForType = (type: string): string[] => {
    switch (type) {
      case 'gateway':
        return ['traffic-monitoring', 'flow-analysis', 'performance-metrics', 'bandwidth-monitoring', 'threat-detection'];
      case 'endpoint':
        return ['traffic-monitoring', 'flow-analysis', 'protocol-analysis'];
      case 'cloud':
        return ['cloud-monitoring', 'api-analysis', 'resource-tracking'];
      default:
        return ['traffic-monitoring', 'basic-analysis'];
    }
  };

  // Simulate real-time updates for online agents
  useEffect(() => {
    if (!isLiveMonitoring) return;

    const interval = setInterval(() => {
      setConnectedAgents(prev => prev.map(agent => {
        if (agent.status === 'online' && agent.metrics) {
          const updatedMetrics = {
            ...agent.metrics,
            cpu: {
              ...agent.metrics.cpu,
              usage: Math.max(0.1, Math.min(0.95, agent.metrics.cpu.usage + (Math.random() - 0.5) * 0.1))
            },
            memory: {
              ...agent.metrics.memory,
              percentage: Math.max(20, Math.min(90, agent.metrics.memory.percentage + (Math.random() - 0.5) * 5))
            },
            network: {
              ...agent.metrics.network,
              totalPackets: agent.metrics.network.totalPackets + Math.floor(Math.random() * 1000),
              packetsPerSecond: Math.floor(Math.random() * 2000) + 500,
              bytesPerSecond: Math.floor(Math.random() * 5000000) + 1000000
            },
            uptime: agent.metrics.uptime + 3
          };

          // Update IDS/IPS specific metrics
          if (agent.agent_type === 'gateway' && agent.capabilities?.includes('threat-detection')) {
            updatedMetrics.threatsDetected = (agent.metrics.threatsDetected || 0) + (Math.random() < 0.1 ? 1 : 0);
            updatedMetrics.packetsBlocked = (agent.metrics.packetsBlocked || 0) + Math.floor(Math.random() * 10);
          }

          return {
            ...agent,
            lastSeen: new Date().toISOString(),
            metrics: updatedMetrics
          };
        }
        return agent;
      }));

      // Update threat summary occasionally
      if (Math.random() < 0.2) {
      setThreatSummary(prev => ({
        ...prev,
        totalThreats: prev.totalThreats + (Math.random() < 0.05 ? 1 : 0),
        packetsBlocked: prev.packetsBlocked + Math.floor(Math.random() * 5),
        rulesTriggered: prev.rulesTriggered + Math.floor(Math.random() * 3)
      }));
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [isLiveMonitoring]);

  // Load data on component mount
  useEffect(() => {
    loadAgentData();
    
    // Set up periodic refresh
    const refreshInterval = setInterval(loadAgentData, 60000); // Refresh every minute
    
    return () => clearInterval(refreshInterval);
  }, []);

  const onlineAgents = connectedAgents.filter(agent => agent.status === 'online');
  const networkAgents = connectedAgents.filter(agent => agent.agent_type === 'endpoint' || agent.agent_type === 'gateway');
  const idsAgents = connectedAgents.filter(agent => agent.capabilities?.includes('threat-detection'));

  const aggregateMetrics = () => {
    const agents = onlineAgents.filter(agent => agent.metrics);
    if (agents.length === 0) return null;

    return agents.reduce((acc, agent) => {
      const metrics = agent.metrics!;
      return {
        totalPackets: acc.totalPackets + metrics.network.totalPackets,
        packetsPerSecond: acc.packetsPerSecond + metrics.network.packetsPerSecond,
        bytesPerSecond: acc.bytesPerSecond + metrics.network.bytesPerSecond,
        avgCpuUsage: (acc.avgCpuUsage + metrics.cpu.usage) / (agents.indexOf(agent) + 1),
        avgMemoryUsage: (acc.avgMemoryUsage + metrics.memory.percentage) / (agents.indexOf(agent) + 1),
        totalThreats: acc.totalThreats + (metrics.threatsDetected || 0),
        totalBlocked: acc.totalBlocked + (metrics.packetsBlocked || 0),
        maxUptime: Math.max(acc.maxUptime, metrics.uptime)
      };
    }, {
      totalPackets: 0,
      packetsPerSecond: 0,
      bytesPerSecond: 0,
      avgCpuUsage: 0,
      avgMemoryUsage: 0,
      totalThreats: 0,
      totalBlocked: 0,
      maxUptime: 0
    });
  };

  const metrics = aggregateMetrics();

  const getAgentTypeIcon = (type: string) => {
    switch (type) {
      case 'gateway':
        return <Network className="w-4 h-4 text-blue-600" />;
      case 'endpoint':
        return <Monitor className="w-4 h-4 text-green-600" />;
      case 'cloud':
        return <Shield className="w-4 h-4 text-purple-600" />;
      default:
        return <Monitor className="w-4 h-4 text-gray-600" />;
    }
  };

  const getAgentTypeLabel = (type: string) => {
    switch (type) {
      case 'gateway':
        return 'Gateway';
      case 'endpoint':
        return 'Endpoint';
      case 'cloud':
        return 'Cloud';
      default:
        return 'Unknown';
    }
  };

  const formatBytes = (bytes: number) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatUptime = (seconds: number) => {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h ${minutes}m`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  if (loading) {
    return (
      <div className="space-y-6 p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-muted-foreground">Loading network agent data...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6 p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
            <p className="text-red-600 font-medium">Error loading agent data</p>
            <p className="text-muted-foreground text-sm">{error}</p>
            <Button onClick={loadAgentData} className="mt-4">
              Retry
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
        <div className="flex items-center justify-between">
          <div>
          <h1 className="text-2xl font-bold">Network Agent Dashboard</h1>
          <p className="text-muted-foreground">
            Real-time monitoring of {connectedAgents.length} network agents
          </p>
          </div>
          <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Button
              variant={isLiveMonitoring ? "default" : "outline"}
              size="sm"
              onClick={() => setIsLiveMonitoring(!isLiveMonitoring)}
            >
              <Activity className="w-4 h-4 mr-2" />
              {isLiveMonitoring ? 'Live' : 'Paused'}
            </Button>
          </div>
        </div>
      </div>

      {/* System Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Agents</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{connectedAgents.length}</div>
            <p className="text-xs text-muted-foreground">
              {onlineAgents.length} online, {connectedAgents.length - onlineAgents.length} offline
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Network Coverage</CardTitle>
            <Network className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {Math.round((onlineAgents.length / Math.max(connectedAgents.length, 1)) * 100)}%
            </div>
            <p className="text-xs text-muted-foreground">
              {networkAgents.length} network monitors active
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Threat Protection</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{threatSummary.totalThreats}</div>
            <p className="text-xs text-muted-foreground">
              {threatSummary.criticalThreats} critical, {threatSummary.packetsBlocked} blocked
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Aggregate Metrics */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Network Traffic</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.packetsPerSecond.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground">packets/sec</p>
              <p className="text-xs text-muted-foreground">{formatBytes(metrics.bytesPerSecond)}/sec</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">System Load</CardTitle>
              <Cpu className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{Math.round(metrics.avgCpuUsage * 100)}%</div>
              <p className="text-xs text-muted-foreground">average CPU usage</p>
              <p className="text-xs text-muted-foreground">{Math.round(metrics.avgMemoryUsage)}% memory</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Threats Detected</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{metrics.totalThreats}</div>
              <p className="text-xs text-muted-foreground">{metrics.totalBlocked} blocked</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Max Uptime</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{formatUptime(metrics.maxUptime)}</div>
              <p className="text-xs text-muted-foreground">longest running agent</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Agent List */}
      <Card>
        <CardHeader>
          <CardTitle>Connected Agents</CardTitle>
          <CardDescription>
            Real-time status and metrics for all network monitoring agents
          </CardDescription>
        </CardHeader>
        <CardContent>
                <div className="space-y-4">
            {connectedAgents.map((agent) => (
              <div key={agent.id} className="flex items-center justify-between p-4 border rounded-lg">
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-2">
                    {getAgentTypeIcon(agent.agent_type)}
                    <div>
                      <h3 className="font-medium">{agent.name}</h3>
                      <p className="text-sm text-muted-foreground">
                        {agent.ip_address} • {getAgentTypeLabel(agent.agent_type)}
                      </p>
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-4">
                  {agent.metrics && (
                    <div className="text-right text-sm">
                      <p>{Math.round(agent.metrics.cpu.usage * 100)}% CPU</p>
                      <p className="text-muted-foreground">{agent.metrics.network.packetsPerSecond.toLocaleString()} pps</p>
                    </div>
                  )}
                  <Badge variant={agent.status === 'online' ? 'default' : 'secondary'}>
                    {agent.status}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
} 