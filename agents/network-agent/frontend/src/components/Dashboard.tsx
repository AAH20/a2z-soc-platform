import React from 'react';
import { useQuery } from '@tanstack/react-query';
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
} from 'lucide-react';
import { api } from '@/services/api';
import { AgentStatus, SystemMetrics, NetworkMetrics } from '@/types';
import { StatusIndicator } from './StatusIndicator';

export function Dashboard() {
  const { data: agentStatus, isLoading: statusLoading } = useQuery<AgentStatus>({
    queryKey: ['agentStatus'],
    queryFn: () => api.getAgentStatus(),
    refetchInterval: 5000,
  });

  const { data: systemMetrics } = useQuery<SystemMetrics>({
    queryKey: ['systemMetrics'],
    queryFn: () => api.getLatestSystemMetrics(),
    refetchInterval: 5000,
  });

  const { data: networkMetrics } = useQuery<NetworkMetrics>({
    queryKey: ['networkMetrics'],
    queryFn: () => api.getLatestNetworkMetrics(),
    refetchInterval: 5000,
  });

  if (statusLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-soft p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Agent Dashboard</h1>
            <p className="text-gray-500 mt-1">Real-time network security monitoring overview</p>
          </div>
          {agentStatus && (
            <div className="flex items-center space-x-3">
              <StatusIndicator status={agentStatus.status} size="lg" />
              <div className="text-right">
                <div className="text-lg font-semibold text-gray-900 capitalize">
                  {agentStatus.status}
                </div>
                <div className="text-sm text-gray-500">
                  {agentStatus.lastHeartbeat && (
                    <>Last seen: {new Date(agentStatus.lastHeartbeat).toLocaleTimeString()}</>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow-soft p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-green-100">
              <Shield className="w-6 h-6 text-green-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Agent Status</p>
              <p className="text-2xl font-semibold text-gray-900 capitalize">
                {agentStatus?.status || 'Unknown'}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-soft p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-blue-100">
              <Activity className="w-6 h-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Network Traffic</p>
              <p className="text-2xl font-semibold text-gray-900">
                {networkMetrics?.totalPackets || 0}
              </p>
              <p className="text-xs text-gray-500">packets processed</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-soft p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-orange-100">
              <AlertTriangle className="w-6 h-6 text-orange-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Threats Detected</p>
              <p className="text-2xl font-semibold text-gray-900">0</p>
              <p className="text-xs text-gray-500">in last 24h</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-soft p-6">
          <div className="flex items-center">
            <div className="p-3 rounded-full bg-purple-100">
              <Clock className="w-6 h-6 text-purple-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-500">Uptime</p>
              <p className="text-2xl font-semibold text-gray-900">
                {agentStatus ? formatUptime(agentStatus.uptime) : '0m'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* System Information */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow-soft p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
            <Server className="w-5 h-5 mr-2" />
            System Information
          </h3>
          {agentStatus && (
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-500">Agent ID:</span>
                <span className="font-mono text-sm">{agentStatus.agentId.slice(0, 8)}...</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Platform:</span>
                <span>{agentStatus.systemInfo.platform}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Architecture:</span>
                <span>{agentStatus.systemInfo.arch}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Node Version:</span>
                <span>{agentStatus.systemInfo.nodeVersion}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Version:</span>
                <span>{agentStatus.version}</span>
              </div>
            </div>
          )}
        </div>

        <div className="bg-white rounded-lg shadow-soft p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
            <TrendingUp className="w-5 h-5 mr-2" />
            Performance Metrics
          </h3>
          {systemMetrics && (
            <div className="space-y-4">
              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-sm text-gray-500 flex items-center">
                    <Cpu className="w-4 h-4 mr-1" />
                    CPU Usage
                  </span>
                  <span className="text-sm font-medium">
                    {Math.round(systemMetrics.cpu.usage * 100)}%
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full"
                    style={{ width: `${Math.round(systemMetrics.cpu.usage * 100)}%` }}
                  ></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-sm text-gray-500 flex items-center">
                    <HardDrive className="w-4 h-4 mr-1" />
                    Memory Usage
                  </span>
                  <span className="text-sm font-medium">
                    {formatBytes(systemMetrics.memory.used)}
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-green-600 h-2 rounded-full"
                    style={{ width: `${systemMetrics.memory.percentage}%` }}
                  ></div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Network Interfaces */}
      <div className="bg-white rounded-lg shadow-soft p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
          <Network className="w-5 h-5 mr-2" />
          Network Interfaces
        </h3>
        {agentStatus?.systemInfo.networkInterfaces && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {agentStatus.systemInfo.networkInterfaces.map((iface, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-medium text-gray-900">{iface.name}</h4>
                  <div className={`w-2 h-2 rounded-full ${iface.active ? 'bg-green-500' : 'bg-gray-400'}`} />
                </div>
                <div className="text-sm text-gray-500">
                  <div>Type: {iface.type}</div>
                  <div className="mt-1">
                    Addresses: {iface.addresses.slice(0, 2).join(', ')}
                    {iface.addresses.length > 2 && ` +${iface.addresses.length - 2} more`}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Protocol Distribution */}
      {networkMetrics?.protocolDistribution && Object.keys(networkMetrics.protocolDistribution).length > 0 && (
        <div className="bg-white rounded-lg shadow-soft p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Protocol Distribution</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Object.entries(networkMetrics.protocolDistribution).map(([protocol, count]) => (
              <div key={protocol} className="text-center">
                <div className="text-2xl font-bold text-primary-600">{count}</div>
                <div className="text-sm text-gray-500 uppercase">{protocol}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
} 