import React, { useState, useEffect } from 'react';
import { 
  Monitor, Laptop, Server, Smartphone, 
  CheckCircle, XCircle, Clock, RefreshCw,
  AlertTriangle, Wifi, Shield, Eye, Download
} from 'lucide-react';
import { agentStatusService, type AgentInfo, type SecurityAlert } from '../../services/agentStatus';

interface AgentStatusOverviewProps {
  showDetails?: boolean;
  maxAgents?: number;
  className?: string;
}

export function AgentStatusOverview({ 
  showDetails = false, 
  maxAgents = 5, 
  className = '' 
}: AgentStatusOverviewProps) {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Subscribe to agent status updates
  useEffect(() => {
    const unsubscribe = agentStatusService.subscribe((updatedAgents) => {
      setAgents(updatedAgents);
      // Fetch latest alerts
      fetchAllAlerts();
    });

    return unsubscribe;
  }, []);

  const fetchAllAlerts = async () => {
    const allAlerts = agentStatusService.getAllAlerts();
    setAlerts(allAlerts.slice(0, 10)); // Get recent 10 alerts
  };

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await agentStatusService.checkAllAgentStatuses();
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  const handleViewAgent = async (agentId: string) => {
    const agent = agentStatusService.getAgent(agentId);
    if (agent?.apiEndpoint) {
      window.open(`${agent.apiEndpoint}/status`, '_blank');
    }
  };

  const onlineAgents = agents.filter(agent => agent.status === 'online');
  const offlineAgents = agents.filter(agent => agent.status === 'offline');
  const checkingAgents = agents.filter(agent => agent.status === 'checking');
  const totalAgents = agents.length;

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'offline':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'checking':
        return <RefreshCw className="w-4 h-4 text-blue-500 animate-spin" />;
      default:
        return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform.toLowerCase()) {
      case 'windows':
        return <Monitor className="w-4 h-4 text-blue-600" />;
      case 'darwin':
      case 'macos':
        return <Laptop className="w-4 h-4 text-gray-600" />;
      case 'linux':
        return <Server className="w-4 h-4 text-orange-600" />;
      default:
        return <Smartphone className="w-4 h-4 text-purple-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'offline':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'checking':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-800 bg-red-100';
      case 'high':
        return 'text-orange-800 bg-orange-100';
      case 'medium':
        return 'text-yellow-800 bg-yellow-100';
      case 'low':
        return 'text-blue-800 bg-blue-100';
      default:
        return 'text-gray-800 bg-gray-100';
    }
  };

  const formatUptime = (uptime: number) => {
    const hours = Math.floor(uptime / 3600000);
    const minutes = Math.floor((uptime % 3600000) / 60000);
    
    if (hours > 24) {
      const days = Math.floor(hours / 24);
      return `${days}d ${hours % 24}h`;
    }
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    
    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Summary Statistics */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <Wifi className="w-5 h-5 text-blue-600 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900">Agent Status Overview</h3>
          </div>
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="p-2 text-gray-400 hover:text-gray-600 transition-colors disabled:opacity-50"
            title="Refresh all agent statuses"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="text-center p-3 bg-gray-50 rounded-lg">
            <div className="text-2xl font-bold text-gray-900">{totalAgents}</div>
            <div className="text-sm text-gray-500">Total Agents</div>
          </div>
          <div className="text-center p-3 bg-green-50 rounded-lg">
            <div className="text-2xl font-bold text-green-600">{onlineAgents.length}</div>
            <div className="text-sm text-green-600">Online</div>
          </div>
          <div className="text-center p-3 bg-red-50 rounded-lg">
            <div className="text-2xl font-bold text-red-600">{offlineAgents.length}</div>
            <div className="text-sm text-red-600">Offline</div>
          </div>
          <div className="text-center p-3 bg-blue-50 rounded-lg">
            <div className="text-2xl font-bold text-blue-600">{checkingAgents.length}</div>
            <div className="text-sm text-blue-600">Checking</div>
          </div>
        </div>

        {/* Agent List */}
        {totalAgents > 0 ? (
          <div className="space-y-3">
            <h4 className="text-sm font-medium text-gray-700">Connected Agents</h4>
            {agents.slice(0, maxAgents).map((agent) => (
              <div key={agent.id} className={`border rounded-lg p-4 ${getStatusColor(agent.status)}`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    {getPlatformIcon(agent.platform)}
                    <div>
                      <div className="font-medium text-gray-900">{agent.name}</div>
                      <div className="text-sm text-gray-500">
                        {agent.platform} • v{agent.version}
                        {agent.hostname && ` • ${agent.hostname}`}
                      </div>
                      {agent.uptime && (
                        <div className="text-xs text-gray-400">
                          Uptime: {formatUptime(agent.uptime)}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {getStatusIcon(agent.status)}
                    <span className="text-sm font-medium">
                      {agent.status.charAt(0).toUpperCase() + agent.status.slice(1)}
                    </span>
                    {agent.apiEndpoint && agent.status === 'online' && (
                      <button
                        onClick={() => handleViewAgent(agent.id)}
                        className="p-1 text-gray-400 hover:text-blue-600 transition-colors"
                        title="View agent dashboard"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
                
                {showDetails && agent.lastSeen && (
                  <div className="mt-2 text-xs text-gray-500">
                    Last seen: {formatTimestamp(agent.lastSeen)}
                  </div>
                )}
              </div>
            ))}
            
            {totalAgents > maxAgents && (
              <div className="text-center pt-2">
                <span className="text-sm text-gray-500">
                  +{totalAgents - maxAgents} more agents
                </span>
              </div>
            )}
          </div>
        ) : (
          <div className="text-center py-8">
            <Shield className="w-12 h-12 text-gray-300 mx-auto mb-3" />
            <p className="text-gray-500 mb-2">No agents connected</p>
            <p className="text-sm text-gray-400 mb-4">
              Deploy agents to start monitoring your network
            </p>
            <button className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
              <Download className="w-4 h-4" />
              <span>Download Agent</span>
            </button>
          </div>
        )}
      </div>

      {/* Recent Security Alerts */}
      {alerts.length > 0 && (
        <div className="bg-white rounded-lg shadow-sm p-6">
          <div className="flex items-center mb-4">
            <AlertTriangle className="w-5 h-5 text-orange-600 mr-2" />
            <h3 className="text-lg font-semibold text-gray-900">Recent Security Alerts</h3>
          </div>
          
          <div className="space-y-3">
            {alerts.slice(0, 5).map((alert) => (
              <div key={alert.id} className="border border-gray-200 rounded-lg p-3">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(alert.severity)}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <span className="text-sm font-medium text-gray-900">{alert.threat}</span>
                    </div>
                    <p className="text-sm text-gray-600 mb-1">
                      {alert.message.length > 100 ? `${alert.message.substring(0, 100)}...` : alert.message}
                    </p>
                    <div className="text-xs text-gray-400">
                      {alert.hostname} • {alert.source} • {formatTimestamp(alert.timestamp)}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default AgentStatusOverview; 