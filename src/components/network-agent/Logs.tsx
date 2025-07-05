import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  FileText,
  Search,
  Filter,
  Download,
  RefreshCw,
  AlertCircle,
  Info,
  AlertTriangle,
  XCircle,
  Clock,
  Terminal,
  Eye,
  Settings,
  Wifi,
  WifiOff
} from 'lucide-react';
import { networkAgentAPI } from '@/services/networkAgent';
import { LogEntry, AgentStatus } from '@/types';

export function Logs() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLevel, setSelectedLevel] = useState('all');
  const [selectedComponent, setSelectedComponent] = useState('all');
  const [timeRange, setTimeRange] = useState('1h');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'disconnected' | 'connecting'>('connecting');

  const { data: logs, isLoading, error, refetch } = useQuery<LogEntry[]>({
    queryKey: ['agentLogs', selectedLevel, selectedComponent, timeRange],
    queryFn: async () => {
      try {
        setConnectionStatus('connecting');
        const result = await networkAgentAPI.getLogs({ 
          level: selectedLevel, 
          component: selectedComponent, 
          timeRange,
          search: searchTerm 
        });
        setConnectionStatus('connected');
        return result;
      } catch (error) {
        setConnectionStatus('disconnected');
        throw error;
      }
    },
    refetchInterval: autoRefresh ? 5000 : false,
    retry: 2,
    retryDelay: 1000,
  });

  const { data: agentStatus } = useQuery<AgentStatus>({
    queryKey: ['agentStatus'],
    queryFn: async () => {
      try {
        const result = await networkAgentAPI.getAgentStatus();
        setConnectionStatus('connected');
        return result;
      } catch (error) {
        setConnectionStatus('disconnected');
        throw error;
      }
    },
    refetchInterval: 5000,
    retry: 1,
  });

  const filteredLogs = logs?.filter(log => 
    searchTerm === '' || 
    log.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
    log.component.toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  const getLogLevelIcon = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'warn':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case 'info':
        return <Info className="w-4 h-4 text-blue-500" />;
      case 'debug':
        return <Terminal className="w-4 h-4 text-gray-500" />;
      default:
        return <FileText className="w-4 h-4 text-gray-500" />;
    }
  };

  const getLogLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'warn':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'info':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      case 'debug':
        return 'text-gray-600 bg-gray-50 border-gray-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const handleExportLogs = () => {
    const logText = filteredLogs.map(log => 
      `[${formatTimestamp(log.timestamp)}] [${log.level.toUpperCase()}] [${log.component}] ${log.message}`
    ).join('\n');
    
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `agent-logs-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const components = ['all', 'agent', 'network', 'threat-detector', 'metrics', 'api'];
  const logLevels = ['all', 'debug', 'info', 'warn', 'error'];

  const logStats = {
    total: filteredLogs.length,
    errors: filteredLogs.filter(log => log.level === 'error').length,
    warnings: filteredLogs.filter(log => log.level === 'warn').length,
    info: filteredLogs.filter(log => log.level === 'info').length,
    debug: filteredLogs.filter(log => log.level === 'debug').length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 flex items-center">
              <FileText className="w-8 h-8 text-purple-600 mr-3" />
              Agent Logs
            </h1>
            <p className="text-gray-500 mt-1">Real-time agent logs and system events</p>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={() => refetch()}
              className="flex items-center space-x-2 px-3 py-2 border border-gray-300 rounded-md text-sm hover:bg-gray-50"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Refresh</span>
            </button>
            <button
              onClick={handleExportLogs}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
            >
              <Download className="w-4 h-4" />
              <span>Export</span>
            </button>
            <div className={`flex items-center space-x-2 px-3 py-2 rounded-md ${
              connectionStatus === 'connected' && agentStatus?.status === 'running' 
                ? 'bg-green-100 text-green-800' 
                : connectionStatus === 'connecting' 
                ? 'bg-yellow-100 text-yellow-800'
                : 'bg-red-100 text-red-800'
            }`}>
              {connectionStatus === 'connected' ? (
                <Wifi className="w-4 h-4" />
              ) : connectionStatus === 'connecting' ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <WifiOff className="w-4 h-4" />
              )}
              <span className="text-sm font-medium">
                {connectionStatus === 'connected' && agentStatus?.status === 'running' 
                  ? 'Agent Connected (Port 5200)' 
                  : connectionStatus === 'connecting'
                  ? 'Connecting to Agent...'
                  : 'Agent Disconnected'
                }
              </span>
            </div>
          </div>
        </div>

        {/* Connection Error Alert */}
        {connectionStatus === 'disconnected' && (
          <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
            <div className="flex items-start">
              <AlertCircle className="w-5 h-5 text-yellow-500 mr-3 mt-0.5" />
              <div>
                <h3 className="text-sm font-medium text-yellow-800">Network Agent Not Connected</h3>
                <p className="text-sm text-yellow-700 mt-1">
                  Unable to connect to the Network Agent on port 5200. Make sure the agent is running.
                </p>
                <div className="mt-2 text-xs text-yellow-600">
                  <p>To start the MacOS Network Agent:</p>
                  <code className="block mt-1 p-2 bg-yellow-100 rounded text-yellow-800">
                    cd agents/network-agent && npm start
                  </code>
                  <p className="mt-1">Or check if it's accessible at: http://localhost:5200/health</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Log Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="flex items-center">
            <FileText className="w-6 h-6 text-gray-600 mr-3" />
            <div>
              <p className="text-sm font-medium text-gray-500">Total Logs</p>
              <p className="text-xl font-semibold text-gray-900">{logStats.total}</p>
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="flex items-center">
            <XCircle className="w-6 h-6 text-red-500 mr-3" />
            <div>
              <p className="text-sm font-medium text-gray-500">Errors</p>
              <p className="text-xl font-semibold text-red-600">{logStats.errors}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="flex items-center">
            <AlertTriangle className="w-6 h-6 text-yellow-500 mr-3" />
            <div>
              <p className="text-sm font-medium text-gray-500">Warnings</p>
              <p className="text-xl font-semibold text-yellow-600">{logStats.warnings}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="flex items-center">
            <Info className="w-6 h-6 text-blue-500 mr-3" />
            <div>
              <p className="text-sm font-medium text-gray-500">Info</p>
              <p className="text-xl font-semibold text-blue-600">{logStats.info}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm p-4">
          <div className="flex items-center">
            <Terminal className="w-6 h-6 text-gray-500 mr-3" />
            <div>
              <p className="text-sm font-medium text-gray-500">Debug</p>
              <p className="text-xl font-semibold text-gray-600">{logStats.debug}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Search Logs
            </label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search messages..."
                className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Log Level
            </label>
            <select
              value={selectedLevel}
              onChange={(e) => setSelectedLevel(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {logLevels.map(level => (
                <option key={level} value={level} className="capitalize">
                  {level === 'all' ? 'All Levels' : level.charAt(0).toUpperCase() + level.slice(1)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Component
            </label>
            <select
              value={selectedComponent}
              onChange={(e) => setSelectedComponent(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {components.map(component => (
                <option key={component} value={component} className="capitalize">
                  {component === 'all' ? 'All Components' : component.replace('-', ' ')}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Time Range
            </label>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="5m">Last 5 minutes</option>
              <option value="1h">Last hour</option>
              <option value="24h">Last 24 hours</option>
              <option value="7d">Last 7 days</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Auto Refresh
            </label>
            <div className="flex items-center space-x-2 mt-2">
              <input
                type="checkbox"
                id="autoRefresh"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <label htmlFor="autoRefresh" className="text-sm text-gray-700">
                Live updates
              </label>
            </div>
          </div>
        </div>
      </div>

      {/* Log Entries */}
      <div className="bg-white rounded-lg shadow-sm">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900 flex items-center">
              <Eye className="w-5 h-5 text-green-600 mr-2" />
              Log Entries ({filteredLogs.length})
            </h3>
            <div className="flex items-center space-x-2">
              {isLoading && (
                <div className="flex items-center space-x-2 text-sm text-gray-500">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Loading...</span>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="max-h-96 overflow-y-auto">
          {filteredLogs.length > 0 ? (
            <div className="space-y-1 p-4">
              {filteredLogs.map((log, index) => (
                <div
                  key={index}
                  className={`p-3 border-l-4 rounded-r-md ${getLogLevelColor(log.level)}`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3 flex-1">
                      {getLogLevelIcon(log.level)}
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-1">
                          <span className="font-medium text-xs uppercase tracking-wide">
                            {log.level}
                          </span>
                          <span className="text-sm text-gray-600">
                            [{log.component}]
                          </span>
                          <span className="text-xs text-gray-500">
                            {formatTimestamp(log.timestamp)}
                          </span>
                        </div>
                        <div className="text-sm text-gray-900 font-mono">
                          {log.message}
                        </div>
                        {log.metadata && Object.keys(log.metadata).length > 0 && (
                          <div className="mt-2 text-xs text-gray-600">
                            <details className="cursor-pointer">
                              <summary className="text-blue-600 hover:text-blue-800">
                                View metadata
                              </summary>
                              <pre className="mt-1 p-2 bg-gray-100 rounded text-xs overflow-x-auto">
                                {JSON.stringify(log.metadata, null, 2)}
                              </pre>
                            </details>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center">
              <FileText className="w-12 h-12 text-gray-300 mx-auto mb-4" />
              <div className="text-sm text-gray-500">
                {isLoading ? 'Loading logs...' : 'No log entries found for the selected filters'}
              </div>
              {!isLoading && (
                <div className="text-xs text-gray-400 mt-1">
                  Try adjusting your search criteria or time range
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Log Settings */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
          <Settings className="w-5 h-5 text-blue-600 mr-2" />
          Log Settings
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center justify-between mb-2">
              <span className="font-medium text-gray-900">Log Retention</span>
              <Clock className="w-4 h-4 text-gray-500" />
            </div>
            <div className="text-sm text-gray-600">
              Logs are retained for 30 days by default
            </div>
          </div>

          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center justify-between mb-2">
              <span className="font-medium text-gray-900">Log Level</span>
              <AlertCircle className="w-4 h-4 text-gray-500" />
            </div>
            <div className="text-sm text-gray-600">
              Current level: {agentStatus?.systemInfo ? 'Info' : 'Unknown'}
            </div>
          </div>

          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center justify-between mb-2">
              <span className="font-medium text-gray-900">Log Size</span>
              <FileText className="w-4 h-4 text-gray-500" />
            </div>
            <div className="text-sm text-gray-600">
              Current size: {Math.round(filteredLogs.length * 0.1)}KB
            </div>
          </div>
        </div>
      </div>
    </div>
  );
} 