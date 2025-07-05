import React, { useState, useEffect } from 'react';
import {
  Settings,
  Download,
  Plus,
  Trash2,
  RefreshCw,
  Monitor,
  Server,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Copy,
  Shield,
  Activity,
  Package,
  Eye,
  BarChart3,
  Network,
  Clock,
  Wifi,
  WifiOff,
  PlayCircle,
  PauseCircle,
  Terminal
} from 'lucide-react';

interface IDSAgent {
  id: string;
  name: string;
  ipAddress: string;
  platform: string;
  version?: string;
  status: 'online' | 'offline' | 'unknown' | 'checking';
  lastSeen?: string;
  uptime?: number;
  idsMetrics?: {
    packetsProcessed: number;
    threatsDetected: number;
    packetsBlocked: number;
    rulesActive: number;
    processingRate: number;
    avgLatency: number;
    cpuUsage: number;
    memoryUsage: number;
  };
  logs?: Array<{
    timestamp: string;
    level: 'info' | 'warn' | 'error' | 'critical';
    message: string;
    component?: string;
  }>;
}

interface PacketLog {
  timestamp: string;
  sourceIP: string;
  destIP: string;
  protocol: string;
  action: 'allowed' | 'blocked' | 'alerted';
  ruleId?: string;
  message: string;
}

export function AgentConfiguration() {
  const [selectedTab, setSelectedTab] = useState('overview');
  const [isMonitoring, setIsMonitoring] = useState(true);
  const [agents, setAgents] = useState<IDSAgent[]>([
    {
      id: 'ids-001',
      name: 'Primary IDS/IPS Gateway',
      ipAddress: '192.168.1.50',
      platform: 'linux',
      version: '2.1.3',
      status: 'online',
      lastSeen: new Date().toISOString(),
      uptime: 172800,
      idsMetrics: {
        packetsProcessed: 2847592,
        threatsDetected: 47,
        packetsBlocked: 1230,
        rulesActive: 3456,
        processingRate: 15000,
        avgLatency: 0.23,
        cpuUsage: 65,
        memoryUsage: 45
      },
      logs: [
        { timestamp: new Date().toISOString(), level: 'info', message: 'IDS engine started successfully', component: 'core' },
        { timestamp: new Date(Date.now() - 60000).toISOString(), level: 'warn', message: 'High CPU usage detected', component: 'monitor' },
        { timestamp: new Date(Date.now() - 120000).toISOString(), level: 'critical', message: 'Malware signature detected', component: 'detection' }
      ]
    },
    {
      id: 'ids-002',
      name: 'DMZ Security Monitor',
      ipAddress: '10.0.1.25',
      platform: 'linux',
      version: '2.1.2',
      status: 'online',
      lastSeen: new Date().toISOString(),
      uptime: 86400,
      idsMetrics: {
        packetsProcessed: 1234567,
        threatsDetected: 23,
        packetsBlocked: 567,
        rulesActive: 2100,
        processingRate: 8500,
        avgLatency: 0.15,
        cpuUsage: 42,
        memoryUsage: 38
      },
      logs: [
        { timestamp: new Date().toISOString(), level: 'info', message: 'Packet processing normal', component: 'engine' },
        { timestamp: new Date(Date.now() - 30000).toISOString(), level: 'error', message: 'SSH brute force detected', component: 'detection' }
      ]
    },
    {
      id: 'ids-003',
      name: 'Cloud Edge Sensor',
      ipAddress: '172.16.0.100',
      platform: 'windows',
      status: 'offline',
      lastSeen: new Date(Date.now() - 3600000).toISOString()
    }
  ]);

  const [packetLogs, setPacketLogs] = useState<PacketLog[]>([
    { timestamp: new Date().toISOString(), sourceIP: '203.0.113.42', destIP: '192.168.1.100', protocol: 'TCP', action: 'blocked', ruleId: 'SSH_BRUTE_FORCE', message: 'SSH brute force attempt blocked' },
    { timestamp: new Date(Date.now() - 30000).toISOString(), sourceIP: '198.51.100.123', destIP: '192.168.1.50', protocol: 'HTTP', action: 'alerted', ruleId: 'SQL_INJECTION', message: 'Potential SQL injection detected' },
    { timestamp: new Date(Date.now() - 60000).toISOString(), sourceIP: '10.0.0.15', destIP: '192.168.1.100', protocol: 'HTTPS', action: 'allowed', message: 'Normal HTTPS traffic' }
  ]);

  const [showAddForm, setShowAddForm] = useState(false);
  const [newAgent, setNewAgent] = useState({
    name: '',
    ipAddress: '',
    platform: 'linux'
  });

  const platforms = [
    { 
      name: 'Linux x64', 
      icon: Server, 
      download: 'a2z-ids-linux-x64.tar.gz',
      description: 'Ubuntu/CentOS/RHEL (x64)',
      installCmd: 'tar -xzf a2z-ids-linux-x64.tar.gz && sudo ./install.sh'
    },
    { 
      name: 'Windows x64', 
      icon: Monitor, 
      download: 'a2z-ids-windows-x64.exe',
      description: 'Windows Server 2019+ (x64)',
      installCmd: 'a2z-ids-windows-x64.exe /S /D=C:\\A2Z-IDS'
    },
    { 
      name: 'Docker', 
      icon: Package, 
      download: 'docker-compose.yml',
      description: 'Containerized deployment',
      installCmd: 'docker-compose up -d'
    },
    { 
      name: 'ARM Linux', 
      icon: Server, 
      download: 'a2z-ids-arm64.tar.gz',
      description: 'ARM64 devices',
      installCmd: 'tar -xzf a2z-ids-arm64.tar.gz && sudo ./install.sh'
    }
  ];

  // Simulate real-time updates
  useEffect(() => {
    if (!isMonitoring) return;

    const interval = setInterval(() => {
      setAgents(prev => prev.map(agent => {
        if (agent.status === 'online' && agent.idsMetrics) {
          const newPacketsProcessed = agent.idsMetrics.packetsProcessed + Math.floor(Math.random() * 1000) + 500;
          const newThreatsDetected = agent.idsMetrics.threatsDetected + (Math.random() < 0.1 ? 1 : 0);
          
          // Add new log entry occasionally
          const newLogs = [...(agent.logs || [])];
          if (Math.random() < 0.3) {
            const logLevels = ['info', 'warn', 'error'] as const;
            const components = ['core', 'detection', 'engine', 'monitor'];
            const messages = [
              'Packet processing normal',
              'Rule signature updated',
              'Memory usage optimal',
              'Threat detected and blocked',
              'Performance metrics collected'
            ];
            
            newLogs.unshift({
              timestamp: new Date().toISOString(),
              level: logLevels[Math.floor(Math.random() * logLevels.length)],
              message: messages[Math.floor(Math.random() * messages.length)],
              component: components[Math.floor(Math.random() * components.length)]
            });
            
            // Keep only last 20 logs
            newLogs.splice(20);
          }

          return {
            ...agent,
            lastSeen: new Date().toISOString(),
            idsMetrics: {
              ...agent.idsMetrics,
              packetsProcessed: newPacketsProcessed,
              threatsDetected: newThreatsDetected,
              processingRate: Math.floor(Math.random() * 5000) + 10000,
              avgLatency: Math.random() * 0.5 + 0.1,
              cpuUsage: Math.floor(Math.random() * 30) + 40,
              memoryUsage: Math.floor(Math.random() * 20) + 35
            },
            logs: newLogs
          };
        }
        return agent;
      }));

      // Add new packet log occasionally
      if (Math.random() < 0.4) {
        const actions = ['allowed', 'blocked', 'alerted'] as const;
        const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS'];
        const sourceIPs = ['203.0.113.42', '198.51.100.123', '172.16.0.10', '10.0.0.15'];
        const destIPs = ['192.168.1.100', '192.168.1.50', '10.0.1.25'];
        
        const newPacketLog: PacketLog = {
          timestamp: new Date().toISOString(),
          sourceIP: sourceIPs[Math.floor(Math.random() * sourceIPs.length)],
          destIP: destIPs[Math.floor(Math.random() * destIPs.length)],
          protocol: protocols[Math.floor(Math.random() * protocols.length)],
          action: actions[Math.floor(Math.random() * actions.length)],
          ruleId: Math.random() > 0.5 ? `RULE_${Math.floor(Math.random() * 1000)}` : undefined,
          message: 'Real-time packet processing log'
        };
        
        setPacketLogs(prev => [newPacketLog, ...prev.slice(0, 49)]);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [isMonitoring]);

  const handleDownload = (platform: any) => {
    let content = '';
    let mimeType = 'application/octet-stream';
    
    switch (platform.name) {
      case 'Linux x64':
        content = `#!/bin/bash
# A2Z IDS/IPS Agent Installer for Linux
echo "Installing A2Z IDS/IPS Agent..."
echo "Version: 2.1.3"
echo "Platform: Linux x64"
echo "Installing IDS core engine..."
echo "Installing threat detection rules..."
echo "Installing ML models..."
echo "Configuring network interfaces..."
echo "Agent ID: $(uuidgen)"
echo "Installation complete!"
echo "Connect to: https://soc.a2z-platform.com"`;
        break;
      
      case 'Windows x64':
        content = `@echo off
REM A2Z IDS/IPS Agent Installer for Windows
echo Installing A2Z IDS/IPS Agent...
echo Version: 2.1.3
echo Platform: Windows x64
echo Installing IDS service...
echo Configuring Windows Defender integration...
echo Installation complete!
echo Agent ID: {$(powershell -Command "[guid]::NewGuid()")}
echo Connect to: https://soc.a2z-platform.com
pause`;
        break;
      
      case 'Docker':
        content = `version: '3.8'
services:
  a2z-ids:
    image: a2zsoc/ids-ips:latest
    container_name: a2z-ids
    restart: unless-stopped
    network_mode: host
    privileged: true
    environment:
      - A2Z_SOC_URL=https://soc.a2z-platform.com
      - AGENT_ID=\${AGENT_ID}
    volumes:
      - ./config:/etc/a2z-ids
      - ./logs:/var/log/a2z-ids
      - ./pcap:/var/lib/a2z-ids/pcap
    cap_add:
      - NET_ADMIN
      - NET_RAW`;
        mimeType = 'text/yaml';
        break;
    }

    const blob = new Blob([content], { type: mimeType });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = platform.download;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };

  const handleAddAgent = () => {
    if (newAgent.name && newAgent.ipAddress) {
      const agent: IDSAgent = {
        id: Date.now().toString(),
        ...newAgent,
        status: 'unknown'
      };
      setAgents([...agents, agent]);
      setNewAgent({ name: '', ipAddress: '', platform: 'linux' });
      setShowAddForm(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'bg-green-900 text-green-400';
      case 'offline': return 'bg-red-900 text-red-400';
      case 'checking': return 'bg-blue-900 text-blue-400';
      default: return 'bg-gray-700 text-gray-400';
    }
  };

  const getActionColor = (action: string) => {
    switch (action) {
      case 'allowed': return 'text-green-400';
      case 'blocked': return 'text-red-400';
      case 'alerted': return 'text-yellow-400';
      default: return 'text-gray-400';
    }
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'info': return 'text-blue-400';
      case 'warn': return 'text-yellow-400';
      case 'error': return 'text-orange-400';
      case 'critical': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const formatNumber = (num: number) => {
    return new Intl.NumberFormat().format(num);
  };

  const onlineAgents = agents.filter(a => a.status === 'online');
  const totalPacketsProcessed = onlineAgents.reduce((sum, agent) => 
    sum + (agent.idsMetrics?.packetsProcessed || 0), 0
  );
  const totalThreatsDetected = onlineAgents.reduce((sum, agent) => 
    sum + (agent.idsMetrics?.threatsDetected || 0), 0
  );

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="bg-gray-800 rounded-lg shadow-lg p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center">
                <Shield className="w-8 h-8 text-blue-400 mr-3" />
                IDS/IPS Agent Management
              </h1>
              <p className="text-gray-400 mt-1">Deploy and manage IDS/IPS agents with real-time monitoring</p>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={() => setIsMonitoring(!isMonitoring)}
                className={`flex items-center space-x-2 px-4 py-2 rounded-md font-medium transition-colors ${
                  isMonitoring ? 'bg-green-600 hover:bg-green-700 text-white' : 'bg-gray-600 hover:bg-gray-700 text-gray-300'
                }`}
              >
                {isMonitoring ? <PlayCircle className="w-4 h-4" /> : <PauseCircle className="w-4 h-4" />}
                <span>{isMonitoring ? 'Live Monitoring' : 'Monitoring Paused'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Wifi className="w-6 h-6 text-green-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Online Agents</p>
                <p className="text-2xl font-semibold text-green-400">{onlineAgents.length}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Package className="w-6 h-6 text-blue-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Packets Processed</p>
                <p className="text-2xl font-semibold text-blue-400">{formatNumber(totalPacketsProcessed)}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <AlertTriangle className="w-6 h-6 text-red-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Threats Detected</p>
                <p className="text-2xl font-semibold text-red-400">{totalThreatsDetected}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Activity className="w-6 h-6 text-purple-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Avg Processing Rate</p>
                <p className="text-2xl font-semibold text-purple-400">
                  {formatNumber(Math.floor(onlineAgents.reduce((sum, agent) => 
                    sum + (agent.idsMetrics?.processingRate || 0), 0) / Math.max(onlineAgents.length, 1)))} /s
                </p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <BarChart3 className="w-6 h-6 text-cyan-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Total Agents</p>
                <p className="text-2xl font-semibold text-cyan-400">{agents.length}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="bg-gray-800 rounded-lg shadow-lg border border-gray-700">
          <div className="flex border-b border-gray-700">
            {[
              { id: 'overview', label: 'Agent Overview', icon: BarChart3 },
              { id: 'download', label: 'Download Agents', icon: Download },
              { id: 'packets', label: 'Packet Logs', icon: Package },
              { id: 'logs', label: 'System Logs', icon: Terminal }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSelectedTab(tab.id)}
                className={`flex items-center space-x-2 px-6 py-4 font-medium transition-colors ${
                  selectedTab === tab.id
                    ? 'text-blue-400 border-b-2 border-blue-400 bg-gray-750'
                    : 'text-gray-400 hover:text-white hover:bg-gray-750'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            ))}
          </div>

          <div className="p-6">
            {selectedTab === 'overview' && (
              <div className="space-y-6">
                {/* Agent Management Header */}
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-white">Deployed IDS/IPS Agents</h3>
                  <button
                    onClick={() => setShowAddForm(true)}
                    className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Add Agent</span>
                  </button>
                </div>

                {/* Add Agent Form */}
                {showAddForm && (
                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h4 className="text-md font-semibold text-white mb-4">Register New IDS/IPS Agent</h4>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-1">Agent Name</label>
                        <input
                          type="text"
                          value={newAgent.name}
                          onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })}
                          placeholder="Edge Security Gateway"
                          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-1">IP Address</label>
                        <input
                          type="text"
                          value={newAgent.ipAddress}
                          onChange={(e) => setNewAgent({ ...newAgent, ipAddress: e.target.value })}
                          placeholder="10.0.1.50"
                          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
                        />
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-gray-300 mb-1">Platform</label>
                        <select
                          value={newAgent.platform}
                          onChange={(e) => setNewAgent({ ...newAgent, platform: e.target.value })}
                          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
                        >
                          <option value="linux">Linux</option>
                          <option value="windows">Windows</option>
                          <option value="docker">Docker</option>
                        </select>
                      </div>
                      <div className="flex items-end space-x-2">
                        <button
                          onClick={handleAddAgent}
                          disabled={!newAgent.name || !newAgent.ipAddress}
                          className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-md disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          Add Agent
                        </button>
                        <button
                          onClick={() => setShowAddForm(false)}
                          className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-md"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* Agents Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {agents.map((agent) => (
                    <div key={agent.id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center space-x-3">
                          <div className={`w-3 h-3 rounded-full ${agent.status === 'online' ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`}></div>
                          <div>
                            <h4 className="font-semibold text-white">{agent.name}</h4>
                            <p className="text-sm text-gray-400 font-mono">{agent.ipAddress}</p>
                          </div>
                        </div>
                        <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(agent.status)}`}>
                          {agent.status}
                        </span>
                      </div>
                      
                      {agent.idsMetrics && (
                        <div className="grid grid-cols-2 gap-3 mb-4">
                          <div className="bg-gray-700 rounded p-3">
                            <p className="text-xs text-gray-400">Packets Processed</p>
                            <p className="text-lg font-semibold text-blue-400">{formatNumber(agent.idsMetrics.packetsProcessed)}</p>
                          </div>
                          <div className="bg-gray-700 rounded p-3">
                            <p className="text-xs text-gray-400">Threats Detected</p>
                            <p className="text-lg font-semibold text-red-400">{agent.idsMetrics.threatsDetected}</p>
                          </div>
                          <div className="bg-gray-700 rounded p-3">
                            <p className="text-xs text-gray-400">Processing Rate</p>
                            <p className="text-lg font-semibold text-green-400">{formatNumber(agent.idsMetrics.processingRate)}/s</p>
                          </div>
                          <div className="bg-gray-700 rounded p-3">
                            <p className="text-xs text-gray-400">CPU Usage</p>
                            <p className="text-lg font-semibold text-purple-400">{agent.idsMetrics.cpuUsage}%</p>
                          </div>
                        </div>
                      )}
                      
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-gray-400">
                          Last seen: {agent.lastSeen ? new Date(agent.lastSeen).toLocaleTimeString() : 'Never'}
                        </span>
                        <span className="text-gray-400">
                          v{agent.version || 'Unknown'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedTab === 'download' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white mb-4">Download IDS/IPS Agents</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  {platforms.map((platform) => {
                    const Icon = platform.icon;
                    return (
                      <div key={platform.name} className="bg-gray-750 rounded-lg p-4 border border-gray-600 hover:border-blue-400 transition-colors">
                        <div className="flex items-center mb-3">
                          <Icon className="w-6 h-6 text-blue-400 mr-2" />
                          <h4 className="font-semibold text-white">{platform.name}</h4>
                        </div>
                        <p className="text-sm text-gray-400 mb-4">{platform.description}</p>
                        
                        <div className="space-y-3">
                          <button
                            onClick={() => handleDownload(platform)}
                            className="flex items-center justify-center space-x-2 w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
                          >
                            <Download className="w-4 h-4" />
                            <span>Download</span>
                          </button>
                          
                          <div className="text-xs text-gray-400">
                            <p className="font-medium mb-1">Install command:</p>
                            <div className="flex items-center space-x-1 bg-gray-700 p-2 rounded font-mono text-xs">
                              <code className="flex-1">{platform.installCmd}</code>
                              <button
                                onClick={() => navigator.clipboard.writeText(platform.installCmd)}
                                className="text-blue-400 hover:text-blue-300"
                              >
                                <Copy className="w-3 h-3" />
                              </button>
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {selectedTab === 'packets' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Package className="w-5 h-5 text-blue-400 mr-2" />
                  Real-time Packet Processing Logs
                </h3>
                
                <div className="bg-gray-750 rounded-lg border border-gray-600 overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead className="bg-gray-700 border-b border-gray-600">
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Time</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Destination</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Protocol</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Action</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Rule</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Message</th>
                        </tr>
                      </thead>
                      <tbody className="bg-gray-750 divide-y divide-gray-600">
                        {packetLogs.slice(0, 20).map((log, index) => (
                          <tr key={`${log.timestamp}-${index}`} className="hover:bg-gray-700 transition-colors">
                            <td className="px-4 py-3 text-sm text-gray-300">
                              {new Date(log.timestamp).toLocaleTimeString()}
                            </td>
                            <td className="px-4 py-3 text-sm text-white font-mono">{log.sourceIP}</td>
                            <td className="px-4 py-3 text-sm text-white font-mono">{log.destIP}</td>
                            <td className="px-4 py-3 text-sm text-blue-400">{log.protocol}</td>
                            <td className="px-4 py-3 text-sm">
                              <span className={`font-medium ${getActionColor(log.action)}`}>
                                {log.action}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-400 font-mono">
                              {log.ruleId || '-'}
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-300">{log.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {selectedTab === 'logs' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Terminal className="w-5 h-5 text-blue-400 mr-2" />
                  System Logs
                </h3>
                
                <div className="space-y-4">
                  {agents.filter(a => a.logs && a.logs.length > 0).map((agent) => (
                    <div key={agent.id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                      <h4 className="font-semibold text-white mb-3 flex items-center">
                        <Monitor className="w-4 h-4 text-green-400 mr-2" />
                        {agent.name}
                      </h4>
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {agent.logs?.map((log, index) => (
                          <div key={index} className="flex items-start space-x-3 text-sm">
                            <span className="text-gray-400 font-mono">
                              {new Date(log.timestamp).toLocaleTimeString()}
                            </span>
                            <span className={`font-medium ${getLevelColor(log.level)}`}>
                              [{log.level.toUpperCase()}]
                            </span>
                            <span className="text-gray-400">
                              {log.component}:
                            </span>
                            <span className="text-gray-300 flex-1">
                              {log.message}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
} 