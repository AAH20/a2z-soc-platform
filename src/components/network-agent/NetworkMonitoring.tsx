import React, { useState, useEffect } from 'react';
import {
  Activity,
  Globe,
  Network,
  Shield,
  Zap,
  TrendingUp,
  Eye,
  Download,
  Search,
  AlertTriangle,
  Wifi,
  WifiOff,
  Monitor,
  PlayCircle,
  PauseCircle,
  Server,
  Package,
  BarChart3,
  Clock,
  Database,
  Filter
} from 'lucide-react';

interface PacketData {
  timestamp: string;
  sourceIP: string;
  destIP: string;
  protocol: string;
  port: number;
  size: number;
  direction: 'inbound' | 'outbound';
  classification: 'normal' | 'suspicious' | 'blocked';
}

interface ConnectedAgent {
  id: string;
  name: string;
  ipAddress: string;
  status: 'online' | 'offline';
  lastSeen: string;
  location?: string;
  version?: string;
  metrics?: {
    packetsPerSecond: number;
    bytesPerSecond: number;
    connections: number;
    protocols: Record<string, number>;
    topSources: Array<{ ip: string; packets: number; bytes: number; country?: string }>;
    packetHistory: PacketData[];
    interfaceStats: {
      rxPackets: number;
      txPackets: number;
      rxBytes: number;
      txBytes: number;
      errors: number;
      drops: number;
    };
    qos: {
      latency: number;
      jitter: number;
      packetLoss: number;
    };
  };
}

export function NetworkMonitoring() {
  const [selectedAgent, setSelectedAgent] = useState<string>('all');
  const [timeRange, setTimeRange] = useState('1h');
  const [isLiveMonitoring, setIsLiveMonitoring] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTab, setSelectedTab] = useState('overview');
  const [packetFilter, setPacketFilter] = useState('all');

  // Mock connected agents with enhanced data
  const [connectedAgents, setConnectedAgents] = useState<ConnectedAgent[]>([
    {
      id: '1',
      name: 'Production Server',
      ipAddress: '192.168.1.100',
      status: 'online',
      lastSeen: new Date().toISOString(),
      location: 'Data Center A',
      version: '2.1.3',
      metrics: {
        packetsPerSecond: 1250,
        bytesPerSecond: 2500000,
        connections: 45,
        protocols: { TCP: 800, UDP: 300, ICMP: 150, HTTP: 500, HTTPS: 300, DNS: 200, FTP: 50, SSH: 25 },
        topSources: [
          { ip: '10.0.0.15', packets: 2500, bytes: 1250000, country: 'US' },
          { ip: '192.168.1.50', packets: 1800, bytes: 900000, country: 'CA' },
          { ip: '203.0.113.42', packets: 1200, bytes: 600000, country: 'UK' }
        ],
        packetHistory: [
          { timestamp: new Date().toISOString(), sourceIP: '10.0.0.15', destIP: '192.168.1.100', protocol: 'TCP', port: 443, size: 1460, direction: 'inbound', classification: 'normal' },
          { timestamp: new Date(Date.now() - 1000).toISOString(), sourceIP: '192.168.1.100', destIP: '8.8.8.8', protocol: 'UDP', port: 53, size: 64, direction: 'outbound', classification: 'normal' },
          { timestamp: new Date(Date.now() - 2000).toISOString(), sourceIP: '203.0.113.42', destIP: '192.168.1.100', protocol: 'TCP', port: 22, size: 78, direction: 'inbound', classification: 'suspicious' }
        ],
        interfaceStats: {
          rxPackets: 15420000,
          txPackets: 12380000,
          rxBytes: 8500000000,
          txBytes: 6200000000,
          errors: 12,
          drops: 3
        },
        qos: {
          latency: 2.3,
          jitter: 0.8,
          packetLoss: 0.01
        }
      }
    },
    {
      id: '2',
      name: 'Development Machine',
      ipAddress: '192.168.1.101',
      status: 'offline',
      lastSeen: new Date(Date.now() - 3600000).toISOString(),
      location: 'Office Floor 2',
      version: '2.1.1'
    },
    {
      id: '3',
      name: 'Web Server',
      ipAddress: '192.168.1.102',
      status: 'online',
      lastSeen: new Date().toISOString(),
      location: 'DMZ',
      version: '2.1.3',
      metrics: {
        packetsPerSecond: 850,
        bytesPerSecond: 1800000,
        connections: 32,
        protocols: { TCP: 600, UDP: 150, HTTP: 450, HTTPS: 400, DNS: 100 },
        topSources: [
          { ip: '172.16.0.10', packets: 1800, bytes: 900000, country: 'US' },
          { ip: '192.168.1.25', packets: 1200, bytes: 600000, country: 'US' }
        ],
        packetHistory: [],
        interfaceStats: {
          rxPackets: 8200000,
          txPackets: 7100000,
          rxBytes: 4200000000,
          txBytes: 3800000000,
          errors: 5,
          drops: 1
        },
        qos: {
          latency: 1.8,
          jitter: 0.5,
          packetLoss: 0.005
        }
      }
    }
  ]);

  // Simulate real-time updates
  useEffect(() => {
    if (!isLiveMonitoring) return;

    const interval = setInterval(() => {
      setConnectedAgents(prev => prev.map(agent => {
        if (agent.status === 'online' && agent.metrics) {
          // Generate new packet data
          const newPacket: PacketData = {
            timestamp: new Date().toISOString(),
            sourceIP: Math.random() > 0.5 ? agent.ipAddress : `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            destIP: Math.random() > 0.5 ? agent.ipAddress : `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            protocol: ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
            port: Math.floor(Math.random() * 65535),
            size: Math.floor(Math.random() * 1500) + 64,
            direction: Math.random() > 0.5 ? 'inbound' : 'outbound',
            classification: Math.random() > 0.95 ? 'suspicious' : (Math.random() > 0.98 ? 'blocked' : 'normal')
          };

          return {
            ...agent,
            lastSeen: new Date().toISOString(),
            metrics: {
              ...agent.metrics,
              packetsPerSecond: Math.floor(Math.random() * 2000) + 500,
              bytesPerSecond: Math.floor(Math.random() * 5000000) + 1000000,
              connections: Math.floor(Math.random() * 100) + 20,
              protocols: {
                TCP: Math.floor(Math.random() * 1000) + 500,
                UDP: Math.floor(Math.random() * 500) + 200,
                ICMP: Math.floor(Math.random() * 200) + 50,
                HTTP: Math.floor(Math.random() * 600) + 300,
                HTTPS: Math.floor(Math.random() * 400) + 200,
                DNS: Math.floor(Math.random() * 300) + 100,
                FTP: Math.floor(Math.random() * 100) + 25,
                SSH: Math.floor(Math.random() * 50) + 10
              },
              packetHistory: [newPacket, ...agent.metrics.packetHistory.slice(0, 99)],
              qos: {
                latency: Math.random() * 5 + 1,
                jitter: Math.random() * 2,
                packetLoss: Math.random() * 0.1
              }
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

    return agents.reduce((acc, agent) => {
      if (!agent.metrics) return acc;
      
      return {
        packetsPerSecond: acc.packetsPerSecond + agent.metrics.packetsPerSecond,
        bytesPerSecond: acc.bytesPerSecond + agent.metrics.bytesPerSecond,
        connections: acc.connections + agent.metrics.connections,
        protocols: Object.keys(agent.metrics.protocols).reduce((protAcc, protocol) => {
          protAcc[protocol] = (protAcc[protocol] || 0) + agent.metrics!.protocols[protocol];
          return protAcc;
        }, {} as Record<string, number>),
        topSources: [...acc.topSources, ...agent.metrics.topSources],
        packetHistory: [...acc.packetHistory, ...agent.metrics.packetHistory]
      };
    }, {
      packetsPerSecond: 0,
      bytesPerSecond: 0,
      connections: 0,
      protocols: {} as Record<string, number>,
      topSources: [] as Array<{ ip: string; packets: number; bytes: number; country?: string }>,
      packetHistory: [] as PacketData[]
    });
  };

  const metrics = aggregateMetrics();
  const onlineAgents = connectedAgents.filter(agent => agent.status === 'online');
  const offlineAgents = connectedAgents.filter(agent => agent.status === 'offline');

  const formatBytes = (bytes: number) => {
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const getProtocolColor = (protocol: string) => {
    const colors: Record<string, string> = {
      TCP: 'bg-blue-500',
      UDP: 'bg-green-500',
      ICMP: 'bg-yellow-500',
      HTTP: 'bg-purple-500',
      HTTPS: 'bg-indigo-500',
      DNS: 'bg-pink-500',
      FTP: 'bg-orange-500',
      SSH: 'bg-red-500'
    };
    return colors[protocol] || 'bg-gray-500';
  };

  const getClassificationColor = (classification: string) => {
    const colors: Record<string, string> = {
      normal: 'text-green-400',
      suspicious: 'text-yellow-400',
      blocked: 'text-red-400'
    };
    return colors[classification] || 'text-gray-400';
  };

  const filteredPackets = metrics?.packetHistory.filter(packet => {
    if (packetFilter === 'all') return true;
    return packet.classification === packetFilter;
  }) || [];

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="bg-gray-800 rounded-lg shadow-lg p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center">
                <Activity className="w-8 h-8 text-blue-400 mr-3" />
                Network Monitoring
              </h1>
              <p className="text-gray-400 mt-1">Real-time network traffic analysis across connected agents</p>
            </div>
            <div className="flex items-center space-x-4">
              <select 
                value={selectedAgent} 
                onChange={(e) => setSelectedAgent(e.target.value)}
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-sm text-white focus:ring-2 focus:ring-blue-500"
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
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-sm text-white focus:ring-2 focus:ring-blue-500"
              >
                <option value="5m">Last 5 minutes</option>
                <option value="1h">Last hour</option>
                <option value="24h">Last 24 hours</option>
                <option value="7d">Last 7 days</option>
              </select>
              <button
                onClick={() => setIsLiveMonitoring(!isLiveMonitoring)}
                className={`flex items-center space-x-2 px-3 py-2 rounded-md transition-colors ${
                  isLiveMonitoring ? 'bg-green-600 hover:bg-green-700 text-white' : 'bg-gray-600 hover:bg-gray-700 text-gray-300'
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
              <WifiOff className="w-6 h-6 text-red-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Offline Agents</p>
                <p className="text-2xl font-semibold text-red-400">{offlineAgents.length}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Activity className="w-6 h-6 text-blue-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Packets/sec</p>
                <p className="text-2xl font-semibold text-blue-400">
                  {metrics ? metrics.packetsPerSecond.toLocaleString() : 0}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <TrendingUp className="w-6 h-6 text-purple-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Bandwidth</p>
                <p className="text-2xl font-semibold text-purple-400">
                  {metrics ? formatBytes(metrics.bytesPerSecond) + '/s' : '0 B/s'}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Network className="w-6 h-6 text-orange-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Connections</p>
                <p className="text-2xl font-semibold text-orange-400">
                  {metrics ? metrics.connections.toLocaleString() : 0}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="bg-gray-800 rounded-lg shadow-lg border border-gray-700">
          <div className="flex border-b border-gray-700">
            {[
              { id: 'overview', label: 'Overview', icon: BarChart3 },
              { id: 'agents', label: 'Agent Details', icon: Server },
              { id: 'protocols', label: 'Protocol Analysis', icon: Network },
              { id: 'packets', label: 'Packet Inspection', icon: Package },
              { id: 'performance', label: 'Performance', icon: TrendingUp }
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
                {/* Protocol Distribution */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                      <Network className="w-5 h-5 text-blue-400 mr-2" />
                      Protocol Distribution
                    </h3>
                    <div className="space-y-3">
                      {metrics && Object.entries(metrics.protocols)
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 6)
                        .map(([protocol, count]) => {
                          const percentage = ((count / Object.values(metrics.protocols).reduce((a, b) => a + b, 0)) * 100).toFixed(1);
                          return (
                            <div key={protocol} className="flex items-center justify-between">
                              <div className="flex items-center space-x-3">
                                <div className={`w-3 h-3 rounded-full ${getProtocolColor(protocol)}`}></div>
                                <span className="text-sm font-medium text-gray-300">{protocol}</span>
                              </div>
                              <div className="flex items-center space-x-3">
                                <span className="text-sm text-gray-400">{count.toLocaleString()}</span>
                                <span className="text-sm text-gray-500">{percentage}%</span>
                              </div>
                            </div>
                          );
                        })
                      }
                    </div>
                  </div>

                  {/* Top Sources */}
                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                      <Globe className="w-5 h-5 text-green-400 mr-2" />
                      Top Traffic Sources
                    </h3>
                    <div className="space-y-3">
                      {metrics && metrics.topSources
                        .sort((a, b) => b.packets - a.packets)
                        .slice(0, 5)
                        .map((source, index) => (
                          <div key={source.ip} className="flex items-center justify-between p-3 bg-gray-700 rounded border border-gray-600">
                            <div className="flex items-center space-x-3">
                              <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-xs font-bold text-white">
                                {index + 1}
                              </div>
                              <div>
                                <p className="text-sm font-medium text-white">{source.ip}</p>
                                <p className="text-xs text-gray-400">{source.country || 'Unknown'}</p>
                              </div>
                            </div>
                            <div className="text-right">
                              <p className="text-sm font-medium text-blue-400">{source.packets.toLocaleString()} packets</p>
                              <p className="text-xs text-gray-400">{formatBytes(source.bytes)}</p>
                            </div>
                          </div>
                        ))
                      }
                    </div>
                  </div>
                </div>
              </div>
            )}

            {selectedTab === 'agents' && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Server className="w-5 h-5 text-blue-400 mr-2" />
                  Connected Agents Details
                </h3>
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {connectedAgents.map((agent) => (
                    <div key={agent.id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center space-x-3">
                          <div className={`w-3 h-3 rounded-full ${agent.status === 'online' ? 'bg-green-400' : 'bg-red-400'}`}></div>
                          <div>
                            <h4 className="font-semibold text-white">{agent.name}</h4>
                            <p className="text-sm text-gray-400">{agent.ipAddress}</p>
                          </div>
                        </div>
                        <span className={`px-2 py-1 text-xs rounded-full ${
                          agent.status === 'online' 
                            ? 'bg-green-900 text-green-400' 
                            : 'bg-red-900 text-red-400'
                        }`}>
                          {agent.status}
                        </span>
                      </div>
                      
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Location:</span>
                          <span className="text-white">{agent.location || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Version:</span>
                          <span className="text-white">{agent.version || 'Unknown'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Last Seen:</span>
                          <span className="text-white">{new Date(agent.lastSeen).toLocaleTimeString()}</span>
                        </div>
                        
                        {agent.metrics && (
                          <>
                            <div className="border-t border-gray-600 pt-3 mt-3">
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <p className="text-gray-400">Packets/sec</p>
                                  <p className="text-blue-400 font-semibold">{agent.metrics.packetsPerSecond.toLocaleString()}</p>
                                </div>
                                <div>
                                  <p className="text-gray-400">Bandwidth</p>
                                  <p className="text-purple-400 font-semibold">{formatBytes(agent.metrics.bytesPerSecond)}/s</p>
                                </div>
                                <div>
                                  <p className="text-gray-400">Connections</p>
                                  <p className="text-orange-400 font-semibold">{agent.metrics.connections}</p>
                                </div>
                                <div>
                                  <p className="text-gray-400">Latency</p>
                                  <p className="text-green-400 font-semibold">{agent.metrics.qos.latency.toFixed(1)}ms</p>
                                </div>
                              </div>
                            </div>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedTab === 'protocols' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <Network className="w-5 h-5 text-blue-400 mr-2" />
                  Protocol Analysis
                </h3>
                {metrics && (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {Object.entries(metrics.protocols)
                      .sort(([,a], [,b]) => b - a)
                      .map(([protocol, count]) => {
                        const total = Object.values(metrics.protocols).reduce((a, b) => a + b, 0);
                        const percentage = ((count / total) * 100).toFixed(1);
                        
                        return (
                          <div key={protocol} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                            <div className="flex items-center justify-between mb-3">
                              <div className="flex items-center space-x-2">
                                <div className={`w-3 h-3 rounded-full ${getProtocolColor(protocol)}`}></div>
                                <h4 className="font-semibold text-white">{protocol}</h4>
                              </div>
                              <span className="text-sm text-gray-400">{percentage}%</span>
                            </div>
                            
                            <div className="space-y-2">
                              <div className="flex justify-between text-sm">
                                <span className="text-gray-400">Packets:</span>
                                <span className="text-white">{count.toLocaleString()}</span>
                              </div>
                              <div className="w-full bg-gray-600 rounded-full h-2">
                                <div 
                                  className={`${getProtocolColor(protocol)} h-2 rounded-full transition-all duration-300`}
                                  style={{ width: `${percentage}%` }}
                                ></div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                )}
              </div>
            )}

            {selectedTab === 'packets' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-white flex items-center">
                    <Package className="w-5 h-5 text-blue-400 mr-2" />
                    Real-time Packet Inspection
                  </h3>
                  <div className="flex items-center space-x-3">
                    <select
                      value={packetFilter}
                      onChange={(e) => setPacketFilter(e.target.value)}
                      className="px-3 py-1 bg-gray-700 border border-gray-600 rounded text-sm text-white"
                    >
                      <option value="all">All Packets</option>
                      <option value="normal">Normal</option>
                      <option value="suspicious">Suspicious</option>
                      <option value="blocked">Blocked</option>
                    </select>
                    <div className="flex items-center space-x-2 text-sm text-gray-400">
                      <Filter className="w-4 h-4" />
                      <span>{filteredPackets.length} packets</span>
                    </div>
                  </div>
                </div>
                
                <div className="bg-gray-750 rounded-lg border border-gray-600 overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead className="bg-gray-700 border-b border-gray-600">
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Time</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Destination</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Protocol</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Port</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Size</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Direction</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                        </tr>
                      </thead>
                      <tbody className="bg-gray-750 divide-y divide-gray-600">
                        {filteredPackets.slice(0, 50).map((packet, index) => (
                          <tr key={`${packet.timestamp}-${index}`} className="hover:bg-gray-700 transition-colors">
                            <td className="px-4 py-3 text-sm text-gray-300">
                              {new Date(packet.timestamp).toLocaleTimeString()}
                            </td>
                            <td className="px-4 py-3 text-sm text-white font-mono">{packet.sourceIP}</td>
                            <td className="px-4 py-3 text-sm text-white font-mono">{packet.destIP}</td>
                            <td className="px-4 py-3 text-sm">
                              <span className={`px-2 py-1 rounded text-xs text-white ${getProtocolColor(packet.protocol)}`}>
                                {packet.protocol}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm text-gray-300">{packet.port}</td>
                            <td className="px-4 py-3 text-sm text-gray-300">{formatBytes(packet.size)}</td>
                            <td className="px-4 py-3 text-sm">
                              <span className={`flex items-center space-x-1 ${packet.direction === 'inbound' ? 'text-blue-400' : 'text-green-400'}`}>
                                <span>{packet.direction === 'inbound' ? '→' : '←'}</span>
                                <span>{packet.direction}</span>
                              </span>
                            </td>
                            <td className="px-4 py-3 text-sm">
                              <span className={`px-2 py-1 rounded text-xs font-medium ${
                                packet.classification === 'normal' ? 'bg-green-900 text-green-400' :
                                packet.classification === 'suspicious' ? 'bg-yellow-900 text-yellow-400' :
                                'bg-red-900 text-red-400'
                              }`}>
                                {packet.classification}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {selectedTab === 'performance' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <TrendingUp className="w-5 h-5 text-blue-400 mr-2" />
                  Performance Metrics
                </h3>
                
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {onlineAgents.map((agent) => (
                    agent.metrics && (
                      <div key={agent.id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                        <h4 className="font-semibold text-white mb-4">{agent.name}</h4>
                        
                        <div className="grid grid-cols-2 gap-4 mb-4">
                          <div className="bg-gray-700 rounded p-3 border border-gray-600">
                            <p className="text-sm text-gray-400">Network Latency</p>
                            <p className="text-xl font-semibold text-green-400">{agent.metrics.qos.latency.toFixed(1)}ms</p>
                          </div>
                          <div className="bg-gray-700 rounded p-3 border border-gray-600">
                            <p className="text-sm text-gray-400">Packet Loss</p>
                            <p className="text-xl font-semibold text-blue-400">{(agent.metrics.qos.packetLoss * 100).toFixed(3)}%</p>
                          </div>
                        </div>
                        
                        <div className="space-y-3">
                          <h5 className="text-sm font-medium text-gray-300">Interface Statistics</h5>
                          <div className="grid grid-cols-2 gap-3 text-sm">
                            <div className="flex justify-between">
                              <span className="text-gray-400">RX Packets:</span>
                              <span className="text-white">{agent.metrics.interfaceStats.rxPackets.toLocaleString()}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">TX Packets:</span>
                              <span className="text-white">{agent.metrics.interfaceStats.txPackets.toLocaleString()}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">RX Bytes:</span>
                              <span className="text-white">{formatBytes(agent.metrics.interfaceStats.rxBytes)}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">TX Bytes:</span>
                              <span className="text-white">{formatBytes(agent.metrics.interfaceStats.txBytes)}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Errors:</span>
                              <span className="text-red-400">{agent.metrics.interfaceStats.errors}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Drops:</span>
                              <span className="text-yellow-400">{agent.metrics.interfaceStats.drops}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )
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