import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  XCircle,
  CheckCircle,
  Eye,
  Filter,
  Download,
  Settings,
  Zap,
  WifiOff,
  Wifi,
  Clock,
  TrendingUp,
  Users,
  Activity,
  Search,
  MapPin,
  FileText,
  BarChart3,
  Target
} from 'lucide-react';

interface ConnectedAgent {
  id: string;
  name: string;
  ipAddress: string;
  status: 'online' | 'offline';
  lastSeen: string;
  threatStats?: {
    totalThreats: number;
    criticalThreats: number;
    highThreats: number;
    mediumThreats: number;
    lowThreats: number;
    blockedIPs: number;
    mitigatedThreats: number;
    activeThreats: number;
  };
}

interface ThreatAlert {
  id: string;
  agentId: string;
  agentName: string;
  timestamp: string;
  type: 'signature' | 'anomaly' | 'behavioral' | 'volumetric' | 'malware' | 'intrusion' | 'dos' | 'bruteforce';
  severity: 'low' | 'medium' | 'high' | 'critical';
  sourceIP: string;
  destinationIP?: string;
  protocol?: string;
  port?: number;
  description: string;
  rule?: string;
  status: 'active' | 'investigating' | 'resolved' | 'false_positive';
  location?: string;
  attackVector?: string;
  confidence?: number;
  impactScore?: number;
}

interface ThreatRule {
  id: string;
  name: string;
  type: 'signature' | 'anomaly' | 'behavioral' | 'volumetric';
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  triggerCount: number;
  lastTriggered?: string;
  description?: string;
  category?: string;
  accuracy?: number;
}

export function ThreatDetection() {
  const [selectedAgent, setSelectedAgent] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [selectedStatus, setSelectedStatus] = useState('all');
  const [isRealTimeEnabled, setIsRealTimeEnabled] = useState(true);
  const [selectedTab, setSelectedTab] = useState('overview');
  const [searchTerm, setSearchTerm] = useState('');

  // Mock connected agents with enhanced threat stats
  const [connectedAgents, setConnectedAgents] = useState<ConnectedAgent[]>([
    {
      id: '1',
      name: 'Production Server',
      ipAddress: '192.168.1.100',
      status: 'online',
      lastSeen: new Date().toISOString(),
      threatStats: {
        totalThreats: 45,
        criticalThreats: 2,
        highThreats: 8,
        mediumThreats: 15,
        lowThreats: 20,
        blockedIPs: 12,
        mitigatedThreats: 38,
        activeThreats: 7
      }
    },
    {
      id: '2',
      name: 'Development Machine',
      ipAddress: '192.168.1.101',
      status: 'offline',
      lastSeen: new Date(Date.now() - 3600000).toISOString()
    },
    {
      id: '3',
      name: 'Web Server',
      ipAddress: '192.168.1.102',
      status: 'online',
      lastSeen: new Date().toISOString(),
      threatStats: {
        totalThreats: 23,
        criticalThreats: 1,
        highThreats: 5,
        mediumThreats: 8,
        lowThreats: 9,
        blockedIPs: 6,
        mitigatedThreats: 20,
        activeThreats: 3
      }
    }
  ]);

  // Enhanced mock threat alerts
  const [threatAlerts, setThreatAlerts] = useState<ThreatAlert[]>([
    {
      id: '1',
      agentId: '1',
      agentName: 'Production Server',
      timestamp: new Date(Date.now() - 300000).toISOString(),
      type: 'intrusion',
      severity: 'critical',
      sourceIP: '203.0.113.42',
      destinationIP: '192.168.1.100',
      protocol: 'TCP',
      port: 22,
      description: 'Multiple failed SSH login attempts detected from suspicious IP',
      rule: 'SSH_BRUTE_FORCE',
      status: 'active',
      location: 'Russia',
      attackVector: 'Credential Stuffing',
      confidence: 95,
      impactScore: 8.5
    },
    {
      id: '2',
      agentId: '1',
      agentName: 'Production Server',
      timestamp: new Date(Date.now() - 600000).toISOString(),
      type: 'anomaly',
      severity: 'high',
      sourceIP: '198.51.100.123',
      destinationIP: '192.168.1.100',
      protocol: 'HTTPS',
      port: 443,
      description: 'Unusual data exfiltration pattern detected - large file transfers',
      rule: 'DATA_EXFIL_ANOMALY',
      status: 'investigating',
      location: 'China',
      attackVector: 'Data Exfiltration',
      confidence: 87,
      impactScore: 7.2
    },
    {
      id: '3',
      agentId: '3',
      agentName: 'Web Server',
      timestamp: new Date(Date.now() - 900000).toISOString(),
      type: 'malware',
      severity: 'critical',
      sourceIP: '185.220.101.50',
      destinationIP: '192.168.1.102',
      protocol: 'HTTP',
      port: 80,
      description: 'Malware signature detected in web traffic - potential trojan download',
      rule: 'MALWARE_DETECTION',
      status: 'resolved',
      location: 'Germany',
      attackVector: 'Malware Download',
      confidence: 98,
      impactScore: 9.1
    },
    {
      id: '4',
      agentId: '1',
      agentName: 'Production Server',
      timestamp: new Date(Date.now() - 1200000).toISOString(),
      type: 'dos',
      severity: 'high',
      sourceIP: '172.16.254.1',
      destinationIP: '192.168.1.100',
      protocol: 'TCP',
      port: 80,
      description: 'DDoS attack detected - high volume of requests from single source',
      rule: 'DDOS_DETECTION',
      status: 'resolved',
      location: 'United States',
      attackVector: 'Volume-based DDoS',
      confidence: 92,
      impactScore: 6.8
    }
  ]);

  // Enhanced mock threat rules
  const [threatRules, setThreatRules] = useState<ThreatRule[]>([
    {
      id: '1',
      name: 'SSH Brute Force Detection',
      type: 'signature',
      severity: 'high',
      enabled: true,
      triggerCount: 24,
      lastTriggered: new Date(Date.now() - 300000).toISOString(),
      description: 'Detects multiple failed SSH authentication attempts',
      category: 'Authentication',
      accuracy: 94
    },
    {
      id: '2',
      name: 'Port Scan Detection',
      type: 'behavioral',
      severity: 'medium',
      enabled: true,
      triggerCount: 156,
      lastTriggered: new Date(Date.now() - 1800000).toISOString(),
      description: 'Identifies network reconnaissance activities',
      category: 'Reconnaissance',
      accuracy: 88
    },
    {
      id: '3',
      name: 'Malware Signature Match',
      type: 'signature',
      severity: 'critical',
      enabled: true,
      triggerCount: 3,
      lastTriggered: new Date(Date.now() - 7200000).toISOString(),
      description: 'Matches known malware signatures in network traffic',
      category: 'Malware',
      accuracy: 98
    },
    {
      id: '4',
      name: 'Data Exfiltration Anomaly',
      type: 'anomaly',
      severity: 'high',
      enabled: true,
      triggerCount: 12,
      lastTriggered: new Date(Date.now() - 600000).toISOString(),
      description: 'Detects unusual outbound data patterns',
      category: 'Data Loss Prevention',
      accuracy: 85
    },
    {
      id: '5',
      name: 'DDoS Volume Detection',
      type: 'volumetric',
      severity: 'high',
      enabled: true,
      triggerCount: 8,
      lastTriggered: new Date(Date.now() - 1200000).toISOString(),
      description: 'Identifies high-volume traffic patterns',
      category: 'Denial of Service',
      accuracy: 91
    }
  ]);

  // Simulate real-time updates
  useEffect(() => {
    if (!isRealTimeEnabled) return;

    const interval = setInterval(() => {
      // Randomly add new threats
      if (Math.random() < 0.3) {
        const threatTypes = ['intrusion', 'anomaly', 'malware', 'dos', 'bruteforce'];
        const severities = ['low', 'medium', 'high', 'critical'];
        const statuses = ['active', 'investigating'];
        const locations = ['Russia', 'China', 'United States', 'Germany', 'Brazil', 'India'];
        const attackVectors = ['Credential Stuffing', 'Data Exfiltration', 'Malware Download', 'Volume-based DDoS', 'SQL Injection'];
        
        const newThreat: ThreatAlert = {
          id: Date.now().toString(),
          agentId: Math.random() > 0.5 ? '1' : '3',
          agentName: Math.random() > 0.5 ? 'Production Server' : 'Web Server',
          timestamp: new Date().toISOString(),
          type: threatTypes[Math.floor(Math.random() * threatTypes.length)] as any,
          severity: severities[Math.floor(Math.random() * severities.length)] as any,
          sourceIP: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          destinationIP: Math.random() > 0.5 ? '192.168.1.100' : '192.168.1.102',
          protocol: ['TCP', 'UDP', 'HTTP', 'HTTPS'][Math.floor(Math.random() * 4)],
          port: Math.floor(Math.random() * 65535),
          description: 'Real-time threat detected',
          status: statuses[Math.floor(Math.random() * statuses.length)] as any,
          location: locations[Math.floor(Math.random() * locations.length)],
          attackVector: attackVectors[Math.floor(Math.random() * attackVectors.length)],
          confidence: Math.floor(Math.random() * 30) + 70,
          impactScore: Math.random() * 5 + 5
        };
        
        setThreatAlerts(prev => [newThreat, ...prev.slice(0, 19)]);
      }

      // Update threat stats
      setConnectedAgents(prev => prev.map(agent => {
        if (agent.status === 'online' && agent.threatStats) {
          const newThreatIncrease = Math.floor(Math.random() * 3);
          return {
            ...agent,
            lastSeen: new Date().toISOString(),
            threatStats: {
              ...agent.threatStats,
              totalThreats: agent.threatStats.totalThreats + newThreatIncrease,
              criticalThreats: agent.threatStats.criticalThreats + (Math.random() < 0.1 ? 1 : 0),
              activeThreats: Math.max(0, agent.threatStats.activeThreats + Math.floor(Math.random() * 3) - 1)
            }
          };
        }
        return agent;
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, [isRealTimeEnabled]);

  const getFilteredThreats = () => {
    return threatAlerts.filter(threat => {
      if (selectedAgent !== 'all' && threat.agentId !== selectedAgent) return false;
      if (selectedSeverity !== 'all' && threat.severity !== selectedSeverity) return false;
      if (selectedStatus !== 'all' && threat.status !== selectedStatus) return false;
      if (searchTerm && !threat.description.toLowerCase().includes(searchTerm.toLowerCase()) && 
          !threat.sourceIP.includes(searchTerm)) return false;
      return true;
    });
  };

  const aggregatedStats = connectedAgents
    .filter(agent => agent.status === 'online' && agent.threatStats)
    .reduce((acc, agent) => {
      if (!agent.threatStats) return acc;
      return {
        totalThreats: acc.totalThreats + agent.threatStats.totalThreats,
        criticalThreats: acc.criticalThreats + agent.threatStats.criticalThreats,
        highThreats: acc.highThreats + agent.threatStats.highThreats,
        mediumThreats: acc.mediumThreats + agent.threatStats.mediumThreats,
        lowThreats: acc.lowThreats + agent.threatStats.lowThreats,
        blockedIPs: acc.blockedIPs + agent.threatStats.blockedIPs,
        mitigatedThreats: acc.mitigatedThreats + agent.threatStats.mitigatedThreats,
        activeThreats: acc.activeThreats + agent.threatStats.activeThreats
      };
    }, {
      totalThreats: 0,
      criticalThreats: 0,
      highThreats: 0,
      mediumThreats: 0,
      lowThreats: 0,
      blockedIPs: 0,
      mitigatedThreats: 0,
      activeThreats: 0
    });

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <XCircle className="w-4 h-4" />;
      case 'high': return <AlertTriangle className="w-4 h-4" />;
      case 'medium': return <Eye className="w-4 h-4" />;
      case 'low': return <CheckCircle className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-900';
      case 'high': return 'text-orange-400 bg-orange-900';
      case 'medium': return 'text-yellow-400 bg-yellow-900';
      case 'low': return 'text-green-400 bg-green-900';
      default: return 'text-gray-400 bg-gray-700';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-red-400 bg-red-900';
      case 'investigating': return 'text-yellow-400 bg-yellow-900';
      case 'resolved': return 'text-green-400 bg-green-900';
      case 'false_positive': return 'text-gray-400 bg-gray-700';
      default: return 'text-gray-400 bg-gray-700';
    }
  };

  const toggleRule = (ruleId: string) => {
    setThreatRules(prev => prev.map(rule => 
      rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule
    ));
  };

  const filteredThreats = getFilteredThreats();
  const onlineAgents = connectedAgents.filter(agent => agent.status === 'online');

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="space-y-6 p-6">
      {/* Header */}
        <div className="bg-gray-800 rounded-lg shadow-lg p-6 border border-gray-700">
        <div className="flex items-center justify-between">
          <div>
              <h1 className="text-2xl font-bold text-white flex items-center">
                <Shield className="w-8 h-8 text-red-400 mr-3" />
              Threat Detection
            </h1>
              <p className="text-gray-400 mt-1">Real-time threat monitoring and advanced security analytics</p>
          </div>
          <div className="flex items-center space-x-4">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                <input
                  type="text"
                  placeholder="Search threats..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-md text-sm text-white focus:ring-2 focus:ring-blue-500"
                />
              </div>
            <button
              onClick={() => setIsRealTimeEnabled(!isRealTimeEnabled)}
                className={`flex items-center space-x-2 px-3 py-2 rounded-md transition-colors ${
                  isRealTimeEnabled ? 'bg-green-600 hover:bg-green-700 text-white' : 'bg-gray-600 hover:bg-gray-700 text-gray-300'
              }`}
            >
                {isRealTimeEnabled ? <Activity className="w-4 h-4 animate-pulse" /> : <Activity className="w-4 h-4" />}
              <span className="text-sm font-medium">
                  {isRealTimeEnabled ? 'Live Detection' : 'Detection Paused'}
              </span>
            </button>
          </div>
        </div>
      </div>

        {/* Threat Overview Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-4 lg:grid-cols-8 gap-4">
          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Shield className="w-6 h-6 text-blue-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Total Threats</p>
                <p className="text-2xl font-semibold text-blue-400">{aggregatedStats.totalThreats}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
          <div className="flex items-center">
              <XCircle className="w-6 h-6 text-red-400 mr-3" />
            <div>
                <p className="text-sm font-medium text-gray-400">Critical</p>
                <p className="text-2xl font-semibold text-red-400">{aggregatedStats.criticalThreats}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <AlertTriangle className="w-6 h-6 text-orange-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">High</p>
                <p className="text-2xl font-semibold text-orange-400">{aggregatedStats.highThreats}</p>
            </div>
          </div>
        </div>
        
          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
          <div className="flex items-center">
              <Eye className="w-6 h-6 text-yellow-400 mr-3" />
            <div>
                <p className="text-sm font-medium text-gray-400">Medium</p>
                <p className="text-2xl font-semibold text-yellow-400">{aggregatedStats.mediumThreats}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <CheckCircle className="w-6 h-6 text-green-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Low</p>
                <p className="text-2xl font-semibold text-green-400">{aggregatedStats.lowThreats}</p>
            </div>
          </div>
        </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
          <div className="flex items-center">
              <Target className="w-6 h-6 text-purple-400 mr-3" />
            <div>
                <p className="text-sm font-medium text-gray-400">Active</p>
                <p className="text-2xl font-semibold text-purple-400">{aggregatedStats.activeThreats}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Users className="w-6 h-6 text-cyan-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Blocked IPs</p>
                <p className="text-2xl font-semibold text-cyan-400">{aggregatedStats.blockedIPs}</p>
            </div>
          </div>
        </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
          <div className="flex items-center">
              <Zap className="w-6 h-6 text-emerald-400 mr-3" />
            <div>
                <p className="text-sm font-medium text-gray-400">Mitigated</p>
                <p className="text-2xl font-semibold text-emerald-400">{aggregatedStats.mitigatedThreats}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="bg-gray-800 rounded-lg shadow-lg border border-gray-700">
          <div className="flex border-b border-gray-700">
            {[
              { id: 'overview', label: 'Threat Overview', icon: BarChart3 },
              { id: 'alerts', label: 'Active Alerts', icon: AlertTriangle },
              { id: 'rules', label: 'Detection Rules', icon: Settings },
              { id: 'analytics', label: 'Threat Analytics', icon: TrendingUp }
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
                {/* Recent Threats */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                    <Clock className="w-5 h-5 text-blue-400 mr-2" />
                    Recent Threat Activity
                  </h3>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    {filteredThreats.slice(0, 6).map((threat) => (
                      <div key={threat.id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center space-x-3">
                            <div className={`p-2 rounded-full ${getSeverityColor(threat.severity)}`}>
                              {getSeverityIcon(threat.severity)}
                            </div>
                            <div>
                              <h4 className="font-semibold text-white">{threat.type.charAt(0).toUpperCase() + threat.type.slice(1)} Attack</h4>
                              <p className="text-sm text-gray-400">{threat.agentName}</p>
                            </div>
                          </div>
                          <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(threat.severity)}`}>
                            {threat.severity}
                          </span>
                        </div>
                        
                        <p className="text-sm text-gray-300 mb-3">{threat.description}</p>
                        
                        <div className="grid grid-cols-2 gap-3 text-xs">
                          <div className="flex justify-between">
                            <span className="text-gray-400">Source:</span>
                            <span className="text-white font-mono">{threat.sourceIP}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Confidence:</span>
                            <span className="text-green-400">{threat.confidence}%</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Location:</span>
                            <span className="text-white">{threat.location}</span>
                          </div>
                          <div className="flex justify-between">
                            <span className="text-gray-400">Impact:</span>
                            <span className="text-orange-400">{threat.impactScore?.toFixed(1)}/10</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Agent Status */}
                <div>
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                    <Wifi className="w-5 h-5 text-blue-400 mr-2" />
                    Agent Threat Status
                  </h3>
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                    {onlineAgents.map((agent) => (
                      <div key={agent.id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h4 className="font-semibold text-white">{agent.name}</h4>
                            <p className="text-sm text-gray-400">{agent.ipAddress}</p>
                          </div>
                          <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
      </div>

                        {agent.threatStats && (
                          <div className="space-y-2">
                            <div className="flex justify-between text-sm">
                              <span className="text-gray-400">Total Threats:</span>
                              <span className="text-white">{agent.threatStats.totalThreats}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-gray-400">Active:</span>
                              <span className="text-red-400">{agent.threatStats.activeThreats}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-gray-400">Mitigated:</span>
                              <span className="text-green-400">{agent.threatStats.mitigatedThreats}</span>
                            </div>
                            <div className="flex justify-between text-sm">
                              <span className="text-gray-400">Blocked IPs:</span>
                              <span className="text-blue-400">{agent.threatStats.blockedIPs}</span>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
        </div>
      )}

            {selectedTab === 'alerts' && (
              <div className="space-y-6">
                {/* Filters */}
                <div className="flex flex-wrap gap-4 items-center">
                  <select 
                    value={selectedAgent} 
                    onChange={(e) => setSelectedAgent(e.target.value)}
                    className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-sm text-white focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="all">All Agents</option>
                    {connectedAgents.map(agent => (
                      <option key={agent.id} value={agent.id}>{agent.name}</option>
                    ))}
                  </select>
                  
                  <select 
                    value={selectedSeverity} 
                    onChange={(e) => setSelectedSeverity(e.target.value)}
                    className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-sm text-white focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  
                  <select 
                    value={selectedStatus} 
                    onChange={(e) => setSelectedStatus(e.target.value)}
                    className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-sm text-white focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="all">All Statuses</option>
                    <option value="active">Active</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                    <option value="false_positive">False Positive</option>
                  </select>
                  
                  <div className="flex items-center space-x-2 text-sm text-gray-400">
                    <Filter className="w-4 h-4" />
                    <span>{filteredThreats.length} alerts</span>
              </div>
            </div>

                {/* Threat Alerts Table */}
                <div className="bg-gray-750 rounded-lg border border-gray-600 overflow-hidden">
            <div className="overflow-x-auto">
                <table className="w-full">
                      <thead className="bg-gray-700 border-b border-gray-600">
                    <tr>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Severity</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Type</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Target</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Description</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Confidence</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                          <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Time</th>
                    </tr>
                  </thead>
                      <tbody className="bg-gray-750 divide-y divide-gray-600">
                    {filteredThreats.map((threat) => (
                          <tr key={threat.id} className="hover:bg-gray-700 transition-colors">
                            <td className="px-4 py-3">
                              <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                            {getSeverityIcon(threat.severity)}
                                <span className="ml-1">{threat.severity}</span>
                            </span>
                            </td>
                            <td className="px-4 py-3 text-sm text-white">{threat.type}</td>
                            <td className="px-4 py-3">
                              <div>
                                <p className="text-sm text-white font-mono">{threat.sourceIP}</p>
                                <p className="text-xs text-gray-400">{threat.location}</p>
                          </div>
                        </td>
                            <td className="px-4 py-3 text-sm text-white font-mono">{threat.destinationIP}</td>
                            <td className="px-4 py-3 text-sm text-gray-300 max-w-xs truncate">{threat.description}</td>
                            <td className="px-4 py-3 text-sm text-green-400">{threat.confidence}%</td>
                            <td className="px-4 py-3">
                              <span className={`inline-flex px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(threat.status)}`}>
                            {threat.status.replace('_', ' ')}
                          </span>
                        </td>
                            <td className="px-4 py-3 text-sm text-gray-300">
                              {new Date(threat.timestamp).toLocaleTimeString()}
                            </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                  </div>
                </div>
                </div>
              )}

            {selectedTab === 'rules' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-white">Detection Rules Management</h3>
                  <div className="flex items-center space-x-3">
                    <span className="text-sm text-gray-400">{threatRules.filter(rule => rule.enabled).length} of {threatRules.length} rules enabled</span>
            </div>
          </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {threatRules.map((rule) => (
                    <div key={rule.id} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <h4 className="font-semibold text-white">{rule.name}</h4>
                            <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(rule.severity)}`}>
                              {rule.severity}
                            </span>
                          </div>
                          <p className="text-sm text-gray-400 mb-2">{rule.description}</p>
                          <div className="flex items-center space-x-4 text-xs text-gray-500">
                            <span>Category: {rule.category}</span>
                            <span>Type: {rule.type}</span>
                            <span>Accuracy: {rule.accuracy}%</span>
                          </div>
                        </div>
                    <button
                      onClick={() => toggleRule(rule.id)}
                          className={`ml-4 relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                            rule.enabled ? 'bg-blue-600' : 'bg-gray-600'
                      }`}
                    >
                      <span
                            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                              rule.enabled ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-3 text-sm border-t border-gray-600 pt-3">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Triggers:</span>
                          <span className="text-white">{rule.triggerCount}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Last Triggered:</span>
                          <span className="text-gray-300">
                            {rule.lastTriggered ? new Date(rule.lastTriggered).toLocaleDateString() : 'Never'}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedTab === 'analytics' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white mb-4 flex items-center">
                  <TrendingUp className="w-5 h-5 text-blue-400 mr-2" />
                  Threat Analytics & Intelligence
                </h3>
                
                {/* Threat Type Distribution */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h4 className="font-semibold text-white mb-4">Threat Type Distribution</h4>
                    <div className="space-y-3">
                      {Object.entries(threatAlerts.reduce((acc, threat) => {
                        acc[threat.type] = (acc[threat.type] || 0) + 1;
                        return acc;
                      }, {} as Record<string, number>))
                      .sort(([,a], [,b]) => b - a)
                      .map(([type, count]) => {
                        const percentage = ((count / threatAlerts.length) * 100).toFixed(1);
                        return (
                          <div key={type} className="flex items-center justify-between">
                            <div className="flex items-center space-x-3">
                              <div className="w-3 h-3 rounded-full bg-blue-500"></div>
                              <span className="text-sm font-medium text-gray-300 capitalize">{type}</span>
                            </div>
                            <div className="flex items-center space-x-3">
                              <span className="text-sm text-gray-400">{count}</span>
                              <span className="text-sm text-gray-500">{percentage}%</span>
                    </div>
                  </div>
                        );
                      })}
                    </div>
                  </div>

                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h4 className="font-semibold text-white mb-4">Geographic Threat Sources</h4>
                    <div className="space-y-3">
                      {Object.entries(threatAlerts.reduce((acc, threat) => {
                        if (threat.location) {
                          acc[threat.location] = (acc[threat.location] || 0) + 1;
                        }
                        return acc;
                      }, {} as Record<string, number>))
                      .sort(([,a], [,b]) => b - a)
                      .slice(0, 5)
                      .map(([location, count]) => (
                        <div key={location} className="flex items-center justify-between p-3 bg-gray-700 rounded border border-gray-600">
                          <div className="flex items-center space-x-3">
                            <MapPin className="w-4 h-4 text-red-400" />
                            <span className="text-sm font-medium text-white">{location}</span>
                          </div>
                          <span className="text-sm text-red-400">{count} threats</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Attack Vector Analysis */}
                <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                  <h4 className="font-semibold text-white mb-4">Attack Vector Analysis</h4>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {Object.entries(threatAlerts.reduce((acc, threat) => {
                      if (threat.attackVector) {
                        acc[threat.attackVector] = (acc[threat.attackVector] || 0) + 1;
                      }
                      return acc;
                    }, {} as Record<string, number>))
                    .sort(([,a], [,b]) => b - a)
                    .map(([vector, count]) => (
                      <div key={vector} className="bg-gray-700 rounded p-3 border border-gray-600">
                        <p className="text-sm text-gray-400">{vector}</p>
                        <p className="text-lg font-semibold text-white">{count} attacks</p>
                </div>
              ))}
            </div>
          </div>
            </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
} 