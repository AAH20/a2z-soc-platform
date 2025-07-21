import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { 
  LineChart, 
  Line, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  PieChart, 
  Pie, 
  Cell, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer 
} from 'recharts';
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Database, 
  Search, 
  Filter, 
  Download,
  RefreshCw,
  Eye,
  Clock,
  TrendingUp,
  Server,
  Network,
  Users,
  Lock
} from 'lucide-react';

interface SIEMMetrics {
  eventsPerSecond: number;
  totalEvents: number;
  activeAlerts: number;
  securityScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  correlationRules: number;
  threatsBlocked: number;
  uptime: number;
}

interface SIEMEvent {
  id: string;
  timestamp: string;
  source: string;
  eventType: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  message: string;
  sourceIp?: string;
  destinationIp?: string;
  user?: string;
  tags: string[];
}

interface SIEMAlert {
  id: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  timestamp: string;
  status: 'OPEN' | 'INVESTIGATING' | 'RESOLVED';
  assignedTo?: string;
  affectedSystems: string[];
  indicators: string[];
}

const SIEMDashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<SIEMMetrics>({
    eventsPerSecond: 0,
    totalEvents: 0,
    activeAlerts: 0,
    securityScore: 0,
    riskLevel: 'LOW',
    correlationRules: 0,
    threatsBlocked: 0,
    uptime: 0
  });

  const [events, setEvents] = useState<SIEMEvent[]>([]);
  const [alerts, setAlerts] = useState<SIEMAlert[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Dark mode colors for charts
  const chartColors = {
    primary: '#3b82f6',
    secondary: '#10b981',
    warning: '#f59e0b',
    danger: '#ef4444',
    info: '#06b6d4',
    purple: '#8b5cf6',
    background: '#1e293b',
    text: '#f1f5f9'
  };

  // Mock data for demonstration
  const mockTimeSeriesData = [
    { time: '00:00', events: 120, alerts: 2, threats: 0 },
    { time: '04:00', events: 89, alerts: 1, threats: 1 },
    { time: '08:00', events: 234, alerts: 5, threats: 2 },
    { time: '12:00', events: 445, alerts: 8, threats: 3 },
    { time: '16:00', events: 389, alerts: 6, threats: 1 },
    { time: '20:00', events: 267, alerts: 4, threats: 2 }
  ];

  const mockThreatDistribution = [
    { name: 'Malware', value: 35, color: chartColors.danger },
    { name: 'Intrusion', value: 28, color: chartColors.warning },
    { name: 'Data Breach', value: 20, color: chartColors.purple },
    { name: 'DDoS', value: 17, color: chartColors.info }
  ];

  const mockTopSources = [
    { source: '192.168.1.100', events: 1234, severity: 'HIGH' },
    { source: '10.0.0.15', events: 987, severity: 'MEDIUM' },
    { source: '172.16.0.50', events: 756, severity: 'CRITICAL' },
    { source: '192.168.2.200', events: 543, severity: 'LOW' },
    { source: '10.1.1.25', events: 432, severity: 'HIGH' }
  ];

  useEffect(() => {
    fetchSIEMData();
    const interval = setInterval(fetchSIEMData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchSIEMData = async () => {
    try {
      setIsLoading(true);
      
      // Fetch metrics
      const metricsResponse = await fetch('/api/siem/metrics');
      if (metricsResponse.ok) {
        const metricsData = await metricsResponse.json();
        setMetrics(metricsData.statistics || {
          eventsPerSecond: Math.floor(Math.random() * 100),
          totalEvents: Math.floor(Math.random() * 10000),
          activeAlerts: Math.floor(Math.random() * 20),
          securityScore: Math.floor(Math.random() * 100),
          riskLevel: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][Math.floor(Math.random() * 4)] as any,
          correlationRules: 45,
          threatsBlocked: Math.floor(Math.random() * 500),
          uptime: 99.8
        });
      }

      // Fetch recent events
      const eventsResponse = await fetch('/api/siem/events?limit=50');
      if (eventsResponse.ok) {
        const eventsData = await eventsResponse.json();
        setEvents(eventsData.events || generateMockEvents());
      }

      // Fetch alerts
      const alertsResponse = await fetch('/api/siem/alerts');
      if (alertsResponse.ok) {
        const alertsData = await alertsResponse.json();
        setAlerts(alertsData.alerts || generateMockAlerts());
      }

    } catch (err) {
      setError('Failed to fetch SIEM data');
      console.error('SIEM data fetch error:', err);
      
      // Use mock data on error
      setMetrics({
        eventsPerSecond: Math.floor(Math.random() * 100),
        totalEvents: Math.floor(Math.random() * 10000),
        activeAlerts: Math.floor(Math.random() * 20),
        securityScore: Math.floor(Math.random() * 100),
        riskLevel: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][Math.floor(Math.random() * 4)] as any,
        correlationRules: 45,
        threatsBlocked: Math.floor(Math.random() * 500),
        uptime: 99.8
      });
      setEvents(generateMockEvents());
      setAlerts(generateMockAlerts());
    } finally {
      setIsLoading(false);
    }
  };

  const generateMockEvents = (): SIEMEvent[] => {
    const eventTypes = ['Login Attempt', 'File Access', 'Network Connection', 'System Alert', 'Security Violation'];
    const severities: ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const sources = ['Web Server', 'Database', 'Firewall', 'IDS', 'Application'];
    
    return Array.from({ length: 20 }, (_, i) => ({
      id: `event-${i}`,
      timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
      source: sources[Math.floor(Math.random() * sources.length)],
      eventType: eventTypes[Math.floor(Math.random() * eventTypes.length)],
      severity: severities[Math.floor(Math.random() * severities.length)],
      message: `Security event detected from ${sources[Math.floor(Math.random() * sources.length)]}`,
      sourceIp: `192.168.1.${Math.floor(Math.random() * 255)}`,
      destinationIp: `10.0.0.${Math.floor(Math.random() * 255)}`,
      user: `user${Math.floor(Math.random() * 100)}`,
      tags: ['security', 'monitoring', 'alert'].slice(0, Math.floor(Math.random() * 3) + 1)
    }));
  };

  const generateMockAlerts = (): SIEMAlert[] => {
    const titles = [
      'Suspicious Login Activity',
      'Potential Data Exfiltration',
      'Malware Detection',
      'Unauthorized Access Attempt',
      'DDoS Attack Detected'
    ];
    const severities: ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const statuses: ('OPEN' | 'INVESTIGATING' | 'RESOLVED')[] = ['OPEN', 'INVESTIGATING', 'RESOLVED'];
    
    return Array.from({ length: 10 }, (_, i) => ({
      id: `alert-${i}`,
      title: titles[Math.floor(Math.random() * titles.length)],
      description: `Security alert requiring immediate attention`,
      severity: severities[Math.floor(Math.random() * severities.length)],
      timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
      status: statuses[Math.floor(Math.random() * statuses.length)],
      assignedTo: Math.random() > 0.5 ? 'security-team' : undefined,
      affectedSystems: ['Web Server', 'Database'].slice(0, Math.floor(Math.random() * 2) + 1),
      indicators: ['IP: 192.168.1.100', 'User: admin'].slice(0, Math.floor(Math.random() * 2) + 1)
    }));
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-500 text-white';
      case 'HIGH': return 'bg-orange-500 text-white';
      case 'MEDIUM': return 'bg-yellow-500 text-black';
      case 'LOW': return 'bg-green-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getRiskLevelColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'CRITICAL': return 'text-red-400';
      case 'HIGH': return 'text-orange-400';
      case 'MEDIUM': return 'text-yellow-400';
      case 'LOW': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  const filteredEvents = events.filter(event => {
    const matchesSearch = event.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         event.source.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = filterSeverity === 'all' || event.severity === filterSeverity;
    return matchesSearch && matchesSeverity;
  });

  if (isLoading && events.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 bg-slate-900">
        <div className="flex items-center space-x-2 text-slate-400">
          <RefreshCw className="h-6 w-6 animate-spin" />
          <span>Loading SIEM Dashboard...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-slate-900 min-h-screen text-slate-100 w-full">
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-blue-400" />
              <h1 className="text-3xl font-bold text-white">SIEM Dashboard</h1>
            </div>
            <Badge variant="outline" className="text-green-400 border-green-400">
              <Activity className="h-3 w-3 mr-1" />
              Live
            </Badge>
          </div>
          
          <div className="flex items-center space-x-4">
            <Button 
              onClick={fetchSIEMData} 
              variant="outline" 
              size="sm"
              className="border-slate-600 text-slate-300 hover:bg-slate-700"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            <Button 
              variant="outline" 
              size="sm"
              className="border-slate-600 text-slate-300 hover:bg-slate-700"
            >
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </div>

        {error && (
          <Alert className="border-red-500 bg-red-500/10 text-red-400">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Events/Second</p>
                  <p className="text-2xl font-bold text-white">{metrics.eventsPerSecond}</p>
                </div>
                <Activity className="h-8 w-8 text-blue-400" />
              </div>
              <div className="mt-2">
                <Progress value={Math.min(metrics.eventsPerSecond, 100)} className="h-2" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Total Events</p>
                  <p className="text-2xl font-bold text-white">{metrics.totalEvents.toLocaleString()}</p>
                </div>
                <Database className="h-8 w-8 text-green-400" />
              </div>
              <div className="mt-2 text-xs text-slate-400">
                <TrendingUp className="h-3 w-3 inline mr-1" />
                +12% from yesterday
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Active Alerts</p>
                  <p className="text-2xl font-bold text-white">{metrics.activeAlerts}</p>
                </div>
                <AlertTriangle className="h-8 w-8 text-orange-400" />
              </div>
              <div className="mt-2 text-xs text-slate-400">
                <Clock className="h-3 w-3 inline mr-1" />
                Last updated: now
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Risk Level</p>
                  <p className={`text-2xl font-bold ${getRiskLevelColor(metrics.riskLevel)}`}>
                    {metrics.riskLevel}
                  </p>
                </div>
                <Lock className="h-8 w-8 text-purple-400" />
              </div>
              <div className="mt-2">
                <Progress 
                  value={metrics.securityScore} 
                  className="h-2"
                />
                <p className="text-xs text-slate-400 mt-1">Security Score: {metrics.securityScore}%</p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Tabs */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="bg-slate-800 border-slate-700">
            <TabsTrigger value="overview" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              Overview
            </TabsTrigger>
            <TabsTrigger value="events" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              Events
            </TabsTrigger>
            <TabsTrigger value="alerts" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              Alerts
            </TabsTrigger>
            <TabsTrigger value="analytics" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              Analytics
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Real-time Events Chart */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Event Timeline</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <AreaChart data={mockTimeSeriesData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="time" stroke="#9ca3af" />
                      <YAxis stroke="#9ca3af" />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1e293b', 
                          border: '1px solid #374151',
                          borderRadius: '6px',
                          color: '#f1f5f9'
                        }} 
                      />
                      <Area 
                        type="monotone" 
                        dataKey="events" 
                        stroke={chartColors.primary} 
                        fill={chartColors.primary} 
                        fillOpacity={0.3}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              {/* Threat Distribution */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Threat Distribution</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={mockThreatDistribution}
                        cx="50%"
                        cy="50%"
                        outerRadius={100}
                        dataKey="value"
                      >
                        {mockThreatDistribution.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1e293b', 
                          border: '1px solid #374151',
                          borderRadius: '6px',
                          color: '#f1f5f9'
                        }} 
                      />
                      <Legend 
                        wrapperStyle={{ color: '#f1f5f9' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </div>

            {/* Top Event Sources */}
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Top Event Sources</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {mockTopSources.map((source, index) => (
                    <div key={index} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <Server className="h-5 w-5 text-slate-400" />
                        <div>
                          <p className="font-medium text-white">{source.source}</p>
                          <p className="text-sm text-slate-400">{source.events} events</p>
                        </div>
                      </div>
                      <Badge className={getSeverityColor(source.severity)}>
                        {source.severity}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="events" className="space-y-6">
            {/* Search and Filter */}
            <Card className="bg-slate-800 border-slate-700">
              <CardContent className="p-6">
                <div className="flex items-center space-x-4">
                  <div className="flex-1">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-slate-400" />
                      <Input
                        placeholder="Search events..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="pl-10 bg-slate-700 border-slate-600 text-white placeholder:text-slate-400"
                      />
                    </div>
                  </div>
                  <Select value={filterSeverity} onValueChange={setFilterSeverity}>
                    <SelectTrigger className="w-48 bg-slate-700 border-slate-600 text-white">
                      <Filter className="h-4 w-4 mr-2" />
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-700 border-slate-600">
                      <SelectItem value="all">All Severities</SelectItem>
                      <SelectItem value="CRITICAL">Critical</SelectItem>
                      <SelectItem value="HIGH">High</SelectItem>
                      <SelectItem value="MEDIUM">Medium</SelectItem>
                      <SelectItem value="LOW">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            </Card>

            {/* Events Table */}
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Recent Security Events</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {filteredEvents.slice(0, 20).map((event) => (
                    <div key={event.id} className="flex items-center justify-between p-4 bg-slate-700 rounded-lg hover:bg-slate-600 transition-colors">
                      <div className="flex items-center space-x-4">
                        <Badge className={getSeverityColor(event.severity)}>
                          {event.severity}
                        </Badge>
                        <div>
                          <p className="font-medium text-white">{event.eventType}</p>
                          <p className="text-sm text-slate-400">{event.message}</p>
                          <div className="flex items-center space-x-4 mt-1 text-xs text-slate-500">
                            <span>Source: {event.source}</span>
                            {event.sourceIp && <span>IP: {event.sourceIp}</span>}
                            {event.user && <span>User: {event.user}</span>}
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-slate-400">
                          {new Date(event.timestamp).toLocaleString()}
                        </p>
                        <div className="flex items-center space-x-2 mt-1">
                          {event.tags.map((tag, index) => (
                            <Badge key={index} variant="outline" className="text-xs border-slate-600 text-slate-400">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="alerts" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
              {alerts.map((alert) => (
                <Card key={alert.id} className="bg-slate-800 border-slate-700">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-lg text-white">{alert.title}</CardTitle>
                      <Badge className={getSeverityColor(alert.severity)}>
                        {alert.severity}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-slate-300">{alert.description}</p>
                    
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">Status:</span>
                        <Badge variant="outline" className="border-slate-600 text-slate-300">
                          {alert.status}
                        </Badge>
                      </div>
                      
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">Time:</span>
                        <span className="text-slate-300">
                          {new Date(alert.timestamp).toLocaleString()}
                        </span>
                      </div>
                      
                      {alert.assignedTo && (
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">Assigned:</span>
                          <span className="text-slate-300">{alert.assignedTo}</span>
                        </div>
                      )}
                    </div>
                    
                    {alert.affectedSystems.length > 0 && (
                      <div>
                        <p className="text-sm text-slate-400 mb-2">Affected Systems:</p>
                        <div className="flex flex-wrap gap-1">
                          {alert.affectedSystems.map((system, index) => (
                            <Badge key={index} variant="outline" className="text-xs border-slate-600 text-slate-400">
                              {system}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {alert.indicators.length > 0 && (
                      <div>
                        <p className="text-sm text-slate-400 mb-2">Indicators:</p>
                        <div className="space-y-1">
                          {alert.indicators.map((indicator, index) => (
                            <p key={index} className="text-xs text-slate-500 font-mono">
                              {indicator}
                            </p>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    <div className="flex space-x-2">
                      <Button size="sm" variant="outline" className="border-slate-600 text-slate-300 hover:bg-slate-700">
                        <Eye className="h-3 w-3 mr-1" />
                        View
                      </Button>
                      {alert.status === 'OPEN' && (
                        <Button size="sm" className="bg-blue-600 hover:bg-blue-700">
                          Investigate
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="analytics" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Alert Trends */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Alert Trends</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={mockTimeSeriesData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="time" stroke="#9ca3af" />
                      <YAxis stroke="#9ca3af" />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1e293b', 
                          border: '1px solid #374151',
                          borderRadius: '6px',
                          color: '#f1f5f9'
                        }} 
                      />
                      <Line 
                        type="monotone" 
                        dataKey="alerts" 
                        stroke={chartColors.warning} 
                        strokeWidth={2}
                        dot={{ fill: chartColors.warning }}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="threats" 
                        stroke={chartColors.danger} 
                        strokeWidth={2}
                        dot={{ fill: chartColors.danger }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              {/* System Performance */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">System Performance</CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-slate-400">Uptime</span>
                      <span className="text-sm text-white">{metrics.uptime}%</span>
                    </div>
                    <Progress value={metrics.uptime} className="h-2" />
                  </div>
                  
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-slate-400">Correlation Rules</span>
                      <span className="text-sm text-white">{metrics.correlationRules}</span>
                    </div>
                    <Progress value={(metrics.correlationRules / 50) * 100} className="h-2" />
                  </div>
                  
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-slate-400">Threats Blocked</span>
                      <span className="text-sm text-white">{metrics.threatsBlocked}</span>
                    </div>
                    <Progress value={Math.min((metrics.threatsBlocked / 1000) * 100, 100)} className="h-2" />
                  </div>
                  
                  <div className="pt-4 border-t border-slate-600">
                    <div className="grid grid-cols-2 gap-4 text-center">
                      <div>
                        <p className="text-2xl font-bold text-green-400">{metrics.threatsBlocked}</p>
                        <p className="text-xs text-slate-400">Threats Blocked</p>
                      </div>
                      <div>
                        <p className="text-2xl font-bold text-blue-400">{metrics.correlationRules}</p>
                        <p className="text-xs text-slate-400">Active Rules</p>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export { SIEMDashboard }; 