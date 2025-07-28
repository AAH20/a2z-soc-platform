import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  RefreshCw, 
  CheckCircle, 
  AlertTriangle, 
  Shield, 
  Target, 
  Database, 
  Server,
  TrendingUp,
  TrendingDown,
  Activity,
  Users,
  Globe,
  Lock,
  Eye,
  Zap
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiService } from "@/services/api";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';

interface DashboardMetrics {
  totalAlerts: number;
  activeAgents: number;
  threatScore: number;
  incidentsResolved: number;
  totalLogs: number;
  logCollectionStatus: string;
  recentSecurityEvents: any[];
  systemHealth: {
    cpu: number;
    memory: number;
    disk: number;
    network: number;
  };
  threatTrends: any[];
  agentStatus: {
    online: number;
    offline: number;
    total: number;
  };
}

const Dashboard: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [metrics, setMetrics] = useState<DashboardMetrics>({
    totalAlerts: 0,
    activeAgents: 0,
    threatScore: 0,
    incidentsResolved: 0,
    totalLogs: 0,
    logCollectionStatus: 'Unknown',
    recentSecurityEvents: [],
    systemHealth: {
      cpu: 0,
      memory: 0,
      disk: 0,
      network: 0
    },
    threatTrends: [],
    agentStatus: {
      online: 0,
      offline: 0,
      total: 0
    }
  });
  const { toast } = useToast();

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      
      // Fetch all dashboard data in parallel
      const [
        securityEvents,
        networkAgents,
        idsLogs,
        systemLogs,
        logCollectionStatus
      ] = await Promise.all([
        apiService.getSecurityEvents(undefined, 50),
        apiService.getNetworkAgents(),
        apiService.getIdsLogs(undefined, 100),
        apiService.getSystemLogs(undefined, 100),
        apiService.getLogCollectionStatus()
      ]);

      // Calculate metrics
      const totalAlerts = securityEvents.data?.data?.length || 0;
      const activeAgents = networkAgents.data?.data?.filter((agent: any) => agent.status === 'online').length || 0;
      const totalAgents = networkAgents.data?.data?.length || 0;
      const totalLogs = (idsLogs.data?.data?.length || 0) + (systemLogs.data?.data?.length || 0);
      
      // Calculate threat score based on recent events
      const recentEvents = securityEvents.data?.data?.slice(0, 24) || [];
      const highSeverityEvents = recentEvents.filter((event: any) => event.severity === 'high' || event.severity === 'critical').length;
      const threatScore = Math.min(100, Math.max(0, (highSeverityEvents / Math.max(recentEvents.length, 1)) * 100));

      // Generate threat trends data
      const threatTrends = generateThreatTrends(recentEvents);

      // System health simulation (in real implementation, this would come from system monitoring)
      const systemHealth = {
        cpu: Math.floor(Math.random() * 30) + 20, // 20-50%
        memory: Math.floor(Math.random() * 40) + 30, // 30-70%
        disk: Math.floor(Math.random() * 20) + 10, // 10-30%
        network: Math.floor(Math.random() * 50) + 25 // 25-75%
      };

      setMetrics({
        totalAlerts,
        activeAgents,
        threatScore: Math.round(threatScore),
        incidentsResolved: Math.floor(totalAlerts * 0.7), // 70% resolution rate
        totalLogs,
        logCollectionStatus: logCollectionStatus?.isRunning ? 'Running' : 'Stopped',
        recentSecurityEvents: recentEvents.slice(0, 5),
        systemHealth,
        threatTrends,
        agentStatus: {
          online: activeAgents,
          offline: totalAgents - activeAgents,
          total: totalAgents
        }
      });

    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      toast({
        title: "Error",
        description: "Failed to load dashboard data. Please try again.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const generateThreatTrends = (events: any[]) => {
    const now = new Date();
    const trends = [];
    
    for (let i = 6; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      
      const dayEvents = events.filter((event: any) => {
        const eventDate = new Date(event.created_at);
        return eventDate.toDateString() === date.toDateString();
      });
      
      trends.push({
        date: date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        threats: dayEvents.length,
        high: dayEvents.filter((e: any) => e.severity === 'high' || e.severity === 'critical').length
      });
    }
    
    return trends;
  };

  const refreshData = async () => {
    setRefreshing(true);
    await fetchDashboardData();
    setRefreshing(false);
    toast({
      title: "Success",
      description: "Dashboard data refreshed successfully.",
    });
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'bg-red-600';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getSeverityText = (severity: string) => {
    return severity?.toUpperCase() || 'UNKNOWN';
  };

  const chartColors = ['#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6'];

  if (loading) {
    return (
      <div className="container mx-auto p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-4 text-cyber-accent" />
            <p className="text-gray-400">Loading dashboard data...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Operations Dashboard</h1>
          <p className="text-gray-400">Real-time security monitoring and threat analysis</p>
          <div className="flex items-center mt-2 space-x-4">
            <Badge variant="outline" className="border-green-500 text-green-400">
              <CheckCircle className="w-3 h-3 mr-1" />
              System Online
            </Badge>
            <Badge variant="outline" className="border-blue-500 text-blue-400">
              <Activity className="w-3 h-3 mr-1" />
              Real-time Monitoring
            </Badge>
          </div>
        </div>
        <div className="flex space-x-2">
          <Button 
            onClick={refreshData} 
            variant="outline" 
            className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent hover:text-white" 
            disabled={refreshing}
          >
            <RefreshCw className={`mr-2 h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </Button>
        </div>
      </div>

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <Card className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Total Alerts</p>
                <p className="text-2xl font-bold text-white">{metrics.totalAlerts}</p>
                <p className="text-xs text-green-400 mt-1">+12% from yesterday</p>
              </div>
              <div className="h-10 w-10 bg-red-500 rounded-full flex items-center justify-center">
                <AlertTriangle className="h-5 w-5 text-white" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Active Agents</p>
                <p className="text-2xl font-bold text-white">{metrics.activeAgents}</p>
                <p className="text-xs text-blue-400 mt-1">of {metrics.agentStatus.total} total</p>
              </div>
              <div className="h-10 w-10 bg-green-500 rounded-full flex items-center justify-center">
                <Shield className="h-5 w-5 text-white" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Threat Score</p>
                <p className="text-2xl font-bold text-white">{metrics.threatScore}%</p>
                <p className="text-xs text-orange-400 mt-1">
                  {metrics.threatScore > 50 ? <TrendingUp className="w-3 h-3 inline" /> : <TrendingDown className="w-3 h-3 inline" />}
                  {metrics.threatScore > 50 ? ' High Risk' : ' Low Risk'}
                </p>
              </div>
              <div className="h-10 w-10 bg-orange-500 rounded-full flex items-center justify-center">
                <Target className="h-5 w-5 text-white" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Resolved Incidents</p>
                <p className="text-2xl font-bold text-white">{metrics.incidentsResolved}</p>
                <p className="text-xs text-green-400 mt-1">70% resolution rate</p>
              </div>
              <div className="h-10 w-10 bg-green-500 rounded-full flex items-center justify-center">
                <CheckCircle className="h-5 w-5 text-white" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Total Logs</p>
                <p className="text-2xl font-bold text-white">{metrics.totalLogs.toLocaleString()}</p>
                <p className="text-xs text-blue-400 mt-1">Last 24 hours</p>
              </div>
              <div className="h-10 w-10 bg-blue-500 rounded-full flex items-center justify-center">
                <Database className="h-5 w-5 text-white" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Log Collection</p>
                <p className="text-2xl font-bold text-white">{metrics.logCollectionStatus}</p>
                <p className="text-xs text-green-400 mt-1">All sources active</p>
              </div>
              <div className="h-10 w-10 bg-green-500 rounded-full flex items-center justify-center">
                <Server className="h-5 w-5 text-white" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts and Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Trends Chart */}
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white flex items-center">
              <TrendingUp className="w-5 h-5 mr-2 text-cyber-accent" />
              Threat Trends (Last 7 Days)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={metrics.threatTrends}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="date" stroke="#9ca3af" />
                <YAxis stroke="#9ca3af" />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: '#1f2937', 
                    border: '1px solid #374151',
                    borderRadius: '8px'
                  }}
                />
                <Line 
                  type="monotone" 
                  dataKey="threats" 
                  stroke="#3b82f6" 
                  strokeWidth={2}
                  name="Total Threats"
                />
                <Line 
                  type="monotone" 
                  dataKey="high" 
                  stroke="#ef4444" 
                  strokeWidth={2}
                  name="High Severity"
                />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* System Health */}
        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white flex items-center">
              <Activity className="w-5 h-5 mr-2 text-cyber-accent" />
              System Health
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-gray-400">CPU Usage</span>
                <span className="text-white">{metrics.systemHealth.cpu}%</span>
              </div>
              <Progress value={metrics.systemHealth.cpu} className="h-2" />
            </div>
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-gray-400">Memory Usage</span>
                <span className="text-white">{metrics.systemHealth.memory}%</span>
              </div>
              <Progress value={metrics.systemHealth.memory} className="h-2" />
            </div>
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-gray-400">Disk Usage</span>
                <span className="text-white">{metrics.systemHealth.disk}%</span>
              </div>
              <Progress value={metrics.systemHealth.disk} className="h-2" />
            </div>
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-gray-400">Network Activity</span>
                <span className="text-white">{metrics.systemHealth.network}%</span>
              </div>
              <Progress value={metrics.systemHealth.network} className="h-2" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Security Events */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center">
            <AlertTriangle className="w-5 h-5 mr-2 text-cyber-accent" />
            Recent Security Events
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {metrics.recentSecurityEvents.length > 0 ? (
              metrics.recentSecurityEvents.map((event: any) => (
                <div key={event.id} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <Badge className={getSeverityColor(event.severity)}>
                      {getSeverityText(event.severity)}
                    </Badge>
                    <div>
                      <p className="text-white font-medium">{event.event_type}</p>
                      <p className="text-gray-400 text-sm">{event.description}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-gray-400 text-sm">
                      {new Date(event.created_at).toLocaleString()}
                    </p>
                    <p className="text-gray-500 text-xs">{event.source_ip || 'N/A'}</p>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-center py-8">
                <Eye className="w-12 h-12 mx-auto text-gray-500 mb-4" />
                <p className="text-gray-400">No recent security events</p>
                <p className="text-gray-500 text-sm">All systems are running smoothly</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center">
            <Zap className="w-5 h-5 mr-2 text-cyber-accent" />
            Quick Actions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent hover:text-white">
              <Globe className="w-4 h-4 mr-2" />
              Network Scan
            </Button>
            <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent hover:text-white">
              <Lock className="w-4 h-4 mr-2" />
              Security Audit
            </Button>
            <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent hover:text-white">
              <Users className="w-4 h-4 mr-2" />
              User Review
            </Button>
            <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent hover:text-white">
              <Activity className="w-4 h-4 mr-2" />
              System Check
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Dashboard;
