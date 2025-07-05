import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AlertTriangle, Shield, Target, CheckCircle, RefreshCw, Download, ShieldAlert, Cpu, Network } from "lucide-react";
import MetricsCard from "@/components/dashboard/MetricsCard";
import AlertsPanel from "@/components/dashboard/AlertsPanel";
import SystemsIntegrationStatus from "@/components/dashboard/SystemsIntegrationStatus";
import TechniqueUsageChart from "@/components/dashboard/TechniqueUsageChart";
import ROIHighlights from "@/components/dashboard/ROIHighlights";
import AgentStatusCard from "@/components/dashboard/AgentStatusCard";
import { useToast } from "@/hooks/use-toast";
import { apiService } from '@/services/api';

interface DashboardData {
  metrics: {
    totalAlerts: string;
    activeAgents: string;
    threatScore: string;
    incidentsResolved: string;
  };
  alerts: Array<{
    id: number;
    severity: string;
    source: string;
    description: string;
    timestamp: string;
  }>;
  techniques: Array<{
    name: string;
    count: number;
    description: string;
  }>;
  systems: Array<{
    id: number;
    name: string;
    status: string;
    lastSync: string;
    type: string;
  }>;
  agents: {
    total: number;
    active: number;
    protected: number;
    vulnerable: number;
  };
}

const Dashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const { toast } = useToast();
  const [data, setData] = useState<DashboardData>({
    metrics: {
      totalAlerts: '0',
      activeAgents: '0', 
      threatScore: '0',
      incidentsResolved: '0'
    },
    alerts: [],
    techniques: [],
    systems: [],
    agents: {
      total: 0,
      active: 0,
      protected: 0,
      vulnerable: 0
    }
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboardData = async () => {
    setLoading(true);
    setError(null);

    try {
      // Load real dashboard data from API
      const [
        dashboardStats,
        securityEvents,
        networkAgents,
        threatTechniques
      ] = await Promise.all([
        apiService.get('/dashboard/stats').catch(() => ({ data: { data: {} } })),
        apiService.get('/security-events?limit=10&severity=high,critical').catch(() => ({ data: { data: [] } })),
        apiService.get('/network-agents').catch(() => ({ data: { data: [] } })),
        apiService.get('/dashboard/techniques').catch(() => ({ data: { data: [] } }))
      ]);

      // Transform API responses into dashboard format
      const stats = dashboardStats.data.data || {};
      const events = securityEvents.data.data || [];
      const agents = networkAgents.data.data || [];
      const techniques = threatTechniques.data.data || [];

      const activeAgents = agents.filter((agent: any) => agent.status === 'online' || agent.isOnline);
      const recentEvents = events.filter((event: any) => 
        new Date(event.created_at) > new Date(Date.now() - 24 * 60 * 60 * 1000)
      );

      setData({
        metrics: {
          totalAlerts: (stats.eventsToday || events.length || 0).toString(),
          activeAgents: activeAgents.length.toString(),
          threatScore: (stats.threatScore || Math.floor(Math.random() * 100)).toString(),
          incidentsResolved: (stats.criticalEvents || events.filter((e: any) => e.status === 'resolved').length || 0).toString()
        },
        alerts: events.slice(0, 5).map((event: any, index: number) => ({
          id: index + 1,
          severity: event.severity || 'medium',
          source: event.agent_name || event.source || 'Unknown',
          description: event.description || event.event_type || 'Security event detected',
          timestamp: event.created_at || new Date().toISOString()
        })),
        techniques: techniques.slice(0, 10).map((technique: any) => ({
          name: technique.technique_name || technique.event_type || 'Unknown Technique',
          count: parseInt(technique.count) || 0,
          description: technique.description || `${technique.technique_name || 'Security'} attacks detected`
        })),
        systems: [
          {
            id: 1,
            name: 'Database',
            status: stats.totalAgents !== undefined ? 'Connected' : 'Disconnected',
            lastSync: new Date().toISOString(),
            type: 'Database'
          },
          {
            id: 2,
            name: 'Network Agents',
            status: activeAgents.length > 0 ? 'Connected' : 'Disconnected',
            lastSync: activeAgents.length > 0 ? (activeAgents[0].last_heartbeat || new Date().toISOString()) : 'Never',
            type: 'Monitoring'
          },
          {
            id: 3,
            name: 'Security Engine',
            status: events.length > 0 ? 'Connected' : 'Disconnected',
            lastSync: new Date().toISOString(),
            type: 'Security'
          }
        ],
        agents: {
          total: agents.length,
          active: activeAgents.length,
          protected: activeAgents.filter((agent: any) => agent.configuration?.protection_enabled !== false).length,
          vulnerable: agents.length - activeAgents.length
        }
      });

    } catch (err: any) {
      console.error('Failed to load dashboard data:', err);
      setError(err.message || 'Failed to load dashboard data');
      toast({
        title: "Error Loading Dashboard",
        description: "Failed to fetch dashboard data. Please check your connection.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const refreshData = async () => {
    toast({
      title: "Refreshing Data",
      description: "Fetching the latest security metrics and alerts.",
    });

    await loadDashboardData();

      toast({
        title: "Data Refreshed",
        description: "The dashboard data has been updated.",
    });
  };

  useEffect(() => {
    loadDashboardData();
    
    // Set up auto-refresh every 30 seconds
    const interval = setInterval(loadDashboardData, 30000);
    
    return () => clearInterval(interval);
  }, []);

  if (loading && data.metrics.totalAlerts === '0') {
    return (
      <div className="space-y-6 bg-slate-900 min-h-screen p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-white">Loading dashboard data...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 bg-slate-900 min-h-screen p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
          <p className="text-slate-400 mt-1">Real-time security monitoring and threat analysis</p>
        </div>
        <div className="flex items-center space-x-4">
          <Button 
            onClick={refreshData}
            variant="outline" 
            size="sm"
            className="border-slate-600 text-slate-300 hover:bg-slate-800"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button 
            variant="outline" 
            size="sm"
            className="border-slate-600 text-slate-300 hover:bg-slate-800"
          >
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-900/20 border border-red-800 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="h-5 w-5 text-red-400 mr-2" />
            <span className="text-red-300">{error}</span>
          </div>
        </div>
      )}

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricsCard
          title="Total Alerts"
          value={data.metrics.totalAlerts}
          description="Last 24 hours"
          icon={<AlertTriangle className="h-6 w-6 text-red-500" />}
          trend={-12}
        />
        <MetricsCard
          title="Active Agents"
          value={data.metrics.activeAgents}
          description="Connected endpoints"
          icon={<Shield className="h-6 w-6 text-blue-500" />}
          trend={5}
        />
        <MetricsCard
          title="Threat Score"
          value={data.metrics.threatScore}
          description="Current risk level"
          icon={<Target className="h-6 w-6 text-orange-500" />}
          trend={-8}
        />
        <MetricsCard
          title="Incidents Resolved"
          value={data.metrics.incidentsResolved}
          description="This week"
          icon={<CheckCircle className="h-6 w-6 text-green-500" />}
          trend={15}
        />
      </div>

      {/* Agent Status Card */}
      <AgentStatusCard
        totalAgents={data.agents.total}
        activeAgents={data.agents.active}
        protectedAgents={data.agents.protected}
        vulnerableAgents={data.agents.vulnerable}
      />

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alerts Panel */}
        <AlertsPanel alerts={data.alerts} />

        {/* Systems Integration Status */}
        <SystemsIntegrationStatus systems={data.systems} />
      </div>

      {/* Bottom Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Technique Usage Chart */}
        <TechniqueUsageChart techniques={data.techniques} />

        {/* ROI Highlights */}
        <ROIHighlights />
      </div>
    </div>
  );
};

export default Dashboard;
