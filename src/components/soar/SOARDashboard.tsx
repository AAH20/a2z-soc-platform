import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  Play,
  Pause,
  Square,
  Settings,
  Plus,
  Edit,
  Trash2,
  Eye,
  RefreshCw,
  Clock,
  CheckCircle,
  AlertTriangle,
  Shield,
  Zap,
  Activity,
  BarChart3,
  Users,
  Target,
  Timer,
  TrendingUp,
  AlertCircle,
  FileText,
  Workflow,
  Bot,
  Cpu,
  Database,
  Network,
  Lock
} from 'lucide-react';
import { apiService } from '@/services/api';
import { useToast } from '@/hooks/use-toast';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';

interface SOARMetrics {
  totalPlaybooks: number;
  activeExecutions: number;
  completedToday: number;
  averageExecutionTime: number;
  successRate: number;
  activeIncidents: number;
  resolvedIncidents: number;
  integrations: number;
}

interface SOARPlaybook {
  id: string;
  name: string;
  description: string;
  status: 'ACTIVE' | 'INACTIVE' | 'DRAFT';
  trigger: string;
  actions: number;
  lastExecuted?: string;
  executionCount: number;
  successRate: number;
  averageTime: number;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

interface SOARIncident {
  id: string;
  title: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED';
  assignedTo?: string;
  createdAt: string;
  updatedAt: string;
  playbookId?: string;
  affectedSystems: string[];
  indicators: string[];
}

interface SOARExecution {
  id: string;
  playbookId: string;
  playbookName: string;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'PAUSED';
  startedAt: string;
  completedAt?: string;
  duration?: number;
  progress: number;
  currentStep: string;
  totalSteps: number;
  triggeredBy: string;
}

const SOARDashboard: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [metrics, setMetrics] = useState<SOARMetrics>({
    totalPlaybooks: 0,
    activeExecutions: 0,
    completedToday: 0,
    averageExecutionTime: 0,
    successRate: 0,
    activeIncidents: 0,
    resolvedIncidents: 0,
    integrations: 0
  });
  const [playbooks, setPlaybooks] = useState<SOARPlaybook[]>([]);
  const [incidents, setIncidents] = useState<SOARIncident[]>([]);
  const [executions, setExecutions] = useState<SOARExecution[]>([]);
  const [showCreateIncident, setShowCreateIncident] = useState(false);
  const [showCreatePlaybook, setShowCreatePlaybook] = useState(false);
  const [newIncident, setNewIncident] = useState({
    title: '',
    description: '',
    severity: 'MEDIUM' as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    affectedSystems: ''
  });
  const [newPlaybook, setNewPlaybook] = useState({
    name: '',
    description: '',
    trigger: '',
    severity: 'MEDIUM' as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  });
  const { toast } = useToast();

  const fetchSOARData = async () => {
    try {
      setLoading(true);
      
      // Fetch security events and transform them into SOAR data
      const [securityEvents, networkAgents] = await Promise.all([
        apiService.getSecurityEvents(undefined, 100),
        apiService.getNetworkAgents()
      ]);

      const events = securityEvents.data?.data || [];
      const agents = networkAgents.data?.data || [];

      // Transform security events into SOAR incidents
      const soarIncidents: SOARIncident[] = events
        .filter((event: any) => event.severity === 'high' || event.severity === 'critical')
        .map((event: any) => ({
          id: event.id,
          title: `${event.event_type} - ${event.description}`,
          description: event.description,
          severity: event.severity.toUpperCase() as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
          status: event.status === 'new' ? 'OPEN' :
                  event.status === 'investigating' ? 'IN_PROGRESS' :
                  event.status === 'resolved' ? 'RESOLVED' : 'CLOSED',
          createdAt: event.created_at,
          updatedAt: event.updated_at,
          affectedSystems: [event.destination_ip || 'Unknown'],
          indicators: [event.source_ip || 'Unknown']
        }));

      // Generate playbooks based on detected threats
      const threatTypes = new Set();
      events.forEach((event: any) => {
        if (event.severity === 'high' || event.severity === 'critical') {
          threatTypes.add(event.event_type);
        }
      });

      const soarPlaybooks: SOARPlaybook[] = Array.from(threatTypes).map((threatType, index) => ({
        id: `playbook-${index}`,
        name: `${threatType} Response Playbook`,
        description: `Automated response for ${threatType} incidents`,
        status: 'ACTIVE' as const,
        trigger: threatType as string,
        actions: Math.floor(Math.random() * 5) + 3,
        executionCount: Math.floor(Math.random() * 20) + 1,
        successRate: Math.floor(Math.random() * 20) + 80,
        averageTime: Math.floor(Math.random() * 300) + 60,
        severity: 'HIGH' as const
      }));

      // Generate executions based on recent incidents
      const soarExecutions: SOARExecution[] = soarIncidents
        .filter(incident => incident.status === 'IN_PROGRESS' || incident.status === 'RESOLVED')
        .slice(0, 10)
        .map((incident, index) => ({
          id: `execution-${index}`,
          playbookId: incident.playbookId || `playbook-${index}`,
          playbookName: soarPlaybooks[index % soarPlaybooks.length]?.name || 'Unknown Playbook',
          status: incident.status === 'IN_PROGRESS' ? 'RUNNING' : 'COMPLETED',
          startedAt: incident.createdAt,
          completedAt: incident.status === 'RESOLVED' ? incident.updatedAt : undefined,
          duration: incident.status === 'RESOLVED' ? Math.floor(Math.random() * 300) + 60 : undefined,
          progress: incident.status === 'IN_PROGRESS' ? Math.floor(Math.random() * 80) + 20 : 100,
          currentStep: incident.status === 'IN_PROGRESS' ? 'Analyzing threat indicators' : 'Completed',
          totalSteps: 5,
          triggeredBy: 'Automated Detection'
        }));

      // Calculate metrics
      const totalPlaybooks = soarPlaybooks.length;
      const activeExecutions = soarExecutions.filter(exec => exec.status === 'RUNNING').length;
      const completedToday = soarExecutions.filter(exec => {
        if (!exec.completedAt) return false;
        const today = new Date().toDateString();
        return new Date(exec.completedAt).toDateString() === today;
      }).length;
      const averageExecutionTime = soarExecutions
        .filter(exec => exec.duration)
        .reduce((acc, exec) => acc + (exec.duration || 0), 0) / Math.max(soarExecutions.filter(exec => exec.duration).length, 1);
      const successRate = soarExecutions
        .filter(exec => exec.status === 'COMPLETED')
        .length / Math.max(soarExecutions.length, 1) * 100;
      const activeIncidents = soarIncidents.filter(incident => incident.status === 'OPEN' || incident.status === 'IN_PROGRESS').length;
      const resolvedIncidents = soarIncidents.filter(incident => incident.status === 'RESOLVED' || incident.status === 'CLOSED').length;

      setMetrics({
        totalPlaybooks,
        activeExecutions,
        completedToday,
        averageExecutionTime: Math.round(averageExecutionTime),
        successRate: Math.round(successRate),
        activeIncidents,
        resolvedIncidents,
        integrations: 4 // Wazuh, Snort, Suricata, Syslog
      });

      setPlaybooks(soarPlaybooks);
      setIncidents(soarIncidents);
      setExecutions(soarExecutions);

    } catch (error) {
      console.error('Error fetching SOAR data:', error);
      toast({
        title: "Error",
        description: "Failed to load SOAR data. Please try again.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const refreshData = async () => {
    setRefreshing(true);
    await fetchSOARData();
    setRefreshing(false);
    toast({
      title: "Success",
      description: "SOAR data refreshed successfully.",
    });
  };

  const createIncident = async () => {
    try {
      // In a real implementation, this would call the API
      const newIncidentData: SOARIncident = {
        id: `incident-${Date.now()}`,
        title: newIncident.title,
        description: newIncident.description,
        severity: newIncident.severity,
        status: 'OPEN',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        affectedSystems: newIncident.affectedSystems.split(',').map(s => s.trim()),
        indicators: []
      };

      setIncidents(prev => [newIncidentData, ...prev]);
      setShowCreateIncident(false);
      setNewIncident({ title: '', description: '', severity: 'MEDIUM', affectedSystems: '' });
      
      toast({
        title: "Success",
        description: "Incident created successfully.",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to create incident.",
        variant: "destructive"
      });
    }
  };

  const createPlaybook = async () => {
    try {
      const newPlaybookData: SOARPlaybook = {
        id: `playbook-${Date.now()}`,
        name: newPlaybook.name,
        description: newPlaybook.description,
        status: 'ACTIVE',
        trigger: newPlaybook.trigger,
        actions: 3,
        executionCount: 0,
        successRate: 100,
        averageTime: 120,
        severity: newPlaybook.severity
      };

      setPlaybooks(prev => [newPlaybookData, ...prev]);
      setShowCreatePlaybook(false);
      setNewPlaybook({ name: '', description: '', trigger: '', severity: 'MEDIUM' });
      
      toast({
        title: "Success",
        description: "Playbook created successfully.",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to create playbook.",
        variant: "destructive"
      });
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ACTIVE':
      case 'RUNNING':
      case 'COMPLETED':
      case 'RESOLVED':
        return 'bg-green-500';
      case 'INACTIVE':
      case 'PAUSED':
      case 'OPEN':
        return 'bg-yellow-500';
      case 'FAILED':
      case 'CRITICAL':
        return 'bg-red-500';
      case 'IN_PROGRESS':
        return 'bg-blue-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-600';
      case 'HIGH':
        return 'bg-orange-500';
      case 'MEDIUM':
        return 'bg-yellow-500';
      case 'LOW':
        return 'bg-blue-500';
      default:
        return 'bg-gray-500';
    }
  };

  useEffect(() => {
    fetchSOARData();
  }, []);

  if (loading) {
    return (
      <div className="container mx-auto p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-4 text-cyber-accent" />
            <p className="text-gray-400">Loading SOAR dashboard...</p>
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
          <h1 className="text-3xl font-bold text-white">SOAR Operations Center</h1>
          <p className="text-gray-400">Security Orchestration, Automation, and Response</p>
          <div className="flex items-center mt-2 space-x-4">
            <Badge variant="outline" className="border-green-500 text-green-400">
              <Bot className="w-3 h-3 mr-1" />
              Automation Active
            </Badge>
            <Badge variant="outline" className="border-blue-500 text-blue-400">
              <Workflow className="w-3 h-3 mr-1" />
              {metrics.activeExecutions} Active Workflows
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

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Total Playbooks</p>
                <p className="text-2xl font-bold text-white">{metrics.totalPlaybooks}</p>
                <p className="text-xs text-green-400 mt-1">+2 this week</p>
              </div>
              <div className="h-10 w-10 bg-blue-500 rounded-full flex items-center justify-center">
                <Workflow className="h-5 w-5 text-white" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Active Executions</p>
                <p className="text-2xl font-bold text-white">{metrics.activeExecutions}</p>
                <p className="text-xs text-blue-400 mt-1">Real-time workflows</p>
              </div>
              <div className="h-10 w-10 bg-green-500 rounded-full flex items-center justify-center">
                <Activity className="h-5 w-5 text-white" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">Success Rate</p>
                <p className="text-2xl font-bold text-white">{metrics.successRate}%</p>
                <p className="text-xs text-green-400 mt-1">
                  <TrendingUp className="w-3 h-3 inline" />
                  +5% this month
                </p>
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
                <p className="text-sm text-slate-400">Avg Execution Time</p>
                <p className="text-2xl font-bold text-white">{metrics.averageExecutionTime}s</p>
                <p className="text-xs text-blue-400 mt-1">Optimized workflows</p>
              </div>
              <div className="h-10 w-10 bg-purple-500 rounded-full flex items-center justify-center">
                <Timer className="h-5 w-5 text-white" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList className="grid w-full grid-cols-4 bg-slate-800">
          <TabsTrigger value="overview" className="data-[state=active]:bg-cyber-accent">Overview</TabsTrigger>
          <TabsTrigger value="playbooks" className="data-[state=active]:bg-cyber-accent">Playbooks</TabsTrigger>
          <TabsTrigger value="incidents" className="data-[state=active]:bg-cyber-accent">Incidents</TabsTrigger>
          <TabsTrigger value="executions" className="data-[state=active]:bg-cyber-accent">Executions</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Automation Performance Chart */}
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <BarChart3 className="w-5 h-5 mr-2 text-cyber-accent" />
                  Automation Performance
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={[
                    { name: 'Malware', completed: 15, failed: 2 },
                    { name: 'Phishing', completed: 12, failed: 1 },
                    { name: 'DDoS', completed: 8, failed: 0 },
                    { name: 'Port Scan', completed: 20, failed: 3 }
                  ]}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="name" stroke="#9ca3af" />
                    <YAxis stroke="#9ca3af" />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1f2937', 
                        border: '1px solid #374151',
                        borderRadius: '8px'
                      }}
                    />
                    <Bar dataKey="completed" fill="#10b981" name="Completed" />
                    <Bar dataKey="failed" fill="#ef4444" name="Failed" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Recent Activity */}
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center">
                  <Activity className="w-5 h-5 mr-2 text-cyber-accent" />
                  Recent Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {executions.slice(0, 5).map((execution) => (
                    <div key={execution.id} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className={`w-2 h-2 rounded-full ${getStatusColor(execution.status)}`}></div>
                        <div>
                          <p className="text-white font-medium">{execution.playbookName}</p>
                          <p className="text-gray-400 text-sm">{execution.currentStep}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-gray-400 text-sm">
                          {new Date(execution.startedAt).toLocaleTimeString()}
                        </p>
                        {execution.status === 'RUNNING' && (
                          <Progress value={execution.progress} className="w-20 h-1 mt-1" />
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Playbooks Tab */}
        <TabsContent value="playbooks" className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-semibold text-white">Automation Playbooks</h2>
            <Dialog open={showCreatePlaybook} onOpenChange={setShowCreatePlaybook}>
              <DialogTrigger asChild>
                <Button className="bg-cyber-accent hover:bg-cyber-accent/90">
                  <Plus className="w-4 h-4 mr-2" />
                  Create Playbook
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-slate-800 border-slate-700">
                <DialogHeader>
                  <DialogTitle className="text-white">Create New Playbook</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium text-gray-300">Name</label>
                    <Input
                      value={newPlaybook.name}
                      onChange={(e) => setNewPlaybook(prev => ({ ...prev, name: e.target.value }))}
                      className="bg-slate-700 border-slate-600 text-white"
                      placeholder="Enter playbook name"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-300">Description</label>
                    <Textarea
                      value={newPlaybook.description}
                      onChange={(e) => setNewPlaybook(prev => ({ ...prev, description: e.target.value }))}
                      className="bg-slate-700 border-slate-600 text-white"
                      placeholder="Enter playbook description"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-300">Trigger</label>
                    <Input
                      value={newPlaybook.trigger}
                      onChange={(e) => setNewPlaybook(prev => ({ ...prev, trigger: e.target.value }))}
                      className="bg-slate-700 border-slate-600 text-white"
                      placeholder="Enter trigger condition"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-300">Severity</label>
                    <Select value={newPlaybook.severity} onValueChange={(value: any) => setNewPlaybook(prev => ({ ...prev, severity: value }))}>
                      <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="bg-slate-700 border-slate-600">
                        <SelectItem value="LOW">Low</SelectItem>
                        <SelectItem value="MEDIUM">Medium</SelectItem>
                        <SelectItem value="HIGH">High</SelectItem>
                        <SelectItem value="CRITICAL">Critical</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" onClick={() => setShowCreatePlaybook(false)}>
                      Cancel
                    </Button>
                    <Button onClick={createPlaybook} className="bg-cyber-accent hover:bg-cyber-accent/90">
                      Create Playbook
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {playbooks.map((playbook) => (
              <Card key={playbook.id} className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
                <CardHeader>
                  <div className="flex justify-between items-start">
                    <CardTitle className="text-white text-lg">{playbook.name}</CardTitle>
                    <Badge className={getStatusColor(playbook.status)}>
                      {playbook.status}
                    </Badge>
                  </div>
                  <p className="text-gray-400 text-sm">{playbook.description}</p>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Trigger:</span>
                    <span className="text-white">{playbook.trigger}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Actions:</span>
                    <span className="text-white">{playbook.actions}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Success Rate:</span>
                    <span className="text-green-400">{playbook.successRate}%</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Avg Time:</span>
                    <span className="text-white">{playbook.averageTime}s</span>
                  </div>
                  <div className="flex space-x-2">
                    <Button size="sm" variant="outline" className="flex-1">
                      <Play className="w-3 h-3 mr-1" />
                      Execute
                    </Button>
                    <Button size="sm" variant="outline">
                      <Edit className="w-3 h-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Incidents Tab */}
        <TabsContent value="incidents" className="space-y-6">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-semibold text-white">Security Incidents</h2>
            <Dialog open={showCreateIncident} onOpenChange={setShowCreateIncident}>
              <DialogTrigger asChild>
                <Button className="bg-cyber-accent hover:bg-cyber-accent/90">
                  <Plus className="w-4 h-4 mr-2" />
                  Create Incident
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-slate-800 border-slate-700">
                <DialogHeader>
                  <DialogTitle className="text-white">Create New Incident</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium text-gray-300">Title</label>
                    <Input
                      value={newIncident.title}
                      onChange={(e) => setNewIncident(prev => ({ ...prev, title: e.target.value }))}
                      className="bg-slate-700 border-slate-600 text-white"
                      placeholder="Enter incident title"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-300">Description</label>
                    <Textarea
                      value={newIncident.description}
                      onChange={(e) => setNewIncident(prev => ({ ...prev, description: e.target.value }))}
                      className="bg-slate-700 border-slate-600 text-white"
                      placeholder="Enter incident description"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-300">Severity</label>
                    <Select value={newIncident.severity} onValueChange={(value: any) => setNewIncident(prev => ({ ...prev, severity: value }))}>
                      <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="bg-slate-700 border-slate-600">
                        <SelectItem value="LOW">Low</SelectItem>
                        <SelectItem value="MEDIUM">Medium</SelectItem>
                        <SelectItem value="HIGH">High</SelectItem>
                        <SelectItem value="CRITICAL">Critical</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-300">Affected Systems</label>
                    <Input
                      value={newIncident.affectedSystems}
                      onChange={(e) => setNewIncident(prev => ({ ...prev, affectedSystems: e.target.value }))}
                      className="bg-slate-700 border-slate-600 text-white"
                      placeholder="Enter affected systems (comma-separated)"
                    />
                  </div>
                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" onClick={() => setShowCreateIncident(false)}>
                      Cancel
                    </Button>
                    <Button onClick={createIncident} className="bg-cyber-accent hover:bg-cyber-accent/90">
                      Create Incident
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          <div className="space-y-4">
            {incidents.map((incident) => (
              <Card key={incident.id} className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <Badge className={getSeverityColor(incident.severity)}>
                        {incident.severity}
                      </Badge>
                      <div>
                        <h3 className="text-white font-medium">{incident.title}</h3>
                        <p className="text-gray-400 text-sm">{incident.description}</p>
                        <div className="flex items-center space-x-4 mt-2">
                          <span className="text-gray-500 text-xs">
                            Created: {new Date(incident.createdAt).toLocaleString()}
                          </span>
                          <span className="text-gray-500 text-xs">
                            Systems: {incident.affectedSystems.length}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge className={getStatusColor(incident.status)}>
                        {incident.status}
                      </Badge>
                      <Button size="sm" variant="outline">
                        <Eye className="w-3 h-3 mr-1" />
                        View
                      </Button>
                      <Button size="sm" variant="outline">
                        <Play className="w-3 h-3 mr-1" />
                        Execute
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Executions Tab */}
        <TabsContent value="executions" className="space-y-6">
          <h2 className="text-xl font-semibold text-white">Workflow Executions</h2>
          
          <div className="space-y-4">
            {executions.map((execution) => (
              <Card key={execution.id} className="bg-slate-800 border-slate-700 hover:border-cyber-accent transition-colors">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className={`w-3 h-3 rounded-full ${getStatusColor(execution.status)}`}></div>
                      <div>
                        <h3 className="text-white font-medium">{execution.playbookName}</h3>
                        <p className="text-gray-400 text-sm">{execution.currentStep}</p>
                        <div className="flex items-center space-x-4 mt-2">
                          <span className="text-gray-500 text-xs">
                            Started: {new Date(execution.startedAt).toLocaleString()}
                          </span>
                          <span className="text-gray-500 text-xs">
                            Triggered by: {execution.triggeredBy}
                          </span>
                          {execution.duration && (
                            <span className="text-gray-500 text-xs">
                              Duration: {execution.duration}s
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      {execution.status === 'RUNNING' && (
                        <div className="text-center">
                          <Progress value={execution.progress} className="w-20 h-2 mb-1" />
                          <span className="text-xs text-gray-400">{execution.progress}%</span>
                        </div>
                      )}
                      <div className="text-right">
                        <Badge className={getStatusColor(execution.status)}>
                          {execution.status}
                        </Badge>
                        <p className="text-xs text-gray-400 mt-1">
                          Step {Math.ceil((execution.progress / 100) * execution.totalSteps)} of {execution.totalSteps}
                        </p>
                      </div>
                      <div className="flex space-x-2">
                        {execution.status === 'RUNNING' && (
                          <>
                            <Button size="sm" variant="outline">
                              <Pause className="w-3 h-3" />
                            </Button>
                            <Button size="sm" variant="outline">
                              <Square className="w-3 h-3" />
                            </Button>
                          </>
                        )}
                        <Button size="sm" variant="outline">
                          <Eye className="w-3 h-3" />
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SOARDashboard; 