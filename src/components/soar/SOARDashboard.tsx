import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Textarea } from '@/components/ui/textarea';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { 
  BarChart, 
  Bar, 
  LineChart, 
  Line, 
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
  Activity,
  Users,
  Zap,
  GitBranch,
  Shield,
  Target,
  Workflow,
  Timer,
  BarChart3
} from 'lucide-react';

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
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Dialog states
  const [showCreateIncident, setShowCreateIncident] = useState(false);
  const [showCreatePlaybook, setShowCreatePlaybook] = useState(false);

  // Form states
  const [newIncident, setNewIncident] = useState({
    title: '',
    description: '',
    severity: 'MEDIUM' as const,
    affectedSystems: ''
  });

  const [newPlaybook, setNewPlaybook] = useState({
    name: '',
    description: '',
    trigger: '',
    severity: 'MEDIUM' as const
  });

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
  const mockExecutionTrends = [
    { time: '00:00', executions: 5, success: 4, failed: 1 },
    { time: '04:00', executions: 8, success: 7, failed: 1 },
    { time: '08:00', executions: 15, success: 12, failed: 3 },
    { time: '12:00', executions: 22, success: 20, failed: 2 },
    { time: '16:00', executions: 18, success: 16, failed: 2 },
    { time: '20:00', executions: 12, success: 11, failed: 1 }
  ];

  const mockIncidentTypes = [
    { name: 'Malware', value: 35, color: chartColors.danger },
    { name: 'Phishing', value: 28, color: chartColors.warning },
    { name: 'Data Breach', value: 20, color: chartColors.purple },
    { name: 'DDoS', value: 17, color: chartColors.info }
  ];

  useEffect(() => {
    fetchSOARData();
    const interval = setInterval(fetchSOARData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchSOARData = async () => {
    try {
      setIsLoading(true);
      
      // Fetch metrics
      const metricsResponse = await fetch('/api/soar/metrics');
      if (metricsResponse.ok) {
        const metricsData = await metricsResponse.json();
        setMetrics(metricsData.statistics || generateMockMetrics());
      }

      // Fetch playbooks
      const playbooksResponse = await fetch('/api/soar/playbooks');
      if (playbooksResponse.ok) {
        const playbooksData = await playbooksResponse.json();
        setPlaybooks(playbooksData.playbooks || generateMockPlaybooks());
      }

      // Fetch incidents
      const incidentsResponse = await fetch('/api/soar/incidents');
      if (incidentsResponse.ok) {
        const incidentsData = await incidentsResponse.json();
        setIncidents(incidentsData.incidents || generateMockIncidents());
      }

      // Fetch executions
      const executionsResponse = await fetch('/api/soar/executions');
      if (executionsResponse.ok) {
        const executionsData = await executionsResponse.json();
        setExecutions(executionsData.executions || generateMockExecutions());
      }

    } catch (err) {
      setError('Failed to fetch SOAR data');
      console.error('SOAR data fetch error:', err);
      
      // Use mock data on error
      setMetrics(generateMockMetrics());
      setPlaybooks(generateMockPlaybooks());
      setIncidents(generateMockIncidents());
      setExecutions(generateMockExecutions());
    } finally {
      setIsLoading(false);
    }
  };

  const generateMockMetrics = (): SOARMetrics => ({
    totalPlaybooks: Math.floor(Math.random() * 20) + 10,
    activeExecutions: Math.floor(Math.random() * 5),
    completedToday: Math.floor(Math.random() * 50) + 10,
    averageExecutionTime: Math.floor(Math.random() * 300) + 60,
    successRate: Math.floor(Math.random() * 20) + 80,
    activeIncidents: Math.floor(Math.random() * 15) + 5,
    resolvedIncidents: Math.floor(Math.random() * 100) + 50,
    integrations: 5
  });

  const generateMockPlaybooks = (): SOARPlaybook[] => {
    const names = [
      'Malware Response',
      'Phishing Investigation',
      'Data Breach Containment',
      'DDoS Mitigation',
      'Insider Threat Detection'
    ];
    const triggers = ['Email Alert', 'SIEM Alert', 'Manual Trigger', 'API Call', 'Scheduled'];
    const statuses: ('ACTIVE' | 'INACTIVE' | 'DRAFT')[] = ['ACTIVE', 'INACTIVE', 'DRAFT'];
    const severities: ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    
    return Array.from({ length: 8 }, (_, i) => ({
      id: `playbook-${i}`,
      name: names[Math.floor(Math.random() * names.length)],
      description: `Automated response playbook for security incidents`,
      status: statuses[Math.floor(Math.random() * statuses.length)],
      trigger: triggers[Math.floor(Math.random() * triggers.length)],
      actions: Math.floor(Math.random() * 10) + 3,
      lastExecuted: Math.random() > 0.3 ? new Date(Date.now() - Math.random() * 86400000).toISOString() : undefined,
      executionCount: Math.floor(Math.random() * 100) + 10,
      successRate: Math.floor(Math.random() * 20) + 80,
      averageTime: Math.floor(Math.random() * 300) + 60,
      severity: severities[Math.floor(Math.random() * severities.length)]
    }));
  };

  const generateMockIncidents = (): SOARIncident[] => {
    const titles = [
      'Suspicious Email Detected',
      'Malware Alert on Workstation',
      'Unauthorized Access Attempt',
      'Data Exfiltration Detected',
      'DDoS Attack in Progress'
    ];
    const severities: ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const statuses: ('OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED')[] = ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'];
    const systems = ['Web Server', 'Database', 'Email Server', 'Workstation', 'Firewall'];
    
    return Array.from({ length: 12 }, (_, i) => ({
      id: `incident-${i}`,
      title: titles[Math.floor(Math.random() * titles.length)],
      description: `Security incident requiring immediate attention and response`,
      severity: severities[Math.floor(Math.random() * severities.length)],
      status: statuses[Math.floor(Math.random() * statuses.length)],
      assignedTo: Math.random() > 0.5 ? 'security-team' : undefined,
      createdAt: new Date(Date.now() - Math.random() * 86400000).toISOString(),
      updatedAt: new Date(Date.now() - Math.random() * 3600000).toISOString(),
      playbookId: Math.random() > 0.4 ? `playbook-${Math.floor(Math.random() * 5)}` : undefined,
      affectedSystems: systems.slice(0, Math.floor(Math.random() * 3) + 1),
      indicators: ['IP: 192.168.1.100', 'Hash: abc123def456'].slice(0, Math.floor(Math.random() * 2) + 1)
    }));
  };

  const generateMockExecutions = (): SOARExecution[] => {
    const statuses: ('RUNNING' | 'COMPLETED' | 'FAILED' | 'PAUSED')[] = ['RUNNING', 'COMPLETED', 'FAILED', 'PAUSED'];
    const steps = ['Initialize', 'Collect Data', 'Analyze', 'Respond', 'Report'];
    
    return Array.from({ length: 6 }, (_, i) => ({
      id: `execution-${i}`,
      playbookId: `playbook-${Math.floor(Math.random() * 5)}`,
      playbookName: `Response Playbook ${i + 1}`,
      status: statuses[Math.floor(Math.random() * statuses.length)],
      startedAt: new Date(Date.now() - Math.random() * 3600000).toISOString(),
      completedAt: Math.random() > 0.5 ? new Date(Date.now() - Math.random() * 1800000).toISOString() : undefined,
      duration: Math.floor(Math.random() * 300) + 30,
      progress: Math.floor(Math.random() * 100),
      currentStep: steps[Math.floor(Math.random() * steps.length)],
      totalSteps: steps.length,
      triggeredBy: 'SIEM Alert'
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ACTIVE':
      case 'RUNNING':
      case 'OPEN': return 'bg-green-500 text-white';
      case 'IN_PROGRESS': return 'bg-blue-500 text-white';
      case 'COMPLETED':
      case 'RESOLVED': return 'bg-green-500 text-white';
      case 'FAILED': return 'bg-red-500 text-white';
      case 'PAUSED': return 'bg-yellow-500 text-black';
      case 'CLOSED': return 'bg-gray-500 text-white';
      case 'INACTIVE':
      case 'DRAFT': return 'bg-gray-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const handleCreateIncident = async () => {
    try {
      const response = await fetch('/api/soar/incidents', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ...newIncident,
          affectedSystems: newIncident.affectedSystems.split(',').map(s => s.trim()).filter(Boolean)
        }),
      });

      if (response.ok) {
        setShowCreateIncident(false);
        setNewIncident({ title: '', description: '', severity: 'MEDIUM', affectedSystems: '' });
        fetchSOARData(); // Refresh data
      }
    } catch (err) {
      console.error('Error creating incident:', err);
    }
  };

  const handleCreatePlaybook = async () => {
    try {
      const response = await fetch('/api/soar/playbooks', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newPlaybook),
      });

      if (response.ok) {
        setShowCreatePlaybook(false);
        setNewPlaybook({ name: '', description: '', trigger: '', severity: 'MEDIUM' });
        fetchSOARData(); // Refresh data
      }
    } catch (err) {
      console.error('Error creating playbook:', err);
    }
  };

  if (isLoading && playbooks.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 bg-slate-900">
        <div className="flex items-center space-x-2 text-slate-400">
          <RefreshCw className="h-6 w-6 animate-spin" />
          <span>Loading SOAR Dashboard...</span>
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
              <Workflow className="h-8 w-8 text-purple-400" />
              <h1 className="text-3xl font-bold text-white">SOAR Dashboard</h1>
            </div>
            <Badge variant="outline" className="text-green-400 border-green-400">
              <Activity className="h-3 w-3 mr-1" />
              Orchestrating
            </Badge>
          </div>
          
          <div className="flex items-center space-x-4">
            <Button 
              onClick={fetchSOARData} 
              variant="outline" 
              size="sm"
              className="border-slate-600 text-slate-300 hover:bg-slate-700"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            
            <Dialog open={showCreateIncident} onOpenChange={setShowCreateIncident}>
              <DialogTrigger asChild>
                <Button size="sm" className="bg-orange-600 hover:bg-orange-700">
                  <Plus className="h-4 w-4 mr-2" />
                  New Incident
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-slate-800 border-slate-700 text-white">
                <DialogHeader>
                  <DialogTitle>Create New Incident</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <Input
                    placeholder="Incident title"
                    value={newIncident.title}
                    onChange={(e) => setNewIncident({ ...newIncident, title: e.target.value })}
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                  <Textarea
                    placeholder="Incident description"
                    value={newIncident.description}
                    onChange={(e) => setNewIncident({ ...newIncident, description: e.target.value })}
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                  <Select 
                    value={newIncident.severity} 
                    onValueChange={(value: any) => setNewIncident({ ...newIncident, severity: value })}
                  >
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
                  <Input
                    placeholder="Affected systems (comma separated)"
                    value={newIncident.affectedSystems}
                    onChange={(e) => setNewIncident({ ...newIncident, affectedSystems: e.target.value })}
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                  <div className="flex space-x-2">
                    <Button onClick={handleCreateIncident} className="bg-blue-600 hover:bg-blue-700">
                      Create Incident
                    </Button>
                    <Button 
                      variant="outline" 
                      onClick={() => setShowCreateIncident(false)}
                      className="border-slate-600 text-slate-300 hover:bg-slate-700"
                    >
                      Cancel
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>

            <Dialog open={showCreatePlaybook} onOpenChange={setShowCreatePlaybook}>
              <DialogTrigger asChild>
                <Button size="sm" className="bg-purple-600 hover:bg-purple-700">
                  <Plus className="h-4 w-4 mr-2" />
                  New Playbook
                </Button>
              </DialogTrigger>
              <DialogContent className="bg-slate-800 border-slate-700 text-white">
                <DialogHeader>
                  <DialogTitle>Create New Playbook</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <Input
                    placeholder="Playbook name"
                    value={newPlaybook.name}
                    onChange={(e) => setNewPlaybook({ ...newPlaybook, name: e.target.value })}
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                  <Textarea
                    placeholder="Playbook description"
                    value={newPlaybook.description}
                    onChange={(e) => setNewPlaybook({ ...newPlaybook, description: e.target.value })}
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                  <Input
                    placeholder="Trigger condition"
                    value={newPlaybook.trigger}
                    onChange={(e) => setNewPlaybook({ ...newPlaybook, trigger: e.target.value })}
                    className="bg-slate-700 border-slate-600 text-white"
                  />
                  <Select 
                    value={newPlaybook.severity} 
                    onValueChange={(value: any) => setNewPlaybook({ ...newPlaybook, severity: value })}
                  >
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
                  <div className="flex space-x-2">
                    <Button onClick={handleCreatePlaybook} className="bg-blue-600 hover:bg-blue-700">
                      Create Playbook
                    </Button>
                    <Button 
                      variant="outline" 
                      onClick={() => setShowCreatePlaybook(false)}
                      className="border-slate-600 text-slate-300 hover:bg-slate-700"
                    >
                      Cancel
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
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
                  <p className="text-sm text-slate-400">Active Playbooks</p>
                  <p className="text-2xl font-bold text-white">{metrics.totalPlaybooks}</p>
                </div>
                <GitBranch className="h-8 w-8 text-purple-400" />
              </div>
              <div className="mt-2 text-xs text-slate-400">
                <Activity className="h-3 w-3 inline mr-1" />
                {metrics.activeExecutions} currently running
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Success Rate</p>
                  <p className="text-2xl font-bold text-white">{metrics.successRate}%</p>
                </div>
                <CheckCircle className="h-8 w-8 text-green-400" />
              </div>
              <div className="mt-2">
                <Progress value={metrics.successRate} className="h-2" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Active Incidents</p>
                  <p className="text-2xl font-bold text-white">{metrics.activeIncidents}</p>
                </div>
                <Target className="h-8 w-8 text-orange-400" />
              </div>
              <div className="mt-2 text-xs text-slate-400">
                <Timer className="h-3 w-3 inline mr-1" />
                Avg: {metrics.averageExecutionTime}s response
              </div>
            </CardContent>
          </Card>

          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Integrations</p>
                  <p className="text-2xl font-bold text-white">{metrics.integrations}</p>
                </div>
                <Zap className="h-8 w-8 text-blue-400" />
              </div>
              <div className="mt-2 text-xs text-slate-400">
                <Shield className="h-3 w-3 inline mr-1" />
                All systems connected
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
            <TabsTrigger value="playbooks" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              Playbooks
            </TabsTrigger>
            <TabsTrigger value="incidents" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              Incidents
            </TabsTrigger>
            <TabsTrigger value="executions" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              Executions
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Execution Trends */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Execution Trends</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={mockExecutionTrends}>
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
                        dataKey="executions" 
                        stroke={chartColors.primary} 
                        strokeWidth={2}
                        dot={{ fill: chartColors.primary }}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="success" 
                        stroke={chartColors.secondary} 
                        strokeWidth={2}
                        dot={{ fill: chartColors.secondary }}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="failed" 
                        stroke={chartColors.danger} 
                        strokeWidth={2}
                        dot={{ fill: chartColors.danger }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              {/* Incident Types */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Incident Types</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={mockIncidentTypes}
                        cx="50%"
                        cy="50%"
                        outerRadius={100}
                        dataKey="value"
                      >
                        {mockIncidentTypes.map((entry, index) => (
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

            {/* Recent Activity */}
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Recent Activity</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {executions.slice(0, 5).map((execution) => (
                    <div key={execution.id} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className="flex items-center justify-center w-8 h-8 rounded-full bg-purple-500/20">
                          <Play className="h-4 w-4 text-purple-400" />
                        </div>
                        <div>
                          <p className="font-medium text-white">{execution.playbookName}</p>
                          <p className="text-sm text-slate-400">
                            {execution.currentStep} ({execution.progress}% complete)
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge className={getStatusColor(execution.status)}>
                          {execution.status}
                        </Badge>
                        <span className="text-sm text-slate-400">
                          {new Date(execution.startedAt).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="playbooks" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
              {playbooks.map((playbook) => (
                <Card key={playbook.id} className="bg-slate-800 border-slate-700">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-lg text-white">{playbook.name}</CardTitle>
                      <div className="flex items-center space-x-2">
                        <Badge className={getSeverityColor(playbook.severity)}>
                          {playbook.severity}
                        </Badge>
                        <Badge className={getStatusColor(playbook.status)}>
                          {playbook.status}
                        </Badge>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-slate-300">{playbook.description}</p>
                    
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">Trigger:</span>
                        <span className="text-slate-300">{playbook.trigger}</span>
                      </div>
                      
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">Actions:</span>
                        <span className="text-slate-300">{playbook.actions}</span>
                      </div>
                      
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">Success Rate:</span>
                        <span className="text-slate-300">{playbook.successRate}%</span>
                      </div>
                      
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">Avg Time:</span>
                        <span className="text-slate-300">{playbook.averageTime}s</span>
                      </div>
                      
                      {playbook.lastExecuted && (
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">Last Run:</span>
                          <span className="text-slate-300">
                            {new Date(playbook.lastExecuted).toLocaleDateString()}
                          </span>
                        </div>
                      )}
                    </div>
                    
                    <div className="flex space-x-2">
                      <Button size="sm" variant="outline" className="border-slate-600 text-slate-300 hover:bg-slate-700">
                        <Eye className="h-3 w-3 mr-1" />
                        View
                      </Button>
                      {playbook.status === 'ACTIVE' && (
                        <Button size="sm" className="bg-green-600 hover:bg-green-700">
                          <Play className="h-3 w-3 mr-1" />
                          Execute
                        </Button>
                      )}
                      <Button size="sm" variant="outline" className="border-slate-600 text-slate-300 hover:bg-slate-700">
                        <Edit className="h-3 w-3 mr-1" />
                        Edit
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="incidents" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
              {incidents.map((incident) => (
                <Card key={incident.id} className="bg-slate-800 border-slate-700">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-lg text-white">{incident.title}</CardTitle>
                      <div className="flex items-center space-x-2">
                        <Badge className={getSeverityColor(incident.severity)}>
                          {incident.severity}
                        </Badge>
                        <Badge className={getStatusColor(incident.status)}>
                          {incident.status}
                        </Badge>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <p className="text-slate-300">{incident.description}</p>
                    
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-slate-400">Created:</span>
                        <span className="text-slate-300">
                          {new Date(incident.createdAt).toLocaleString()}
                        </span>
                      </div>
                      
                      {incident.assignedTo && (
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">Assigned:</span>
                          <span className="text-slate-300">{incident.assignedTo}</span>
                        </div>
                      )}
                      
                      {incident.playbookId && (
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">Playbook:</span>
                          <span className="text-slate-300">Active</span>
                        </div>
                      )}
                    </div>
                    
                    {incident.affectedSystems.length > 0 && (
                      <div>
                        <p className="text-sm text-slate-400 mb-2">Affected Systems:</p>
                        <div className="flex flex-wrap gap-1">
                          {incident.affectedSystems.map((system, index) => (
                            <Badge key={index} variant="outline" className="text-xs border-slate-600 text-slate-400">
                              {system}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {incident.indicators.length > 0 && (
                      <div>
                        <p className="text-sm text-slate-400 mb-2">Indicators:</p>
                        <div className="space-y-1">
                          {incident.indicators.map((indicator, index) => (
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
                      {incident.status === 'OPEN' && (
                        <Button size="sm" className="bg-blue-600 hover:bg-blue-700">
                          <Play className="h-3 w-3 mr-1" />
                          Respond
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="executions" className="space-y-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Active Executions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {executions.map((execution) => (
                    <div key={execution.id} className="p-4 bg-slate-700 rounded-lg">
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <h4 className="font-medium text-white">{execution.playbookName}</h4>
                          <p className="text-sm text-slate-400">
                            Started {new Date(execution.startedAt).toLocaleString()}
                          </p>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={getStatusColor(execution.status)}>
                            {execution.status}
                          </Badge>
                          {execution.status === 'RUNNING' && (
                            <div className="flex space-x-1">
                              <Button size="sm" variant="outline" className="border-slate-600 text-slate-300 hover:bg-slate-700">
                                <Pause className="h-3 w-3" />
                              </Button>
                              <Button size="sm" variant="outline" className="border-slate-600 text-slate-300 hover:bg-slate-700">
                                <Square className="h-3 w-3" />
                              </Button>
                            </div>
                          )}
                        </div>
                      </div>
                      
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">Progress:</span>
                          <span className="text-slate-300">{execution.progress}%</span>
                        </div>
                        <Progress value={execution.progress} className="h-2" />
                        
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">Current Step:</span>
                          <span className="text-slate-300">
                            {execution.currentStep} ({execution.totalSteps - Math.floor(execution.progress / 20)} remaining)
                          </span>
                        </div>
                        
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">Triggered By:</span>
                          <span className="text-slate-300">{execution.triggeredBy}</span>
                        </div>
                        
                        {execution.duration && (
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-slate-400">Duration:</span>
                            <span className="text-slate-300">{execution.duration}s</span>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export { SOARDashboard }; 