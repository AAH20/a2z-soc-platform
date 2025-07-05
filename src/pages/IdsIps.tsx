import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Shield, ShieldAlert, Play, Pause, Settings, 
  AlertTriangle, CheckCircle, XCircle, Search,
  Filter, Download, Upload, Trash2, Edit
} from 'lucide-react';
import { useToast } from "@/hooks/use-toast";
import { apiService } from '@/services/api';

interface SecurityAgent {
  id: string;
  name: string;
  status: 'online' | 'offline';
  type: string;
  version: string;
  last_heartbeat: string;
  configuration?: any;
}

interface DetectionRule {
  id: string;
  rule_id: string;
  name: string;
  description: string;
  severity: string;
  category: string;
  is_enabled: boolean;
  rule_type: string;
  created_at: string;
}

interface ThreatAlert {
  id: string;
  event_type: string;
  severity: string;
  source_ip: string;
  destination_ip: string;
  description: string;
  status: string;
  created_at: string;
  agent_name?: string;
}

const IdsIps: React.FC = () => {
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState('overview');
  const [agents, setAgents] = useState<SecurityAgent[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');

  const loadData = async () => {
    setLoading(true);
    try {
      const [agentsResponse, rulesResponse, alertsResponse] = await Promise.all([
        apiService.get('/network-agents'),
        apiService.get('/detection-rules'),
        apiService.get('/security-events?limit=50')
      ]);

      setAgents(agentsResponse.data.data || []);
      setRules(rulesResponse.data.data || []);
      setAlerts(alertsResponse.data.data || []);
    } catch (error) {
      console.error('Failed to load IDS/IPS data:', error);
      toast({
        title: "Error Loading Data",
        description: "Failed to fetch IDS/IPS data. Please try again.",
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const toggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      await apiService.put(`/detection-rules/${ruleId}`, { is_enabled: enabled });
      setRules(rules.map(rule => 
        rule.id === ruleId ? { ...rule, is_enabled: enabled } : rule
      ));
      toast({
        title: "Rule Updated",
        description: `Rule ${enabled ? 'enabled' : 'disabled'} successfully.`,
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update rule status.",
        variant: "destructive"
      });
    }
  };

  const updateAlertStatus = async (alertId: string, status: string) => {
    try {
      await apiService.put(`/security-events/${alertId}`, { status });
      setAlerts(alerts.map(alert => 
        alert.id === alertId ? { ...alert, status } : alert
      ));
      toast({
        title: "Alert Updated",
        description: "Alert status updated successfully.",
      });
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to update alert status.",
        variant: "destructive"
      });
    }
  };

  useEffect(() => {
    loadData();
    
    // Refresh data every 30 seconds
    const interval = setInterval(loadData, 30000);
    return () => clearInterval(interval);
  }, []);

  // Filter functions
  const filteredAgents = agents.filter(agent => {
    const matchesSearch = agent.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || agent.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const filteredRules = rules.filter(rule => {
    const matchesSearch = rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || 
                         (statusFilter === 'enabled' ? rule.is_enabled : !rule.is_enabled);
    return matchesSearch && matchesStatus;
  });

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = alert.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         alert.source_ip.includes(searchTerm);
    const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
    const matchesStatus = statusFilter === 'all' || alert.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
      case 'active':
      case 'enabled':
        return 'bg-green-500';
      case 'offline':
      case 'inactive':
      case 'disabled':
        return 'bg-red-500';
      case 'warning':
        return 'bg-yellow-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-500';
      case 'high':
        return 'bg-orange-500';
      case 'medium':
        return 'bg-yellow-500';
      case 'low':
        return 'bg-green-500';
      default:
        return 'bg-gray-500';
    }
  };

  if (loading) {
    return (
      <div className="space-y-6 bg-slate-900 min-h-screen p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-white">Loading IDS/IPS data...</div>
        </div>
      </div>
    );
  }

  const activeAgents = agents.filter(agent => agent.status === 'online');
  const enabledRules = rules.filter(rule => rule.is_enabled);
  const criticalAlerts = alerts.filter(alert => alert.severity === 'critical' && alert.status === 'new');

  return (
    <div className="space-y-6 bg-slate-900 min-h-screen p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">IDS/IPS Management</h1>
          <p className="mt-2 text-slate-400">
            Intrusion Detection and Prevention System monitoring and configuration
          </p>
        </div>
        <div className="flex space-x-3">
          <Button onClick={loadData} variant="outline" className="border-slate-600 text-slate-300">
            <Search className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          <Button className="bg-blue-600 hover:bg-blue-700">
            <Download className="h-4 w-4 mr-2" />
            Export Configuration
          </Button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <Card className="bg-slate-800 border-slate-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Active Agents</p>
                <p className="text-2xl font-bold text-white">{activeAgents.length}</p>
              </div>
              <Shield className="h-8 w-8 text-blue-500" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              {agents.length} total agents
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Detection Rules</p>
                <p className="text-2xl font-bold text-white">{enabledRules.length}</p>
              </div>
              <Settings className="h-8 w-8 text-green-500" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              {rules.length} total rules
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">Critical Alerts</p>
                <p className="text-2xl font-bold text-white">{criticalAlerts.length}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-500" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              Last 24 hours
            </p>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-slate-400 text-sm">System Status</p>
                <p className="text-2xl font-bold text-green-400">Operational</p>
              </div>
              <CheckCircle className="h-8 w-8 text-green-500" />
            </div>
            <p className="text-xs text-slate-400 mt-2">
              All systems running
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="bg-slate-800">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="agents">Security Agents</TabsTrigger>
          <TabsTrigger value="rules">Detection Rules</TabsTrigger>
          <TabsTrigger value="alerts">Threat Alerts</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Recent Alerts</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {alerts.slice(0, 5).map((alert) => (
                    <div key={alert.id} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className={`w-3 h-3 rounded-full ${getSeverityColor(alert.severity)}`} />
                        <div>
                          <p className="text-white font-medium">{alert.description}</p>
                          <p className="text-slate-400 text-sm">{alert.source_ip} → {alert.destination_ip}</p>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-slate-300">
                        {alert.severity}
                      </Badge>
                    </div>
                  ))}
                  {alerts.length === 0 && (
                    <div className="text-slate-400 text-center py-8">
                      No alerts to display
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Agent Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {agents.slice(0, 5).map((agent) => (
                    <div key={agent.id} className="flex items-center justify-between p-3 bg-slate-700 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className={`w-3 h-3 rounded-full ${getStatusColor(agent.status)}`} />
                        <div>
                          <p className="text-white font-medium">{agent.name}</p>
                          <p className="text-slate-400 text-sm">{agent.type} v{agent.version}</p>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-slate-300">
                        {agent.status}
                      </Badge>
                    </div>
                  ))}
                  {agents.length === 0 && (
                    <div className="text-slate-400 text-center py-8">
                      No agents configured
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="agents" className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Input
                placeholder="Search agents..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-800 border-slate-600 text-white w-64"
              />
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="bg-slate-800 border-slate-600 text-white w-40">
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="online">Online</SelectItem>
                  <SelectItem value="offline">Offline</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-slate-700">
                    <tr>
                      <th className="text-left p-4 text-slate-300">Agent Name</th>
                      <th className="text-left p-4 text-slate-300">Type</th>
                      <th className="text-left p-4 text-slate-300">Status</th>
                      <th className="text-left p-4 text-slate-300">Version</th>
                      <th className="text-left p-4 text-slate-300">Last Heartbeat</th>
                      <th className="text-left p-4 text-slate-300">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAgents.map((agent) => (
                      <tr key={agent.id} className="border-t border-slate-600">
                        <td className="p-4 text-white font-medium">{agent.name}</td>
                        <td className="p-4 text-slate-300">{agent.type}</td>
                        <td className="p-4">
                          <Badge 
                            variant="outline" 
                            className={`${getStatusColor(agent.status)} text-white border-none`}
                          >
                            {agent.status}
                          </Badge>
                        </td>
                        <td className="p-4 text-slate-300">{agent.version}</td>
                        <td className="p-4 text-slate-300">
                          {new Date(agent.last_heartbeat).toLocaleString()}
                        </td>
                        <td className="p-4">
                          <div className="flex space-x-2">
                            <Button size="sm" variant="outline" className="border-slate-600 text-slate-300">
                              <Settings className="h-4 w-4" />
                            </Button>
                            <Button size="sm" variant="outline" className="border-slate-600 text-slate-300">
                              <Edit className="h-4 w-4" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {filteredAgents.length === 0 && (
                  <div className="text-slate-400 text-center py-8">
                    No agents found matching your criteria
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="rules" className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Input
                placeholder="Search rules..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-800 border-slate-600 text-white w-64"
              />
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="bg-slate-800 border-slate-600 text-white w-40">
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Rules</SelectItem>
                  <SelectItem value="enabled">Enabled</SelectItem>
                  <SelectItem value="disabled">Disabled</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button className="bg-blue-600 hover:bg-blue-700">
              <Upload className="h-4 w-4 mr-2" />
              Import Rules
            </Button>
          </div>

          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-slate-700">
                    <tr>
                      <th className="text-left p-4 text-slate-300">Rule Name</th>
                      <th className="text-left p-4 text-slate-300">Category</th>
                      <th className="text-left p-4 text-slate-300">Severity</th>
                      <th className="text-left p-4 text-slate-300">Type</th>
                      <th className="text-left p-4 text-slate-300">Status</th>
                      <th className="text-left p-4 text-slate-300">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRules.map((rule) => (
                      <tr key={rule.id} className="border-t border-slate-600">
                        <td className="p-4">
                          <div>
                            <p className="text-white font-medium">{rule.name}</p>
                            <p className="text-slate-400 text-sm">{rule.description}</p>
                          </div>
                        </td>
                        <td className="p-4 text-slate-300">{rule.category}</td>
                        <td className="p-4">
                          <Badge 
                            variant="outline" 
                            className={`${getSeverityColor(rule.severity)} text-white border-none`}
                          >
                            {rule.severity}
                          </Badge>
                        </td>
                        <td className="p-4 text-slate-300">{rule.rule_type}</td>
                        <td className="p-4">
                          <Button
                            size="sm"
                            variant={rule.is_enabled ? "default" : "outline"}
                            onClick={() => toggleRule(rule.id, !rule.is_enabled)}
                            className={rule.is_enabled ? "bg-green-600 hover:bg-green-700" : "border-slate-600 text-slate-300"}
                          >
                            {rule.is_enabled ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
                          </Button>
                        </td>
                        <td className="p-4">
                          <div className="flex space-x-2">
                            <Button size="sm" variant="outline" className="border-slate-600 text-slate-300">
                              <Edit className="h-4 w-4" />
                            </Button>
                            <Button size="sm" variant="outline" className="border-red-600 text-red-300">
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {filteredRules.length === 0 && (
                  <div className="text-slate-400 text-center py-8">
                    No rules found matching your criteria
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="alerts" className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Input
                placeholder="Search alerts..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-800 border-slate-600 text-white w-64"
              />
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="bg-slate-800 border-slate-600 text-white w-40">
                  <SelectValue placeholder="Filter by severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severity</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="bg-slate-800 border-slate-600 text-white w-40">
                  <SelectValue placeholder="Filter by status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="new">New</SelectItem>
                  <SelectItem value="investigating">Investigating</SelectItem>
                  <SelectItem value="resolved">Resolved</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-slate-700">
                    <tr>
                      <th className="text-left p-4 text-slate-300">Alert</th>
                      <th className="text-left p-4 text-slate-300">Severity</th>
                      <th className="text-left p-4 text-slate-300">Source</th>
                      <th className="text-left p-4 text-slate-300">Destination</th>
                      <th className="text-left p-4 text-slate-300">Status</th>
                      <th className="text-left p-4 text-slate-300">Timestamp</th>
                      <th className="text-left p-4 text-slate-300">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAlerts.map((alert) => (
                      <tr key={alert.id} className="border-t border-slate-600">
                        <td className="p-4">
                          <div>
                            <p className="text-white font-medium">{alert.description}</p>
                            <p className="text-slate-400 text-sm">{alert.event_type}</p>
                          </div>
                        </td>
                        <td className="p-4">
                          <Badge 
                            variant="outline" 
                            className={`${getSeverityColor(alert.severity)} text-white border-none`}
                          >
                            {alert.severity}
                          </Badge>
                        </td>
                        <td className="p-4 text-slate-300">{alert.source_ip}</td>
                        <td className="p-4 text-slate-300">{alert.destination_ip}</td>
                        <td className="p-4">
                          <Select
                            value={alert.status}
                            onValueChange={(status) => updateAlertStatus(alert.id, status)}
                          >
                            <SelectTrigger className="bg-slate-700 border-slate-600 text-white w-32">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="new">New</SelectItem>
                              <SelectItem value="investigating">Investigating</SelectItem>
                              <SelectItem value="resolved">Resolved</SelectItem>
                              <SelectItem value="false_positive">False Positive</SelectItem>
                            </SelectContent>
                          </Select>
                        </td>
                        <td className="p-4 text-slate-300">
                          {new Date(alert.created_at).toLocaleString()}
                        </td>
                        <td className="p-4">
                          <Button size="sm" variant="outline" className="border-slate-600 text-slate-300">
                            View Details
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {filteredAlerts.length === 0 && (
                  <div className="text-slate-400 text-center py-8">
                    No alerts found matching your criteria
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default IdsIps; 