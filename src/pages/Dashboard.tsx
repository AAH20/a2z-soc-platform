import React, { useState, useEffect } from 'react';
import MainLayout from '@/components/layout/MainLayout';
import MetricsCard from '@/components/dashboard/MetricsCard';
import AlertsPanel from '@/components/dashboard/AlertsPanel';
import TechniqueUsageChart from '@/components/dashboard/TechniqueUsageChart';
import AgentStatusCard from '@/components/dashboard/AgentStatusCard';
import SystemsIntegrationStatus from '@/components/dashboard/SystemsIntegrationStatus';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { 
  ShieldAlert, Activity, Cpu, Network, Target, Bell, Settings, 
  Database, Search, Cloud, FileCheck, CheckCircle, FileText,
  Calendar, Clock, Download, Brain, CloudUpload, Server, CloudCog
} from 'lucide-react';
import { useToast } from "@/hooks/use-toast";

// Updated mock data to match the expected interfaces
const mockMetrics = [
  { id: 1, title: 'Total Alerts', value: '1,457', trend: 5, icon: <ShieldAlert className="h-5 w-5" /> },
  { id: 2, title: 'CPU Usage', value: '68%', trend: -3, icon: <Cpu className="h-5 w-5" /> },
  { id: 3, title: 'Network Traffic', value: '345 GB', trend: 2, icon: <Network className="h-5 w-5" /> },
  { id: 4, title: 'Campaigns Active', value: '7', trend: 1, icon: <Target className="h-5 w-5" /> },
];

const mockAlerts = [
  { id: 1, severity: 'High', source: 'Firewall', description: 'DDoS attack detected on web server', timestamp: '2024-03-15T14:30:00Z' },
  { id: 2, severity: 'Medium', source: 'Email Gateway', description: 'Possible phishing attempt via email', timestamp: '2024-03-15T13:45:00Z' },
  { id: 3, severity: 'Low', source: 'Database Monitor', description: 'Unauthorized access attempt to database', timestamp: '2024-03-15T12:00:00Z' },
];

const mockTechniqueUsage = [
  { name: 'Phishing', count: 45, description: 'Email-based attacks' },
  { name: 'Malware', count: 30, description: 'Malicious software attacks' },
  { name: 'Brute Force', count: 25, description: 'Password attacks' },
];

const mockAgents = [
  { id: 1, name: 'Agent-001', status: 'Online', lastCheckIn: '2024-03-15T15:00:00Z', version: '1.0.0', os: 'Linux' },
  { id: 2, name: 'Agent-002', status: 'Offline', lastCheckIn: '2024-03-14T23:59:59Z', version: '1.0.0', os: 'Windows' },
];

const mockIntegrations = [
  { id: 1, name: 'Splunk', status: 'Connected', lastSync: '2024-03-15T15:00:00Z', type: 'SIEM' },
  { id: 2, name: 'Jira', status: 'Connected', lastSync: '2024-03-15T14:30:00Z', type: 'Ticketing' },
  { id: 3, name: 'Slack', status: 'Disconnected', lastSync: '2024-03-14T10:15:00Z', type: 'Notification' },
];

const Dashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const { toast } = useToast();
  const [metrics, setMetrics] = useState(mockMetrics);
  const [alerts, setAlerts] = useState(mockAlerts);
  const [techniqueUsage, setTechniqueUsage] = useState(mockTechniqueUsage);
  const [agents, setAgents] = useState(mockAgents);
  const [integrations, setIntegrations] = useState(mockIntegrations);

  const refreshData = () => {
    toast({
      title: "Refreshing Data",
      description: "Fetching the latest security metrics and alerts.",
    });

    // Simulate API data refresh
    setTimeout(() => {
      setMetrics([
        { id: 1, title: 'Total Alerts', value: '1,503', trend: 8, icon: <ShieldAlert className="h-5 w-5" /> },
        { id: 2, title: 'CPU Usage', value: '62%', trend: -5, icon: <Cpu className="h-5 w-5" /> },
        { id: 3, title: 'Network Traffic', value: '367 GB', trend: 4, icon: <Network className="h-5 w-5" /> },
        { id: 4, title: 'Campaigns Active', value: '9', trend: 2, icon: <Target className="h-5 w-5" /> },
      ]);
      setAlerts([
        { id: 1, severity: 'High', source: 'Firewall', description: 'Ransomware attack detected on file server', timestamp: '2024-03-16T02:15:00Z' },
        { id: 2, severity: 'Medium', source: 'IDS', description: 'Brute force attack on SSH detected', timestamp: '2024-03-15T22:30:00Z' },
        { id: 3, severity: 'Low', source: 'Endpoint Protection', description: 'New software installed on endpoint', timestamp: '2024-03-15T20:45:00Z' },
      ]);
      setTechniqueUsage([
        { name: 'Phishing', count: 52, description: 'Email-based attacks' },
        { name: 'Malware', count: 35, description: 'Malicious software attacks' },
        { name: 'Brute Force', count: 28, description: 'Password attacks' },
      ]);
      setAgents([
        { id: 1, name: 'Agent-001', status: 'Online', lastCheckIn: '2024-03-16T03:00:00Z', version: '1.0.1', os: 'Linux' },
        { id: 2, name: 'Agent-002', status: 'Offline', lastCheckIn: '2024-03-15T21:59:59Z', version: '1.0.0', os: 'Windows' },
      ]);
      setIntegrations([
        { id: 1, name: 'Splunk', status: 'Connected', lastSync: '2024-03-16T03:00:00Z', type: 'SIEM' },
        { id: 2, name: 'Jira', status: 'Connected', lastSync: '2024-03-16T02:30:00Z', type: 'Ticketing' },
        { id: 3, name: 'Slack', status: 'Connected', lastSync: '2024-03-16T02:15:00Z', type: 'Notification' },
      ]);

      toast({
        title: "Data Refreshed",
        description: "The dashboard data has been updated.",
      });
    }, 1500);
  };

  useEffect(() => {
    // Initial data load or setup can be done here
  }, []);

  return (
    <MainLayout>
      <div className="px-2">
        <h1 className="text-2xl font-bold mb-2 text-white">Security Operations Dashboard</h1>
        <p className="text-gray-400 mb-6">Overview of your security posture and integrated systems</p>
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full mb-6">
          <TabsList className="grid w-full grid-cols-7 h-12 bg-cyber-darker border border-cyber-gray">
            <TabsTrigger value="overview" className="flex items-center gap-2">
              <Activity className="h-4 w-4" />
              <span>Overview</span>
            </TabsTrigger>
            <TabsTrigger value="alerts" className="flex items-center gap-2">
              <Bell className="h-4 w-4" />
              <span>Alerts</span>
            </TabsTrigger>
            <TabsTrigger value="systems" className="flex items-center gap-2">
              <Database className="h-4 w-4" />
              <span>Systems</span>
            </TabsTrigger>
            <TabsTrigger value="compliance" className="flex items-center gap-2">
              <FileCheck className="h-4 w-4" />
              <span>Compliance</span>
            </TabsTrigger>
            <TabsTrigger value="explainable-ai" className="flex items-center gap-2">
              <Brain className="h-4 w-4" />
              <span>XAI</span>
            </TabsTrigger>
            <TabsTrigger value="cloud-storage" className="flex items-center gap-2">
              <CloudUpload className="h-4 w-4" />
              <span>Cloud</span>
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              <span>Settings</span>
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="overview" className="mt-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              {metrics.map(metric => (
                <MetricsCard
                  key={metric.id}
                  title={metric.title}
                  value={metric.value}
                  trend={metric.trend}
                  icon={metric.icon}
                />
              ))}
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <AlertsPanel alerts={alerts} />
              <TechniqueUsageChart data={techniqueUsage} />
            </div>
            
            <div className="grid grid-cols-1 gap-6">
              <AgentStatusCard agents={agents} />
            </div>
          </TabsContent>

          <TabsContent value="alerts" className="mt-4">
            <AlertsPanel alerts={alerts} />
          </TabsContent>

          <TabsContent value="systems" className="mt-4">
            <SystemsIntegrationStatus integrations={integrations} />
          </TabsContent>

          <TabsContent value="compliance" className="mt-4">
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle className="text-lg font-medium">Compliance Overview</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-400">
                  Review compliance status across various standards and regulations.
                </p>
                <div className="mt-4 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <FileText className="h-5 w-5 text-blue-400" />
                      <div>
                        <div className="font-medium">PCI DSS</div>
                        <div className="text-xs text-gray-400">Payment Card Industry Data Security Standard</div>
                      </div>
                    </div>
                    <div className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Compliant</div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <FileText className="h-5 w-5 text-purple-400" />
                      <div>
                        <div className="font-medium">HIPAA</div>
                        <div className="text-xs text-gray-400">Health Insurance Portability and Accountability Act</div>
                      </div>
                    </div>
                    <div className="text-xs px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded-full">Needs Review</div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <FileText className="h-5 w-5 text-teal-400" />
                      <div>
                        <div className="font-medium">GDPR</div>
                        <div className="text-xs text-gray-400">General Data Protection Regulation</div>
                      </div>
                    </div>
                    <div className="text-xs px-2 py-1 bg-red-500/20 text-red-400 rounded-full">Non-Compliant</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Explainable AI Tab (New) */}
          <TabsContent value="explainable-ai" className="mt-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              <MetricsCard
                title="AI Models"
                value="4"
                description="Active explainable models"
                icon={<Brain className="h-5 w-5" />}
              />
              <MetricsCard
                title="XAI Insights"
                value="218"
                description="Generated this month"
                icon={<Activity className="h-5 w-5" />}
              />
              <MetricsCard
                title="Model Accuracy"
                value="94.2%"
                description="Average prediction accuracy"
                icon={<CheckCircle className="h-5 w-5" />}
                trend={2}
              />
              <MetricsCard
                title="Processing"
                value="3.2TB"
                description="Data analyzed daily"
                icon={<Server className="h-5 w-5" />}
              />
            </div>
            
            {/* AI Models Dashboard */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader>
                  <CardTitle className="text-lg font-medium">Active AI Models</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between border-b border-cyber-gray pb-3">
                      <div className="flex items-center space-x-3">
                        <Brain className="h-5 w-5 text-blue-400" />
                        <div>
                          <div className="font-medium">Anomaly Detection</div>
                          <div className="text-xs text-gray-400">LIME-backed detection model</div>
                        </div>
                      </div>
                      <div className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Active</div>
                    </div>
                    
                    <div className="flex items-center justify-between border-b border-cyber-gray pb-3">
                      <div className="flex items-center space-x-3">
                        <Brain className="h-5 w-5 text-purple-400" />
                        <div>
                          <div className="font-medium">Threat Classification</div>
                          <div className="text-xs text-gray-400">SHAP-based decision trees</div>
                        </div>
                      </div>
                      <div className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Active</div>
                    </div>
                    
                    <div className="flex items-center justify-between border-b border-cyber-gray pb-3">
                      <div className="flex items-center space-x-3">
                        <Brain className="h-5 w-5 text-teal-400" />
                        <div>
                          <div className="font-medium">Network Pattern Analysis</div>
                          <div className="text-xs text-gray-400">Integrated Gradients model</div>
                        </div>
                      </div>
                      <div className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Active</div>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <Brain className="h-5 w-5 text-amber-400" />
                        <div>
                          <div className="font-medium">Alert Prioritization</div>
                          <div className="text-xs text-gray-400">Attention-based neural network</div>
                        </div>
                      </div>
                      <div className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Active</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader>
                  <CardTitle className="text-lg font-medium">XAI Insights</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3 text-sm">
                    <div className="p-3 border border-cyber-gray rounded-md">
                      <p className="font-medium text-cyber-accent mb-1">Anomaly Detection Insight</p>
                      <p className="text-gray-300 mb-2">Alert #A-2384 was triggered due to unusual login pattern with 92% confidence.</p>
                      <p className="text-xs text-gray-400">Key factors: Time of day (43%), Geo-location (32%), Device fingerprint (25%)</p>
                    </div>
                    
                    <div className="p-3 border border-cyber-gray rounded-md">
                      <p className="font-medium text-cyber-accent mb-1">Threat Classification Insight</p>
                      <p className="text-gray-300 mb-2">Network traffic classified as potential data exfiltration with 89% confidence.</p>
                      <p className="text-xs text-gray-400">Key factors: Destination (62%), Payload size (21%), Timing pattern (17%)</p>
                    </div>
                    
                    <div className="p-3 border border-cyber-gray rounded-md">
                      <p className="font-medium text-cyber-accent mb-1">Pattern Analysis Insight</p>
                      <p className="text-gray-300 mb-2">Detected potential lateral movement between hosts SRV-034 and SRV-089.</p>
                      <p className="text-xs text-gray-400">Key factors: Connection frequency (54%), Protocol anomalies (31%), Time window (15%)</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
            
            {/* AI Learning and Feature Importance */}
            <div className="grid grid-cols-1 gap-6">
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader>
                  <CardTitle className="text-lg font-medium">Feature Importance in Alert Generation</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <h3 className="text-sm font-medium mb-2 text-cyber-accent">Network-based Alerts</h3>
                        <div className="space-y-2">
                          <div className="flex items-center">
                            <div className="w-32 text-xs text-gray-400">Destination IP</div>
                            <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                              <div className="h-full bg-blue-500 rounded-full" style={{ width: '78%' }}></div>
                            </div>
                            <div className="w-10 text-right text-xs ml-2">78%</div>
                          </div>
                          <div className="flex items-center">
                            <div className="w-32 text-xs text-gray-400">Protocol Anomalies</div>
                            <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                              <div className="h-full bg-blue-500 rounded-full" style={{ width: '65%' }}></div>
                            </div>
                            <div className="w-10 text-right text-xs ml-2">65%</div>
                          </div>
                          <div className="flex items-center">
                            <div className="w-32 text-xs text-gray-400">Traffic Volume</div>
                            <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                              <div className="h-full bg-blue-500 rounded-full" style={{ width: '51%' }}></div>
                            </div>
                            <div className="w-10 text-right text-xs ml-2">51%</div>
                          </div>
                          <div className="flex items-center">
                            <div className="w-32 text-xs text-gray-400">Time Pattern</div>
                            <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                              <div className="h-full bg-blue-500 rounded-full" style={{ width: '43%' }}></div>
                            </div>
                            <div className="w-10 text-right text-xs ml-2">43%</div>
                          </div>
                        </div>
                      </div>
                      
                      <div>
                        <h3 className="text-sm font-medium mb-2 text-cyber-accent">Host-based Alerts</h3>
                        <div className="space-y-2">
                          <div className="flex items-center">
                            <div className="w-32 text-xs text-gray-400">Process Activity</div>
                            <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                              <div className="h-full bg-purple-500 rounded-full" style={{ width: '84%' }}></div>
                            </div>
                            <div className="w-10 text-right text-xs ml-2">84%</div>
                          </div>
                          <div className="flex items-center">
                            <div className="w-32 text-xs text-gray-400">File System Changes</div>
                            <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                              <div className="h-full bg-purple-500 rounded-full" style={{ width: '76%' }}></div>
                            </div>
                            <div className="w-10 text-right text-xs ml-2">76%</div>
                          </div>
                          <div className="flex items-center">
                            <div className="w-32 text-xs text-gray-400">Registry Changes</div>
                            <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                              <div className="h-full bg-purple-500 rounded-full" style={{ width: '58%' }}></div>
                            </div>
                            <div className="w-10 text-right text-xs ml-2">58%</div>
                          </div>
                          <div className="flex items-center">
                            <div className="w-32 text-xs text-gray-400">User Behavior</div>
                            <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                              <div className="h-full bg-purple-500 rounded-full" style={{ width: '47%' }}></div>
                            </div>
                            <div className="w-10 text-right text-xs ml-2">47%</div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Cloud Storage Tab (New) */}
          <TabsContent value="cloud-storage" className="mt-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <MetricsCard
                title="AWS S3"
                value="1.2TB"
                description="Storage currently used"
                icon={<CloudCog className="h-5 w-5" />}
              />
              <MetricsCard
                title="Google BigQuery"
                value="845GB"
                description="Data analyzed monthly"
                icon={<Database className="h-5 w-5" />}
              />
              <MetricsCard
                title="Azure Storage"
                value="987GB"
                description="Total blob storage"
                icon={<Cloud className="h-5 w-5" />}
              />
            </div>
            
            {/* Cloud Platform Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
              {/* AWS Integration Card */}
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <div>
                    <CardTitle className="text-md font-medium">AWS S3 Integration</CardTitle>
                    <p className="text-xs text-cyber-accent mt-1">Amazon Web Services</p>
                  </div>
                  <Cloud className="h-5 w-5 text-orange-400" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 mt-2">
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Status:</span>
                      <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Connected</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Buckets:</span>
                      <span className="text-xs">8</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Total Objects:</span>
                      <span className="text-xs">23,485</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Region:</span>
                      <span className="text-xs">us-east-1</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Last Sync:</span>
                      <span className="text-xs">10 mins ago</span>
                    </div>
                    <div className="flex justify-end mt-2">
                      <button className="flex items-center text-xs px-3 py-1 bg-cyber-accent/20 text-cyber-accent rounded hover:bg-cyber-accent/30 transition-colors">
                        <CloudUpload className="h-3 w-3 mr-1" />
                        Manage Buckets
                      </button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Google BigQuery Card */}
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <div>
                    <CardTitle className="text-md font-medium">Google BigQuery</CardTitle>
                    <p className="text-xs text-cyber-accent mt-1">Google Cloud Platform</p>
                  </div>
                  <Database className="h-5 w-5 text-blue-400" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 mt-2">
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Status:</span>
                      <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Connected</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Projects:</span>
                      <span className="text-xs">3</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Datasets:</span>
                      <span className="text-xs">12</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Region:</span>
                      <span className="text-xs">us-central1</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Last Sync:</span>
                      <span className="text-xs">25 mins ago</span>
                    </div>
                    <div className="flex justify-end mt-2">
                      <button className="flex items-center text-xs px-3 py-1 bg-cyber-accent/20 text-cyber-accent rounded hover:bg-cyber-accent/30 transition-colors">
                        <Database className="h-3 w-3 mr-1" />
                        View Queries
                      </button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Azure Storage Card */}
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <div>
                    <CardTitle className="text-md font-medium">Azure Storage</CardTitle>
                    <p className="text-xs text-cyber-accent mt-1">Microsoft Azure</p>
                  </div>
                  <CloudCog className="h-5 w-5 text-blue-500" />
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 mt-2">
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Status:</span>
                      <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Connected</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Accounts:</span>
                      <span className="text-xs">2</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Containers:</span>
                      <span className="text-xs">14</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Region:</span>
                      <span className="text-xs">East US</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-gray-400">Last Sync:</span>
                      <span className="text-xs">15 mins ago</span>
                    </div>
                    <div className="flex justify-end mt-2">
                      <button className="flex items-center text-xs px-3 py-1 bg-cyber-accent/20 text-cyber-accent rounded hover:bg-cyber-accent/30 transition-colors">
                        <Cloud className="h-3 w-3 mr-1" />
                        Manage Storage
                      </button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
            
            {/* Storage Usage Summary */}
            <div className="grid grid-cols-1 gap-6">
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader>
                  <CardTitle className="text-lg font-medium">Cloud Storage Usage</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-sm font-medium mb-2 text-cyber-accent">AWS S3 Usage</h3>
                      <div className="space-y-2">
                        <div className="flex items-center">
                          <div className="w-32 text-xs text-gray-400">soc-logs</div>
                          <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                            <div className="h-full bg-orange-500 rounded-full" style={{ width: '72%' }}></div>
                          </div>
                          <div className="w-20 text-right text-xs ml-2">720GB</div>
                        </div>
                        <div className="flex items-center">
                          <div className="w-32 text-xs text-gray-400">threat-intel</div>
                          <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                            <div className="h-full bg-orange-500 rounded-full" style={{ width: '32%' }}></div>
                          </div>
                          <div className="w-20 text-right text-xs ml-2">320GB</div>
                        </div>
                        <div className="flex items-center">
                          <div className="w-32 text-xs text-gray-400">network-captures</div>
                          <div className="flex-1 h-2 bg-cyber-gray rounded-full overflow-hidden">
                            <div className="h-full bg-orange-500 rounded-full" style={{ width: '18%' }}></div>
                          </div>
                          <div className="w-20 text-right text-xs ml-2">180GB</div>
                        </div>
                      </div>
                    </div>
                    
                    <div>
                      <h3 className="font-medium text-sm mb-2">System Usage</h3>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
};

export default Dashboard;
