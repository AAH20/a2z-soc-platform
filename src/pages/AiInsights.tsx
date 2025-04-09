
import React, { useState, useEffect } from 'react';
import MainLayout from '@/components/layout/MainLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Brain, RefreshCw, Zap, Settings, LineChart, AlertCircle, CheckCircle2, Shield } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import ModelInterface from '@/components/ai/ModelInterface';
import AdvancedChart from '@/components/visualizations/AdvancedChart';
import { modelConfigurations, securityPrompts, runModelAnalysis, saveModelConfiguration } from '@/services/aiService';

const mockAnalyticsTrendData = [
  { date: '2023-10-01', alerts: 145, falsePositives: 32, meanTimeToDetect: 42 },
  { date: '2023-10-02', alerts: 132, falsePositives: 28, meanTimeToDetect: 38 },
  { date: '2023-10-03', alerts: 165, falsePositives: 30, meanTimeToDetect: 45 },
  { date: '2023-10-04', alerts: 175, falsePositives: 35, meanTimeToDetect: 50 },
  { date: '2023-10-05', alerts: 156, falsePositives: 25, meanTimeToDetect: 36 },
  { date: '2023-10-06', alerts: 189, falsePositives: 42, meanTimeToDetect: 55 },
  { date: '2023-10-07', alerts: 178, falsePositives: 38, meanTimeToDetect: 48 },
  { date: '2023-10-08', alerts: 163, falsePositives: 30, meanTimeToDetect: 43 },
  { date: '2023-10-09', alerts: 142, falsePositives: 25, meanTimeToDetect: 39 },
  { date: '2023-10-10', alerts: 158, falsePositives: 33, meanTimeToDetect: 44 },
  { date: '2023-10-11', alerts: 175, falsePositives: 36, meanTimeToDetect: 48 },
  { date: '2023-10-12', alerts: 167, falsePositives: 31, meanTimeToDetect: 42 },
  { date: '2023-10-13', alerts: 185, falsePositives: 40, meanTimeToDetect: 52 },
  { date: '2023-10-14', alerts: 178, falsePositives: 37, meanTimeToDetect: 47 },
];

const mockRecommendationsData = [
  { id: 1, category: 'Detection', title: 'Update Wazuh rules for Log4j vulnerabilities', priority: 'high', source: 'GPT-4', implemented: false },
  { id: 2, category: 'Prevention', title: 'Implement IP blocking for repeated failed authentications', priority: 'medium', source: 'Claude', implemented: true },
  { id: 3, category: 'Response', title: 'Create automated playbook for ransomware detection', priority: 'high', source: 'Security Copilot', implemented: false },
  { id: 4, category: 'Configuration', title: 'Adjust Elasticsearch shard allocation for better performance', priority: 'low', source: 'Gemini', implemented: false },
  { id: 5, category: 'Monitoring', title: 'Add monitoring for DNS tunneling attempts', priority: 'medium', source: 'GPT-4', implemented: true },
  { id: 6, category: 'Detection', title: 'Enhance network segmentation rules in Snort', priority: 'high', source: 'Security Copilot', implemented: false },
  { id: 7, category: 'Configuration', title: 'Optimize Suricata performance settings', priority: 'medium', source: 'Claude', implemented: false },
  { id: 8, category: 'Response', title: 'Update incident response procedure for cloud assets', priority: 'medium', source: 'Gemini', implemented: true },
];

const coverageData = [
  { technique: 'Initial Access', coverage: 78, benchmarkCoverage: 85 },
  { technique: 'Execution', coverage: 82, benchmarkCoverage: 80 },
  { technique: 'Persistence', coverage: 65, benchmarkCoverage: 75 },
  { technique: 'Privilege Escalation', coverage: 70, benchmarkCoverage: 78 },
  { technique: 'Defense Evasion', coverage: 58, benchmarkCoverage: 72 },
  { technique: 'Credential Access', coverage: 85, benchmarkCoverage: 80 },
  { technique: 'Discovery', coverage: 75, benchmarkCoverage: 65 },
  { technique: 'Lateral Movement', coverage: 62, benchmarkCoverage: 70 },
  { technique: 'Collection', coverage: 80, benchmarkCoverage: 75 },
  { technique: 'Command and Control', coverage: 72, benchmarkCoverage: 82 },
  { technique: 'Exfiltration', coverage: 68, benchmarkCoverage: 75 },
  { technique: 'Impact', coverage: 75, benchmarkCoverage: 70 },
];

const AiInsights: React.FC = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const { toast } = useToast();
  const [recommendations, setRecommendations] = useState(mockRecommendationsData);
  
  // Demo function to simulate data refresh
  const refreshData = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
      toast({
        title: "Data refreshed",
        description: "AI insights have been updated successfully",
      });
    }, 1500);
  };

  // Demo function to toggle recommendation implementation status
  const toggleRecommendation = (id: number) => {
    setRecommendations(prev => 
      prev.map(rec => rec.id === id ? { ...rec, implemented: !rec.implemented } : rec)
    );
    toast({
      title: "Status updated",
      description: `Recommendation status has been updated.`,
    });
  };

  // Demo useEffect to simulate initial data loading
  useEffect(() => {
    console.log("AI Insights data loaded");
  }, []);

  return (
    <MainLayout>
      <div className="px-2">
        <div className="flex justify-between items-center mb-2">
          <div>
            <h1 className="text-2xl font-bold text-white">AI Insights</h1>
            <p className="text-gray-400">Advanced AI analysis and recommendations for your security operations</p>
          </div>
          <Button variant="outline" className="flex items-center gap-2" onClick={refreshData} disabled={isRefreshing}>
            {isRefreshing ? <RefreshCw className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            <span>Refresh Data</span>
          </Button>
        </div>
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full mb-6">
          <TabsList className="grid w-full grid-cols-4 h-12 bg-cyber-darker border border-cyber-gray">
            <TabsTrigger value="overview" className="flex items-center gap-2">
              <Brain className="h-4 w-4" />
              <span>Overview</span>
            </TabsTrigger>
            <TabsTrigger value="models" className="flex items-center gap-2">
              <Zap className="h-4 w-4" />
              <span>Models</span>
            </TabsTrigger>
            <TabsTrigger value="recommendations" className="flex items-center gap-2">
              <Shield className="h-4 w-4" />
              <span>Recommendations</span>
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              <span>Settings</span>
            </TabsTrigger>
          </TabsList>
          
          {/* Overview Tab */}
          <TabsContent value="overview" className="mt-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg font-medium text-white">AI Processing Status</CardTitle>
                  <CardDescription className="text-gray-400">
                    Current status of AI analysis engines
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-2 bg-cyber-success rounded-full animate-pulse"></div>
                        <span className="text-sm text-white">GPT-4 Analysis</span>
                      </div>
                      <span className="text-xs text-gray-400">Last run: 15 mins ago</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-2 bg-cyber-success rounded-full animate-pulse"></div>
                        <span className="text-sm text-white">Claude Analysis</span>
                      </div>
                      <span className="text-xs text-gray-400">Last run: 32 mins ago</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-2 bg-cyber-warning rounded-full"></div>
                        <span className="text-sm text-white">Gemini Analysis</span>
                      </div>
                      <span className="text-xs text-gray-400">Last run: 2 hours ago</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <div className="h-2 w-2 bg-cyber-danger rounded-full"></div>
                        <span className="text-sm text-white">Security Copilot</span>
                      </div>
                      <span className="text-xs text-gray-400">Not configured</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg font-medium text-white">Log Processing</CardTitle>
                  <CardDescription className="text-gray-400">
                    Status of AI log processing by source
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="space-y-1">
                      <div className="flex justify-between">
                        <span className="text-sm text-white">Wazuh Logs</span>
                        <span className="text-xs text-cyber-success">Processed</span>
                      </div>
                      <div className="w-full h-1.5 bg-cyber-darker rounded-full overflow-hidden">
                        <div className="h-full bg-cyber-success" style={{ width: '100%' }}></div>
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between">
                        <span className="text-sm text-white">Elasticsearch</span>
                        <span className="text-xs text-cyber-success">Processed</span>
                      </div>
                      <div className="w-full h-1.5 bg-cyber-darker rounded-full overflow-hidden">
                        <div className="h-full bg-cyber-success" style={{ width: '100%' }}></div>
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between">
                        <span className="text-sm text-white">Snort/Suricata</span>
                        <span className="text-xs text-cyber-success">Processed</span>
                      </div>
                      <div className="w-full h-1.5 bg-cyber-darker rounded-full overflow-hidden">
                        <div className="h-full bg-cyber-success" style={{ width: '100%' }}></div>
                      </div>
                    </div>
                    <div className="space-y-1">
                      <div className="flex justify-between">
                        <span className="text-sm text-white">Opensearch</span>
                        <span className="text-xs text-cyber-warning">In Progress</span>
                      </div>
                      <div className="w-full h-1.5 bg-cyber-darker rounded-full overflow-hidden">
                        <div className="h-full bg-cyber-warning" style={{ width: '65%' }}></div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg font-medium text-white">AI Insights Summary</CardTitle>
                  <CardDescription className="text-gray-400">
                    Key findings from AI analysis
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex items-start gap-2">
                      <AlertCircle className="h-5 w-5 text-cyber-danger flex-shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-white text-sm font-medium">Critical Finding</h4>
                        <p className="text-xs text-gray-400">Potential data exfiltration attempt detected in network logs</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-2">
                      <AlertCircle className="h-5 w-5 text-cyber-warning flex-shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-white text-sm font-medium">Performance Issue</h4>
                        <p className="text-xs text-gray-400">Elasticsearch cluster showing signs of resource constraint</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-2">
                      <CheckCircle2 className="h-5 w-5 text-cyber-success flex-shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-white text-sm font-medium">Improved Detection</h4>
                        <p className="text-xs text-gray-400">False positive rate reduced by 18% with AI-tuned rules</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-2">
                      <Shield className="h-5 w-5 text-cyber-accent flex-shrink-0 mt-0.5" />
                      <div>
                        <h4 className="text-white text-sm font-medium">Coverage Gap</h4>
                        <p className="text-xs text-gray-400">Limited visibility into container orchestration environments</p>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              <AdvancedChart
                title="Security Analytics Trends"
                description="Alert volume and detection metrics over time"
                data={mockAnalyticsTrendData}
                xAxisKey="date"
                series={[
                  { name: "Total Alerts", dataKey: "alerts", color: "#0EA5E9" },
                  { name: "False Positives", dataKey: "falsePositives", color: "#F59E0B" },
                  { name: "MTTD (min)", dataKey: "meanTimeToDetect", color: "#10B981" }
                ]}
                type="line"
              />
              
              <AdvancedChart
                title="MITRE ATT&CK Coverage"
                description="Current detection coverage vs. industry benchmark"
                data={coverageData}
                xAxisKey="technique"
                series={[
                  { name: "Current Coverage", dataKey: "coverage", color: "#0EA5E9" },
                  { name: "Industry Benchmark", dataKey: "benchmarkCoverage", color: "#64748B" }
                ]}
                type="bar"
              />
            </div>
            
            <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden mb-6">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg font-medium text-white">Top AI-Generated Recommendations</CardTitle>
                <CardDescription className="text-gray-400">
                  High-priority actions to improve security posture
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {recommendations.filter(r => r.priority === 'high' && !r.implemented).slice(0, 4).map(rec => (
                    <div key={rec.id} className="flex items-start gap-3 p-3 bg-cyber-darker rounded-md">
                      <Shield className="h-5 w-5 text-cyber-accent flex-shrink-0 mt-0.5" />
                      <div className="flex-1">
                        <div className="flex justify-between">
                          <h4 className="text-white text-sm font-medium">{rec.title}</h4>
                          <span className="text-xs px-2 py-1 rounded-full bg-cyber-danger/20 text-cyber-danger">
                            {rec.priority}
                          </span>
                        </div>
                        <div className="flex justify-between mt-2">
                          <span className="text-xs text-gray-400">Category: {rec.category}</span>
                          <span className="text-xs text-gray-400">Source: {rec.source}</span>
                        </div>
                        <div className="mt-3 flex justify-end">
                          <Button 
                            variant="outline" 
                            size="sm" 
                            className="text-xs h-7"
                            onClick={() => toggleRecommendation(rec.id)}
                          >
                            Mark as Implemented
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          {/* Models Tab */}
          <TabsContent value="models" className="mt-4">
            <div className="mb-6">
              <ModelInterface 
                model={{
                  ...modelConfigurations.gpt,
                  lastSync: '15 mins ago',
                  status: 'connected',
                  icon: <Brain className="h-5 w-5" style={{ color: '#0EA5E9' }} />
                }}
                onSaveConfig={saveModelConfiguration}
                onRunAnalysis={runModelAnalysis}
                presetPrompts={[
                  ...securityPrompts.general,
                  ...securityPrompts.logs.slice(0, 2)
                ]}
              />
              
              <ModelInterface 
                model={{
                  ...modelConfigurations.claude,
                  lastSync: '32 mins ago',
                  status: 'connected',
                  icon: <Brain className="h-5 w-5" style={{ color: '#8B5CF6' }} />
                }}
                onSaveConfig={saveModelConfiguration}
                onRunAnalysis={runModelAnalysis}
                presetPrompts={[
                  ...securityPrompts.logs,
                  ...securityPrompts.recommendations.slice(0, 2)
                ]}
              />
              
              <ModelInterface 
                model={{
                  ...modelConfigurations.gemini,
                  lastSync: '2 hours ago',
                  status: 'connected',
                  icon: <Brain className="h-5 w-5" style={{ color: '#F59E0B' }} />
                }}
                onSaveConfig={saveModelConfiguration}
                onRunAnalysis={runModelAnalysis}
                presetPrompts={[
                  ...securityPrompts.recommendations,
                  ...securityPrompts.general.slice(0, 2)
                ]}
              />
              
              <ModelInterface 
                model={{
                  ...modelConfigurations['security-copilot'],
                  status: 'disconnected',
                  icon: <Shield className="h-5 w-5" style={{ color: '#EC4899' }} />
                }}
                onSaveConfig={saveModelConfiguration}
                onRunAnalysis={runModelAnalysis}
                presetPrompts={securityPrompts.general}
              />
            </div>
          </TabsContent>
          
          {/* Recommendations Tab */}
          <TabsContent value="recommendations" className="mt-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
              <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
                <CardHeader className="py-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg font-medium text-white">Total</CardTitle>
                    <div className="h-8 w-8 rounded-full bg-cyber-darker flex items-center justify-center">
                      <span className="text-white font-medium">{recommendations.length}</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="text-xs text-gray-400">All recommendations</div>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
                <CardHeader className="py-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg font-medium text-white">High Priority</CardTitle>
                    <div className="h-8 w-8 rounded-full bg-cyber-danger/20 flex items-center justify-center">
                      <span className="text-cyber-danger font-medium">{recommendations.filter(r => r.priority === 'high').length}</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="text-xs text-gray-400">Require immediate attention</div>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
                <CardHeader className="py-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg font-medium text-white">Implemented</CardTitle>
                    <div className="h-8 w-8 rounded-full bg-cyber-success/20 flex items-center justify-center">
                      <span className="text-cyber-success font-medium">{recommendations.filter(r => r.implemented).length}</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="text-xs text-gray-400">Successfully completed</div>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
                <CardHeader className="py-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg font-medium text-white">Pending</CardTitle>
                    <div className="h-8 w-8 rounded-full bg-cyber-warning/20 flex items-center justify-center">
                      <span className="text-cyber-warning font-medium">{recommendations.filter(r => !r.implemented).length}</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="text-xs text-gray-400">Awaiting implementation</div>
                </CardContent>
              </Card>
            </div>
            
            <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden mb-6">
              <CardHeader className="pb-2">
                <div className="flex justify-between items-center">
                  <div>
                    <CardTitle className="text-lg font-medium text-white">All Recommendations</CardTitle>
                    <CardDescription className="text-gray-400">
                      AI-generated security improvements
                    </CardDescription>
                  </div>
                  <div>
                    <select className="bg-cyber-darker text-white border border-cyber-gray rounded-md p-1 text-sm">
                      <option value="all">All Categories</option>
                      <option value="detection">Detection</option>
                      <option value="prevention">Prevention</option>
                      <option value="response">Response</option>
                      <option value="configuration">Configuration</option>
                      <option value="monitoring">Monitoring</option>
                    </select>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="divide-y divide-cyber-gray">
                  {recommendations.map(rec => (
                    <div key={rec.id} className="py-4 first:pt-0 flex items-start">
                      <div className="flex-1">
                        <div className="flex items-start justify-between">
                          <div className="flex items-start gap-3">
                            <div className={`w-5 h-5 mt-0.5 rounded-full flex items-center justify-center ${
                              rec.priority === 'high' ? 'bg-cyber-danger/20 text-cyber-danger' :
                              rec.priority === 'medium' ? 'bg-cyber-warning/20 text-cyber-warning' :
                              'bg-cyber-success/20 text-cyber-success'
                            }`}>
                              {rec.priority === 'high' ? '!' : rec.priority === 'medium' ? '•' : '-'}
                            </div>
                            <div>
                              <h4 className={`text-sm font-medium ${rec.implemented ? 'text-gray-500 line-through' : 'text-white'}`}>
                                {rec.title}
                              </h4>
                              <div className="flex gap-2 mt-1">
                                <span className="text-xs px-2 py-0.5 rounded-full bg-cyber-darker text-gray-400">
                                  {rec.category}
                                </span>
                                <span className="text-xs px-2 py-0.5 rounded-full bg-cyber-darker text-gray-400">
                                  Source: {rec.source}
                                </span>
                              </div>
                            </div>
                          </div>
                          <div className="flex gap-2">
                            <Button
                              variant={rec.implemented ? "default" : "outline"}
                              size="sm"
                              className="text-xs h-7"
                              onClick={() => toggleRecommendation(rec.id)}
                            >
                              {rec.implemented ? "Implemented" : "Mark Complete"}
                            </Button>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
            
            <AdvancedChart
              title="Recommendations Analysis"
              description="Distribution of AI recommendations by category and implementation status"
              data={[
                { category: "Detection", completed: 2, pending: 3 },
                { category: "Prevention", completed: 1, pending: 1 },
                { category: "Response", completed: 1, pending: 1 },
                { category: "Configuration", completed: 0, pending: 2 },
                { category: "Monitoring", completed: 1, pending: 0 },
              ]}
              xAxisKey="category"
              series={[
                { name: "Completed", dataKey: "completed", color: "#10B981" },
                { name: "Pending", dataKey: "pending", color: "#F59E0B" },
              ]}
              type="bar"
              stacked={true}
            />
          </TabsContent>
          
          {/* Settings Tab */}
          <TabsContent value="settings" className="mt-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="md:col-span-2">
                <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden mb-6">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg font-medium text-white">AI Analysis Configuration</CardTitle>
                    <CardDescription className="text-gray-400">
                      Configure how AI models analyze your security data
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-6">
                      <div className="space-y-2">
                        <label className="text-sm text-gray-400">Analysis Frequency</label>
                        <select className="w-full px-3 py-2 bg-cyber-darker border border-cyber-gray text-white rounded-md focus:outline-none focus:ring-1 focus:ring-cyber-accent">
                          <option value="0">Manual analysis only</option>
                          <option value="15">Every 15 minutes</option>
                          <option value="30">Every 30 minutes</option>
                          <option value="60" selected>Every hour</option>
                          <option value="360">Every 6 hours</option>
                          <option value="720">Every 12 hours</option>
                          <option value="1440">Every 24 hours</option>
                        </select>
                      </div>
                      
                      <div className="space-y-2">
                        <label className="text-sm text-gray-400">Data Sources to Include</label>
                        <div className="space-y-2">
                          <div className="flex items-center">
                            <input 
                              type="checkbox" 
                              id="src-wazuh" 
                              checked
                              className="mr-2 rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                            />
                            <label htmlFor="src-wazuh" className="text-white">Wazuh Logs</label>
                          </div>
                          <div className="flex items-center">
                            <input 
                              type="checkbox" 
                              id="src-elasticsearch" 
                              checked
                              className="mr-2 rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                            />
                            <label htmlFor="src-elasticsearch" className="text-white">Elasticsearch Data</label>
                          </div>
                          <div className="flex items-center">
                            <input 
                              type="checkbox" 
                              id="src-snort" 
                              checked
                              className="mr-2 rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                            />
                            <label htmlFor="src-snort" className="text-white">Snort/Suricata Alerts</label>
                          </div>
                          <div className="flex items-center">
                            <input 
                              type="checkbox" 
                              id="src-opensearch" 
                              checked
                              className="mr-2 rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                            />
                            <label htmlFor="src-opensearch" className="text-white">Opensearch Data</label>
                          </div>
                          <div className="flex items-center">
                            <input 
                              type="checkbox" 
                              id="src-threat-intel" 
                              checked
                              className="mr-2 rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                            />
                            <label htmlFor="src-threat-intel" className="text-white">Threat Intelligence</label>
                          </div>
                        </div>
                      </div>
                      
                      <div className="space-y-2">
                        <label className="text-sm text-gray-400">Time Range for Analysis</label>
                        <select className="w-full px-3 py-2 bg-cyber-darker border border-cyber-gray text-white rounded-md focus:outline-none focus:ring-1 focus:ring-cyber-accent">
                          <option value="1">Last hour</option>
                          <option value="6">Last 6 hours</option>
                          <option value="24" selected>Last 24 hours</option>
                          <option value="72">Last 3 days</option>
                          <option value="168">Last 7 days</option>
                          <option value="720">Last 30 days</option>
                        </select>
                      </div>
                      
                      <div className="space-y-2">
                        <label className="text-sm text-gray-400">Analysis Priority</label>
                        <div className="space-y-3">
                          <div className="flex items-center justify-between">
                            <span className="text-white">Detection Enhancement</span>
                            <select className="bg-cyber-darker border border-cyber-gray text-white rounded-md focus:outline-none focus:ring-1 focus:ring-cyber-accent px-2 py-1">
                              <option value="1">Low</option>
                              <option value="2">Medium</option>
                              <option value="3" selected>High</option>
                            </select>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-white">Performance Optimization</span>
                            <select className="bg-cyber-darker border border-cyber-gray text-white rounded-md focus:outline-none focus:ring-1 focus:ring-cyber-accent px-2 py-1">
                              <option value="1">Low</option>
                              <option value="2" selected>Medium</option>
                              <option value="3">High</option>
                            </select>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-white">Compliance Analysis</span>
                            <select className="bg-cyber-darker border border-cyber-gray text-white rounded-md focus:outline-none focus:ring-1 focus:ring-cyber-accent px-2 py-1">
                              <option value="1">Low</option>
                              <option value="2" selected>Medium</option>
                              <option value="3">High</option>
                            </select>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-white">Threat Hunting</span>
                            <select className="bg-cyber-darker border border-cyber-gray text-white rounded-md focus:outline-none focus:ring-1 focus:ring-cyber-accent px-2 py-1">
                              <option value="1">Low</option>
                              <option value="2">Medium</option>
                              <option value="3" selected>High</option>
                            </select>
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex justify-end mt-6">
                      <Button className="px-4 py-2 bg-cyber-accent text-white rounded-md hover:bg-cyber-accent/90 transition">
                        Save Settings
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>
              
              <div>
                <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden mb-6">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg font-medium text-white">AI Models</CardTitle>
                    <CardDescription className="text-gray-400">
                      Select which AI models to use
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <input 
                            type="checkbox" 
                            id="model-gpt" 
                            checked
                            className="rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                          />
                          <label htmlFor="model-gpt" className="text-white">GPT-4</label>
                        </div>
                        <Badge className="bg-cyber-success">Connected</Badge>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <input 
                            type="checkbox" 
                            id="model-claude" 
                            checked
                            className="rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                          />
                          <label htmlFor="model-claude" className="text-white">Claude 3.7 Sonnet</label>
                        </div>
                        <Badge className="bg-cyber-success">Connected</Badge>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <input 
                            type="checkbox" 
                            id="model-gemini" 
                            checked
                            className="rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                          />
                          <label htmlFor="model-gemini" className="text-white">Gemini 2.5 Pro</label>
                        </div>
                        <Badge className="bg-cyber-success">Connected</Badge>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <input 
                            type="checkbox" 
                            id="model-sec-copilot" 
                            className="rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                          />
                          <label htmlFor="model-sec-copilot" className="text-white">Security Copilot</label>
                        </div>
                        <Badge variant="outline">Not Configured</Badge>
                      </div>
                    </div>
                    
                    <div className="mt-6 pt-6 border-t border-cyber-gray">
                      <h4 className="text-sm font-medium text-white mb-4">AI Engine Settings</h4>
                      
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-white">Use Streaming Responses</span>
                          <div className="relative inline-flex h-6 w-11 items-center rounded-full bg-cyber-gray">
                            <input type="checkbox" className="peer sr-only" id="streaming" checked />
                            <span className="absolute inset-y-0 start-0 m-1 h-4 w-4 rounded-full bg-white transition-all peer-checked:start-5 peer-checked:bg-cyber-accent"></span>
                          </div>
                        </div>
                        
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-white">Cache Responses</span>
                          <div className="relative inline-flex h-6 w-11 items-center rounded-full bg-cyber-gray">
                            <input type="checkbox" className="peer sr-only" id="cache" checked />
                            <span className="absolute inset-y-0 start-0 m-1 h-4 w-4 rounded-full bg-white transition-all peer-checked:start-5 peer-checked:bg-cyber-accent"></span>
                          </div>
                        </div>
                        
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-white">Parallel Processing</span>
                          <div className="relative inline-flex h-6 w-11 items-center rounded-full bg-cyber-gray">
                            <input type="checkbox" className="peer sr-only" id="parallel" checked />
                            <span className="absolute inset-y-0 start-0 m-1 h-4 w-4 rounded-full bg-white transition-all peer-checked:start-5 peer-checked:bg-cyber-accent"></span>
                          </div>
                        </div>
                        
                        <div className="flex items-center justify-between">
                          <span className="text-sm text-white">Auto-apply Recommendations</span>
                          <div className="relative inline-flex h-6 w-11 items-center rounded-full bg-cyber-gray">
                            <input type="checkbox" className="peer sr-only" id="auto-apply" />
                            <span className="absolute inset-y-0 start-0 m-1 h-4 w-4 rounded-full bg-white transition-all peer-checked:start-5 peer-checked:bg-cyber-accent"></span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                
                <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg font-medium text-white">Notification Settings</CardTitle>
                    <CardDescription className="text-gray-400">
                      Configure AI insight notifications
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-white">Critical Insights</span>
                        <div className="relative inline-flex h-6 w-11 items-center rounded-full bg-cyber-gray">
                          <input type="checkbox" className="peer sr-only" id="notify-critical" checked />
                          <span className="absolute inset-y-0 start-0 m-1 h-4 w-4 rounded-full bg-white transition-all peer-checked:start-5 peer-checked:bg-cyber-accent"></span>
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-white">New Recommendations</span>
                        <div className="relative inline-flex h-6 w-11 items-center rounded-full bg-cyber-gray">
                          <input type="checkbox" className="peer sr-only" id="notify-recommendations" checked />
                          <span className="absolute inset-y-0 start-0 m-1 h-4 w-4 rounded-full bg-white transition-all peer-checked:start-5 peer-checked:bg-cyber-accent"></span>
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-white">Analysis Completed</span>
                        <div className="relative inline-flex h-6 w-11 items-center rounded-full bg-cyber-gray">
                          <input type="checkbox" className="peer sr-only" id="notify-analysis" />
                          <span className="absolute inset-y-0 start-0 m-1 h-4 w-4 rounded-full bg-white transition-all peer-checked:start-5 peer-checked:bg-cyber-accent"></span>
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-white">Configuration Changes</span>
                        <div className="relative inline-flex h-6 w-11 items-center rounded-full bg-cyber-gray">
                          <input type="checkbox" className="peer sr-only" id="notify-config" />
                          <span className="absolute inset-y-0 start-0 m-1 h-4 w-4 rounded-full bg-white transition-all peer-checked:start-5 peer-checked:bg-cyber-accent"></span>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
};

export default AiInsights;
