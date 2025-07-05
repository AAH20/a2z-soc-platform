import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Brain, RefreshCw, Zap, Settings, CheckCircle2, Shield, Code, AlertTriangle, CheckCircle, Target } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import ModelInterface from '@/components/ai/ModelInterface';
import CodeSecurityAnalyzer from '@/components/ai/CodeSecurityAnalyzer';
import ManusInterface from '@/components/ai/ManusInterface';
import { modelConfigurations, securityPrompts, runModelAnalysis, saveModelConfiguration } from '@/services/aiService';
import { apiService } from '@/services/api';

interface Recommendation {
  id: number;
  category: string;
  title: string;
  priority: string;
  source: string;
  implemented: boolean;
  status?: string;
  created_at?: string;
}

const AiInsights: React.FC = () => {
  const [activeTab, setActiveTab] = useState("insights");
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showCodeAnalyzer, setShowCodeAnalyzer] = useState(false);
  const [showManusInterface, setShowManusInterface] = useState(false);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();
  
  const fetchRecommendations = async () => {
    try {
      setIsLoading(true);
      const response = await apiService.get('/api/security-recommendations');
      if (response.data?.success) {
        const dbRecommendations = response.data.data.map((rec: any) => ({
          id: rec.id,
          category: rec.category || 'General',
          title: rec.title,
          priority: rec.priority,
          source: rec.source || 'AI Analysis',
          implemented: rec.status === 'implemented',
          status: rec.status,
          created_at: rec.created_at
        }));
        setRecommendations(dbRecommendations);
      }
    } catch (error) {
      console.error('Failed to fetch recommendations:', error);
      toast({
        title: "Failed to load recommendations",
        description: "Using cached data",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };
  
  const refreshData = async () => {
    setIsRefreshing(true);
    try {
      await fetchRecommendations();
      toast({
        title: "Data refreshed",
        description: "AI insights have been updated successfully",
      });
    } catch (error) {
      toast({
        title: "Refresh failed",
        description: "Could not update AI insights",
        variant: "destructive",
      });
    } finally {
      setIsRefreshing(false);
    }
  };

  const toggleRecommendation = async (id: number) => {
    try {
      const recommendation = recommendations.find(rec => rec.id === id);
      if (!recommendation) return;

      const newStatus = recommendation.implemented ? 'pending' : 'implemented';
      
      const response = await apiService.patch(`/api/security-recommendations/${id}`, {
        status: newStatus
      });

      if (response.data?.success) {
        setRecommendations(prev => 
          prev.map(rec => rec.id === id ? { ...rec, implemented: !rec.implemented, status: newStatus } : rec)
        );
        toast({
          title: "Status updated",
          description: "Recommendation status has been updated.",
        });
      }
    } catch (error) {
      console.error('Failed to update recommendation:', error);
      toast({
        title: "Update failed",
        description: "Could not update recommendation status",
        variant: "destructive",
      });
    }
  };

  useEffect(() => {
    fetchRecommendations();
  }, []);

  return (
    <div className="space-y-6 bg-slate-900 min-h-screen p-6">
      <div className="flex items-center gap-2">
        <Brain className="h-6 w-6 text-blue-400" />
        <h1 className="text-2xl font-bold text-white">AI Security Insights</h1>
      </div>
      
      <p className="text-slate-400 mb-4">
        Advanced AI-powered threat detection and security analysis for comprehensive protection.
      </p>
      
      <Tabs defaultValue="insights" className="w-full">
        <TabsList className="mb-4 w-full flex flex-wrap justify-start gap-2 bg-slate-800 border-slate-700">
          <TabsTrigger 
            value="insights" 
            className="data-[state=active]:bg-blue-600 data-[state=active]:text-white text-slate-300"
          >
            <Brain className="h-4 w-4 mr-2" />
            AI Insights
          </TabsTrigger>
          <TabsTrigger 
            value="threats" 
            className="data-[state=active]:bg-blue-600 data-[state=active]:text-white text-slate-300"
          >
            <AlertTriangle className="h-4 w-4 mr-2" />
            Threat Analysis
          </TabsTrigger>
          <TabsTrigger 
            value="recommendations" 
            className="data-[state=active]:bg-blue-600 data-[state=active]:text-white text-slate-300"
          >
            <Target className="h-4 w-4 mr-2" />
            Recommendations
          </TabsTrigger>
          <TabsTrigger 
            value="settings" 
            className="data-[state=active]:bg-blue-600 data-[state=active]:text-white text-slate-300"
          >
            <Settings className="h-4 w-4 mr-2" />
            AI Settings
          </TabsTrigger>
          <TabsTrigger 
            value="code-security" 
            className="data-[state=active]:bg-blue-600 data-[state=active]:text-white text-slate-300"
          >
            <Code className="h-4 w-4 mr-2" />
            Code Security
          </TabsTrigger>
        </TabsList>
        
        {/* AI Insights Tab */}
        <TabsContent value="insights" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <Card className="bg-slate-800 border-slate-700 overflow-hidden">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg font-medium text-white">AI Processing Status</CardTitle>
                <CardDescription className="text-slate-400">
                  Current status of AI analysis engines
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse"></div>
                      <span className="text-sm text-white">GPT-4 Analysis</span>
                    </div>
                    <span className="text-xs text-slate-400">Last run: 15 mins ago</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse"></div>
                      <span className="text-sm text-white">Claude Analysis</span>
                    </div>
                    <span className="text-xs text-slate-400">Last run: 32 mins ago</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 bg-yellow-500 rounded-full"></div>
                      <span className="text-sm text-white">Gemini Analysis</span>
                    </div>
                    <span className="text-xs text-slate-400">Last run: 2 hours ago</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-2 bg-red-500 rounded-full"></div>
                      <span className="text-sm text-white">Security Copilot</span>
                    </div>
                    <span className="text-xs text-slate-400">Not configured</span>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-slate-800 border-slate-700 overflow-hidden">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg font-medium text-white">Log Processing</CardTitle>
                <CardDescription className="text-slate-400">
                  Status of AI log processing by source
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="space-y-1">
                    <div className="flex justify-between">
                      <span className="text-sm text-white">Wazuh Logs</span>
                      <span className="text-xs text-green-500">Processed</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-700 rounded-full overflow-hidden">
                      <div className="h-full bg-green-500" style={{ width: '100%' }}></div>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between">
                      <span className="text-sm text-white">Elasticsearch</span>
                      <span className="text-xs text-green-500">Processed</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-700 rounded-full overflow-hidden">
                      <div className="h-full bg-green-500" style={{ width: '100%' }}></div>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between">
                      <span className="text-sm text-white">Snort/Suricata</span>
                      <span className="text-xs text-green-500">Processed</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-700 rounded-full overflow-hidden">
                      <div className="h-full bg-green-500" style={{ width: '100%' }}></div>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between">
                      <span className="text-sm text-white">Opensearch</span>
                      <span className="text-xs text-blue-500">In Progress</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-700 rounded-full overflow-hidden">
                      <div className="h-full bg-blue-500" style={{ width: '65%' }}></div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-slate-800 border-slate-700 overflow-hidden">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg font-medium text-white">AI Recommendations</CardTitle>
                <CardDescription className="text-slate-400">
                  Quick stats on security recommendations
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-white">Total Recommendations</span>
                    <span className="text-lg font-bold text-white">{recommendations.length}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-white">Implemented</span>
                    <span className="text-lg font-bold text-green-500">
                      {recommendations.filter(r => r.implemented).length}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-white">High Priority</span>
                    <span className="text-lg font-bold text-red-500">
                      {recommendations.filter(r => r.priority === 'high').length}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-white">Implementation Rate</span>
                    <span className="text-lg font-bold text-blue-500">
                      {Math.round((recommendations.filter(r => r.implemented).length / recommendations.length) * 100)}%
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Manus AI Tab */}
        <TabsContent value="manus" className="mt-4">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h2 className="text-xl font-semibold text-white">Manus AI Console</h2>
              <p className="text-slate-400">Autonomous security agent for advanced threat analysis and response</p>
            </div>
            <Button
              onClick={() => setShowManusInterface(true)}
              className="bg-blue-600 hover:bg-blue-700 flex items-center gap-2"
            >
              <Shield className="h-4 w-4" />
              Open Manus Console
            </Button>
          </div>
          
          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <div className="text-center py-8">
                <Shield className="h-16 w-16 text-blue-500 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-white mb-2">Manus AI Integration</h3>
                <p className="text-slate-400 mb-4">
                  Autonomous security agent with multi-modal capabilities for real-time threat analysis
                </p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                  <div className="bg-slate-700 p-4 rounded-lg">
                    <h4 className="text-white font-medium mb-2">Autonomous Analysis</h4>
                    <p className="text-sm text-slate-400">Continuous monitoring and threat detection</p>
                  </div>
                  <div className="bg-slate-700 p-4 rounded-lg">
                    <h4 className="text-white font-medium mb-2">Incident Response</h4>
                    <p className="text-sm text-slate-400">Automated response to security incidents</p>
                  </div>
                  <div className="bg-slate-700 p-4 rounded-lg">
                    <h4 className="text-white font-medium mb-2">Task Management</h4>
                    <p className="text-sm text-slate-400">Orchestrate security operations tasks</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Models Tab */}
        <TabsContent value="models" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {Object.values(modelConfigurations).map((model) => (
              <ModelInterface
                key={model.type}
                model={model}
                onSaveConfig={saveModelConfiguration}
                onRunAnalysis={runModelAnalysis}
                presetPrompts={securityPrompts.general}
              />
            ))}
          </div>
        </TabsContent>

        {/* Recommendations Tab */}
        <TabsContent value="recommendations" className="mt-4">
          <div className="space-y-4">
            {recommendations.map((rec) => (
              <Card key={rec.id} className="bg-slate-800 border-slate-700">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge variant={rec.priority === 'high' ? 'destructive' : rec.priority === 'medium' ? 'default' : 'secondary'}>
                          {rec.priority.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="border-slate-600 text-slate-300">{rec.category}</Badge>
                        <Badge variant="outline" className="border-slate-600 text-slate-300">{rec.source}</Badge>
                      </div>
                      <h3 className="text-white font-medium mb-1">{rec.title}</h3>
                    </div>
                    <div className="flex items-center gap-2">
                      {rec.implemented ? (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      ) : (
                        <AlertTriangle className="h-5 w-5 text-yellow-500" />
                      )}
                      <Button
                        size="sm"
                        variant="outline"
                        className="border-slate-600 text-slate-300 hover:bg-slate-700"
                        onClick={() => toggleRecommendation(rec.id)}
                      >
                        {rec.implemented ? 'Mark as Not Implemented' : 'Mark as Implemented'}
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* Settings Tab */}
        <TabsContent value="settings" className="mt-4">
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white">AI Configuration</CardTitle>
              <CardDescription className="text-slate-400">
                Configure AI models and analysis parameters
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div>
                  <h4 className="text-sm font-medium text-white mb-4">Enabled AI Models</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          id="model-gpt"
                          defaultChecked
                          className="rounded border-slate-600 text-blue-500 focus:ring-blue-500 bg-slate-700"
                        />
                        <label htmlFor="model-gpt" className="text-white">GPT-4</label>
                      </div>
                      <Badge variant="outline" className="border-green-500 text-green-500">Connected</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          id="model-claude"
                          defaultChecked
                          className="rounded border-slate-600 text-blue-500 focus:ring-blue-500 bg-slate-700"
                        />
                        <label htmlFor="model-claude" className="text-white">Claude</label>
                      </div>
                      <Badge variant="outline" className="border-green-500 text-green-500">Connected</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          id="model-gemini"
                          defaultChecked
                          className="rounded border-slate-600 text-blue-500 focus:ring-blue-500 bg-slate-700"
                        />
                        <label htmlFor="model-gemini" className="text-white">Gemini</label>
                      </div>
                      <Badge variant="outline" className="border-green-500 text-green-500">Connected</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          id="model-sec-copilot"
                          className="rounded border-slate-600 text-blue-500 focus:ring-blue-500 bg-slate-700"
                        />
                        <label htmlFor="model-sec-copilot" className="text-white">Security Copilot</label>
                      </div>
                      <Badge variant="outline" className="border-slate-600 text-slate-400">Not Configured</Badge>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Code Security Tab */}
        <TabsContent value="code-security" className="mt-4">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h2 className="text-xl font-semibold text-white">Code Security Analysis</h2>
              <p className="text-slate-400">AI-powered security vulnerability detection for your code</p>
            </div>
            <Button
              onClick={() => setShowCodeAnalyzer(true)}
              className="bg-blue-600 hover:bg-blue-700 flex items-center gap-2"
            >
              <Code className="h-4 w-4" />
              Open Code Analyzer
            </Button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardContent className="p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="flex items-center justify-center w-12 h-12 bg-blue-500/20 rounded-lg">
                    <Shield className="h-6 w-6 text-blue-400" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">JavaScript</h3>
                    <p className="text-sm text-slate-400">Node.js & React</p>
                  </div>
                </div>
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Last Scan</span>
                    <span className="text-white">2 hours ago</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Vulnerabilities</span>
                    <span className="text-red-400 font-medium">3 High, 5 Medium</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Security Score</span>
                    <span className="text-yellow-400 font-medium">72/100</span>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-slate-800 border-slate-700">
              <CardContent className="p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="flex items-center justify-center w-12 h-12 bg-green-500/20 rounded-lg">
                    <Shield className="h-6 w-6 text-green-400" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">Python</h3>
                    <p className="text-sm text-slate-400">Flask & Django</p>
                  </div>
                </div>
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Last Scan</span>
                    <span className="text-white">1 day ago</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Vulnerabilities</span>
                    <span className="text-blue-400 font-medium">1 Medium, 2 Low</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Security Score</span>
                    <span className="text-green-400 font-medium">89/100</span>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-slate-800 border-slate-700">
              <CardContent className="p-6">
                <div className="flex items-center gap-3 mb-4">
                  <div className="flex items-center justify-center w-12 h-12 bg-orange-500/20 rounded-lg">
                    <Shield className="h-6 w-6 text-orange-400" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold text-white">Java</h3>
                    <p className="text-sm text-slate-400">Spring Boot</p>
                  </div>
                </div>
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Last Scan</span>
                    <span className="text-white">3 days ago</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Vulnerabilities</span>
                    <span className="text-red-400 font-medium">2 Critical, 4 High</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-slate-400">Security Score</span>
                    <span className="text-red-400 font-medium">45/100</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
      
      {showCodeAnalyzer && (
        <CodeSecurityAnalyzer onClose={() => setShowCodeAnalyzer(false)} />
      )}
      
      {showManusInterface && (
        <ManusInterface onClose={() => setShowManusInterface(false)} />
      )}
    </div>
  );
};

export default AiInsights; 