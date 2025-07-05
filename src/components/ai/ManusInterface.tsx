import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
import { Progress } from '../ui/progress';
import { Alert, AlertDescription } from '../ui/alert';
import { Textarea } from '../ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { 
  Brain, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Clock, 
  Play, 
  Pause, 
  RefreshCw,
  Download,
  Eye,
  Bot,
  Zap,
  Target,
  Activity
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { manusService, ManusTask, ManusSecurityAnalysisRequest, ManusSecurityAnalysisResult, ManusIncidentResponse } from '@/services/manusService';

interface ManusInterfaceProps {
  onClose?: () => void;
}

const ManusInterface: React.FC<ManusInterfaceProps> = ({ onClose }) => {
  const [isInitialized, setIsInitialized] = useState(false);
  const [activeTasks, setActiveTasks] = useState<ManusTask[]>([]);
  const [selectedTask, setSelectedTask] = useState<ManusTask | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [analysisRequest, setAnalysisRequest] = useState<ManusSecurityAnalysisRequest>({
    severity: 'medium',
    focusAreas: ['threat-detection']
  });
  const { toast } = useToast();

  useEffect(() => {
    initializeManus();
    setupEventListeners();
    
    return () => {
      // Cleanup event listeners
      window.removeEventListener('manus-progress', handleProgress);
      window.removeEventListener('manus-completed', handleCompletion);
    };
  }, []);

  const initializeManus = async () => {
    setIsLoading(true);
    try {
      const initialized = await manusService.initialize();
      setIsInitialized(initialized);
      
      if (initialized) {
        const tasks = await manusService.getActiveTasks();
        setActiveTasks(tasks);
        
        // Start autonomous monitoring
        await manusService.startAutonomousMonitoring();
        
        toast({
          title: "Manus AI Initialized",
          description: "Autonomous security agent is now active and monitoring your environment.",
        });
      } else {
        toast({
          title: "Initialization Failed",
          description: "Could not connect to Manus AI. Please check your configuration.",
          variant: "destructive"
        });
      }
    } catch (error) {
      console.error('Failed to initialize Manus:', error);
      toast({
        title: "Connection Error",
        description: "Failed to connect to Manus AI service.",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const setupEventListeners = () => {
    window.addEventListener('manus-progress', handleProgress);
    window.addEventListener('manus-completed', handleCompletion);
  };

  const handleProgress = (event: any) => {
    const { taskId, progress } = event.detail;
    setActiveTasks(prev => prev.map(task => 
      task.id === taskId ? { ...task, progress } : task
    ));
  };

  const handleCompletion = (event: any) => {
    const { taskId, results } = event.detail;
    setActiveTasks(prev => prev.map(task => 
      task.id === taskId ? { ...task, status: 'completed', results, progress: 100 } : task
    ));
    
    toast({
      title: "Analysis Complete",
      description: "Manus has finished autonomous security analysis.",
    });
  };

  const startSecurityAnalysis = async () => {
    if (!isInitialized) {
      toast({
        title: "Not Initialized",
        description: "Manus AI is not initialized. Please try again.",
        variant: "destructive"
      });
      return;
    }

    try {
      setIsLoading(true);
      const taskId = await manusService.createSecurityAnalysisTask(analysisRequest);
      
      const newTask = await manusService.getTaskStatus(taskId);
      if (newTask) {
        setActiveTasks(prev => [...prev, newTask]);
      }
      
      toast({
        title: "Analysis Started",
        description: "Manus is autonomously analyzing your security environment.",
      });
    } catch (error) {
      console.error('Failed to start analysis:', error);
      toast({
        title: "Analysis Failed",
        description: "Could not start security analysis.",
        variant: "destructive"
      });
    } finally {
      setIsLoading(false);
    }
  };

  const startIncidentResponse = async (incidentId: string, incidentType: string) => {
    try {
      const taskId = await manusService.createIncidentResponseTask(incidentId, incidentType);
      
      const newTask = await manusService.getTaskStatus(taskId);
      if (newTask) {
        setActiveTasks(prev => [...prev, newTask]);
      }
      
      toast({
        title: "Incident Response Initiated",
        description: "Manus is autonomously handling the incident response.",
      });
    } catch (error) {
      console.error('Failed to start incident response:', error);
      toast({
        title: "Response Failed",
        description: "Could not initiate incident response.",
        variant: "destructive"
      });
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending': return <Clock className="h-4 w-4 text-yellow-400" />;
      case 'in-progress': return <Activity className="h-4 w-4 text-blue-400" />;
      case 'completed': return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'failed': return <XCircle className="h-4 w-4 text-red-400" />;
      default: return <Clock className="h-4 w-4 text-gray-400" />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'security-analysis': return <Shield className="h-4 w-4" />;
      case 'threat-investigation': return <Target className="h-4 w-4" />;
      case 'incident-response': return <AlertTriangle className="h-4 w-4" />;
      case 'compliance-audit': return <CheckCircle className="h-4 w-4" />;
      case 'vulnerability-assessment': return <Eye className="h-4 w-4" />;
      default: return <Brain className="h-4 w-4" />;
    }
  };

  const renderTaskResults = (task: ManusTask) => {
    if (!task.results) return null;

    if (task.type === 'security-analysis') {
      const results = task.results as ManusSecurityAnalysisResult;
      return (
        <div className="space-y-4">
          <Alert className="border-cyber-lightgray bg-cyber-darker">
            <Brain className="h-4 w-4" />
            <AlertDescription className="text-white">
              <strong>Analysis Summary:</strong> {results.summary}
            </AlertDescription>
          </Alert>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-cyber-darker border-cyber-lightgray">
              <CardHeader className="pb-3">
                <CardTitle className="text-white text-sm">Threats Identified</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {results.threats.map((threat, index) => (
                  <div key={index} className="p-3 bg-cyber-gray rounded-md">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-white font-medium">{threat.type}</span>
                      <Badge className={`${
                        threat.severity === 'critical' ? 'bg-red-600' :
                        threat.severity === 'high' ? 'bg-orange-600' :
                        threat.severity === 'medium' ? 'bg-yellow-600' : 'bg-blue-600'
                      } text-white`}>
                        {threat.severity.toUpperCase()}
                      </Badge>
                    </div>
                    <p className="text-sm text-gray-300 mb-2">{threat.description}</p>
                    <div className="text-xs text-gray-400">
                      Confidence: {Math.round(threat.confidence * 100)}%
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card className="bg-cyber-darker border-cyber-lightgray">
              <CardHeader className="pb-3">
                <CardTitle className="text-white text-sm">Recommendations</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {results.recommendations.map((rec, index) => (
                  <div key={index} className="p-3 bg-cyber-gray rounded-md">
                    <div className="flex items-center gap-2 mb-2">
                      <Badge className={`${
                        rec.priority === 'immediate' ? 'bg-red-600' :
                        rec.priority === 'short-term' ? 'bg-orange-600' : 'bg-blue-600'
                      } text-white`}>
                        {rec.priority}
                      </Badge>
                    </div>
                    <p className="text-sm text-white">{rec.action}</p>
                    <p className="text-xs text-gray-400 mt-1">{rec.rationale}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {results.detailedReport && (
            <Card className="bg-cyber-darker border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-white">Detailed Analysis Report</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <h4 className="text-white font-medium mb-2">Executive Summary</h4>
                  <p className="text-gray-300 text-sm">{results.detailedReport.executiveSummary}</p>
                </div>
                
                <div>
                  <h4 className="text-white font-medium mb-2">Technical Findings</h4>
                  <p className="text-gray-300 text-sm">{results.detailedReport.technicalFindings}</p>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-2">Attack Timeline</h4>
                  <div className="space-y-2">
                    {results.detailedReport.timeline.map((event, index) => (
                      <div key={index} className="flex items-start gap-3 p-2 bg-cyber-gray rounded">
                        <div className="text-xs text-gray-400 min-w-0 flex-shrink-0">
                          {new Date(event.timestamp).toLocaleString()}
                        </div>
                        <div className="flex-1">
                          <div className="text-sm text-white">{event.event}</div>
                          <div className="text-xs text-gray-400">Source: {event.source}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      );
    }

    if (task.type === 'incident-response') {
      const results = task.results as ManusIncidentResponse;
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-cyber-darker border-cyber-lightgray">
              <CardHeader className="pb-3">
                <CardTitle className="text-white text-sm">Containment Actions</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2">
                  {results.containmentActions.map((action, index) => (
                    <li key={index} className="flex items-start gap-2">
                      <CheckCircle className="h-4 w-4 text-green-400 mt-0.5 flex-shrink-0" />
                      <span className="text-sm text-gray-300">{action}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-cyber-darker border-cyber-lightgray">
              <CardHeader className="pb-3">
                <CardTitle className="text-white text-sm">Investigation Steps</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-2">
                  {results.investigationSteps.map((step, index) => (
                    <li key={index} className="flex items-start gap-2">
                      <Eye className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
                      <span className="text-sm text-gray-300">{step}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          </div>

          <Card className="bg-cyber-darker border-cyber-lightgray">
            <CardHeader className="pb-3">
              <CardTitle className="text-white text-sm">Indicators of Compromise (IoCs)</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {results.iocList.map((ioc, index) => (
                  <div key={index} className="p-2 bg-cyber-gray rounded font-mono text-sm text-orange-400">
                    {ioc}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      );
    }

    return null;
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <Card className="w-full max-w-6xl h-[90vh] bg-cyber-gray border-cyber-lightgray overflow-hidden">
        <CardHeader className="border-b border-cyber-lightgray">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-10 h-10 bg-gradient-to-r from-purple-500 to-blue-500 rounded-lg">
                <Bot className="h-6 w-6 text-white" />
              </div>
              <div>
                <CardTitle className="text-xl text-white">Manus AI - Autonomous Security Agent</CardTitle>
                <p className="text-sm text-gray-400">Advanced AI-powered security operations and incident response</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge className={`${isInitialized ? 'bg-green-600' : 'bg-red-600'} text-white`}>
                {isInitialized ? 'Connected' : 'Disconnected'}
              </Badge>
              {onClose && (
                <Button variant="outline" onClick={onClose} className="text-white">
                  Close
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
        
        <CardContent className="p-6 h-full overflow-hidden">
          <Tabs defaultValue="dashboard" className="h-full">
            <TabsList className="grid w-full grid-cols-4 mb-6">
              <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
              <TabsTrigger value="analysis">Security Analysis</TabsTrigger>
              <TabsTrigger value="incident">Incident Response</TabsTrigger>
              <TabsTrigger value="tasks">Task Manager</TabsTrigger>
            </TabsList>
            
            <TabsContent value="dashboard" className="h-full overflow-auto">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <Card className="bg-cyber-darker border-cyber-lightgray">
                  <CardContent className="p-6">
                    <div className="flex items-center gap-3">
                      <Activity className="h-8 w-8 text-blue-400" />
                      <div>
                        <div className="text-2xl font-bold text-white">{activeTasks.length}</div>
                        <div className="text-sm text-gray-400">Active Tasks</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                
                <Card className="bg-cyber-darker border-cyber-lightgray">
                  <CardContent className="p-6">
                    <div className="flex items-center gap-3">
                      <Shield className="h-8 w-8 text-green-400" />
                      <div>
                        <div className="text-2xl font-bold text-white">
                          {activeTasks.filter(t => t.status === 'completed').length}
                        </div>
                        <div className="text-sm text-gray-400">Completed</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                
                <Card className="bg-cyber-darker border-cyber-lightgray">
                  <CardContent className="p-6">
                    <div className="flex items-center gap-3">
                      <Zap className="h-8 w-8 text-yellow-400" />
                      <div>
                        <div className="text-2xl font-bold text-white">
                          {isInitialized ? 'Online' : 'Offline'}
                        </div>
                        <div className="text-sm text-gray-400">AI Status</div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              <Card className="bg-cyber-darker border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Recent Autonomous Activities</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {activeTasks.slice(0, 5).map(task => (
                      <div key={task.id} className="flex items-center justify-between p-3 bg-cyber-gray rounded-lg">
                        <div className="flex items-center gap-3">
                          {getTypeIcon(task.type)}
                          <div>
                            <div className="text-white font-medium">{task.description}</div>
                            <div className="text-xs text-gray-400">
                              {new Date(task.createdAt).toLocaleString()}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          {getStatusIcon(task.status)}
                          <Badge className={`${
                            task.priority === 'critical' ? 'bg-red-600' :
                            task.priority === 'high' ? 'bg-orange-600' :
                            task.priority === 'medium' ? 'bg-yellow-600' : 'bg-blue-600'
                          } text-white`}>
                            {task.priority}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
            
            <TabsContent value="analysis" className="h-full overflow-auto">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-full">
                <div>
                  <Card className="bg-cyber-darker border-cyber-lightgray">
                    <CardHeader>
                      <CardTitle className="text-white">Configure Security Analysis</CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div>
                        <label className="text-sm text-gray-400 mb-2 block">Severity Level</label>
                        <Select 
                          value={analysisRequest.severity} 
                          onValueChange={(value) => setAnalysisRequest(prev => ({...prev, severity: value as any}))}
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="info">Info</SelectItem>
                            <SelectItem value="low">Low</SelectItem>
                            <SelectItem value="medium">Medium</SelectItem>
                            <SelectItem value="high">High</SelectItem>
                            <SelectItem value="critical">Critical</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      
                      <div>
                        <label className="text-sm text-gray-400 mb-2 block">Focus Areas</label>
                        <div className="space-y-2">
                          {['threat-detection', 'incident-analysis', 'vulnerability-assessment', 'compliance-check', 'anomaly-detection'].map(area => (
                            <div key={area} className="flex items-center">
                              <input 
                                type="checkbox" 
                                id={area}
                                checked={analysisRequest.focusAreas?.includes(area)}
                                onChange={(e) => {
                                  const areas = analysisRequest.focusAreas || [];
                                  if (e.target.checked) {
                                    setAnalysisRequest(prev => ({
                                      ...prev, 
                                      focusAreas: [...areas, area]
                                    }));
                                  } else {
                                    setAnalysisRequest(prev => ({
                                      ...prev, 
                                      focusAreas: areas.filter(a => a !== area)
                                    }));
                                  }
                                }}
                                className="mr-2 rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                              />
                              <label htmlFor={area} className="text-white capitalize">
                                {area.replace('-', ' ')}
                              </label>
                            </div>
                          ))}
                        </div>
                      </div>
                      
                      <Button 
                        onClick={startSecurityAnalysis}
                        disabled={!isInitialized || isLoading}
                        className="w-full bg-cyber-primary hover:bg-cyber-primary/80"
                      >
                        {isLoading ? (
                          <>
                            <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                            Starting Analysis...
                          </>
                        ) : (
                          <>
                            <Play className="h-4 w-4 mr-2" />
                            Start Autonomous Analysis
                          </>
                        )}
                      </Button>
                    </CardContent>
                  </Card>
                </div>
                
                <div>
                  <Card className="bg-cyber-darker border-cyber-lightgray h-full">
                    <CardHeader>
                      <CardTitle className="text-white">Analysis Results</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {selectedTask ? (
                        renderTaskResults(selectedTask)
                      ) : (
                        <div className="text-center py-8">
                          <Brain className="h-16 w-16 text-gray-500 mx-auto mb-4" />
                          <p className="text-gray-400">No analysis selected. Start a new analysis or select from active tasks.</p>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>
            
            <TabsContent value="incident" className="h-full overflow-auto">
              <Card className="bg-cyber-darker border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Autonomous Incident Response</CardTitle>
                  <p className="text-gray-400">Manus can automatically initiate incident response procedures</p>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Button 
                      onClick={() => startIncidentResponse('INC-001', 'Data Breach')}
                      className="bg-red-600 hover:bg-red-700 text-white p-6 h-auto flex-col gap-2"
                    >
                      <AlertTriangle className="h-8 w-8" />
                      <span>Data Breach Response</span>
                    </Button>
                    
                    <Button 
                      onClick={() => startIncidentResponse('INC-002', 'Malware Infection')}
                      className="bg-orange-600 hover:bg-orange-700 text-white p-6 h-auto flex-col gap-2"
                    >
                      <Shield className="h-8 w-8" />
                      <span>Malware Response</span>
                    </Button>
                    
                    <Button 
                      onClick={() => startIncidentResponse('INC-003', 'DDoS Attack')}
                      className="bg-purple-600 hover:bg-purple-700 text-white p-6 h-auto flex-col gap-2"
                    >
                      <Target className="h-8 w-8" />
                      <span>DDoS Response</span>
                    </Button>
                    
                    <Button 
                      onClick={() => startIncidentResponse('INC-004', 'Insider Threat')}
                      className="bg-yellow-600 hover:bg-yellow-700 text-white p-6 h-auto flex-col gap-2"
                    >
                      <Eye className="h-8 w-8" />
                      <span>Insider Threat Response</span>
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
            
            <TabsContent value="tasks" className="h-full overflow-auto">
              <Card className="bg-cyber-darker border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Active Manus Tasks</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {activeTasks.map(task => (
                      <div 
                        key={task.id} 
                        className={`p-4 bg-cyber-gray rounded-lg border cursor-pointer transition ${
                          selectedTask?.id === task.id ? 'border-cyber-primary' : 'border-cyber-lightgray'
                        }`}
                        onClick={() => setSelectedTask(task)}
                      >
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-3">
                            {getTypeIcon(task.type)}
                            <div>
                              <div className="text-white font-medium">{task.description}</div>
                              <div className="text-xs text-gray-400">ID: {task.id}</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {getStatusIcon(task.status)}
                            <Badge className={`${
                              task.priority === 'critical' ? 'bg-red-600' :
                              task.priority === 'high' ? 'bg-orange-600' :
                              task.priority === 'medium' ? 'bg-yellow-600' : 'bg-blue-600'
                            } text-white`}>
                              {task.priority}
                            </Badge>
                          </div>
                        </div>
                        
                        {task.progress !== undefined && task.status === 'in-progress' && (
                          <div className="mb-3">
                            <Progress value={task.progress} className="h-2" />
                            <div className="text-xs text-gray-400 mt-1">
                              Progress: {Math.round(task.progress)}%
                            </div>
                          </div>
                        )}
                        
                        <div className="flex justify-between text-xs text-gray-400">
                          <span>Created: {new Date(task.createdAt).toLocaleString()}</span>
                          {task.completedAt && (
                            <span>Completed: {new Date(task.completedAt).toLocaleString()}</span>
                          )}
                        </div>
                      </div>
                    ))}
                    
                    {activeTasks.length === 0 && (
                      <div className="text-center py-8">
                        <Bot className="h-16 w-16 text-gray-500 mx-auto mb-4" />
                        <p className="text-gray-400">No active tasks. Manus is ready to assist with security operations.</p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default ManusInterface; 