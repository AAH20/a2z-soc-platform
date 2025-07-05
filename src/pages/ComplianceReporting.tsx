import React, { useState, useEffect } from 'react';
import { 
  Tabs, 
  TabsContent, 
  TabsList, 
  TabsTrigger 
} from '@/components/ui/tabs';
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle,
  CardFooter
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from '@/components/ui/table';
import { 
  FileText, 
  Clock, 
  ClipboardList, 
  FolderArchive,
  Download,
  Calendar,
  SendHorizonal,
  Bell,
  Plus,
  Trash2,
  Edit,
  CheckCircle2,
  Search,
  AlertTriangle,
  Shield,
  Network,
  Server,
  Database,
  Cloud,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Activity
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import { 
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { useAuth } from '@/components/auth/AuthProvider';
import complianceService, { 
  ComplianceAssessment, 
  ComplianceReport, 
  NetworkResource,
  ComplianceFinding,
  ComplianceRecommendation 
} from '@/services/complianceService';
import { apiService } from '@/services/api';

interface ComplianceTemplate {
  id: number;
  name: string;
  description: string;
  framework: string;
  lastGenerated: string;
  sections: string[];
}

interface ScheduledReport {
  id: number;
  name: string;
  template: string;
  frequency: string;
  nextRun: string;
  recipients: string[];
  status: string;
}

interface AuditTrail {
  id: number;
  action: string;
  reportName: string;
  user: string;
  timestamp: string;
  ipAddress: string;
}

interface EvidenceItem {
  id: number;
  name: string;
  description: string;
  relatedControl: string;
  framework: string;
  dateCollected: string;
  collectedBy: string;
  status: string;
}

const ComplianceReporting: React.FC = () => {
  const { toast } = useToast();
  const { user, tenant } = useAuth();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [loading, setLoading] = useState(false);
  const [currentAssessment, setCurrentAssessment] = useState<ComplianceAssessment | null>(null);
  const [networkResources, setNetworkResources] = useState<NetworkResource[]>([]);
  const [selectedFramework, setSelectedFramework] = useState('soc2');
  const [complianceReports, setComplianceReports] = useState<ComplianceReport[]>([]);
  const [complianceTemplates, setComplianceTemplates] = useState<ComplianceTemplate[]>([]);
  const [scheduledReports, setScheduledReports] = useState<ScheduledReport[]>([]);
  const [auditTrails, setAuditTrails] = useState<AuditTrail[]>([]);
  const [evidenceItems, setEvidenceItems] = useState<EvidenceItem[]>([]);
  const [lastRefresh, setLastRefresh] = useState<string>(new Date().toISOString());

  // Available compliance frameworks
  const frameworks = [
    { id: 'soc2', name: 'SOC 2 Type II', description: 'Service Organization Control 2' },
    { id: 'gdpr', name: 'GDPR', description: 'General Data Protection Regulation' },
    { id: 'hipaa', name: 'HIPAA', description: 'Health Insurance Portability and Accountability Act' },
    { id: 'iso27001', name: 'ISO 27001', description: 'Information Security Management' },
    { id: 'pci-dss', name: 'PCI DSS', description: 'Payment Card Industry Data Security Standard' },
  ];

  // Fetch all compliance data from API
  const loadComplianceData = async () => {
    try {
      setLoading(true);
      
      const [templatesRes, reportsRes, auditRes, evidenceRes] = await Promise.all([
        apiService.get('/api/compliance/templates'),
        apiService.get('/api/compliance/scheduled-reports'),
        apiService.get('/api/audit-logs'),
        apiService.get('/api/compliance/evidence')
      ]);
      
      if (templatesRes.data?.success) {
        setComplianceTemplates(templatesRes.data.data);
      }
      
      if (reportsRes.data?.success) {
        setScheduledReports(reportsRes.data.data);
      }
      
      if (auditRes.data?.success) {
        const auditData = auditRes.data.data.map((audit: any) => ({
          id: audit.id,
          action: audit.action,
          reportName: audit.resource_type || 'System',
          user: audit.user_email || audit.user_id,
          timestamp: audit.timestamp,
          ipAddress: audit.ip_address || 'N/A'
        }));
        setAuditTrails(auditData);
      }
      
      if (evidenceRes.data?.success) {
        setEvidenceItems(evidenceRes.data.data);
      }
      
      // Fetch assessment data if framework is selected
      if (selectedFramework) {
        const assessment = await complianceService.runAssessment(selectedFramework);
        setCurrentAssessment(assessment);
        
        if (assessment.resources) {
          setNetworkResources(assessment.resources);
        }
      }
      
      setLastRefresh(new Date().toISOString());
      
    } catch (error) {
      console.error('Failed to load compliance data:', error);
      toast({
        title: "Failed to load compliance data",
        description: "Using cached data where available",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadComplianceData();
  }, [selectedFramework]);

  const generateReport = async (frameworkId: string, reportName?: string) => {
    if (!tenant?.id) return;

    setLoading(true);
    try {
      const report = await complianceService.generateComplianceReport(
        tenant.id, 
        frameworkId, 
        reportName || `${frameworks.find(f => f.id === frameworkId)?.name} Compliance Report`
      );
      
      setComplianceReports(prev => [report, ...prev]);
      
      toast({
        title: "Report Generated Successfully",
        description: `${report.reportName} has been generated and is ready for download.`,
      });
    } catch (error) {
      console.error('Error generating report:', error);
      toast({
        title: "Report Generation Failed",
        description: "There was an error generating the compliance report.",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async (reportId: string) => {
    try {
      // In a real implementation, this would generate and download the actual report
      const report = complianceReports.find(r => r.id === reportId);
      if (report) {
        const reportData = JSON.stringify(report, null, 2);
        const blob = new Blob([reportData], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${report.reportName.replace(/\s+/g, '_')}_${report.generatedAt.split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        toast({
          title: "Report Downloaded",
          description: "The compliance report has been downloaded successfully.",
        });
      }
    } catch (error) {
      toast({
        title: "Download Failed",
        description: "There was an error downloading the report.",
        variant: "destructive",
      });
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'compliant':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'partially-compliant':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'non-compliant':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'pass':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'fail':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'not-applicable':
        return 'bg-gray-100 text-gray-800 border-gray-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <AlertTriangle className="h-4 w-4 text-red-600" />;
      case 'high':
        return <AlertTriangle className="h-4 w-4 text-orange-600" />;
      case 'medium':
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />;
      case 'low':
        return <AlertTriangle className="h-4 w-4 text-blue-600" />;
      default:
        return <Shield className="h-4 w-4 text-gray-600" />;
    }
  };

  const getResourceIcon = (type: string) => {
    switch (type) {
      case 'ec2':
      case 'vm':
      case 'compute':
        return <Server className="h-4 w-4" />;
      case 'database':
        return <Database className="h-4 w-4" />;
      case 'network':
        return <Network className="h-4 w-4" />;
      case 'container':
      case 'function':
        return <Cloud className="h-4 w-4" />;
      default:
        return <Server className="h-4 w-4" />;
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const formatCurrency = (amount: string) => {
    return amount;
  };

  return (
    <div className="h-screen w-full bg-slate-900 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white">Compliance Reporting</h1>
            <p className="text-slate-400 mt-2">
              Dynamic compliance assessments based on your connected infrastructure
            </p>
          </div>
          <div className="flex items-center space-x-4">
            <Select value={selectedFramework} onValueChange={setSelectedFramework}>
              <SelectTrigger className="w-64 bg-slate-800 border-slate-700 text-white">
                <SelectValue placeholder="Select Framework" />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-700">
                {frameworks.map((framework) => (
                  <SelectItem key={framework.id} value={framework.id} className="text-white">
                    {framework.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button 
              onClick={() => loadComplianceData()} 
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700"
            >
              {loading ? (
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4 mr-2" />
              )}
              Refresh Assessment
            </Button>
          </div>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="bg-slate-800 border-slate-700">
            <TabsTrigger value="dashboard" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              <Activity className="h-4 w-4 mr-2" />
              Dashboard
            </TabsTrigger>
            <TabsTrigger value="assessment" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              <ClipboardList className="h-4 w-4 mr-2" />
              Assessment Details
            </TabsTrigger>
            <TabsTrigger value="resources" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              <Network className="h-4 w-4 mr-2" />
              Infrastructure
            </TabsTrigger>
            <TabsTrigger value="reports" className="data-[state=active]:bg-slate-700 data-[state=active]:text-white">
              <FileText className="h-4 w-4 mr-2" />
              Reports
            </TabsTrigger>
          </TabsList>

          {/* Dashboard Tab */}
          <TabsContent value="dashboard">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Overall Compliance Score */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Shield className="h-5 w-5 mr-2" />
                    Compliance Score
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-center">
                    <div className="text-4xl font-bold text-white mb-2">
                      {currentAssessment?.overallScore || 0}%
                    </div>
                    <Badge className={getStatusColor(currentAssessment?.status || 'unknown')}>
                      {currentAssessment?.status?.replace('-', ' ').toUpperCase() || 'UNKNOWN'}
                    </Badge>
                    <Progress 
                      value={currentAssessment?.overallScore || 0} 
                      className="mt-4"
                    />
                  </div>
                </CardContent>
              </Card>

              {/* Risk Score */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <AlertTriangle className="h-5 w-5 mr-2" />
                    Risk Score
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-center">
                    <div className="text-4xl font-bold text-white mb-2">
                      {currentAssessment?.riskScore || 0}/100
                    </div>
                    <div className="text-slate-400">
                      {(currentAssessment?.riskScore || 0) < 30 ? 'Low Risk' : 
                       (currentAssessment?.riskScore || 0) < 70 ? 'Medium Risk' : 'High Risk'}
                    </div>
                    <Progress 
                      value={currentAssessment?.riskScore || 0} 
                      className="mt-4"
                    />
                  </div>
                </CardContent>
              </Card>

              {/* Resource Summary */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center">
                    <Server className="h-5 w-5 mr-2" />
                    Infrastructure
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between text-white">
                      <span>Total Resources</span>
                      <span className="font-bold">{currentAssessment?.resourceSummary?.totalResources || 0}</span>
                    </div>
                    <div className="flex justify-between text-green-400">
                      <span>Compliant</span>
                      <span className="font-bold">{currentAssessment?.resourceSummary?.compliantResources || 0}</span>
                    </div>
                    <div className="flex justify-between text-red-400">
                      <span>Non-Compliant</span>
                      <span className="font-bold">{currentAssessment?.resourceSummary?.nonCompliantResources || 0}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Controls Status Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Control Status</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <CheckCircle2 className="h-5 w-5 text-green-500" />
                        <span className="text-white">Compliant Controls</span>
                      </div>
                      <span className="text-2xl font-bold text-green-500">
                        {currentAssessment?.compliantControls || 0}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <AlertTriangle className="h-5 w-5 text-red-500" />
                        <span className="text-white">Non-Compliant Controls</span>
                      </div>
                      <span className="text-2xl font-bold text-red-500">
                        {currentAssessment?.nonCompliantControls || 0}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Clock className="h-5 w-5 text-gray-500" />
                        <span className="text-white">Not Applicable</span>
                      </div>
                      <span className="text-2xl font-bold text-gray-500">
                        {currentAssessment?.notApplicableControls || 0}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Resource Breakdown</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {Object.entries(currentAssessment?.resourceSummary?.resourceBreakdown || {}).map(([type, count]) => (
                      <div key={type} className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          {getResourceIcon(type)}
                          <span className="text-white capitalize">{type}</span>
                        </div>
                        <span className="font-bold text-white">{count}</span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Quick Actions */}
            <Card className="bg-slate-800 border-slate-700 mt-6">
              <CardHeader>
                <CardTitle className="text-white">Quick Actions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex space-x-4">
                  <Button 
                    onClick={() => generateReport(selectedFramework)}
                    disabled={loading}
                    className="bg-blue-600 hover:bg-blue-700"
                  >
                    <FileText className="h-4 w-4 mr-2" />
                    Generate Report
                  </Button>
                  <Button 
                    onClick={() => setActiveTab('assessment')}
                    variant="outline"
                    className="border-slate-600 text-white hover:bg-slate-700"
                  >
                    <ClipboardList className="h-4 w-4 mr-2" />
                    View Findings
                  </Button>
                  <Button 
                    onClick={() => setActiveTab('resources')}
                    variant="outline"
                    className="border-slate-600 text-white hover:bg-slate-700"
                  >
                    <Network className="h-4 w-4 mr-2" />
                    Review Infrastructure
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Assessment Details Tab */}
          <TabsContent value="assessment">
            <div className="space-y-6">
              {/* Executive Summary */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Executive Summary</CardTitle>
                  <CardDescription className="text-slate-400">
                    Last updated: {formatDate(lastRefresh)}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="prose prose-invert max-w-none">
                    <p className="text-slate-300 whitespace-pre-line">
                      {currentAssessment?.assessment?.executiveSummary || 
                       `This compliance assessment evaluated ${currentAssessment?.resourceSummary?.totalResources || 0} resources across your infrastructure against ${frameworks.find(f => f.id === selectedFramework)?.name} requirements.`}
                    </p>
                  </div>
                </CardContent>
              </Card>

              {/* Findings Table */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Compliance Findings</CardTitle>
                  <CardDescription className="text-slate-400">
                    Detailed analysis of control assessments and violations
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="rounded-md border border-slate-700">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-slate-700">
                          <TableHead className="text-slate-300">Control</TableHead>
                          <TableHead className="text-slate-300">Severity</TableHead>
                          <TableHead className="text-slate-300">Status</TableHead>
                          <TableHead className="text-slate-300">Affected Resources</TableHead>
                          <TableHead className="text-slate-300">Estimated Effort</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(currentAssessment?.findings || []).map((finding) => (
                          <TableRow key={finding.id} className="border-slate-700">
                            <TableCell className="text-white">
                              <div>
                                <div className="font-medium">{finding.controlName}</div>
                                <div className="text-sm text-slate-400">{finding.description}</div>
                              </div>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center space-x-2">
                                {getSeverityIcon(finding.severity)}
                                <span className="text-white capitalize">{finding.severity}</span>
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge className={getStatusColor(finding.status)}>
                                {finding.status.replace('-', ' ').toUpperCase()}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-white">
                              {finding.affectedResources.length}
                            </TableCell>
                            <TableCell className="text-white">
                              {finding.estimatedEffort}
                            </TableCell>
                          </TableRow>
                        ))}
                        {(!currentAssessment?.findings || currentAssessment.findings.length === 0) && (
                          <TableRow className="border-slate-700">
                            <TableCell colSpan={5} className="text-center text-slate-400 py-8">
                              No compliance findings available. Generate an assessment to see detailed results.
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </Card>

              {/* Recommendations */}
              <Card className="bg-slate-800 border-slate-700">
                <CardHeader>
                  <CardTitle className="text-white">Recommendations</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {(currentAssessment?.recommendations || []).map((rec) => (
                      <div key={rec.id} className="border border-slate-700 rounded-lg p-4">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1">
                            <h4 className="font-medium text-white">{rec.title}</h4>
                            <p className="text-sm text-slate-400 mt-1">{rec.description}</p>
                          </div>
                          <div className="flex items-center space-x-2 ml-4">
                            <Badge variant="outline" className="border-slate-600 text-slate-300">
                              {rec.priority}
                            </Badge>
                            <Badge variant="outline" className="border-slate-600 text-slate-300">
                              {formatCurrency(rec.estimatedCost)}
                            </Badge>
                          </div>
                        </div>
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-slate-400">
                            Expected Impact: {rec.expectedImpact}
                          </span>
                          <span className="text-slate-400">
                            Time: {rec.implementationTime}
                          </span>
                        </div>
                      </div>
                    ))}
                    {(!currentAssessment?.recommendations || currentAssessment.recommendations.length === 0) && (
                      <div className="text-center text-slate-400 py-8">
                        No recommendations available at this time.
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Infrastructure Tab */}
          <TabsContent value="resources">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Connected Infrastructure</CardTitle>
                <CardDescription className="text-slate-400">
                  Resources being monitored for compliance assessment
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="rounded-md border border-slate-700">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-slate-700">
                        <TableHead className="text-slate-300">Resource</TableHead>
                        <TableHead className="text-slate-300">Type</TableHead>
                        <TableHead className="text-slate-300">Provider</TableHead>
                        <TableHead className="text-slate-300">Region</TableHead>
                        <TableHead className="text-slate-300">Status</TableHead>
                        <TableHead className="text-slate-300">Compliance Score</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {networkResources.map((resource) => {
                        const complianceChecks = Object.values(resource.compliance);
                        const passedChecks = complianceChecks.filter(Boolean).length;
                        const complianceScore = Math.round((passedChecks / complianceChecks.length) * 100);
                        
                        return (
                          <TableRow key={resource.id} className="border-slate-700">
                            <TableCell className="text-white">
                              <div className="flex items-center space-x-2">
                                {getResourceIcon(resource.type)}
                                <div>
                                  <div className="font-medium">{resource.name}</div>
                                  <div className="text-sm text-slate-400">{resource.id}</div>
                                </div>
                              </div>
                            </TableCell>
                            <TableCell className="text-white capitalize">{resource.type}</TableCell>
                            <TableCell className="text-white uppercase">{resource.provider}</TableCell>
                            <TableCell className="text-white">{resource.region}</TableCell>
                            <TableCell>
                              <Badge className={getStatusColor(resource.status)}>
                                {resource.status.toUpperCase()}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center space-x-2">
                                <Progress value={complianceScore} className="w-16" />
                                <span className="text-white text-sm">{complianceScore}%</span>
                              </div>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                      {networkResources.length === 0 && (
                        <TableRow className="border-slate-700">
                          <TableCell colSpan={6} className="text-center text-slate-400 py-8">
                            No infrastructure resources found. Connect your cloud providers to see compliance data.
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Reports Tab */}
          <TabsContent value="reports">
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-semibold text-white">Generated Reports</h3>
                  <p className="text-slate-400">Download and manage compliance reports</p>
                </div>
                <Button 
                  onClick={() => generateReport(selectedFramework)}
                  disabled={loading}
                  className="bg-blue-600 hover:bg-blue-700"
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Generate New Report
                </Button>
              </div>

              <Card className="bg-slate-800 border-slate-700">
                <CardContent className="p-6">
                  <div className="rounded-md border border-slate-700">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-slate-700">
                          <TableHead className="text-slate-300">Report Name</TableHead>
                          <TableHead className="text-slate-300">Framework</TableHead>
                          <TableHead className="text-slate-300">Generated</TableHead>
                          <TableHead className="text-slate-300">Status</TableHead>
                          <TableHead className="text-slate-300">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {complianceReports.map((report) => (
                          <TableRow key={report.id} className="border-slate-700">
                            <TableCell className="text-white">
                              <div>
                                <div className="font-medium">{report.reportName}</div>
                                <div className="text-sm text-slate-400">ID: {report.id}</div>
                              </div>
                            </TableCell>
                            <TableCell className="text-white">{report.frameworkId.toUpperCase()}</TableCell>
                            <TableCell className="text-white">{formatDate(report.generatedAt)}</TableCell>
                            <TableCell>
                              <Badge className={getStatusColor(report.metadata.approvalStatus)}>
                                {report.metadata.approvalStatus.toUpperCase()}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center space-x-2">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => downloadReport(report.id)}
                                  className="border-slate-600 text-white hover:bg-slate-700"
                                >
                                  <Download className="h-4 w-4" />
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>
                        ))}
                        {complianceReports.length === 0 && (
                          <TableRow className="border-slate-700">
                            <TableCell colSpan={5} className="text-center text-slate-400 py-8">
                              No compliance reports generated yet. Click "Generate New Report" to create one.
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
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

export default ComplianceReporting;
