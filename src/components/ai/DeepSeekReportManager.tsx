import React, { useState, useEffect } from 'react';
import { 
  deepseekService, 
  SecurityAssessmentReport, 
  IncidentAnalysisReport, 
  ComplianceReport, 
  ThreatIntelligenceReport 
} from '../../services/deepseekService';
import { Button } from '../ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs';
import { Input } from '../ui/input';
import { Textarea } from '../ui/textarea';
import { Badge } from '../ui/badge';
import { Progress } from '../ui/progress';
import { Alert, AlertDescription } from '../ui/alert';
import { Separator } from '../ui/separator';
import { 
  FileText, 
  Download, 
  Eye, 
  AlertTriangle, 
  Shield, 
  TrendingUp, 
  Users, 
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  Info
} from 'lucide-react';

interface DeepSeekReportManagerProps {
  onClose?: () => void;
}

type ReportType = 'security-assessment' | 'incident-analysis' | 'compliance' | 'threat-intelligence';

const DeepSeekReportManager: React.FC<DeepSeekReportManagerProps> = ({ onClose }) => {
  const [activeTab, setActiveTab] = useState<ReportType>('security-assessment');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedReports, setGeneratedReports] = useState<{
    [key: string]: SecurityAssessmentReport | IncidentAnalysisReport | ComplianceReport | ThreatIntelligenceReport;
  }>({});
  const [connectionStatus, setConnectionStatus] = useState<'unknown' | 'connected' | 'disconnected'>('unknown');
  const [error, setError] = useState<string | null>(null);

  // Security Assessment Form State
  const [securityAssessmentForm, setSecurityAssessmentForm] = useState({
    organizationName: '',
    vulnerabilities: '',
    systemsScanned: '',
    complianceFrameworks: '',
    businessContext: ''
  });

  // Incident Analysis Form State
  const [incidentAnalysisForm, setIncidentAnalysisForm] = useState({
    incidentId: '',
    description: '',
    timelineEvents: '',
    affectedSystems: '',
    logData: '',
    initialFindings: ''
  });

  // Compliance Report Form State
  const [complianceForm, setComplianceForm] = useState({
    framework: 'ISO 27001',
    organizationName: '',
    controlsData: ''
  });

  // Threat Intelligence Form State
  const [threatIntelForm, setThreatIntelForm] = useState({
    industry: '',
    size: '',
    geographicLocation: '',
    technologyStack: '',
    criticalAssets: '',
    activeCampaigns: '',
    emergingThreats: '',
    indicators: ''
  });

  useEffect(() => {
    initializeDeepSeek();
  }, []);

  const initializeDeepSeek = async () => {
    try {
      const initialized = await deepseekService.initialize();
      if (initialized) {
        const connected = await deepseekService.checkConnection();
        setConnectionStatus(connected ? 'connected' : 'disconnected');
      } else {
        setConnectionStatus('disconnected');
      }
    } catch (error) {
      console.error('Failed to initialize DeepSeek:', error);
      setConnectionStatus('disconnected');
      setError('Failed to connect to DeepSeek service');
    }
  };

  const generateSecurityAssessmentReport = async () => {
    setIsGenerating(true);
    setError(null);
    
    try {
      const assessmentData = {
        vulnerabilities: securityAssessmentForm.vulnerabilities ? JSON.parse(securityAssessmentForm.vulnerabilities) : [],
        systemsScanned: securityAssessmentForm.systemsScanned.split(',').map(s => s.trim()),
        complianceFrameworks: securityAssessmentForm.complianceFrameworks.split(',').map(s => s.trim()),
        businessContext: securityAssessmentForm.businessContext
      };
      
      const report = await deepseekService.generateSecurityAssessmentReport(
        securityAssessmentForm.organizationName,
        assessmentData
      );
      
      setGeneratedReports(prev => ({
        ...prev,
        [`security-${Date.now()}`]: report
      }));
    } catch (error) {
      setError(`Failed to generate security assessment report: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const generateIncidentAnalysisReport = async () => {
    setIsGenerating(true);
    setError(null);
    
    try {
      const incidentData = {
        incidentId: incidentAnalysisForm.incidentId,
        description: incidentAnalysisForm.description,
        timelineEvents: incidentAnalysisForm.timelineEvents ? JSON.parse(incidentAnalysisForm.timelineEvents) : [],
        affectedSystems: incidentAnalysisForm.affectedSystems.split(',').map(s => s.trim()),
        logData: incidentAnalysisForm.logData,
        initialFindings: incidentAnalysisForm.initialFindings
      };
      
      const report = await deepseekService.generateIncidentAnalysisReport(incidentData);
      
      setGeneratedReports(prev => ({
        ...prev,
        [`incident-${Date.now()}`]: report
      }));
    } catch (error) {
      setError(`Failed to generate incident analysis report: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const generateComplianceReport = async () => {
    setIsGenerating(true);
    setError(null);
    
    try {
      const controlsData = complianceForm.controlsData ? JSON.parse(complianceForm.controlsData) : [];
      
      const report = await deepseekService.generateComplianceReport(
        complianceForm.framework,
        complianceForm.organizationName,
        controlsData
      );
      
      setGeneratedReports(prev => ({
        ...prev,
        [`compliance-${Date.now()}`]: report
      }));
    } catch (error) {
      setError(`Failed to generate compliance report: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const generateThreatIntelligenceReport = async () => {
    setIsGenerating(true);
    setError(null);
    
    try {
      const organizationProfile = {
        industry: threatIntelForm.industry,
        size: threatIntelForm.size,
        geographicLocation: threatIntelForm.geographicLocation,
        technologyStack: threatIntelForm.technologyStack.split(',').map(s => s.trim()),
        criticalAssets: threatIntelForm.criticalAssets.split(',').map(s => s.trim())
      };
      
      const threatData = {
        activeCampaigns: threatIntelForm.activeCampaigns ? JSON.parse(threatIntelForm.activeCampaigns) : [],
        emergingThreats: threatIntelForm.emergingThreats ? JSON.parse(threatIntelForm.emergingThreats) : [],
        indicators: threatIntelForm.indicators ? JSON.parse(threatIntelForm.indicators) : []
      };
      
      const report = await deepseekService.generateThreatIntelligenceReport(organizationProfile, threatData);
      
      setGeneratedReports(prev => ({
        ...prev,
        [`threat-${Date.now()}`]: report
      }));
    } catch (error) {
      setError(`Failed to generate threat intelligence report: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const exportReport = async (reportKey: string, format: 'pdf' | 'docx' | 'html' | 'json') => {
    try {
      const report = generatedReports[reportKey];
      if (!report) return;
      
      const blob = await deepseekService.exportReport(report, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${reportKey}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      setError(`Failed to export report: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case 'disconnected':
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return <AlertCircle className="h-4 w-4 text-yellow-500" />;
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
        return 'bg-blue-500';
      default:
        return 'bg-gray-500';
    }
  };

  const renderReportSummary = (reportKey: string, report: any) => {
    const reportType = reportKey.split('-')[0];
    let icon = <FileText className="h-5 w-5" />;
    let title = 'Report';
    let summary = '';

    switch (reportType) {
      case 'security':
        icon = <Shield className="h-5 w-5" />;
        title = 'Security Assessment Report';
        summary = report.executiveSummary || 'Security assessment completed';
        break;
      case 'incident':
        icon = <AlertTriangle className="h-5 w-5" />;
        title = 'Incident Analysis Report';
        summary = `Incident ${report.incidentId} analysis completed`;
        break;
      case 'compliance':
        icon = <CheckCircle className="h-5 w-5" />;
        title = `${report.framework} Compliance Report`;
        summary = `Overall compliance: ${report.overallCompliance}%`;
        break;
      case 'threat':
        icon = <TrendingUp className="h-5 w-5" />;
        title = 'Threat Intelligence Report';
        summary = 'Current threat landscape analysis';
        break;
    }

    return (
      <Card key={reportKey} className="mb-4">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              {icon}
              <CardTitle className="text-lg">{title}</CardTitle>
            </div>
            <div className="flex space-x-2">
              <Button variant="outline" size="sm" onClick={() => exportReport(reportKey, 'json')}>
                <Download className="h-4 w-4 mr-1" />
                JSON
              </Button>
              <Button variant="outline" size="sm" onClick={() => exportReport(reportKey, 'html')}>
                <Download className="h-4 w-4 mr-1" />
                HTML
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-gray-600 mb-2">{summary}</p>
          <div className="flex items-center space-x-4 text-xs text-gray-500">
            <span>Generated: {new Date(report.generatedAt).toLocaleString()}</span>
            <span>ID: {report.id}</span>
          </div>
        </CardContent>
      </Card>
    );
  };

  return (
    <div className="max-w-6xl mx-auto p-6 bg-white">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold">DeepSeek Report Manager</h1>
          <p className="text-gray-600">Generate comprehensive security reports using AI analysis</p>
        </div>
        <div className="flex items-center space-x-2">
          {getStatusIcon(connectionStatus)}
          <span className="text-sm text-gray-600">
            {connectionStatus === 'connected' ? 'Connected' : 
             connectionStatus === 'disconnected' ? 'Disconnected' : 'Checking...'}
          </span>
          {onClose && (
            <Button variant="outline" onClick={onClose}>Close</Button>
          )}
        </div>
      </div>

      {error && (
        <Alert className="mb-6">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Tabs value={activeTab} onValueChange={(value) => setActiveTab(value as ReportType)}>
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="security-assessment">
            <Shield className="h-4 w-4 mr-2" />
            Security Assessment
          </TabsTrigger>
          <TabsTrigger value="incident-analysis">
            <AlertTriangle className="h-4 w-4 mr-2" />
            Incident Analysis
          </TabsTrigger>
          <TabsTrigger value="compliance">
            <CheckCircle className="h-4 w-4 mr-2" />
            Compliance
          </TabsTrigger>
          <TabsTrigger value="threat-intelligence">
            <TrendingUp className="h-4 w-4 mr-2" />
            Threat Intelligence
          </TabsTrigger>
        </TabsList>

        <TabsContent value="security-assessment" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Security Assessment Report</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input
                placeholder="Organization Name"
                value={securityAssessmentForm.organizationName}
                onChange={(e) => setSecurityAssessmentForm(prev => ({ ...prev, organizationName: e.target.value }))}
              />
              <Textarea
                placeholder="Vulnerabilities (JSON format)"
                value={securityAssessmentForm.vulnerabilities}
                onChange={(e) => setSecurityAssessmentForm(prev => ({ ...prev, vulnerabilities: e.target.value }))}
                rows={4}
              />
              <Input
                placeholder="Systems Scanned (comma-separated)"
                value={securityAssessmentForm.systemsScanned}
                onChange={(e) => setSecurityAssessmentForm(prev => ({ ...prev, systemsScanned: e.target.value }))}
              />
              <Input
                placeholder="Compliance Frameworks (comma-separated)"
                value={securityAssessmentForm.complianceFrameworks}
                onChange={(e) => setSecurityAssessmentForm(prev => ({ ...prev, complianceFrameworks: e.target.value }))}
              />
              <Textarea
                placeholder="Business Context"
                value={securityAssessmentForm.businessContext}
                onChange={(e) => setSecurityAssessmentForm(prev => ({ ...prev, businessContext: e.target.value }))}
                rows={3}
              />
              <Button 
                onClick={generateSecurityAssessmentReport} 
                disabled={isGenerating || connectionStatus !== 'connected'}
                className="w-full"
              >
                {isGenerating ? 'Generating Report...' : 'Generate Security Assessment Report'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="incident-analysis" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Incident Analysis Report</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Input
                placeholder="Incident ID"
                value={incidentAnalysisForm.incidentId}
                onChange={(e) => setIncidentAnalysisForm(prev => ({ ...prev, incidentId: e.target.value }))}
              />
              <Textarea
                placeholder="Incident Description"
                value={incidentAnalysisForm.description}
                onChange={(e) => setIncidentAnalysisForm(prev => ({ ...prev, description: e.target.value }))}
                rows={3}
              />
              <Textarea
                placeholder="Timeline Events (JSON format)"
                value={incidentAnalysisForm.timelineEvents}
                onChange={(e) => setIncidentAnalysisForm(prev => ({ ...prev, timelineEvents: e.target.value }))}
                rows={4}
              />
              <Input
                placeholder="Affected Systems (comma-separated)"
                value={incidentAnalysisForm.affectedSystems}
                onChange={(e) => setIncidentAnalysisForm(prev => ({ ...prev, affectedSystems: e.target.value }))}
              />
              <Textarea
                placeholder="Log Data Sample"
                value={incidentAnalysisForm.logData}
                onChange={(e) => setIncidentAnalysisForm(prev => ({ ...prev, logData: e.target.value }))}
                rows={5}
              />
              <Textarea
                placeholder="Initial Findings"
                value={incidentAnalysisForm.initialFindings}
                onChange={(e) => setIncidentAnalysisForm(prev => ({ ...prev, initialFindings: e.target.value }))}
                rows={3}
              />
              <Button 
                onClick={generateIncidentAnalysisReport} 
                disabled={isGenerating || connectionStatus !== 'connected'}
                className="w-full"
              >
                {isGenerating ? 'Generating Report...' : 'Generate Incident Analysis Report'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="compliance" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Compliance Report</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <select
                className="w-full p-2 border rounded"
                value={complianceForm.framework}
                onChange={(e) => setComplianceForm(prev => ({ ...prev, framework: e.target.value }))}
              >
                <option value="ISO 27001">ISO 27001</option>
                <option value="SOC 2">SOC 2</option>
                <option value="GDPR">GDPR</option>
                <option value="HIPAA">HIPAA</option>
                <option value="PCI DSS">PCI DSS</option>
              </select>
              <Input
                placeholder="Organization Name"
                value={complianceForm.organizationName}
                onChange={(e) => setComplianceForm(prev => ({ ...prev, organizationName: e.target.value }))}
              />
              <Textarea
                placeholder="Controls Data (JSON format)"
                value={complianceForm.controlsData}
                onChange={(e) => setComplianceForm(prev => ({ ...prev, controlsData: e.target.value }))}
                rows={6}
              />
              <Button 
                onClick={generateComplianceReport} 
                disabled={isGenerating || connectionStatus !== 'connected'}
                className="w-full"
              >
                {isGenerating ? 'Generating Report...' : 'Generate Compliance Report'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threat-intelligence" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Threat Intelligence Report</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <Input
                  placeholder="Industry"
                  value={threatIntelForm.industry}
                  onChange={(e) => setThreatIntelForm(prev => ({ ...prev, industry: e.target.value }))}
                />
                <Input
                  placeholder="Organization Size"
                  value={threatIntelForm.size}
                  onChange={(e) => setThreatIntelForm(prev => ({ ...prev, size: e.target.value }))}
                />
                <Input
                  placeholder="Geographic Location"
                  value={threatIntelForm.geographicLocation}
                  onChange={(e) => setThreatIntelForm(prev => ({ ...prev, geographicLocation: e.target.value }))}
                />
                <Input
                  placeholder="Technology Stack (comma-separated)"
                  value={threatIntelForm.technologyStack}
                  onChange={(e) => setThreatIntelForm(prev => ({ ...prev, technologyStack: e.target.value }))}
                />
              </div>
              <Input
                placeholder="Critical Assets (comma-separated)"
                value={threatIntelForm.criticalAssets}
                onChange={(e) => setThreatIntelForm(prev => ({ ...prev, criticalAssets: e.target.value }))}
              />
              <Textarea
                placeholder="Active Campaigns (JSON format)"
                value={threatIntelForm.activeCampaigns}
                onChange={(e) => setThreatIntelForm(prev => ({ ...prev, activeCampaigns: e.target.value }))}
                rows={4}
              />
              <Textarea
                placeholder="Emerging Threats (JSON format)"
                value={threatIntelForm.emergingThreats}
                onChange={(e) => setThreatIntelForm(prev => ({ ...prev, emergingThreats: e.target.value }))}
                rows={4}
              />
              <Textarea
                placeholder="Indicators of Compromise (JSON format)"
                value={threatIntelForm.indicators}
                onChange={(e) => setThreatIntelForm(prev => ({ ...prev, indicators: e.target.value }))}
                rows={4}
              />
              <Button 
                onClick={generateThreatIntelligenceReport} 
                disabled={isGenerating || connectionStatus !== 'connected'}
                className="w-full"
              >
                {isGenerating ? 'Generating Report...' : 'Generate Threat Intelligence Report'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {isGenerating && (
        <div className="mt-6">
          <Progress value={33} className="w-full" />
          <p className="text-center text-sm text-gray-600 mt-2">Generating report using DeepSeek AI...</p>
        </div>
      )}

      {Object.keys(generatedReports).length > 0 && (
        <div className="mt-8">
          <Separator className="mb-6" />
          <h2 className="text-2xl font-bold mb-4">Generated Reports</h2>
          <div className="space-y-4">
            {Object.entries(generatedReports).map(([key, report]) => 
              renderReportSummary(key, report)
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default DeepSeekReportManager; 