
import React, { useState } from 'react';
import MainLayout from '@/components/layout/MainLayout';
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
  Search
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

// Mock data for compliance templates
const complianceTemplates = [
  {
    id: 1,
    name: "GDPR Compliance Report",
    description: "Assessment of compliance with the General Data Protection Regulation",
    framework: "GDPR",
    lastGenerated: "2023-12-15",
    sections: [
      "Data Protection Policy Review",
      "Data Subject Rights Implementation",
      "Consent Mechanisms",
      "Processor Controls",
      "Cross-border Transfer Compliance",
      "Data Protection Impact Assessments"
    ]
  },
  {
    id: 2,
    name: "HIPAA Security Assessment",
    description: "Evaluation of safeguards for protected health information",
    framework: "HIPAA",
    lastGenerated: "2024-01-10",
    sections: [
      "Administrative Safeguards",
      "Physical Safeguards",
      "Technical Safeguards",
      "Organizational Requirements",
      "Policies and Procedures",
      "Breach Notification Compliance"
    ]
  },
  {
    id: 3,
    name: "SOC 2 Type II Readiness",
    description: "Preparedness assessment for SOC 2 Type II audit",
    framework: "SOC2",
    lastGenerated: "2024-02-05",
    sections: [
      "Security Control Environment",
      "Communication Controls",
      "Risk Management",
      "Monitoring Activities",
      "Logical Access Controls",
      "System Operations"
    ]
  },
  {
    id: 4,
    name: "ISO 27001 Gap Analysis",
    description: "Identification of gaps in ISO 27001 compliance",
    framework: "ISO 27001",
    lastGenerated: "2024-02-20",
    sections: [
      "Information Security Policies",
      "Organization of Information Security",
      "Human Resource Security",
      "Asset Management",
      "Access Control",
      "Cryptography"
    ]
  }
];

// Mock data for scheduled reports
const scheduledReports = [
  {
    id: 1,
    name: "Monthly GDPR Compliance Check",
    template: "GDPR Compliance Report",
    frequency: "Monthly",
    nextRun: "2024-03-15",
    recipients: ["security@example.com", "dpo@example.com"],
    status: "Active"
  },
  {
    id: 2,
    name: "Quarterly HIPAA Assessment",
    template: "HIPAA Security Assessment",
    frequency: "Quarterly",
    nextRun: "2024-04-01",
    recipients: ["compliance@example.com", "security@example.com"],
    status: "Active"
  },
  {
    id: 3,
    name: "Weekly Security Controls Review",
    template: "SOC 2 Type II Readiness",
    frequency: "Weekly",
    nextRun: "2024-03-05",
    recipients: ["infosec@example.com"],
    status: "Paused"
  }
];

// Mock data for audit trails
const auditTrails = [
  {
    id: 1,
    action: "Report Generated",
    reportName: "GDPR Compliance Report",
    user: "admin@example.com",
    timestamp: "2024-03-01 14:25:33",
    ipAddress: "192.168.1.105"
  },
  {
    id: 2,
    action: "Report Scheduled",
    reportName: "HIPAA Security Assessment",
    user: "security@example.com",
    timestamp: "2024-03-01 10:12:45",
    ipAddress: "192.168.1.110"
  },
  {
    id: 3,
    action: "Evidence Uploaded",
    reportName: "SOC 2 Type II Readiness",
    user: "auditor@example.com",
    timestamp: "2024-02-29 16:45:22",
    ipAddress: "192.168.1.115"
  },
  {
    id: 4,
    action: "Report Downloaded",
    reportName: "ISO 27001 Gap Analysis",
    user: "ciso@example.com",
    timestamp: "2024-02-28 09:33:57",
    ipAddress: "192.168.1.120"
  },
  {
    id: 5,
    action: "Template Modified",
    reportName: "GDPR Compliance Report",
    user: "admin@example.com",
    timestamp: "2024-02-27 11:15:40",
    ipAddress: "192.168.1.105"
  }
];

// Mock data for evidence collection
const evidenceItems = [
  {
    id: 1,
    name: "Firewall Configuration Backup",
    description: "Monthly backup of firewall rules and configuration",
    relatedControl: "Access Control",
    framework: "ISO 27001",
    dateCollected: "2024-02-15",
    collectedBy: "system_admin",
    status: "Verified"
  },
  {
    id: 2,
    name: "Employee Security Training Records",
    description: "Annual security awareness training completion records",
    relatedControl: "Human Resource Security",
    framework: "GDPR",
    dateCollected: "2024-01-30",
    collectedBy: "hr_manager",
    status: "Pending Review"
  },
  {
    id: 3,
    name: "Data Processing Agreement",
    description: "Signed DPA with cloud service provider",
    relatedControl: "Processor Controls",
    framework: "GDPR",
    dateCollected: "2024-02-10",
    collectedBy: "legal_team",
    status: "Verified"
  },
  {
    id: 4,
    name: "System Access Logs",
    description: "Quarterly export of access logs for critical systems",
    relatedControl: "Monitoring Activities",
    framework: "SOC 2",
    dateCollected: "2024-03-01",
    collectedBy: "security_analyst",
    status: "Pending Review"
  }
];

const ComplianceReporting: React.FC = () => {
  const [activeTab, setActiveTab] = useState("templates");
  const [selectedTemplate, setSelectedTemplate] = useState<number | null>(null);
  const [showReportDialog, setShowReportDialog] = useState(false);
  const [showScheduleDialog, setShowScheduleDialog] = useState(false);
  const [showEvidenceDialog, setShowEvidenceDialog] = useState(false);
  const [generatedReport, setGeneratedReport] = useState<{ id: number; name: string; format: string } | null>(null);
  
  const { toast } = useToast();

  const generateReport = (templateId: number) => {
    setSelectedTemplate(templateId);
    setShowReportDialog(true);
  };

  const scheduleReport = (templateId: number) => {
    setSelectedTemplate(templateId);
    setShowScheduleDialog(true);
  };

  const handleGenerateNow = () => {
    const template = complianceTemplates.find(t => t.id === selectedTemplate);
    
    if (template) {
      setGeneratedReport({
        id: Date.now(),
        name: template.name,
        format: 'pdf'
      });
      
      setShowReportDialog(false);
      toast({
        title: "Report Generated",
        description: "The compliance report has been generated successfully and is ready for download.",
        duration: 3000,
      });
    }
  };

  const handleDownloadReport = () => {
    if (generatedReport) {
      // In a real-world scenario, this would trigger an actual file download
      toast({
        title: "Downloading Report",
        description: `${generatedReport.name}.${generatedReport.format} is being downloaded.`,
        duration: 3000,
      });
    }
  };

  const handleScheduleReport = () => {
    setShowScheduleDialog(false);
    toast({
      title: "Report Scheduled",
      description: "The compliance report has been scheduled successfully.",
      duration: 3000,
    });
  };

  const handleAddEvidence = () => {
    setShowEvidenceDialog(false);
    toast({
      title: "Evidence Added",
      description: "The evidence item has been added to the collection.",
      duration: 3000,
    });
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "Active":
        return "bg-green-500 text-white";
      case "Paused":
        return "bg-amber-500 text-white";
      case "Verified":
        return "bg-cyber-success text-white";
      case "Pending Review":
        return "bg-amber-500 text-white";
      default:
        return "bg-cyber-gray";
    }
  };

  return (
    <MainLayout>
      <div className="flex flex-col space-y-4">
        <div className="flex items-center gap-2">
          <FileText className="h-6 w-6 text-cyber-accent" />
          <h1 className="text-2xl font-bold">Compliance & Reporting</h1>
        </div>
        
        <p className="text-cyber-lightgray mb-4">
          Generate, schedule, and manage compliance reports and evidence for security audits.
        </p>
        
        {generatedReport && (
          <Card className="bg-cyber-accent/10 border-cyber-accent animate-fade-in">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileText className="h-5 w-5 text-cyber-accent" />
                  <span>Your report "{generatedReport.name}" is ready!</span>
                </div>
                <Button 
                  variant="outline"
                  size="sm"
                  className="text-cyber-accent border-cyber-accent hover:bg-cyber-accent hover:text-white"
                  onClick={handleDownloadReport}
                >
                  <Download className="h-4 w-4 mr-1" />
                  Download {generatedReport.format.toUpperCase()}
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
        
        <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="mb-4 w-full flex flex-wrap justify-start gap-2 bg-transparent">
            <TabsTrigger 
              value="templates" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <FileText className="h-4 w-4 mr-2" />
              Compliance Templates
            </TabsTrigger>
            <TabsTrigger 
              value="scheduled" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <Clock className="h-4 w-4 mr-2" />
              Scheduled Reports
            </TabsTrigger>
            <TabsTrigger 
              value="audit" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <ClipboardList className="h-4 w-4 mr-2" />
              Audit Trails
            </TabsTrigger>
            <TabsTrigger 
              value="evidence" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <FolderArchive className="h-4 w-4 mr-2" />
              Evidence Collection
            </TabsTrigger>
          </TabsList>
          
          {/* Compliance Templates Tab */}
          <TabsContent value="templates" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {complianceTemplates.map((template) => (
                <Card key={template.id} className="bg-cyber-darker border border-cyber-accent/20 hover:border-cyber-accent/50 transition-all">
                  <CardHeader>
                    <div className="flex justify-between items-start">
                      <div>
                        <CardTitle className="flex items-center gap-2">
                          <FileText className="h-5 w-5 text-cyber-accent" />
                          {template.name}
                        </CardTitle>
                        <CardDescription className="mt-1">
                          {template.description}
                        </CardDescription>
                      </div>
                      <Badge className="bg-cyber-accent text-white">
                        {template.framework}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-white mb-2 font-medium">Key sections:</p>
                    <div className="bg-cyber-dark/50 p-3 rounded-md border border-cyber-gray/30">
                      <ul className="text-sm space-y-1 text-cyber-lightgray">
                        {template.sections.slice(0, 4).map((section, index) => (
                          <li key={index} className="flex items-center gap-1">
                            <span className="h-1.5 w-1.5 rounded-full bg-cyber-accent"></span>
                            {section}
                          </li>
                        ))}
                        {template.sections.length > 4 && (
                          <li className="text-cyber-accent font-medium">
                            +{template.sections.length - 4} more sections
                          </li>
                        )}
                      </ul>
                    </div>
                    
                    <div className="text-xs text-cyber-lightgray mt-3">
                      Last generated: {template.lastGenerated}
                    </div>
                  </CardContent>
                  <CardFooter className="flex gap-2 pt-2 justify-end border-t border-cyber-darkgray">
                    <Button 
                      variant="outline" 
                      size="sm"
                      className="text-cyber-accent border-cyber-accent hover:bg-cyber-accent hover:text-white"
                      onClick={() => generateReport(template.id)}
                    >
                      <Download className="h-4 w-4 mr-1" />
                      Generate
                    </Button>
                    <Button 
                      variant="outline" 
                      size="sm"
                      className="text-cyber-accent border-cyber-accent hover:bg-cyber-accent hover:text-white"
                      onClick={() => scheduleReport(template.id)}
                    >
                      <Calendar className="h-4 w-4 mr-1" />
                      Schedule
                    </Button>
                  </CardFooter>
                </Card>
              ))}
            </div>
          </TabsContent>
          
          {/* Scheduled Reports Tab */}
          <TabsContent value="scheduled" className="space-y-4">
            <div className="flex justify-end mb-4">
              <Button 
                className="bg-cyber-accent hover:bg-cyber-accent/90 text-white"
                onClick={() => setShowScheduleDialog(true)}
              >
                <Plus className="h-4 w-4 mr-1" />
                New Scheduled Report
              </Button>
            </div>
            
            <Card className="bg-cyber-gray border-cyber-darkgray">
              <CardHeader>
                <CardTitle className="text-lg">Scheduled Report Jobs</CardTitle>
                <CardDescription>
                  View and manage automated report generation jobs
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader className="bg-cyber-darker">
                    <TableRow>
                      <TableHead>Report Name</TableHead>
                      <TableHead>Template</TableHead>
                      <TableHead>Frequency</TableHead>
                      <TableHead>Next Run</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {scheduledReports.map((report) => (
                      <TableRow key={report.id}>
                        <TableCell>{report.name}</TableCell>
                        <TableCell>{report.template}</TableCell>
                        <TableCell>{report.frequency}</TableCell>
                        <TableCell>{report.nextRun}</TableCell>
                        <TableCell>
                          <Badge className={getStatusColor(report.status)}>
                            {report.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right space-x-1">
                          <Button size="icon" variant="ghost">
                            <Edit className="h-4 w-4 text-cyber-accent" />
                          </Button>
                          <Button size="icon" variant="ghost">
                            <Bell className="h-4 w-4 text-cyber-accent" />
                          </Button>
                          <Button size="icon" variant="ghost">
                            <Trash2 className="h-4 w-4 text-cyber-accent" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
            
            <Card className="bg-cyber-gray border-cyber-darkgray">
              <CardHeader>
                <CardTitle className="text-lg">Distribution Settings</CardTitle>
                <CardDescription>
                  Configure email notifications and report delivery options
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-cyber-darker p-4 rounded-md">
                    <h3 className="text-sm font-medium mb-2 flex items-center">
                      <SendHorizonal className="h-4 w-4 mr-2 text-cyber-accent" />
                      Email Delivery
                    </h3>
                    <p className="text-xs text-cyber-lightgray mb-2">
                      Reports will be sent via email to configured recipients with secure PDF attachments
                    </p>
                    <div className="mt-2">
                      <Button size="sm" variant="outline" className="text-xs">
                        Configure SMTP
                      </Button>
                    </div>
                  </div>
                  
                  <div className="bg-cyber-darker p-4 rounded-md">
                    <h3 className="text-sm font-medium mb-2 flex items-center">
                      <Bell className="h-4 w-4 mr-2 text-cyber-accent" />
                      Notification Rules
                    </h3>
                    <p className="text-xs text-cyber-lightgray mb-2">
                      Set up alerts for report generation failures or compliance issues detected
                    </p>
                    <div className="mt-2">
                      <Button size="sm" variant="outline" className="text-xs">
                        Manage Rules
                      </Button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          {/* Audit Trails Tab */}
          <TabsContent value="audit" className="space-y-4">
            <Card className="bg-cyber-gray border-cyber-darkgray">
              <CardHeader>
                <div className="flex justify-between items-center">
                  <div>
                    <CardTitle className="text-lg">Compliance Activity Logs</CardTitle>
                    <CardDescription>
                      Comprehensive record of all compliance-related activities
                    </CardDescription>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="relative">
                      <Search className="h-4 w-4 absolute left-2 top-1/2 transform -translate-y-1/2 text-cyber-lightgray" />
                      <Input className="pl-8 h-8" placeholder="Search logs..." />
                    </div>
                    <Button variant="outline" size="sm">
                      <Download className="h-4 w-4 mr-1" />
                      Export
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader className="bg-cyber-darker">
                    <TableRow>
                      <TableHead>Action</TableHead>
                      <TableHead>Report</TableHead>
                      <TableHead>User</TableHead>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>IP Address</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {auditTrails.map((log) => (
                      <TableRow key={log.id}>
                        <TableCell>{log.action}</TableCell>
                        <TableCell>{log.reportName}</TableCell>
                        <TableCell>{log.user}</TableCell>
                        <TableCell>{log.timestamp}</TableCell>
                        <TableCell>{log.ipAddress}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
              <CardFooter className="flex justify-between pt-2 border-t border-cyber-darkgray">
                <div className="text-xs text-cyber-lightgray">
                  Showing 5 of 157 records
                </div>
                <div className="flex items-center space-x-2">
                  <Button variant="outline" size="sm" disabled>
                    Previous
                  </Button>
                  <Button variant="outline" size="sm">
                    Next
                  </Button>
                </div>
              </CardFooter>
            </Card>
            
            <Card className="bg-cyber-gray border-cyber-darkgray">
              <CardHeader>
                <CardTitle className="text-lg">Audit Configuration</CardTitle>
                <CardDescription>
                  Configure audit logging retention and monitoring settings
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-cyber-darker p-4 rounded-md">
                    <h3 className="text-sm font-medium mb-2">Log Retention</h3>
                    <p className="text-xs text-cyber-lightgray">
                      Audit logs are currently kept for 365 days
                    </p>
                  </div>
                  
                  <div className="bg-cyber-darker p-4 rounded-md">
                    <h3 className="text-sm font-medium mb-2">Alerting</h3>
                    <p className="text-xs text-cyber-lightgray">
                      Alerts enabled for suspicious activity
                    </p>
                  </div>
                  
                  <div className="bg-cyber-darker p-4 rounded-md">
                    <h3 className="text-sm font-medium mb-2">Integrity</h3>
                    <p className="text-xs text-cyber-lightgray">
                      Cryptographic verification enabled
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          {/* Evidence Collection Tab */}
          <TabsContent value="evidence" className="space-y-4">
            <div className="flex justify-end mb-4">
              <Button 
                className="bg-cyber-accent hover:bg-cyber-accent/90 text-white"
                onClick={() => setShowEvidenceDialog(true)}
              >
                <Plus className="h-4 w-4 mr-1" />
                Add Evidence
              </Button>
            </div>
            
            <Card className="bg-cyber-gray border-cyber-darkgray">
              <CardHeader>
                <div className="flex justify-between items-center">
                  <div>
                    <CardTitle className="text-lg">Evidence Repository</CardTitle>
                    <CardDescription>
                      Manage collected evidence for compliance and audit purposes
                    </CardDescription>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="relative">
                      <Search className="h-4 w-4 absolute left-2 top-1/2 transform -translate-y-1/2 text-cyber-lightgray" />
                      <Input className="pl-8 h-8" placeholder="Search evidence..." />
                    </div>
                    <Select defaultValue="all">
                      <SelectTrigger className="w-[130px] h-8">
                        <SelectValue placeholder="Framework" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Frameworks</SelectItem>
                        <SelectItem value="gdpr">GDPR</SelectItem>
                        <SelectItem value="hipaa">HIPAA</SelectItem>
                        <SelectItem value="soc2">SOC 2</SelectItem>
                        <SelectItem value="iso27001">ISO 27001</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader className="bg-cyber-darker">
                    <TableRow>
                      <TableHead>Evidence Name</TableHead>
                      <TableHead>Related Control</TableHead>
                      <TableHead>Framework</TableHead>
                      <TableHead>Date Collected</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {evidenceItems.map((item) => (
                      <TableRow key={item.id}>
                        <TableCell>{item.name}</TableCell>
                        <TableCell>{item.relatedControl}</TableCell>
                        <TableCell>{item.framework}</TableCell>
                        <TableCell>{item.dateCollected}</TableCell>
                        <TableCell>
                          <Badge className={getStatusColor(item.status)}>
                            {item.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right space-x-1">
                          <Button size="icon" variant="ghost">
                            <Download className="h-4 w-4 text-cyber-accent" />
                          </Button>
                          <Button size="icon" variant="ghost">
                            <Edit className="h-4 w-4 text-cyber-accent" />
                          </Button>
                          <Button size="icon" variant="ghost">
                            <CheckCircle2 className="h-4 w-4 text-cyber-accent" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="bg-cyber-gray border-cyber-darkgray">
                <CardHeader>
                  <CardTitle className="text-lg">Evidence by Framework</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex justify-between items-center">
                        <span>GDPR</span>
                        <Badge className="bg-cyber-accent">8 items</Badge>
                      </div>
                      <div className="w-full bg-cyber-gray h-2 mt-2 rounded-full">
                        <div className="bg-cyber-accent h-2 rounded-full" style={{ width: '75%' }}></div>
                      </div>
                      <div className="text-xs text-cyber-lightgray mt-1">75% complete</div>
                    </div>
                    
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex justify-between items-center">
                        <span>HIPAA</span>
                        <Badge className="bg-cyber-accent">12 items</Badge>
                      </div>
                      <div className="w-full bg-cyber-gray h-2 mt-2 rounded-full">
                        <div className="bg-cyber-accent h-2 rounded-full" style={{ width: '90%' }}></div>
                      </div>
                      <div className="text-xs text-cyber-lightgray mt-1">90% complete</div>
                    </div>
                    
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex justify-between items-center">
                        <span>SOC 2</span>
                        <Badge className="bg-cyber-accent">15 items</Badge>
                      </div>
                      <div className="w-full bg-cyber-gray h-2 mt-2 rounded-full">
                        <div className="bg-cyber-accent h-2 rounded-full" style={{ width: '60%' }}></div>
                      </div>
                      <div className="text-xs text-cyber-lightgray mt-1">60% complete</div>
                    </div>
                    
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex justify-between items-center">
                        <span>ISO 27001</span>
                        <Badge className="bg-cyber-accent">10 items</Badge>
                      </div>
                      <div className="w-full bg-cyber-gray h-2 mt-2 rounded-full">
                        <div className="bg-cyber-accent h-2 rounded-full" style={{ width: '80%' }}></div>
                      </div>
                      <div className="text-xs text-cyber-lightgray mt-1">80% complete</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-gray border-cyber-darkgray">
                <CardHeader>
                  <CardTitle className="text-lg">Evidence Verification</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="bg-cyber-darker p-4 rounded-md">
                      <h3 className="text-sm font-medium mb-2 flex items-center">
                        <CheckCircle2 className="h-4 w-4 mr-2 text-cyber-accent" />
                        Verification Process
                      </h3>
                      <p className="text-xs text-cyber-lightgray">
                        All evidence is subject to a two-step verification process:
                      </p>
                      <ol className="list-decimal list-inside text-xs text-cyber-lightgray mt-2 space-y-1">
                        <li>Initial review by security analyst</li>
                        <li>Final verification by compliance officer</li>
                      </ol>
                    </div>
                    
                    <div className="bg-cyber-darker p-4 rounded-md">
                      <h3 className="text-sm font-medium mb-2">Current Status</h3>
                      <div className="flex flex-col space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-xs">Verified</span>
                          <span className="text-xs font-medium">35</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs">Pending Review</span>
                          <span className="text-xs font-medium">12</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs">Rejected</span>
                          <span className="text-xs font-medium">3</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
      
      {/* Generate Report Dialog */}
      <Dialog open={showReportDialog} onOpenChange={setShowReportDialog}>
        <DialogContent className="bg-cyber-gray text-white">
          <DialogHeader>
            <DialogTitle>Generate Compliance Report</DialogTitle>
            <DialogDescription>
              Create a new compliance report based on the selected template.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Report Name</label>
              <Input 
                placeholder="Enter report name"
                defaultValue={selectedTemplate ? complianceTemplates.find(t => t.id === selectedTemplate)?.name || '' : ''}
              />
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Report Period</label>
              <div className="flex space-x-2">
                <Input type="date" className="w-full" />
                <span className="flex items-center">to</span>
                <Input type="date" className="w-full" />
              </div>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Include Sections</label>
              <div className="bg-cyber-darker p-3 rounded-md max-h-40 overflow-y-auto">
                {selectedTemplate && complianceTemplates.find(t => t.id === selectedTemplate)?.sections.map((section, index) => (
                  <div key={index} className="flex items-center space-x-2 py-1">
                    <input type="checkbox" id={`section-${index}`} defaultChecked className="rounded" />
                    <label htmlFor={`section-${index}`} className="text-sm">{section}</label>
                  </div>
                ))}
              </div>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Output Format</label>
              <Select defaultValue="pdf">
                <SelectTrigger>
                  <SelectValue placeholder="Select format" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="pdf">PDF Document</SelectItem>
                  <SelectItem value="html">HTML Report</SelectItem>
                  <SelectItem value="xlsx">Excel Spreadsheet</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowReportDialog(false)}>
              Cancel
            </Button>
            <Button className="bg-cyber-accent text-white" onClick={handleGenerateNow}>
              Generate Now
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      
      {/* Schedule Report Dialog */}
      <Dialog open={showScheduleDialog} onOpenChange={setShowScheduleDialog}>
        <DialogContent className="bg-cyber-gray text-white">
          <DialogHeader>
            <DialogTitle>Schedule Compliance Report</DialogTitle>
            <DialogDescription>
              Set up automated generation of compliance reports.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Schedule Name</label>
              <Input placeholder="Enter schedule name" />
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Report Template</label>
              <Select defaultValue={selectedTemplate?.toString() || "1"}>
                <SelectTrigger>
                  <SelectValue placeholder="Select template" />
                </SelectTrigger>
                <SelectContent>
                  {complianceTemplates.map((template) => (
                    <SelectItem key={template.id} value={template.id.toString()}>
                      {template.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Frequency</label>
              <Select defaultValue="monthly">
                <SelectTrigger>
                  <SelectValue placeholder="Select frequency" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="daily">Daily</SelectItem>
                  <SelectItem value="weekly">Weekly</SelectItem>
                  <SelectItem value="monthly">Monthly</SelectItem>
                  <SelectItem value="quarterly">Quarterly</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Recipients</label>
              <Input placeholder="Enter email addresses (comma separated)" />
            </div>
            
            <div className="flex items-center space-x-2">
              <input type="checkbox" id="notify" className="rounded" />
              <label htmlFor="notify" className="text-sm">Notify me when reports are generated</label>
            </div>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowScheduleDialog(false)}>
              Cancel
            </Button>
            <Button className="bg-cyber-accent text-white" onClick={handleScheduleReport}>
              Schedule Report
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      
      {/* Add Evidence Dialog */}
      <Dialog open={showEvidenceDialog} onOpenChange={setShowEvidenceDialog}>
        <DialogContent className="bg-cyber-gray text-white">
          <DialogHeader>
            <DialogTitle>Add Evidence</DialogTitle>
            <DialogDescription>
              Upload and document evidence for compliance requirements.
            </DialogDescription>
          </DialogHeader>
          
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Evidence Name</label>
              <Input placeholder="Enter evidence name" />
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Description</label>
              <Textarea placeholder="Enter evidence description" />
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Related Framework</label>
              <Select defaultValue="gdpr">
                <SelectTrigger>
                  <SelectValue placeholder="Select framework" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="gdpr">GDPR</SelectItem>
                  <SelectItem value="hipaa">HIPAA</SelectItem>
                  <SelectItem value="soc2">SOC 2</SelectItem>
                  <SelectItem value="iso27001">ISO 27001</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Related Control</label>
              <Select defaultValue="access">
                <SelectTrigger>
                  <SelectValue placeholder="Select control" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="access">Access Control</SelectItem>
                  <SelectItem value="data">Data Protection</SelectItem>
                  <SelectItem value="hr">Human Resources</SelectItem>
                  <SelectItem value="incident">Incident Management</SelectItem>
                  <SelectItem value="risk">Risk Assessment</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <label className="text-sm font-medium">Evidence Files</label>
              <div className="border-2 border-dashed border-cyber-darkgray rounded-md p-6 text-center">
                <FolderArchive className="h-8 w-8 mx-auto mb-2 text-cyber-accent" />
                <p className="text-sm text-cyber-lightgray">
                  Drag and drop files here, or click to browse
                </p>
                <Button variant="outline" size="sm" className="mt-2">
                  Upload Files
                </Button>
              </div>
            </div>
          </div>
          
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowEvidenceDialog(false)}>
              Cancel
            </Button>
            <Button className="bg-cyber-accent text-white" onClick={handleAddEvidence}>
              Add Evidence
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
};

export default ComplianceReporting;
