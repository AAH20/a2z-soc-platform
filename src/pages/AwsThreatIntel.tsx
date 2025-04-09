import React, { useState } from 'react';
import MainLayout from '@/components/layout/MainLayout';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
import {
  Cloud,
  Shield,
  AlertTriangle,
  Server,
  Database,
  Lock,
  Eye,
  ShieldCheck,
  FileWarning,
  Search,
  Bell,
  BarChart,
  Network as NetworkIcon, // Fixed import with alias
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const AwsThreatIntel: React.FC = () => {
  const [activeTab, setActiveTab] = useState('overview');

  return (
    <MainLayout>
      <div className="flex flex-col space-y-4">
        <div className="flex items-center gap-2">
          <Cloud className="h-6 w-6 text-cyber-accent" />
          <h1 className="text-2xl font-bold">AWS Threat Intelligence</h1>
        </div>

        <p className="text-cyber-lightgray mb-4">
          Integrated threat intelligence from AWS security services for comprehensive cloud protection.
        </p>

        <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="mb-4 w-full flex flex-wrap justify-start gap-2 bg-transparent">
            <TabsTrigger
              value="overview"
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <Shield className="h-4 w-4 mr-2" />
              Overview
            </TabsTrigger>
            <TabsTrigger
              value="cloudwatch"
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <Eye className="h-4 w-4 mr-2" />
              CloudWatch Integration
            </TabsTrigger>
            <TabsTrigger
              value="guardduty"
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <ShieldCheck className="h-4 w-4 mr-2" />
              GuardDuty Findings
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <Card className="bg-cyber-gray border-cyber-darkgray">
              <CardHeader>
                <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-cyber-accent" />
                      AWS Security Services Overview
                    </CardTitle>
                    <CardDescription className="mt-1">
                      Comprehensive security insights from AWS security services for advanced threat detection
                    </CardDescription>
                  </div>
                  <Badge variant="outline" className="border-cyber-danger text-cyber-danger">
                    Not Connected
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                  <div className="bg-cyber-darker p-4 rounded-md">
                    <div className="flex items-center space-x-3 mb-2">
                      <Eye className="h-5 w-5 text-cyber-accent" />
                      <h3 className="text-white font-medium">AWS CloudWatch</h3>
                    </div>
                    <p className="text-sm text-gray-300">
                      Monitor AWS resources and applications in real-time to identify and respond to system-wide performance 
                      changes and optimize resource utilization.
                    </p>
                    <Badge className="mt-2 bg-cyber-danger text-white">Not Connected</Badge>
                  </div>

                  <div className="bg-cyber-darker p-4 rounded-md">
                    <div className="flex items-center space-x-3 mb-2">
                      <ShieldCheck className="h-5 w-5 text-cyber-accent" />
                      <h3 className="text-white font-medium">AWS GuardDuty</h3>
                    </div>
                    <p className="text-sm text-gray-300">
                      Continuous security monitoring service that analyzes and processes logs to identify unexpected and 
                      potentially unauthorized or malicious activity.
                    </p>
                    <Badge className="mt-2 bg-cyber-danger text-white">Not Connected</Badge>
                  </div>

                  <div className="bg-cyber-darker p-4 rounded-md">
                    <div className="flex items-center space-x-3 mb-2">
                      <FileWarning className="h-5 w-5 text-cyber-accent" />
                      <h3 className="text-white font-medium">AWS Security Hub</h3>
                    </div>
                    <p className="text-sm text-gray-300">
                      Cloud security posture management service that aggregates, organizes, and prioritizes security alerts 
                      from multiple AWS services.
                    </p>
                    <Badge className="mt-2 bg-cyber-danger text-white">Not Connected</Badge>
                  </div>

                  <div className="bg-cyber-darker p-4 rounded-md">
                    <div className="flex items-center space-x-3 mb-2">
                      <Search className="h-5 w-5 text-cyber-accent" />
                      <h3 className="text-white font-medium">AWS Detective</h3>
                    </div>
                    <p className="text-sm text-gray-300">
                      Analyze and visualize security data to rapidly identify the root cause of potential security issues
                      or suspicious activities.
                    </p>
                    <Badge className="mt-2 bg-cyber-danger text-white">Not Connected</Badge>
                  </div>
                </div>

                <div className="bg-cyber-darker p-4 rounded-md mb-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <AlertTriangle className="h-5 w-5 text-cyber-warning" />
                    <h3 className="text-white font-medium">API Configuration Required</h3>
                  </div>
                  
                  <p className="text-gray-300 mb-4">
                    To integrate with AWS Threat Intelligence, you need to configure AWS credentials with appropriate permissions
                    for accessing security services. This integration provides access to AWS security findings and insights.
                  </p>
                  
                  <div className="space-y-4 mb-6">
                    <div className="space-y-2">
                      <label className="text-sm text-gray-400">AWS Access Key ID</label>
                      <Input 
                        type="text" 
                        placeholder="Enter your AWS Access Key ID" 
                        className="bg-cyber-gray border-cyber-lightgray text-white"
                      />
                    </div>
                    
                    <div className="space-y-2">
                      <label className="text-sm text-gray-400">AWS Secret Access Key</label>
                      <Input 
                        type="password" 
                        placeholder="Enter your AWS Secret Access Key" 
                        className="bg-cyber-gray border-cyber-lightgray text-white"
                      />
                    </div>
                    
                    <div className="space-y-2">
                      <label className="text-sm text-gray-400">AWS Region</label>
                      <Input 
                        type="text" 
                        placeholder="e.g., us-east-1" 
                        className="bg-cyber-gray border-cyber-lightgray text-white"
                      />
                    </div>
                  </div>
                  
                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20">
                      Test Connection
                    </Button>
                    <Button className="bg-cyber-accent hover:bg-cyber-accent/80">
                      Connect
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="cloudwatch" className="space-y-4">
            <Card className="bg-cyber-gray border-cyber-darkgray">
              <CardHeader>
                <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Eye className="h-5 w-5 text-cyber-accent" />
                      AWS CloudWatch Integration
                    </CardTitle>
                    <CardDescription className="mt-1">
                      Monitor and respond to AWS resource metrics, logs, and events in real-time
                    </CardDescription>
                  </div>
                  <Badge variant="outline" className="border-cyber-danger text-cyber-danger">
                    Not Connected
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="bg-cyber-darker p-4 rounded-md mb-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <AlertTriangle className="h-5 w-5 text-cyber-warning" />
                    <h3 className="text-white font-medium">CloudWatch Integration Setup</h3>
                  </div>
                  
                  <p className="text-gray-300 mb-4">
                    Connect to AWS CloudWatch to monitor your AWS resources and applications in real-time. 
                    This integration provides access to metrics, logs, events, and alarms for comprehensive monitoring.
                  </p>
                  
                  <div className="space-y-4 mb-6">
                    <div className="space-y-2">
                      <label className="text-sm text-gray-400">AWS CloudWatch Endpoint</label>
                      <Input 
                        type="text" 
                        placeholder="https://monitoring.[region].amazonaws.com" 
                        className="bg-cyber-gray border-cyber-lightgray text-white"
                      />
                    </div>
                    
                    <div className="space-y-2">
                      <label className="text-sm text-gray-400">Metrics Polling Interval (seconds)</label>
                      <Input 
                        type="number" 
                        placeholder="60" 
                        className="bg-cyber-gray border-cyber-lightgray text-white"
                      />
                    </div>
                    
                    <div className="space-y-2">
                      <label className="text-sm text-gray-400">Log Group Pattern</label>
                      <Input 
                        type="text" 
                        placeholder="/aws/lambda/*, /aws/ec2/*" 
                        className="bg-cyber-gray border-cyber-lightgray text-white"
                      />
                    </div>
                  </div>
                  
                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20">
                      Test CloudWatch API
                    </Button>
                    <Button className="bg-cyber-accent hover:bg-cyber-accent/80">
                      Connect CloudWatch
                    </Button>
                  </div>
                </div>

                <div className="mt-6">
                  <h3 className="text-lg font-medium text-white mb-4">CloudWatch Features</h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <BarChart className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">Metrics Integration</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Collect and track metrics for AWS resources and custom applications
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <Database className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">Logs Integration</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Centralize and monitor logs from applications and AWS services
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <Bell className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">Alarms Integration</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Set up alerts based on metric thresholds and log patterns
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="mt-6 p-4 bg-cyber-darker rounded-md border border-cyber-darkgray">
                  <h3 className="text-lg font-medium text-white mb-3">Security Monitoring with CloudWatch</h3>
                  <p className="text-sm text-gray-300 mb-4">
                    CloudWatch helps monitor security-relevant metrics and logs across your AWS infrastructure:
                  </p>
                  
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="bg-cyber-gray p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <Server className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">EC2 Instance Monitoring</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Track CPU usage, network traffic, and disk I/O for unusual patterns
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-gray p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <Shield className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">VPC Flow Logs</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Monitor network traffic patterns and identify potential security threats
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-gray p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <Lock className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">IAM Activity Tracking</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Monitor AWS account activity and authentication events
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-gray p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <Cloud className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">API Activity Monitoring</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Track AWS API calls for unauthorized or suspicious activity
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="guardduty" className="space-y-4">
            <Card className="bg-cyber-gray border-cyber-darkgray">
              <CardHeader>
                <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <ShieldCheck className="h-5 w-5 text-cyber-accent" />
                      AWS GuardDuty Findings
                    </CardTitle>
                    <CardDescription className="mt-1">
                      View and analyze threat intelligence findings from AWS GuardDuty
                    </CardDescription>
                  </div>
                  <Badge variant="outline" className="border-cyber-danger text-cyber-danger">
                    Not Connected
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="bg-cyber-darker p-4 rounded-md mb-6">
                  <div className="flex items-center space-x-3 mb-4">
                    <AlertTriangle className="h-5 w-5 text-cyber-warning" />
                    <h3 className="text-white font-medium">Connect to GuardDuty</h3>
                  </div>
                  
                  <p className="text-gray-300 mb-4">
                    AWS GuardDuty continuously monitors for malicious behavior and unauthorized activity to protect your AWS accounts, 
                    workloads, and data. Connect to view and analyze GuardDuty findings.
                  </p>
                  
                  <div className="flex justify-end space-x-2">
                    <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20">
                      Test GuardDuty API
                    </Button>
                    <Button className="bg-cyber-accent hover:bg-cyber-accent/80">
                      Connect GuardDuty
                    </Button>
                  </div>
                </div>

                <div className="mt-6">
                  <h3 className="text-lg font-medium text-white mb-4">GuardDuty Finding Types</h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <Server className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">EC2 Finding Types</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Detect unusual behavior in EC2 instances including cryptocurrency mining, backdoors, and unusual API calls
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <Shield className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">IAM Finding Types</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Identify suspicious authentication behavior, credential exfiltration, and unauthorized access attempts
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <Database className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">S3 Finding Types</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Detect potentially malicious or suspicious S3 bucket activity including data exfiltration attempts
                          </p>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1 flex-shrink-0">
                          <NetworkIcon className="h-5 w-5 text-cyber-accent" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium text-sm">Network Finding Types</h4>
                          <p className="text-xs text-gray-400 mt-1">
                            Identify suspicious traffic patterns, port scanning, and communication with malicious IP addresses
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="mt-6 p-4 bg-cyber-darker rounded-md border border-cyber-darkgray">
                  <h3 className="text-lg font-medium text-white mb-3">GuardDuty Threat Intelligence</h3>
                  <p className="text-sm text-gray-300 mb-4">
                    GuardDuty incorporates threat intelligence from AWS and third-party sources to identify malicious activity:
                  </p>
                  
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="bg-cyber-gray p-3 rounded-md">
                      <h4 className="text-white font-medium text-sm">IP Address Reputation Lists</h4>
                      <p className="text-xs text-gray-400 mt-1">
                        Detect communication with known malicious IP addresses
                      </p>
                    </div>
                    
                    <div className="bg-cyber-gray p-3 rounded-md">
                      <h4 className="text-white font-medium text-sm">Domain Generation Algorithms</h4>
                      <p className="text-xs text-gray-400 mt-1">
                        Identify communication with domains generated by malware
                      </p>
                    </div>
                    
                    <div className="bg-cyber-gray p-3 rounded-md">
                      <h4 className="text-white font-medium text-sm">Machine Learning Models</h4>
                      <p className="text-xs text-gray-400 mt-1">
                        Detect anomalous behavior based on historical activity patterns
                      </p>
                    </div>
                    
                    <div className="bg-cyber-gray p-3 rounded-md">
                      <h4 className="text-white font-medium text-sm">Threat Intelligence Feeds</h4>
                      <p className="text-xs text-gray-400 mt-1">
                        Incorporate commercial and open-source threat intelligence
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
};

export default AwsThreatIntel;
