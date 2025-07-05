
import React from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { 
  ShieldAlert, 
  RefreshCcw, 
  Settings, 
  Server, 
  BarChart, 
  Shield, 
  Layers, 
  FileText,
  CheckCircle2
} from 'lucide-react';

const Wazuh: React.FC = () => {
  return (
      <div className="px-2">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Wazuh Integration</h1>
            <p className="text-gray-400">Security monitoring and threat detection with Wazuh</p>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20">
              <RefreshCcw className="h-4 w-4 mr-2" />
              Sync
            </Button>
            <Button className="bg-cyber-accent hover:bg-cyber-accent/80">
              <Settings className="h-4 w-4 mr-2" />
              Configure
            </Button>
          </div>
        </div>

        <Card className="bg-cyber-gray border-cyber-lightgray mb-6">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="h-5 w-5 text-cyber-accent" />
                <CardTitle className="text-lg font-medium text-white">Wazuh Server Status</CardTitle>
              </div>
              <Badge className="bg-cyber-success">Connected</Badge>
            </div>
            <CardDescription className="text-gray-400">
              Wazuh Manager v4.3.8 - Last sync: 5 minutes ago
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="bg-cyber-darker p-4 rounded-md">
                <div className="flex items-center space-x-2 mb-2">
                  <Server className="h-4 w-4 text-cyber-accent" />
                  <h3 className="font-medium text-white">Server Health</h3>
                </div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="text-gray-400">CPU Usage:</div>
                  <div className="text-white">24%</div>
                  <div className="text-gray-400">Memory:</div>
                  <div className="text-white">1.8 GB / 8 GB</div>
                  <div className="text-gray-400">Disk:</div>
                  <div className="text-white">42% Used</div>
                  <div className="text-gray-400">Uptime:</div>
                  <div className="text-white">15 days</div>
                </div>
              </div>
              
              <div className="bg-cyber-darker p-4 rounded-md">
                <div className="flex items-center space-x-2 mb-2">
                  <Shield className="h-4 w-4 text-cyber-accent" />
                  <h3 className="font-medium text-white">Agent Status</h3>
                </div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="text-gray-400">Total Agents:</div>
                  <div className="text-white">42</div>
                  <div className="text-gray-400">Active:</div>
                  <div className="text-white">36</div>
                  <div className="text-gray-400">Disconnected:</div>
                  <div className="text-white">4</div>
                  <div className="text-gray-400">Never Connected:</div>
                  <div className="text-white">2</div>
                </div>
              </div>
              
              <div className="bg-cyber-darker p-4 rounded-md">
                <div className="flex items-center space-x-2 mb-2">
                  <BarChart className="h-4 w-4 text-cyber-accent" />
                  <h3 className="font-medium text-white">Alert Statistics</h3>
                </div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="text-gray-400">Total Alerts (24h):</div>
                  <div className="text-white">1,245</div>
                  <div className="text-gray-400">High Severity:</div>
                  <div className="text-white">78</div>
                  <div className="text-gray-400">Medium Severity:</div>
                  <div className="text-white">246</div>
                  <div className="text-gray-400">Low Severity:</div>
                  <div className="text-white">921</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Tabs defaultValue="rules" className="mb-6">
          <TabsList className="bg-cyber-darker">
            <TabsTrigger 
              value="rules" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Rules
            </TabsTrigger>
            <TabsTrigger 
              value="decoders" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Decoders
            </TabsTrigger>
            <TabsTrigger 
              value="groups" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Groups
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="rules" className="mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg font-medium text-white">Wazuh Rules</CardTitle>
                  <div className="flex items-center space-x-2">
                    <Input 
                      placeholder="Search rules..." 
                      className="h-8 bg-cyber-darker border-cyber-lightgray text-white w-56"
                    />
                    <Badge className="bg-cyber-accent">1,284 Rules</Badge>
                  </div>
                </div>
                <CardDescription className="text-gray-400">
                  Rules used to analyze and identify threats in your environment
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    { id: '100150', description: 'Successful sudo to ROOT executed', level: 10, groups: ['sudo', 'authentication_success'] },
                    { id: '80790', description: 'Firewall drop event from internal source IP', level: 12, groups: ['firewall', 'pci_dss_1.4'] },
                    { id: '60125', description: 'Multiple authentication failures', level: 10, groups: ['authentication_failed', 'pci_dss_10.2.4'] },
                    { id: '91015', description: 'Sensitive file modification', level: 9, groups: ['file_modification', 'integrity_monitoring'] },
                    { id: '40758', description: 'Suspicious shell command execution', level: 12, groups: ['command', 'pci_dss_10.2.7'] },
                  ].map((rule) => (
                    <div key={rule.id} className="p-3 bg-cyber-darker rounded-md">
                      <div className="flex justify-between items-start">
                        <div>
                          <div className="flex items-center space-x-2">
                            <Badge variant="outline" className="bg-transparent border-cyber-accent text-cyber-accent">
                              Rule {rule.id}
                            </Badge>
                            <Badge className={
                              rule.level >= 12 ? 'bg-cyber-danger' :
                              rule.level >= 8 ? 'bg-cyber-warning' :
                              'bg-cyber-success'
                            }>
                              Level {rule.level}
                            </Badge>
                          </div>
                          <p className="text-white mt-1">{rule.description}</p>
                        </div>
                        <Button variant="ghost" size="sm" className="text-gray-400 hover:text-white hover:bg-cyber-lightgray/20">
                          View Details
                        </Button>
                      </div>
                      <div className="flex flex-wrap gap-1 mt-2">
                        {rule.groups.map((group) => (
                          <span key={group} className="text-xs px-1.5 py-0.5 bg-cyber-gray rounded text-gray-300">
                            {group}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="decoders" className="mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white">Wazuh Decoders</CardTitle>
                <CardDescription className="text-gray-400">
                  Decoders used to parse and extract information from logs
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {/* Similar structure to rules */}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="groups" className="mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white">Agent Groups</CardTitle>
                <CardDescription className="text-gray-400">
                  Manage agent groups and their configurations
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {/* Agent groups content */}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        <Card className="bg-cyber-gray border-cyber-lightgray mb-6">
          <CardHeader className="pb-2">
            <div className="flex items-center space-x-2">
              <Layers className="h-5 w-5 text-cyber-accent" />
              <CardTitle className="text-lg font-medium text-white">Integration Configuration</CardTitle>
            </div>
            <CardDescription className="text-gray-400">
              Configure the integration between CALDERA and Wazuh
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="bg-cyber-darker p-4 rounded-md">
                <h3 className="font-medium text-white mb-2">Connection Settings</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">Wazuh API URL</label>
                    <Input 
                      value="https://wazuh-manager:55000" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">API Username</label>
                    <Input 
                      value="wazuh-api-user" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">API Password</label>
                    <Input 
                      type="password" 
                      value="••••••••••••" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">Sync Interval (minutes)</label>
                    <Input 
                      type="number" 
                      value="5" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                </div>
              </div>
              
              <div className="bg-cyber-darker p-4 rounded-md">
                <h3 className="font-medium text-white mb-2">Alert Forwarding</h3>
                <div className="flex items-center space-x-2 mb-4 text-sm">
                  <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                  <span className="text-gray-300">Wazuh alerts are being forwarded to CALDERA for correlation</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">Minimum Alert Level</label>
                    <Input 
                      type="number" 
                      value="7" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">Alert Categories</label>
                    <Input 
                      value="pci_dss,authentication,syscheck" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                </div>
              </div>
              
              <div className="flex justify-end space-x-2">
                <Button variant="outline" className="border-cyber-lightgray text-white hover:bg-cyber-lightgray/20">
                  Test Connection
                </Button>
                <Button className="bg-cyber-accent hover:bg-cyber-accent/80">
                  Save Configuration
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-cyber-gray border-cyber-lightgray">
          <CardHeader className="pb-2">
            <div className="flex items-center space-x-2">
              <FileText className="h-5 w-5 text-cyber-accent" />
              <CardTitle className="text-lg font-medium text-white">Documentation</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <p className="text-gray-300">
                The Wazuh integration allows CALDERA to leverage Wazuh's security monitoring capabilities for enhanced threat detection and response. This integration provides:
              </p>
              <ul className="list-disc pl-5 space-y-1 text-gray-300">
                <li>Real-time security event monitoring with Wazuh agents</li>
                <li>Correlation between simulated attacks and detected events</li>
                <li>Validation of detection rules and policies</li>
                <li>Enhanced visibility across your security infrastructure</li>
              </ul>
              <p className="text-gray-300">
                For more details on configuring and using this integration, refer to the complete documentation.
              </p>
              <div className="flex justify-start">
                <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20">
                  View Full Documentation
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
  );
};

export default Wazuh;
