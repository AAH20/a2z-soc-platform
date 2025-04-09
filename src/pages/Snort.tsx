
import React from 'react';
import MainLayout from '@/components/layout/MainLayout';
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
  ActivitySquare, 
  RefreshCcw, 
  Settings, 
  Network, 
  BarChart, 
  FileText,
  Layers,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';

const Snort: React.FC = () => {
  return (
    <MainLayout>
      <div className="px-2">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Snort Integration</h1>
            <p className="text-gray-400">Network intrusion detection with Snort IDS</p>
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
                <ActivitySquare className="h-5 w-5 text-cyber-accent" />
                <CardTitle className="text-lg font-medium text-white">Snort IDS Status</CardTitle>
              </div>
              <Badge className="bg-cyber-success">Connected</Badge>
            </div>
            <CardDescription className="text-gray-400">
              Snort v3.1.0 - Last sync: 10 minutes ago
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="bg-cyber-darker p-4 rounded-md">
                <div className="flex items-center space-x-2 mb-2">
                  <Network className="h-4 w-4 text-cyber-accent" />
                  <h3 className="font-medium text-white">Network Monitoring</h3>
                </div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="text-gray-400">Interfaces:</div>
                  <div className="text-white">4 Active</div>
                  <div className="text-gray-400">Traffic Rate:</div>
                  <div className="text-white">156 Mbps</div>
                  <div className="text-gray-400">Packets Analyzed:</div>
                  <div className="text-white">1.2M / min</div>
                  <div className="text-gray-400">Coverage:</div>
                  <div className="text-white">87%</div>
                </div>
              </div>
              
              <div className="bg-cyber-darker p-4 rounded-md">
                <div className="flex items-center space-x-2 mb-2">
                  <AlertTriangle className="h-4 w-4 text-cyber-accent" />
                  <h3 className="font-medium text-white">Rule Statistics</h3>
                </div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="text-gray-400">Total Rules:</div>
                  <div className="text-white">15,482</div>
                  <div className="text-gray-400">Custom Rules:</div>
                  <div className="text-white">156</div>
                  <div className="text-gray-400">Disabled Rules:</div>
                  <div className="text-white">324</div>
                  <div className="text-gray-400">Last Updated:</div>
                  <div className="text-white">Today, 08:45</div>
                </div>
              </div>
              
              <div className="bg-cyber-darker p-4 rounded-md">
                <div className="flex items-center space-x-2 mb-2">
                  <BarChart className="h-4 w-4 text-cyber-accent" />
                  <h3 className="font-medium text-white">Alert Statistics</h3>
                </div>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  <div className="text-gray-400">Total Alerts (24h):</div>
                  <div className="text-white">863</div>
                  <div className="text-gray-400">High Priority:</div>
                  <div className="text-white">42</div>
                  <div className="text-gray-400">Medium Priority:</div>
                  <div className="text-white">187</div>
                  <div className="text-gray-400">Low Priority:</div>
                  <div className="text-white">634</div>
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
              value="traffic" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Traffic Analysis
            </TabsTrigger>
            <TabsTrigger 
              value="interfaces" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Interfaces
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="rules" className="mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg font-medium text-white">Snort Rules</CardTitle>
                  <div className="flex items-center space-x-2">
                    <Input 
                      placeholder="Search rules..." 
                      className="h-8 bg-cyber-darker border-cyber-lightgray text-white w-56"
                    />
                    <Badge className="bg-cyber-accent">15,482 Rules</Badge>
                  </div>
                </div>
                <CardDescription className="text-gray-400">
                  Snort rules used to detect malicious network traffic
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    { sid: '2001219', description: 'ET EXPLOIT Possible MS17-010 SMB Exploit Attempt', priority: 1, category: 'exploit-kit', enabled: true },
                    { sid: '2403324', description: 'ET MALWARE Ransomware C2 Communication Detected', priority: 1, category: 'malware', enabled: true },
                    { sid: '2402580', description: 'ET SCAN NMAP UDP Scan Detected', priority: 2, category: 'scan', enabled: true },
                    { sid: '2023754', description: 'ET POLICY Bitcoin Miner Activity', priority: 2, category: 'policy', enabled: true },
                    { sid: '2012087', description: 'ET DOS SYN Flood Inbound', priority: 1, category: 'dos', enabled: false },
                  ].map((rule) => (
                    <div key={rule.sid} className="p-3 bg-cyber-darker rounded-md">
                      <div className="flex justify-between items-start">
                        <div>
                          <div className="flex items-center space-x-2">
                            <Badge variant="outline" className="bg-transparent border-cyber-accent text-cyber-accent">
                              SID {rule.sid}
                            </Badge>
                            <Badge className={
                              rule.priority === 1 ? 'bg-cyber-danger' :
                              rule.priority === 2 ? 'bg-cyber-warning' :
                              'bg-cyber-success'
                            }>
                              P{rule.priority}
                            </Badge>
                            {!rule.enabled && (
                              <Badge variant="outline" className="bg-transparent border-cyber-danger text-cyber-danger">
                                Disabled
                              </Badge>
                            )}
                          </div>
                          <p className="text-white mt-1">{rule.description}</p>
                        </div>
                        <Button variant="ghost" size="sm" className="text-gray-400 hover:text-white hover:bg-cyber-lightgray/20">
                          View Details
                        </Button>
                      </div>
                      <div className="flex flex-wrap gap-1 mt-2">
                        <span className="text-xs px-1.5 py-0.5 bg-cyber-gray rounded text-gray-300">
                          {rule.category}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="traffic" className="mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white">Traffic Analysis</CardTitle>
                <CardDescription className="text-gray-400">
                  Real-time network traffic analysis
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {/* Traffic analysis content */}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="interfaces" className="mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-lg font-medium text-white">Network Interfaces</CardTitle>
                <CardDescription className="text-gray-400">
                  Configure network interfaces for monitoring
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {/* Network interfaces content */}
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
              Configure the integration between CALDERA and Snort IDS
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="bg-cyber-darker p-4 rounded-md">
                <h3 className="font-medium text-white mb-2">Connection Settings</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">Snort Server IP</label>
                    <Input 
                      value="192.168.1.50" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">API Port</label>
                    <Input 
                      value="8080" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">API Key</label>
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
                      value="10" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                </div>
              </div>
              
              <div className="bg-cyber-darker p-4 rounded-md">
                <h3 className="font-medium text-white mb-2">Alert Forwarding</h3>
                <div className="flex items-center space-x-2 mb-4 text-sm">
                  <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                  <span className="text-gray-300">Snort alerts are being forwarded to CALDERA for correlation</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">Minimum Priority</label>
                    <Input 
                      type="number" 
                      value="2" 
                      className="bg-cyber-gray border-cyber-lightgray text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm text-gray-400">Alert Categories</label>
                    <Input 
                      value="exploit,malware,scan,dos" 
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
                The Snort integration allows CALDERA to leverage Snort's network intrusion detection capabilities for enhanced threat detection. This integration provides:
              </p>
              <ul className="list-disc pl-5 space-y-1 text-gray-300">
                <li>Real-time network traffic monitoring and analysis</li>
                <li>Detection of malicious network activity during simulated attacks</li>
                <li>Validation of network-based detection rules</li>
                <li>Enhanced visibility into lateral movement and network-based threats</li>
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
    </MainLayout>
  );
};

export default Snort;
