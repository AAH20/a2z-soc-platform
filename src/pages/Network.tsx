
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Wifi, Globe, Server, AlertTriangle } from 'lucide-react';
import CustomProgress from '@/components/ui/custom-progress';

const NetworkPage: React.FC = () => {
  return (
      <div className="space-y-6 bg-slate-900 min-h-screen p-6">
        <div className="flex justify-between items-center">
          <h1 className="text-2xl font-bold text-white">Network Monitoring</h1>
        </div>

        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="grid grid-cols-4 w-full max-w-md">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="traffic">Traffic</TabsTrigger>
            <TabsTrigger value="devices">Devices</TabsTrigger>
            <TabsTrigger value="anomalies">Anomalies</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4 mt-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                    <Wifi className="h-5 w-5 text-cyber-accent" />
                    Network Status
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-300">Uptime</span>
                      <span className="text-sm text-white">99.8%</span>
                    </div>
                    <CustomProgress value={99.8} indicatorColor="#0EA5E9" />
                    
                    <div className="flex justify-between items-center mt-4">
                      <span className="text-sm text-gray-300">Current Traffic</span>
                      <span className="text-sm text-white">2.3 GB/s</span>
                    </div>
                    <CustomProgress value={65} indicatorColor="#10B981" />
                    
                    <div className="flex justify-between items-center mt-4">
                      <span className="text-sm text-gray-300">Connected Devices</span>
                      <span className="text-sm text-white">42</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                    <Globe className="h-5 w-5 text-cyber-warning" />
                    External Traffic
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-300">Inbound</span>
                      <span className="text-sm text-white">1.2 GB/s</span>
                    </div>
                    <CustomProgress value={70} indicatorColor="#F59E0B" />
                    
                    <div className="flex justify-between items-center mt-4">
                      <span className="text-sm text-gray-300">Outbound</span>
                      <span className="text-sm text-white">0.8 GB/s</span>
                    </div>
                    <CustomProgress value={45} indicatorColor="#0EA5E9" />
                    
                    <div className="flex justify-between items-center mt-4">
                      <span className="text-sm text-gray-300">Blocked Traffic</span>
                      <span className="text-sm text-white">0.3 GB/s</span>
                    </div>
                    <CustomProgress value={15} indicatorColor="#EF4444" />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-cyber-danger" />
                    Security Status
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-300">Detected Threats</span>
                      <span className="text-sm text-white">12</span>
                    </div>
                    <CustomProgress value={12} indicatorColor="#EF4444" />
                    
                    <div className="flex justify-between items-center mt-4">
                      <span className="text-sm text-gray-300">Blocked IPs</span>
                      <span className="text-sm text-white">47</span>
                    </div>
                    <CustomProgress value={47} indicatorColor="#F59E0B" />
                    
                    <div className="flex justify-between items-center mt-4">
                      <span className="text-sm text-gray-300">Suspicious Activity</span>
                      <span className="text-sm text-white">8</span>
                    </div>
                    <CustomProgress value={8} indicatorColor="#10B981" />
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                  <Server className="h-5 w-5 text-cyber-success" />
                  Network Topology
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-center p-12 border border-dashed border-cyber-lightgray rounded-md">
                  <p className="text-gray-400">Network topology visualization would be displayed here</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="traffic" className="space-y-4 mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardContent className="pt-6">
                <p className="text-center text-gray-400">Traffic analysis panel would be displayed here</p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="devices" className="space-y-4 mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardContent className="pt-6">
                <p className="text-center text-gray-400">Connected devices list would be displayed here</p>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="anomalies" className="space-y-4 mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardContent className="pt-6">
                <p className="text-center text-gray-400">Network anomalies detection panel would be displayed here</p>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
  );
};

export default NetworkPage;
