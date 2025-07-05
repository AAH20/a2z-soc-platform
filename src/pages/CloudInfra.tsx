import React, { useState } from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { CloudCog, Server, Database, Network, Code, RefreshCcw, Settings } from 'lucide-react';
import CloudCredentialsManager from '@/components/cloud-infra/CloudCredentialsManager';

const CloudInfra: React.FC = () => {
  const [activeTab, setActiveTab] = useState("settings");
  const [isLoading, setIsLoading] = useState(false);

  const fetchResources = async (provider: string, resourceType: string) => {
    setIsLoading(true);
    try {
      // In a real implementation, this would fetch data from the backend API
      console.log(`Fetching ${resourceType} from ${provider}`);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));
      setIsLoading(false);
    } catch (error) {
      console.error('Error fetching resources:', error);
      setIsLoading(false);
    }
  };

  return (
      <div className="px-2">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Multi-Cloud Infrastructure</h1>
            <p className="text-gray-400">Manage and monitor resources across AWS, Azure, and Google Cloud</p>
          </div>
          <div className="flex space-x-2">
            <Button 
              variant="outline" 
              className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20"
              onClick={() => fetchResources('all', 'all')}
              disabled={isLoading}
            >
              <RefreshCcw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button 
              className="bg-cyber-accent hover:bg-cyber-accent/80"
              onClick={() => setActiveTab('settings')}
            >
              <Settings className="h-4 w-4 mr-2" />
              Settings
            </Button>
          </div>
        </div>

        <Tabs defaultValue="settings" value={activeTab} onValueChange={setActiveTab} className="w-full mb-6">
          <TabsList className="bg-cyber-darker mb-4">
            <TabsTrigger 
              value="settings" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <CloudCog className="h-4 w-4 mr-2" />
              Credentials
            </TabsTrigger>
            <TabsTrigger 
              value="compute" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <Server className="h-4 w-4 mr-2" />
              Compute
            </TabsTrigger>
            <TabsTrigger 
              value="containers" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <Database className="h-4 w-4 mr-2" />
              Containers
            </TabsTrigger>
            <TabsTrigger 
              value="serverless" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <Code className="h-4 w-4 mr-2" />
              Serverless
            </TabsTrigger>
            <TabsTrigger 
              value="networking" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              <Network className="h-4 w-4 mr-2" />
              Networking
            </TabsTrigger>
          </TabsList>
          
          {/* Settings/Credentials Tab */}
          <TabsContent value="settings">
            <CloudCredentialsManager />
          </TabsContent>
          
          {/* Compute Tab - VMs */}
          <TabsContent value="compute">
            <Card className="bg-cyber-gray border-cyber-lightgray mb-4">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Server className="h-5 w-5 text-cyber-accent" />
                    <CardTitle className="text-lg font-medium text-white">Virtual Machines</CardTitle>
                  </div>
                  <Badge className="bg-cyber-info">Multi-Cloud</Badge>
                </div>
                <CardDescription className="text-gray-400">
                  Manage virtual machines across AWS EC2, Azure VMs, and Google Cloud Compute Engine
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-12 text-gray-400">
                  <p>Configure cloud provider credentials first to view your virtual machines</p>
                  <Button 
                    variant="outline" 
                    className="mt-4 border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20"
                    onClick={() => setActiveTab('settings')}
                  >
                    <CloudCog className="h-4 w-4 mr-2" />
                    Configure Credentials
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          {/* Containers Tab */}
          <TabsContent value="containers">
            <Card className="bg-cyber-gray border-cyber-lightgray mb-4">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Database className="h-5 w-5 text-cyber-accent" />
                    <CardTitle className="text-lg font-medium text-white">Container Services</CardTitle>
                  </div>
                  <Badge className="bg-cyber-info">Multi-Cloud</Badge>
                </div>
                <CardDescription className="text-gray-400">
                  Manage container services across AWS ECS/EKS, Azure AKS, and Google Cloud GKE
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-12 text-gray-400">
                  <p>Configure cloud provider credentials first to view your container services</p>
                  <Button 
                    variant="outline" 
                    className="mt-4 border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20"
                    onClick={() => setActiveTab('settings')}
                  >
                    <CloudCog className="h-4 w-4 mr-2" />
                    Configure Credentials
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          {/* Serverless Tab */}
          <TabsContent value="serverless">
            <Card className="bg-cyber-gray border-cyber-lightgray mb-4">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Code className="h-5 w-5 text-cyber-accent" />
                    <CardTitle className="text-lg font-medium text-white">Serverless Functions</CardTitle>
                  </div>
                  <Badge className="bg-cyber-info">Multi-Cloud</Badge>
                </div>
                <CardDescription className="text-gray-400">
                  Manage serverless functions across AWS Lambda, Azure Functions, and Google Cloud Functions
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-12 text-gray-400">
                  <p>Configure cloud provider credentials first to view your serverless functions</p>
                  <Button 
                    variant="outline" 
                    className="mt-4 border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20"
                    onClick={() => setActiveTab('settings')}
                  >
                    <CloudCog className="h-4 w-4 mr-2" />
                    Configure Credentials
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          {/* Networking Tab */}
          <TabsContent value="networking">
            <Card className="bg-cyber-gray border-cyber-lightgray mb-4">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Network className="h-5 w-5 text-cyber-accent" />
                    <CardTitle className="text-lg font-medium text-white">Networking Components</CardTitle>
                  </div>
                  <Badge className="bg-cyber-info">Multi-Cloud</Badge>
                </div>
                <CardDescription className="text-gray-400">
                  Manage VPCs, subnets, security groups, and other networking components across cloud providers
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-12 text-gray-400">
                  <p>Configure cloud provider credentials first to view your networking components</p>
                  <Button 
                    variant="outline" 
                    className="mt-4 border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20"
                    onClick={() => setActiveTab('settings')}
                  >
                    <CloudCog className="h-4 w-4 mr-2" />
                    Configure Credentials
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
  );
};

export default CloudInfra; 