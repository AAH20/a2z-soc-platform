
import React, { useState } from 'react';
import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle 
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Search, 
  PlusCircle, 
  Server, 
  Laptop, 
  Wifi, 
  CircleSlash, 
  RefreshCcw,
  ChevronDown
} from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface Agent {
  id: string;
  name: string;
  ipAddress: string;
  status: 'active' | 'inactive' | 'disconnected';
  type: 'server' | 'workstation' | 'network';
  os: string;
  lastSeen: string;
  groups: string[];
}

const agentsData: Agent[] = [
  {
    id: 'AGT-001',
    name: 'WEB-SERVER-PROD-01',
    ipAddress: '192.168.1.10',
    status: 'active',
    type: 'server',
    os: 'Ubuntu 20.04 LTS',
    lastSeen: '2 mins ago',
    groups: ['production', 'web-servers']
  },
  {
    id: 'AGT-002',
    name: 'DB-SERVER-PROD-01',
    ipAddress: '192.168.1.11',
    status: 'active',
    type: 'server',
    os: 'CentOS 8',
    lastSeen: '5 mins ago',
    groups: ['production', 'database']
  },
  {
    id: 'AGT-003',
    name: 'WORKSTATION-HR-01',
    ipAddress: '192.168.2.15',
    status: 'inactive',
    type: 'workstation',
    os: 'Windows 10 Pro',
    lastSeen: '2 days ago',
    groups: ['hr-department', 'windows']
  },
  {
    id: 'AGT-004',
    name: 'LAPTOP-DEV-05',
    ipAddress: '192.168.3.25',
    status: 'active',
    type: 'workstation',
    os: 'macOS 12.0.1',
    lastSeen: '30 mins ago',
    groups: ['development', 'laptops']
  },
  {
    id: 'AGT-005',
    name: 'ROUTER-EDGE-01',
    ipAddress: '192.168.0.1',
    status: 'active',
    type: 'network',
    os: 'Cisco IOS 15.2',
    lastSeen: '15 mins ago',
    groups: ['network', 'edge-devices']
  },
  {
    id: 'AGT-006',
    name: 'FILE-SERVER-BACKUP',
    ipAddress: '192.168.1.20',
    status: 'disconnected',
    type: 'server',
    os: 'Windows Server 2019',
    lastSeen: '5 days ago',
    groups: ['backup', 'file-servers']
  },
];

const Agents: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState('all');
  
  const filteredAgents = agentsData.filter(agent => {
    // Filter by search term
    const matchesSearch = 
      agent.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      agent.ipAddress.includes(searchTerm) ||
      agent.id.toLowerCase().includes(searchTerm.toLowerCase());
    
    // Filter by tab
    if (activeTab === 'all') return matchesSearch;
    if (activeTab === 'active') return matchesSearch && agent.status === 'active';
    if (activeTab === 'inactive') return matchesSearch && agent.status === 'inactive';
    if (activeTab === 'disconnected') return matchesSearch && agent.status === 'disconnected';
    
    return matchesSearch;
  });

  const getAgentTypeIcon = (type: Agent['type']) => {
    switch (type) {
      case 'server':
        return <Server className="h-4 w-4 text-cyber-accent" />;
      case 'workstation':
        return <Laptop className="h-4 w-4 text-cyber-accent" />;
      case 'network':
        return <Wifi className="h-4 w-4 text-cyber-accent" />;
    }
  };

  const getStatusBadge = (status: Agent['status']) => {
    switch (status) {
      case 'active':
        return <Badge className="bg-cyber-success text-white">Active</Badge>;
      case 'inactive':
        return <Badge className="bg-cyber-warning text-white">Inactive</Badge>;
      case 'disconnected':
        return <Badge className="bg-cyber-danger text-white">Disconnected</Badge>;
    }
  };

  return (
      <div className="px-2">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Agent Management</h1>
            <p className="text-gray-400">Deploy and manage agents across your infrastructure</p>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20">
              <RefreshCcw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            <Button className="bg-cyber-accent hover:bg-cyber-accent/80">
              <PlusCircle className="h-4 w-4 mr-2" />
              Deploy Agent
            </Button>
          </div>
        </div>
        
        <Card className="bg-cyber-gray border-cyber-lightgray mb-6">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg font-medium text-white">Agents</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col md:flex-row justify-between mb-4 space-y-4 md:space-y-0 md:space-x-4">
              <div className="relative flex-1">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search agents by name, IP or ID..."
                  className="pl-8 bg-cyber-darker border-cyber-lightgray text-white"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              <div className="flex space-x-2">
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" className="border-cyber-lightgray text-white hover:bg-cyber-lightgray/20">
                      Group Filter
                      <ChevronDown className="ml-2 h-4 w-4 text-gray-400" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent className="bg-cyber-darker border-cyber-lightgray">
                    <DropdownMenuLabel className="text-gray-300">Filter by Group</DropdownMenuLabel>
                    <DropdownMenuSeparator className="bg-cyber-lightgray" />
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">All Groups</DropdownMenuItem>
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">Production</DropdownMenuItem>
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">Development</DropdownMenuItem>
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">Web Servers</DropdownMenuItem>
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">Backup</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
                
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="outline" className="border-cyber-lightgray text-white hover:bg-cyber-lightgray/20">
                      OS Filter
                      <ChevronDown className="ml-2 h-4 w-4 text-gray-400" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent className="bg-cyber-darker border-cyber-lightgray">
                    <DropdownMenuLabel className="text-gray-300">Filter by OS</DropdownMenuLabel>
                    <DropdownMenuSeparator className="bg-cyber-lightgray" />
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">All OS</DropdownMenuItem>
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">Windows</DropdownMenuItem>
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">Linux</DropdownMenuItem>
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">macOS</DropdownMenuItem>
                    <DropdownMenuItem className="text-white hover:bg-cyber-lightgray/20">Network Devices</DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>
            
            <Tabs defaultValue="all" className="mb-4" onValueChange={setActiveTab}>
              <TabsList className="bg-cyber-darker">
                <TabsTrigger 
                  value="all"
                  className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
                >
                  All Agents
                </TabsTrigger>
                <TabsTrigger 
                  value="active"
                  className="data-[state=active]:bg-cyber-success data-[state=active]:text-white"
                >
                  Active
                </TabsTrigger>
                <TabsTrigger 
                  value="inactive"
                  className="data-[state=active]:bg-cyber-warning data-[state=active]:text-white"
                >
                  Inactive
                </TabsTrigger>
                <TabsTrigger 
                  value="disconnected"
                  className="data-[state=active]:bg-cyber-danger data-[state=active]:text-white"
                >
                  Disconnected
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="all" className="mt-0">
                <div className="space-y-4">
                  {filteredAgents.map((agent) => (
                    <div key={agent.id} className="p-4 bg-cyber-darker rounded-md flex flex-col md:flex-row md:items-center justify-between">
                      <div className="flex items-start space-x-4 mb-4 md:mb-0">
                        <div className="rounded-full p-2 bg-cyber-gray/30">
                          {getAgentTypeIcon(agent.type)}
                        </div>
                        <div>
                          <div className="flex items-center space-x-2">
                            <h3 className="font-medium text-white">{agent.name}</h3>
                            {getStatusBadge(agent.status)}
                          </div>
                          <p className="text-sm text-gray-400">{agent.ipAddress} • {agent.os}</p>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {agent.groups.map((group) => (
                              <span key={group} className="text-xs px-1.5 py-0.5 bg-cyber-gray rounded text-gray-300">
                                {group}
                              </span>
                            ))}
                          </div>
                        </div>
                      </div>
                      <div className="flex flex-col md:flex-row items-start md:items-center gap-2 md:gap-4">
                        <div className="text-sm text-gray-400 flex items-center">
                          Last seen: <span className="ml-1 text-white">{agent.lastSeen}</span>
                        </div>
                        <Button variant="outline" size="sm" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20">
                          Actions
                          <ChevronDown className="ml-1 h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </TabsContent>
              
              <TabsContent value="active" className="mt-0">
                {/* Same structure as "all" tab but with filtered agents */}
              </TabsContent>
              
              <TabsContent value="inactive" className="mt-0">
                {/* Same structure as "all" tab but with filtered agents */}
              </TabsContent>
              
              <TabsContent value="disconnected" className="mt-0">
                {/* Same structure as "all" tab but with filtered agents */}
              </TabsContent>
            </Tabs>
            
            {filteredAgents.length === 0 && (
              <div className="py-8 text-center">
                <CircleSlash className="mx-auto h-8 w-8 text-gray-400 mb-2" />
                <h3 className="text-lg font-medium text-white">No agents found</h3>
                <p className="text-gray-400">Try adjusting your search or filters</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
  );
};

export default Agents;
