import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { CircleDollarSign, ShieldCheck, UserCheck, Wifi, Shield, AlertTriangle, CheckCircle, RefreshCw } from 'lucide-react';
import CustomProgress from '@/components/ui/custom-progress';
import { agentStatusService, type AgentInfo } from '../../services/agentStatus';

interface AgentStatusCardProps {
  totalAgents: number;
  activeAgents: number;
  protectedAgents: number;
  vulnerableAgents: number;
}

const AgentStatusCard: React.FC<AgentStatusCardProps> = ({
  totalAgents,
  activeAgents,
  protectedAgents,
  vulnerableAgents,
}) => {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Subscribe to agent status updates
  useEffect(() => {
    const unsubscribe = agentStatusService.subscribe((updatedAgents) => {
      setAgents(updatedAgents);
    });

    return unsubscribe;
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await agentStatusService.checkAllAgentStatuses();
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  const onlineAgents = agents.filter(agent => agent.status === 'online');
  const offlineAgents = agents.filter(agent => agent.status === 'offline');

  const activePercentage = (activeAgents / totalAgents) * 100;
  const protectedPercentage = (protectedAgents / totalAgents) * 100;
  const vulnerablePercentage = (vulnerableAgents / totalAgents) * 100;

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'offline':
        return <AlertTriangle className="w-4 h-4 text-red-500" />;
      case 'checking':
        return <RefreshCw className="w-4 h-4 text-blue-500 animate-spin" />;
      default:
        return <AlertTriangle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform.toLowerCase()) {
      case 'windows':
        return '🖥️';
      case 'darwin':
      case 'macos':
        return '🍎';
      case 'linux':
        return '🐧';
      default:
        return '💻';
    }
  };

  return (
    <Card className="bg-cyber-gray border-cyber-lightgray">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-medium text-white">Agent Status</CardTitle>
        <CardDescription className="text-gray-400">
          Overview of agent deployment and protection status
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <UserCheck className="h-4 w-4 text-cyber-accent" />
              <span className="text-sm font-medium text-white">Active Agents</span>
            </div>
            <span className="text-sm text-gray-400">{activeAgents}</span>
          </div>
          <CustomProgress value={activePercentage} className="w-full" indicatorColor="#10b981" />

          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="h-4 w-4 text-cyber-accent" />
              <span className="text-sm font-medium text-white">Protected Agents</span>
            </div>
            <span className="text-sm text-gray-400">{protectedAgents}</span>
          </div>
          <CustomProgress value={protectedPercentage} className="w-full" indicatorColor="#f59e0b" />

          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <CircleDollarSign className="h-4 w-4 text-cyber-accent" />
              <span className="text-sm font-medium text-white">Vulnerable Agents</span>
            </div>
            <span className="text-sm text-gray-400">{vulnerableAgents}</span>
          </div>
          <CustomProgress value={vulnerablePercentage} className="w-full" indicatorColor="#ef4444" />
        </div>
      </CardContent>
    </Card>
  );
};

export default AgentStatusCard;
