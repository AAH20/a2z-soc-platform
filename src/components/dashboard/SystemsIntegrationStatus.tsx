
import React from 'react';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { CheckCircle2, XCircle, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface SystemStatus {
  name: string;
  status: 'connected' | 'disconnected' | 'degraded';
  lastSync?: string;
  details?: string;
}

interface SystemsIntegrationStatusProps {
  systems: SystemStatus[];
}

const SystemsIntegrationStatus: React.FC<SystemsIntegrationStatusProps> = ({
  systems,
}) => {
  const getStatusIcon = (status: SystemStatus['status']) => {
    switch (status) {
      case 'connected':
        return <CheckCircle2 className="h-5 w-5 text-cyber-success" />;
      case 'disconnected':
        return <XCircle className="h-5 w-5 text-cyber-danger" />;
      case 'degraded':
        return <AlertCircle className="h-5 w-5 text-cyber-warning" />;
    }
  };

  const getStatusClass = (status: SystemStatus['status']) => {
    switch (status) {
      case 'connected':
        return 'bg-cyber-success/20 text-cyber-success';
      case 'disconnected':
        return 'bg-cyber-danger/20 text-cyber-danger';
      case 'degraded':
        return 'bg-cyber-warning/20 text-cyber-warning';
    }
  };

  return (
    <Card className="bg-cyber-gray border-cyber-lightgray">
      <CardHeader>
        <CardTitle className="text-lg font-medium text-white">System Integrations</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {systems.map((system) => (
          <div key={system.name} className="flex items-center justify-between p-3 bg-cyber-darker rounded-md">
            <div className="flex items-center space-x-3">
              {getStatusIcon(system.status)}
              <div>
                <div className="font-medium text-white">{system.name}</div>
                {system.details && <div className="text-xs text-gray-400">{system.details}</div>}
              </div>
            </div>
            <div className="flex items-center space-x-2">
              {system.lastSync && (
                <div className="text-xs text-gray-400">
                  Last sync: {system.lastSync}
                </div>
              )}
              <div className={cn(
                "px-2 py-0.5 rounded-full text-xs",
                getStatusClass(system.status)
              )}>
                {system.status}
              </div>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
};

export default SystemsIntegrationStatus;
