
import React from 'react';
import { 
  Card, 
  CardContent, 
  CardHeader, 
  CardTitle, 
  CardDescription 
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';

interface Alert {
  id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  description: string;
  timestamp: string;
  technique?: string;
}

interface AlertsPanelProps {
  alerts: Alert[];
  expanded?: boolean;
}

const severityColors = {
  low: 'bg-alert-low text-white',
  medium: 'bg-alert-medium text-black',
  high: 'bg-alert-high text-white',
  critical: 'bg-alert-critical text-white',
};

const AlertsPanel: React.FC<AlertsPanelProps> = ({ alerts, expanded = false }) => {
  return (
    <Card className={`bg-cyber-gray border-cyber-lightgray ${!expanded ? 'h-full' : ''}`}>
      <CardHeader className="pb-2">
        <div className="flex justify-between items-center">
          <CardTitle className="text-lg font-medium text-white">Recent Alerts</CardTitle>
          <Badge variant="outline" className="bg-cyber-accent text-white">
            {alerts.length} Total
          </Badge>
        </div>
        <CardDescription className="text-gray-400">
          Security alerts from integrated systems
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className={expanded ? 'h-[500px] pr-4' : 'h-[350px] pr-4'}>
          <div className="space-y-4">
            {alerts.map((alert) => (
              <div 
                key={alert.id} 
                className="bg-cyber-darker p-3 rounded-md border-l-4"
                style={{ borderLeftColor: 
                  alert.severity === 'low' ? '#1E88E5' :
                  alert.severity === 'medium' ? '#FFA000' :
                  alert.severity === 'high' ? '#E53935' : '#B71C1C'
                }}
              >
                <div className="flex justify-between items-start mb-2">
                  <div>
                    <Badge className={severityColors[alert.severity]}>
                      {alert.severity.toUpperCase()}
                    </Badge>
                    <Badge variant="outline" className="ml-2 bg-cyber-gray text-gray-300">
                      {alert.source}
                    </Badge>
                  </div>
                  <span className="text-xs text-gray-400">{alert.timestamp}</span>
                </div>
                <p className="text-sm text-white mb-1">{alert.description}</p>
                {alert.technique && (
                  <Badge variant="outline" className="bg-transparent text-cyber-accent">
                    {alert.technique}
                  </Badge>
                )}
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default AlertsPanel;
