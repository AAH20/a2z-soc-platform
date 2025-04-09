
import React, { useState } from 'react';
import MainLayout from '@/components/layout/MainLayout';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertCircle, Bell, Filter, RefreshCw, X } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useToast } from '@/hooks/use-toast';

type AlertSeverity = "low" | "medium" | "high" | "critical";

interface Alert {
  id: string;
  severity: AlertSeverity;
  source: string;
  description: string;
  timestamp: string;
  technique?: string;
}

// Dummy alerts data with proper typing
const initialAlerts: Alert[] = [
  {
    id: "alert-1",
    severity: "critical",
    source: "Wazuh",
    description: "Potential data exfiltration detected from host 192.168.1.105",
    timestamp: "2023-05-15 14:32:45",
    technique: "Exfiltration"
  },
  {
    id: "alert-2",
    severity: "high",
    source: "Snort",
    description: "Suspicious outbound connection to known malicious IP 45.123.2.5",
    timestamp: "2023-05-15 13:15:22",
    technique: "Command and Control"
  },
  {
    id: "alert-3",
    severity: "medium",
    source: "Suricata",
    description: "Multiple failed login attempts detected on admin portal",
    timestamp: "2023-05-15 12:05:33",
    technique: "Credential Access"
  },
  {
    id: "alert-4",
    severity: "low",
    source: "VirusTotal",
    description: "Suspicious file hash detected in email attachment",
    timestamp: "2023-05-15 11:52:18",
    technique: "Initial Access"
  },
  {
    id: "alert-5",
    severity: "critical",
    source: "Wazuh",
    description: "Privilege escalation attempt detected on server SVR001",
    timestamp: "2023-05-15 10:22:55",
    technique: "Privilege Escalation"
  },
  {
    id: "alert-6",
    severity: "high",
    source: "Snort",
    description: "Unusual port scanning activity detected from internal host",
    timestamp: "2023-05-15 09:47:12",
    technique: "Discovery"
  },
  {
    id: "alert-7",
    severity: "medium",
    source: "Suricata",
    description: "Encrypted communication with untrusted external endpoint",
    timestamp: "2023-05-15 08:33:49",
    technique: "Command and Control"
  },
  {
    id: "alert-8",
    severity: "low",
    source: "VirusTotal",
    description: "Potentially unwanted application detected on workstation WS056",
    timestamp: "2023-05-15 07:18:21",
    technique: "Execution"
  }
];

const severityColors = {
  low: 'bg-alert-low text-white',
  medium: 'bg-alert-medium text-black',
  high: 'bg-alert-high text-white',
  critical: 'bg-alert-critical text-white',
};

const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>(initialAlerts);
  const { toast } = useToast();

  const handleClearAlerts = () => {
    setAlerts([]);
    toast({
      title: "Alerts cleared",
      description: "All alert data has been removed",
      variant: "default",
    });
  };

  const handleRestoreAlerts = () => {
    setAlerts(initialAlerts);
    toast({
      title: "Alerts restored",
      description: "Default alert data has been restored",
      variant: "default",
    });
  };

  return (
    <MainLayout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-white">Security Alerts</h1>
            <Badge variant="outline" className="bg-cyber-accent text-white">
              {alerts.length} Total
            </Badge>
          </div>
          <div className="flex gap-2">
            <Button 
              variant="outline" 
              size="sm" 
              className="gap-2"
              onClick={handleRestoreAlerts}
              disabled={alerts.length === initialAlerts.length}
            >
              <RefreshCw className="h-4 w-4" />
              Restore
            </Button>
            <Button 
              variant="destructive" 
              size="sm" 
              className="gap-2"
              onClick={handleClearAlerts}
              disabled={alerts.length === 0}
            >
              <X className="h-4 w-4" />
              Clear All
            </Button>
          </div>
        </div>

        <Tabs defaultValue="all" className="w-full">
          <div className="flex justify-between mb-4">
            <TabsList className="grid grid-cols-5 w-full max-w-md">
              <TabsTrigger value="all">All</TabsTrigger>
              <TabsTrigger value="critical">Critical</TabsTrigger>
              <TabsTrigger value="high">High</TabsTrigger>
              <TabsTrigger value="medium">Medium</TabsTrigger>
              <TabsTrigger value="low">Low</TabsTrigger>
            </TabsList>
            <Button variant="outline" size="sm" className="gap-2">
              <Filter className="h-4 w-4" />
              Filter
            </Button>
          </div>

          <TabsContent value="all" className="mt-0">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                  <AlertCircle className="h-5 w-5 text-cyber-accent" />
                  All Alerts
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[500px] pr-4">
                  <div className="space-y-4">
                    {alerts.length > 0 ? (
                      alerts.map((alert) => (
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
                      ))
                    ) : (
                      <div className="text-center py-12">
                        <Bell className="h-12 w-12 text-gray-500 mx-auto mb-4" />
                        <p className="text-gray-400">No alerts found</p>
                        <Button 
                          variant="outline" 
                          size="sm" 
                          className="mt-4"
                          onClick={handleRestoreAlerts}
                        >
                          Restore Alerts
                        </Button>
                      </div>
                    )}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          {(["critical", "high", "medium", "low"] as AlertSeverity[]).map((severity) => (
            <TabsContent key={severity} value={severity} className="mt-0">
              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg font-medium text-white flex items-center gap-2">
                    <AlertCircle className="h-5 w-5 text-cyber-accent" />
                    {severity.charAt(0).toUpperCase() + severity.slice(1)} Alerts
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[500px] pr-4">
                    <div className="space-y-4">
                      {alerts.filter(a => a.severity === severity).length > 0 ? (
                        alerts.filter(a => a.severity === severity).map((alert) => (
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
                        ))
                      ) : (
                        <div className="text-center py-12">
                          <Bell className="h-12 w-12 text-gray-500 mx-auto mb-4" />
                          <p className="text-gray-400">No {severity} alerts found</p>
                          <Button 
                            variant="outline" 
                            size="sm" 
                            className="mt-4"
                            onClick={handleRestoreAlerts}
                          >
                            Restore Alerts
                          </Button>
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>
          ))}
        </Tabs>
      </div>
    </MainLayout>
  );
};

export default AlertsPage;
