import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertCircle, Bell, Filter, RefreshCw, X } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useToast } from '@/hooks/use-toast';
import { apiService } from '@/services/api';

type AlertSeverity = "low" | "medium" | "high" | "critical";

interface Alert {
  id: string;
  severity: AlertSeverity;
  source: string;
  description: string;
  timestamp: string;
  technique?: string;
}

const severityColors = {
  low: 'bg-alert-low text-white',
  medium: 'bg-alert-medium text-black',
  high: 'bg-alert-high text-white',
  critical: 'bg-alert-critical text-white',
};

const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const { toast } = useToast();

  const fetchAlerts = async () => {
    try {
      setIsLoading(true);
      const response = await apiService.get('/api/security-events', {
        params: {
          limit: 50,
          sortBy: 'timestamp',
          sortOrder: 'desc'
        }
      });

      if (response.data?.success) {
        const securityEvents = response.data.data.map((event: any) => ({
          id: event.id,
          severity: event.severity || 'medium',
          source: event.source || 'Security Monitor',
          description: event.description || event.event_type,
          timestamp: new Date(event.timestamp).toLocaleString(),
          technique: event.mitre_technique_name || event.technique
        }));
        setAlerts(securityEvents);
      }
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
      toast({
        title: "Failed to load alerts",
        description: "Could not retrieve security events",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearAlerts = async () => {
    try {
      const response = await apiService.delete('/api/security-events');
      if (response.data?.success) {
        setAlerts([]);
        toast({
          title: "Alerts cleared",
          description: "All alert data has been removed",
          variant: "default",
        });
      }
    } catch (error) {
      console.error('Failed to clear alerts:', error);
      toast({
        title: "Failed to clear alerts",
        description: "Could not remove alert data",
        variant: "destructive",
      });
    }
  };

  const handleRefreshAlerts = () => {
    fetchAlerts();
    toast({
      title: "Alerts refreshed",
      description: "Alert data has been updated",
      variant: "default",
    });
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  return (
      <div className="space-y-6 bg-slate-900 min-h-screen p-6">
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
              onClick={handleRefreshAlerts}
              disabled={isLoading}
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button 
              variant="destructive" 
              size="sm" 
              className="gap-2"
              onClick={handleClearAlerts}
              disabled={alerts.length === 0 || isLoading}
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
                    {isLoading ? (
                      <div className="text-center py-12">
                        <RefreshCw className="h-12 w-12 text-gray-500 mx-auto mb-4 animate-spin" />
                        <p className="text-gray-400">Loading alerts...</p>
                      </div>
                    ) : alerts.length > 0 ? (
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
                          onClick={handleRefreshAlerts}
                        >
                          Refresh Alerts
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
                            onClick={handleRefreshAlerts}
                          >
                            Refresh Alerts
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
  );
};

export default AlertsPage;
