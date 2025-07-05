import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Switch } from '@/components/ui/switch';
import { 
  Search, Filter, Download, Play, Pause, RefreshCw, Eye, AlertTriangle,
  XCircle, Server, Activity, Shield, Network, FileText, ChevronDown, 
  ChevronRight, Copy, Target, AlertOctagon
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { format, parseISO } from 'date-fns';
import idsLogsService, { LogEntry, SecurityEvent, LogsFilter, LogsStatistics } from '@/services/idsLogsService';

interface LogsViewerProps {
  agentId?: string;
  initialFilter?: LogsFilter;
}

const LogsViewer: React.FC<LogsViewerProps> = ({ agentId, initialFilter = {} }) => {
  // State management
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [statistics, setStatistics] = useState<LogsStatistics | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRealTimeEnabled, setIsRealTimeEnabled] = useState(false);
  const [isRealTimeConnected, setIsRealTimeConnected] = useState(false);
  const [realTimeStatus, setRealTimeStatus] = useState<string>('Disconnected');
  const [activeProtectionStatus, setActiveProtectionStatus] = useState<string>('Initializing');
  const [networkInterface, setNetworkInterface] = useState<string>('auto-detected');
  const [threatsDetected, setThreatsDetected] = useState<number>(0);
  const [packetsAnalyzed, setPacketsAnalyzed] = useState<number>(0);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [activeTab, setActiveTab] = useState('logs');
  const [expandedLogs, setExpandedLogs] = useState<Set<string>>(new Set());
  
  // Filter state
  const [filter, setFilter] = useState<LogsFilter>({
    limit: 100,
    offset: 0,
    ...initialFilter,
    ...(agentId ? { agentId } : {})
  });
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedLevel, setSelectedLevel] = useState<string>('all');
  const [selectedSource, setSelectedSource] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<string>('1h');

  // Refs for real-time updates
  const eventSourceRef = useRef<EventSource | null>(null);
  const logsContainerRef = useRef<HTMLDivElement>(null);

  // Load initial data
  useEffect(() => {
    loadData();
  }, [filter]);

  // Load logs and related data
  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [logsResponse, eventsResponse, statsResponse] = await Promise.all([
        idsLogsService.getLogs(filter),
        idsLogsService.getSecurityEvents(filter),
        idsLogsService.getLogsStatistics(getTimeRangeFilter())
      ]);

      setLogs(logsResponse.logs);
      setSecurityEvents(eventsResponse.events);
      setStatistics(statsResponse);

      // Update active protection status from response
      if (logsResponse.activeProtection !== undefined) {
        setActiveProtectionStatus(logsResponse.activeProtection ? 'Active Protection Enabled' : 'Enhanced Monitoring');
        setIsRealTimeConnected(logsResponse.activeProtection);
        setRealTimeStatus(logsResponse.protectionLevel || 'Unknown');
      }
      if (logsResponse.networkInterface) {
        setNetworkInterface(logsResponse.networkInterface);
      }
      if (logsResponse.threatsDetected !== undefined) {
        setThreatsDetected(logsResponse.threatsDetected);
      }
      if (logsResponse.packetsAnalyzed !== undefined) {
        setPacketsAnalyzed(logsResponse.packetsAnalyzed);
      }
    } catch (error) {
      console.error('Error loading logs data:', error);
    } finally {
      setIsLoading(false);
    }
  }, [filter]);

  // Get time range filter
  const getTimeRangeFilter = useCallback(() => {
    const now = new Date();
    const ranges: Record<string, number> = {
      '15m': 15 * 60 * 1000,
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000
    };

    const duration = ranges[timeRange] || ranges['1h'];
    return {
      start: new Date(now.getTime() - duration).toISOString(),
      end: now.toISOString()
    };
  }, [timeRange]);

  // Handle real-time updates
  useEffect(() => {
    if (isRealTimeEnabled) {
      startRealTimeUpdates();
    } else {
      stopRealTimeUpdates();
    }

    return () => stopRealTimeUpdates();
  }, [isRealTimeEnabled, filter]);

  const startRealTimeUpdates = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    eventSourceRef.current = idsLogsService.streamLogs(
      filter, 
      // On new log
      (newLog) => {
        setLogs(prevLogs => [newLog, ...prevLogs.slice(0, (filter.limit || 100) - 1)]);
        
        // Auto-scroll to top when new logs arrive
        if (logsContainerRef.current) {
          logsContainerRef.current.scrollTop = 0;
        }
      },
      // On statistics update
      (newStats) => {
        setStatistics(newStats);
      },
      // On connection established
      () => {
        console.log('✅ Real-time monitoring connected to A2Z SOC');
        setIsRealTimeConnected(true);
        setRealTimeStatus('Connected - Live Protection Active');
      },
      // On error
      (error) => {
        console.error('❌ Real-time monitoring error:', error);
        setIsRealTimeConnected(false);
        setRealTimeStatus(`Connection Error: ${error}`);
      }
    );
  }, [filter]);

  const stopRealTimeUpdates = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsRealTimeConnected(false);
    setRealTimeStatus('Disconnected');
  }, []);

  // Handle filter changes
  const handleFilterChange = useCallback((updates: Partial<LogsFilter>) => {
    setFilter(prev => ({ ...prev, ...updates, offset: 0 }));
  }, []);

  const handleSearch = useCallback(() => {
    const newFilter: Partial<LogsFilter> = {};
    
    if (searchTerm) newFilter.search = searchTerm;
    if (selectedLevel !== 'all') newFilter.level = [selectedLevel];
    if (selectedSource !== 'all') newFilter.source = [selectedSource];
    if (selectedCategory !== 'all') newFilter.category = [selectedCategory];
    
    newFilter.timeRange = getTimeRangeFilter();
    
    handleFilterChange(newFilter);
  }, [searchTerm, selectedLevel, selectedSource, selectedCategory, timeRange, handleFilterChange, getTimeRangeFilter]);

  // Reset filters
  const resetFilters = useCallback(() => {
    setSearchTerm('');
    setSelectedLevel('all');
    setSelectedSource('all');
    setSelectedCategory('all');
    setTimeRange('1h');
    setFilter({
      limit: 100,
      offset: 0,
      ...(agentId ? { agentId } : {})
    });
  }, [agentId]);

  // Export logs
  const handleExport = useCallback(async (format: 'json' | 'csv' | 'txt') => {
    try {
      const blob = await idsLogsService.exportLogs(filter, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ids-logs-${new Date().toISOString().split('T')[0]}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error exporting logs:', error);
    }
  }, [filter]);

  // Toggle log expansion
  const toggleLogExpansion = useCallback((logId: string) => {
    setExpandedLogs(prev => {
      const newSet = new Set(prev);
      if (newSet.has(logId)) {
        newSet.delete(logId);
      } else {
        newSet.add(logId);
      }
      return newSet;
    });
  }, []);

  // Get level color
  const getLevelColor = (level: string) => {
    const colors = {
      'DEBUG': 'bg-gray-100 text-gray-800',
      'INFO': 'bg-blue-100 text-blue-800',
      'WARN': 'bg-yellow-100 text-yellow-800',
      'ERROR': 'bg-red-100 text-red-800',
      'CRITICAL': 'bg-red-500 text-white'
    };
    return colors[level as keyof typeof colors] || 'bg-gray-100 text-gray-800';
  };

  // Get source icon
  const getSourceIcon = (source: string) => {
    const icons = {
      'ids-core': Shield,
      'network-agent': Network,
      'detection-engine': Target,
      'packet-capture': Activity
    };
    const Icon = icons[source as keyof typeof icons] || FileText;
    return <Icon className="h-4 w-4" />;
  };

  // Get severity color for events
  const getSeverityColor = (severity: string) => {
    const colors = {
      'low': 'bg-green-100 text-green-800',
      'medium': 'bg-yellow-100 text-yellow-800',
      'high': 'bg-orange-100 text-orange-800',
      'critical': 'bg-red-500 text-white'
    };
    return colors[severity as keyof typeof colors] || 'bg-gray-100 text-gray-800';
  };

  // Copy to clipboard
  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text);
  }, []);

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold">IDS/IPS Active Protection</h2>
            <p className="text-gray-600">Real-time threat detection and network protection</p>
          </div>
          <div className="flex items-center space-x-2">
            <div className="flex items-center space-x-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsRealTimeEnabled(!isRealTimeEnabled)}
                className={isRealTimeEnabled ? 'bg-green-100 text-green-800 border-green-300' : ''}
              >
                {isRealTimeEnabled ? <Pause className="h-4 w-4 mr-2" /> : <Play className="h-4 w-4 mr-2" />}
                {isRealTimeEnabled ? 'Pause Live' : 'Start Live'}
              </Button>
              {isRealTimeEnabled && (
                <div className="flex items-center space-x-2 text-sm">
                  <div className={`w-2 h-2 rounded-full ${isRealTimeConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                  <span className={isRealTimeConnected ? 'text-green-600' : 'text-red-600'}>
                    {realTimeStatus}
                  </span>
                </div>
              )}
            </div>
            <Button variant="outline" size="sm" onClick={loadData} disabled={isLoading}>
              <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Active Protection Status */}
        <Card className="border-l-4 border-l-green-500">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <Shield className={`h-6 w-6 ${isRealTimeConnected ? 'text-green-500' : 'text-orange-500'}`} />
                  <div>
                    <h3 className="font-semibold text-lg">{activeProtectionStatus}</h3>
                    <p className="text-sm text-gray-600">Network Interface: {networkInterface}</p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4 text-center">
                  <div>
                    <p className="text-2xl font-bold text-blue-600">{packetsAnalyzed.toLocaleString()}</p>
                    <p className="text-sm text-gray-600">Packets Analyzed</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-red-600">{threatsDetected.toLocaleString()}</p>
                    <p className="text-sm text-gray-600">Threats Detected</p>
                  </div>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Badge variant={isRealTimeConnected ? "default" : "secondary"} className="px-3 py-1">
                  <Activity className="h-4 w-4 mr-1" />
                  {isRealTimeConnected ? 'ACTIVE PROTECTION' : 'MONITORING'}
                </Badge>
                {isRealTimeConnected && (
                  <Badge variant="outline" className="px-3 py-1 border-green-300 text-green-700">
                    <Target className="h-4 w-4 mr-1" />
                    REAL-TIME BLOCKING
                  </Badge>
                )}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Statistics Cards */}
      {statistics && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600">Total Logs</p>
                  <p className="text-2xl font-bold">{statistics.totalLogs.toLocaleString()}</p>
                </div>
                <FileText className="h-8 w-8 text-blue-500" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600">Critical Events</p>
                  <p className="text-2xl font-bold text-red-600">
                    {statistics.logsPerLevel.CRITICAL || 0}
                  </p>
                </div>
                <AlertTriangle className="h-8 w-8 text-red-500" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600">Active Sources</p>
                  <p className="text-2xl font-bold">{Object.keys(statistics.logsPerSource).length}</p>
                </div>
                <Server className="h-8 w-8 text-green-500" />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600">Errors</p>
                  <p className="text-2xl font-bold text-orange-600">
                    {(statistics.logsPerLevel.ERROR || 0) + (statistics.logsPerLevel.WARN || 0)}
                  </p>
                </div>
                <XCircle className="h-8 w-8 text-orange-500" />
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Filter className="h-5 w-5 mr-2" />
            Filters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
            <div className="md:col-span-2">
              <Label htmlFor="search">Search</Label>
              <div className="relative">
                <Search className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="search"
                  placeholder="Search logs..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                />
              </div>
            </div>
            <div>
              <Label htmlFor="level">Level</Label>
              <Select value={selectedLevel} onValueChange={setSelectedLevel}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Levels</SelectItem>
                  <SelectItem value="DEBUG">Debug</SelectItem>
                  <SelectItem value="INFO">Info</SelectItem>
                  <SelectItem value="WARN">Warning</SelectItem>
                  <SelectItem value="ERROR">Error</SelectItem>
                  <SelectItem value="CRITICAL">Critical</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="source">Source</Label>
              <Select value={selectedSource} onValueChange={setSelectedSource}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Sources</SelectItem>
                  <SelectItem value="ids-core">IDS Core</SelectItem>
                  <SelectItem value="network-agent">Network Agent</SelectItem>
                  <SelectItem value="detection-engine">Detection Engine</SelectItem>
                  <SelectItem value="packet-capture">Packet Capture</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="category">Category</Label>
              <Select value={selectedCategory} onValueChange={setSelectedCategory}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Categories</SelectItem>
                  <SelectItem value="detection">Detection</SelectItem>
                  <SelectItem value="network">Network</SelectItem>
                  <SelectItem value="security">Security</SelectItem>
                  <SelectItem value="system">System</SelectItem>
                  <SelectItem value="performance">Performance</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label htmlFor="timerange">Time Range</Label>
              <Select value={timeRange} onValueChange={setTimeRange}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="15m">Last 15 minutes</SelectItem>
                  <SelectItem value="1h">Last hour</SelectItem>
                  <SelectItem value="6h">Last 6 hours</SelectItem>
                  <SelectItem value="24h">Last 24 hours</SelectItem>
                  <SelectItem value="7d">Last 7 days</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex items-center justify-between mt-4">
            <div className="space-x-2">
              <Button onClick={handleSearch} size="sm">
                <Search className="h-4 w-4 mr-2" />
                Apply Filters
              </Button>
              <Button onClick={resetFilters} variant="outline" size="sm">
                Clear All
              </Button>
            </div>
            <div className="space-x-2">
              <Button 
                onClick={() => handleExport('json')} 
                variant="outline" 
                size="sm"
              >
                <Download className="h-4 w-4 mr-2" />
                Export JSON
              </Button>
              <Button 
                onClick={() => handleExport('csv')} 
                variant="outline" 
                size="sm"
              >
                <Download className="h-4 w-4 mr-2" />
                Export CSV
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="logs">System Logs</TabsTrigger>
          <TabsTrigger value="events">Security Events</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="real-time">Real-time Monitor</TabsTrigger>
        </TabsList>

        {/* System Logs Tab */}
        <TabsContent value="logs" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>System Logs ({logs.length})</span>
                <div className="flex items-center space-x-2">
                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={isRealTimeEnabled}
                      onCheckedChange={setIsRealTimeEnabled}
                    />
                    <Label>Real-time</Label>
                  </div>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea ref={logsContainerRef} className="h-[600px]">
                <div className="space-y-2">
                  {logs.map((log) => (
                    <div
                      key={log.id}
                      className="border rounded-lg p-4 hover:bg-gray-800/50 dark:hover:bg-gray-700/50 transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-start space-x-3 flex-1">
                          <div className="flex-shrink-0">
                            {getSourceIcon(log.source)}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center space-x-2 mb-2">
                              <Badge className={getLevelColor(log.level)}>
                                {log.level}
                              </Badge>
                              <Badge variant="outline">{log.source}</Badge>
                              <Badge variant="outline">{log.category}</Badge>
                              <span className="text-sm text-gray-500">
                                {format(parseISO(log.timestamp), 'MMM dd, yyyy HH:mm:ss')}
                              </span>
                            </div>
                            <p className="text-sm font-medium mb-1">{log.message}</p>
                            <div className="flex items-center space-x-4 text-xs text-gray-500">
                              <span>Agent: {log.agentName}</span>
                              {log.metadata?.sourceIp && (
                                <span>Source: {log.metadata.sourceIp}</span>
                              )}
                              {log.metadata?.destinationIp && (
                                <span>Dest: {log.metadata.destinationIp}</span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toggleLogExpansion(log.id)}
                          >
                            {expandedLogs.has(log.id) ? (
                              <ChevronDown className="h-4 w-4" />
                            ) : (
                              <ChevronRight className="h-4 w-4" />
                            )}
                          </Button>
                          <Dialog>
                            <DialogTrigger asChild>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setSelectedLog(log)}
                              >
                                <Eye className="h-4 w-4" />
                              </Button>
                            </DialogTrigger>
                            <DialogContent className="max-w-4xl">
                              <DialogHeader>
                                <DialogTitle>Log Details</DialogTitle>
                                <DialogDescription>
                                  Detailed view of log entry {log.id}
                                </DialogDescription>
                              </DialogHeader>
                              <div className="space-y-4">
                                <div className="grid grid-cols-2 gap-4">
                                  <div>
                                    <Label>Timestamp</Label>
                                    <p className="text-sm font-mono">
                                      {format(parseISO(log.timestamp), 'MMM dd, yyyy HH:mm:ss.SSS')}
                                    </p>
                                  </div>
                                  <div>
                                    <Label>Level</Label>
                                    <Badge className={getLevelColor(log.level)}>
                                      {log.level}
                                    </Badge>
                                  </div>
                                  <div>
                                    <Label>Source</Label>
                                    <p className="text-sm">{log.source}</p>
                                  </div>
                                  <div>
                                    <Label>Category</Label>
                                    <p className="text-sm">{log.category}</p>
                                  </div>
                                  <div>
                                    <Label>Agent</Label>
                                    <p className="text-sm">{log.agentName}</p>
                                  </div>
                                  <div>
                                    <Label>Agent ID</Label>
                                    <p className="text-sm font-mono">{log.agentId}</p>
                                  </div>
                                </div>
                                <div>
                                  <Label>Message</Label>
                                  <p className="text-sm p-2 bg-gray-100 dark:bg-gray-800 rounded">{log.message}</p>
                                </div>
                                {log.metadata && Object.keys(log.metadata).length > 0 && (
                                  <div>
                                    <Label>Metadata</Label>
                                    <pre className="text-xs p-3 bg-gray-100 dark:bg-gray-800 rounded overflow-auto">
                                      {JSON.stringify(log.metadata, null, 2)}
                                    </pre>
                                  </div>
                                )}
                                {log.rawData && (
                                  <div>
                                    <Label>Raw Data</Label>
                                    <pre className="text-xs p-3 bg-gray-100 dark:bg-gray-800 rounded overflow-auto">
                                      {log.rawData}
                                    </pre>
                                  </div>
                                )}
                                <div className="flex justify-end space-x-2">
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => copyToClipboard(JSON.stringify(log, null, 2))}
                                  >
                                    <Copy className="h-4 w-4 mr-2" />
                                    Copy JSON
                                  </Button>
                                </div>
                              </div>
                            </DialogContent>
                          </Dialog>
                        </div>
                      </div>
                      {expandedLogs.has(log.id) && log.metadata && (
                        <div className="mt-3 pt-3 border-t">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                            {Object.entries(log.metadata).map(([key, value]) => (
                              <div key={key}>
                                <span className="font-medium text-gray-600">{key}:</span>
                                <span className="ml-1">{String(value)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                  {logs.length === 0 && !isLoading && (
                    <div className="text-center py-8 text-gray-500">
                      No logs found matching the current filters.
                    </div>
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Events Tab */}
        <TabsContent value="events" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Security Events ({securityEvents.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {securityEvents.map((event) => (
                  <div
                    key={event.id}
                    className="border rounded-lg p-4 hover:bg-gray-800/50 dark:hover:bg-gray-700/50 transition-colors"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3 flex-1">
                        <div className="flex-shrink-0">
                          <AlertOctagon className="h-5 w-5 text-red-500" />
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-2">
                            <Badge className={getSeverityColor(event.severity)}>
                              {event.severity.toUpperCase()}
                            </Badge>
                            <Badge variant="outline">{event.type}</Badge>
                            <Badge variant="outline">{event.action}</Badge>
                            <span className="text-sm text-gray-500">
                              {format(parseISO(event.timestamp), 'MMM dd, yyyy HH:mm:ss')}
                            </span>
                          </div>
                          <h4 className="font-medium mb-1">{event.description}</h4>
                          <div className="flex items-center space-x-4 text-sm text-gray-600">
                            <span>From: {event.source}</span>
                            <span>To: {event.destination}</span>
                            <span>Confidence: {event.confidence}%</span>
                          </div>
                          {event.ruleName && (
                            <div className="mt-2 text-sm">
                              <span className="font-medium">Rule: </span>
                              <span>{event.ruleName}</span>
                              {event.ruleId && (
                                <span className="text-gray-500 ml-2">({event.ruleId})</span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                      <Dialog>
                        <DialogTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <Eye className="h-4 w-4" />
                          </Button>
                        </DialogTrigger>
                        <DialogContent className="max-w-4xl">
                          <DialogHeader>
                            <DialogTitle>Security Event Details</DialogTitle>
                            <DialogDescription>
                              Detailed analysis of security event {event.id}
                            </DialogDescription>
                          </DialogHeader>
                          <div className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                              <div>
                                <Label>Event Type</Label>
                                <p className="text-sm">{event.type}</p>
                              </div>
                              <div>
                                <Label>Severity</Label>
                                <Badge className={getSeverityColor(event.severity)}>
                                  {event.severity.toUpperCase()}
                                </Badge>
                              </div>
                              <div>
                                <Label>Action Taken</Label>
                                <p className="text-sm">{event.action}</p>
                              </div>
                              <div>
                                <Label>Confidence</Label>
                                <p className="text-sm">{event.confidence}%</p>
                              </div>
                            </div>
                            <div>
                              <Label>Description</Label>
                              <p className="text-sm p-2 bg-gray-100 dark:bg-gray-800 rounded">{event.description}</p>
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                              <div>
                                <Label>Source</Label>
                                <p className="text-sm font-mono">{event.source}</p>
                              </div>
                              <div>
                                <Label>Destination</Label>
                                <p className="text-sm font-mono">{event.destination}</p>
                              </div>
                            </div>
                          </div>
                        </DialogContent>
                      </Dialog>
                    </div>
                  </div>
                ))}
                {securityEvents.length === 0 && !isLoading && (
                  <div className="text-center py-8 text-gray-500">
                    No security events found matching the current filters.
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Analytics Tab */}
        <TabsContent value="analytics" className="space-y-4">
          {statistics && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card>
                <CardHeader>
                  <CardTitle>Logs by Level</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={Object.entries(statistics.logsPerLevel).map(([level, count]) => ({
                          name: level,
                          value: count
                        }))}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {Object.entries(statistics.logsPerLevel).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={`hsl(${index * 45}, 70%, 60%)`} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Activity Over Time</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <LineChart data={statistics.recentActivity}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis 
                        dataKey="timestamp" 
                        tickFormatter={(value) => format(parseISO(value), 'HH:mm')}
                      />
                      <YAxis />
                      <Tooltip 
                        labelFormatter={(value) => format(parseISO(value), 'MMM dd, HH:mm')}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="count" 
                        stroke="#8884d8" 
                        strokeWidth={2}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Top Agents by Log Volume</CardTitle>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={statistics.topAgents} layout="horizontal">
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis type="number" />
                      <YAxis dataKey="agentName" type="category" width={150} />
                      <Tooltip />
                      <Bar dataKey="logCount" fill="#8884d8" />
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Logs by Source</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {Object.entries(statistics.logsPerSource).map(([source, count]) => (
                      <div key={source} className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          {getSourceIcon(source)}
                          <span className="capitalize">{source.replace('-', ' ')}</span>
                        </div>
                        <Badge variant="outline">{count.toLocaleString()}</Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* Real-time Monitor Tab */}
        <TabsContent value="real-time" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Real-time Log Monitor</span>
                <div className="flex items-center space-x-2">
                  <div className={`w-3 h-3 rounded-full ${isRealTimeEnabled ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
                  <span className="text-sm text-gray-600">
                    {isRealTimeEnabled ? 'Live' : 'Stopped'}
                  </span>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Alert className="mb-4">
                <Activity className="h-4 w-4" />
                <AlertDescription>
                  {isRealTimeEnabled 
                    ? 'Real-time monitoring is active. New logs will appear automatically.'
                    : 'Enable real-time monitoring to see logs as they arrive.'
                  }
                </AlertDescription>
              </Alert>
              
              <div className="flex items-center justify-between mb-4">
                <Button
                  onClick={() => setIsRealTimeEnabled(!isRealTimeEnabled)}
                  className={isRealTimeEnabled ? 'bg-red-600 hover:bg-red-700' : 'bg-green-600 hover:bg-green-700'}
                >
                  {isRealTimeEnabled ? (
                    <>
                      <Pause className="h-4 w-4 mr-2" />
                      Stop Monitoring
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4 mr-2" />
                      Start Monitoring
                    </>
                  )}
                </Button>
                <div className="text-sm text-gray-600">
                  Last update: {logs.length > 0 ? format(parseISO(logs[0].timestamp), 'HH:mm:ss') : 'Never'}
                </div>
              </div>

              <ScrollArea className="h-[500px] border rounded-lg p-4">
                <div className="space-y-2 font-mono text-sm">
                  {logs.slice(0, 50).map((log) => (
                    <div
                      key={log.id}
                      className={`p-2 rounded border-l-4 hover:bg-opacity-80 transition-colors ${
                        log.level === 'CRITICAL' ? 'border-red-500 bg-red-50 dark:bg-red-900/20' :
                        log.level === 'ERROR' ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/20' :
                        log.level === 'WARN' ? 'border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20' :
                        log.level === 'INFO' ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' :
                        'border-gray-500 bg-gray-50 dark:bg-gray-800/20'
                      }`}
                    >
                      <div className="flex items-center space-x-2 text-xs text-gray-600 mb-1">
                        <span>{format(parseISO(log.timestamp), 'HH:mm:ss.SSS')}</span>
                        <Badge variant="outline" className="text-xs">
                          {log.level}
                        </Badge>
                        <span>{log.source}</span>
                        <span>{log.agentName}</span>
                      </div>
                      <div className="text-sm">{log.message}</div>
                    </div>
                  ))}
                  {logs.length === 0 && (
                    <div className="text-center py-8 text-gray-500">
                      Waiting for logs...
                    </div>
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default LogsViewer; 