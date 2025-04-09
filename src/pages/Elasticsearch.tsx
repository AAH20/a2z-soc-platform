
import React from 'react';
import MainLayout from '@/components/layout/MainLayout';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertCircle, CheckCircle2, Search, Database, Server, Shield, Code, BarChart3, Layers } from 'lucide-react';
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";

const Elasticsearch = () => {
  const { toast } = useToast();
  
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Code snippet has been copied to your clipboard",
    });
  };
  
  return (
    <MainLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white">Elasticsearch Stack</h1>
          <p className="text-cyber-accent mt-2">Monitor and manage your Elasticsearch deployment</p>
        </div>

        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="bg-cyber-dark border border-cyber-gray">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="logs">Logs</TabsTrigger>
            <TabsTrigger value="indices">Indices</TabsTrigger>
            <TabsTrigger value="queries">Queries</TabsTrigger>
            <TabsTrigger value="integration">Dashboard Integration</TabsTrigger>
          </TabsList>
          
          <TabsContent value="overview" className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium">Cluster Status</CardTitle>
                  <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">Healthy</div>
                  <p className="text-xs text-cyber-accent mt-1">3 nodes online</p>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium">Documents</CardTitle>
                  <Database className="h-4 w-4 text-cyber-accent" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">42.3M</div>
                  <p className="text-xs text-cyber-accent mt-1">+18K in last 24h</p>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium">Storage</CardTitle>
                  <Server className="h-4 w-4 text-cyber-accent" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">238GB</div>
                  <p className="text-xs text-cyber-accent mt-1">64% of capacity</p>
                </CardContent>
              </Card>
            </div>
            
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Stack Components</CardTitle>
                <CardDescription className="text-cyber-accent">Status of the Elasticsearch ecosystem</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-cyber-gray pb-2">
                    <div className="flex items-center gap-2">
                      <Database className="h-5 w-5 text-cyber-accent" />
                      <span>Elasticsearch</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm">v8.11.3</span>
                      <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between border-b border-cyber-gray pb-2">
                    <div className="flex items-center gap-2">
                      <Search className="h-5 w-5 text-cyber-accent" />
                      <span>Kibana</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm">v8.11.3</span>
                      <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between border-b border-cyber-gray pb-2">
                    <div className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-cyber-accent" />
                      <span>X-Pack Security</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm">Enabled</span>
                      <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between border-b border-cyber-gray pb-2">
                    <div className="flex items-center gap-2">
                      <AlertCircle className="h-5 w-5 text-cyber-accent" />
                      <span>Alerting</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm">12 active</span>
                      <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Layers className="h-5 w-5 text-cyber-accent" />
                      <span>Index Lifecycle Management</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm">4 policies</span>
                      <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Deployment Information</CardTitle>
                <CardDescription className="text-cyber-accent">Details about your Elasticsearch deployment</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <h3 className="text-sm font-medium text-cyber-accent mb-1">Cluster URL</h3>
                    <p className="font-mono text-sm">https://elk-cluster-01.example.com:9200</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-cyber-accent mb-1">Kibana URL</h3>
                    <p className="font-mono text-sm">https://kibana.example.com:5601</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-cyber-accent mb-1">Deployment Type</h3>
                    <p className="font-mono text-sm">Self-hosted (Kubernetes)</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-cyber-accent mb-1">Region</h3>
                    <p className="font-mono text-sm">us-east-1</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="logs" className="space-y-4">
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Log Stream</CardTitle>
                <CardDescription className="text-cyber-accent">Recent log entries from Elasticsearch nodes</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 font-mono text-sm max-h-96 overflow-auto">
                  <div className="border-b border-cyber-gray pb-2">
                    <div className="text-cyber-success">[2023-10-14 08:24:31] [INFO] [node-1]</div>
                    <div>Successful shard recovery for [logs-2023.10.14-000001]</div>
                  </div>
                  <div className="border-b border-cyber-gray pb-2">
                    <div className="text-cyber-accent">[2023-10-14 08:22:45] [INFO] [node-3]</div>
                    <div>Cluster health status changed from [YELLOW] to [GREEN]</div>
                  </div>
                  <div className="border-b border-cyber-gray pb-2">
                    <div className="text-red-400">[2023-10-14 08:19:12] [WARN] [node-2]</div>
                    <div>High disk watermark [85%] exceeded on node-2</div>
                  </div>
                  <div className="border-b border-cyber-gray pb-2">
                    <div className="text-cyber-accent">[2023-10-14 08:15:33] [INFO] [node-1]</div>
                    <div>Starting snapshot [backup-2023-10-14] with [3] indices</div>
                  </div>
                  <div className="border-b border-cyber-gray pb-2">
                    <div className="text-cyber-accent">[2023-10-14 08:10:22] [INFO] [node-3]</div>
                    <div>Updating mapping for index [security-events]</div>
                  </div>
                  <div className="border-b border-cyber-gray pb-2">
                    <div className="text-yellow-500">[2023-10-14 08:08:15] [WARN] [node-1]</div>
                    <div>Circuit breaker triggered: [parent] Data too large, data for [&lt;request&gt;] would be [123848638/118.1mb]</div>
                  </div>
                  <div className="border-b border-cyber-gray pb-2">
                    <div className="text-cyber-accent">[2023-10-14 08:05:44] [INFO] [node-2]</div>
                    <div>Rebalancing shards: [15/30] complete</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="indices" className="space-y-4">
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Indices Management</CardTitle>
                <CardDescription className="text-cyber-accent">Monitor and manage Elasticsearch indices</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="grid grid-cols-5 font-medium text-cyber-accent">
                    <div>Index Name</div>
                    <div>Status</div>
                    <div>Docs</div>
                    <div>Size</div>
                    <div>Shards</div>
                  </div>
                  <div className="space-y-2">
                    <div className="grid grid-cols-5 border-b border-cyber-gray pb-2">
                      <div>logs-2023.10.14</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-cyber-success mr-2"></span>Open</div>
                      <div>8.3M</div>
                      <div>42GB</div>
                      <div>5p, 1r</div>
                    </div>
                    <div className="grid grid-cols-5 border-b border-cyber-gray pb-2">
                      <div>security-events</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-cyber-success mr-2"></span>Open</div>
                      <div>12.7M</div>
                      <div>68GB</div>
                      <div>5p, 1r</div>
                    </div>
                    <div className="grid grid-cols-5 border-b border-cyber-gray pb-2">
                      <div>metrics-system</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-cyber-success mr-2"></span>Open</div>
                      <div>21.2M</div>
                      <div>84GB</div>
                      <div>5p, 1r</div>
                    </div>
                    <div className="grid grid-cols-5 border-b border-cyber-gray pb-2">
                      <div>alerts</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-cyber-success mr-2"></span>Open</div>
                      <div>142K</div>
                      <div>2.3GB</div>
                      <div>3p, 1r</div>
                    </div>
                    <div className="grid grid-cols-5">
                      <div>kibana_sample_data</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-yellow-500 mr-2"></span>Read Only</div>
                      <div>35K</div>
                      <div>128MB</div>
                      <div>1p, 0r</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="queries" className="space-y-4">
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Query Performance</CardTitle>
                <CardDescription className="text-cyber-accent">Monitor slow queries and performance issues</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="grid grid-cols-4 font-medium text-cyber-accent">
                    <div>Query Type</div>
                    <div>Index</div>
                    <div>Duration</div>
                    <div>Timestamp</div>
                  </div>
                  <div className="space-y-2">
                    <div className="grid grid-cols-4 border-b border-cyber-gray pb-2">
                      <div>match_phrase</div>
                      <div>security-events</div>
                      <div className="text-red-400">8.2s</div>
                      <div>10:24:31</div>
                    </div>
                    <div className="grid grid-cols-4 border-b border-cyber-gray pb-2">
                      <div>bool</div>
                      <div>logs-2023.10.14</div>
                      <div className="text-yellow-500">2.1s</div>
                      <div>10:22:45</div>
                    </div>
                    <div className="grid grid-cols-4 border-b border-cyber-gray pb-2">
                      <div>terms</div>
                      <div>metrics-system</div>
                      <div>0.4s</div>
                      <div>10:19:12</div>
                    </div>
                    <div className="grid grid-cols-4 border-b border-cyber-gray pb-2">
                      <div>range</div>
                      <div>alerts</div>
                      <div>0.3s</div>
                      <div>10:15:33</div>
                    </div>
                    <div className="grid grid-cols-4">
                      <div>match</div>
                      <div>kibana_sample_data</div>
                      <div>0.1s</div>
                      <div>10:10:22</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="integration" className="space-y-4">
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Dashboard Integration Guide</CardTitle>
                <CardDescription className="text-cyber-accent">How to integrate Elasticsearch data into your SOC dashboard</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-3">
                  <h3 className="text-lg font-medium text-white">1. Configuration</h3>
                  <p className="text-sm text-gray-300">Configure your Elasticsearch connection in the dashboard settings:</p>
                  <div className="bg-cyber-gray p-3 rounded-md font-mono text-sm relative group">
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => copyToClipboard(`{
  "elasticsearch": {
    "host": "https://elk-cluster-01.example.com:9200",
    "apiKey": "YOUR_API_KEY",
    "index": "security-events",
    "refreshInterval": 30
  }
}`)}
                    >
                      Copy
                    </Button>
                    <pre>{`{
  "elasticsearch": {
    "host": "https://elk-cluster-01.example.com:9200",
    "apiKey": "YOUR_API_KEY",
    "index": "security-events",
    "refreshInterval": 30
  }
}`}</pre>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <h3 className="text-lg font-medium text-white">2. Create a Data Source</h3>
                  <p className="text-sm text-gray-300">Add the following code to create an Elasticsearch data source:</p>
                  <div className="bg-cyber-gray p-3 rounded-md font-mono text-sm relative group">
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => copyToClipboard(`import { Client } from '@elastic/elasticsearch';

export const createElasticsearchClient = (config) => {
  return new Client({
    node: config.host,
    auth: {
      apiKey: config.apiKey
    },
    tls: {
      rejectUnauthorized: false // For self-signed certificates
    }
  });
};

export const fetchSecurityEvents = async (client, timeRange = '24h') => {
  const response = await client.search({
    index: 'security-events',
    body: {
      query: {
        range: {
          '@timestamp': {
            gte: \`now-\${timeRange}\`,
            lte: 'now'
          }
        }
      },
      aggs: {
        severity_breakdown: {
          terms: {
            field: 'event.severity'
          }
        },
        events_over_time: {
          date_histogram: {
            field: '@timestamp',
            calendar_interval: '1h'
          }
        }
      },
      size: 100,
      sort: [
        { '@timestamp': { order: 'desc' } }
      ]
    }
  });
  
  return response.body;
};`)}
                    >
                      Copy
                    </Button>
                    <pre>{`import { Client } from '@elastic/elasticsearch';

export const createElasticsearchClient = (config) => {
  return new Client({
    node: config.host,
    auth: {
      apiKey: config.apiKey
    },
    tls: {
      rejectUnauthorized: false // For self-signed certificates
    }
  });
};

export const fetchSecurityEvents = async (client, timeRange = '24h') => {
  const response = await client.search({
    index: 'security-events',
    body: {
      query: {
        range: {
          '@timestamp': {
            gte: \`now-\${timeRange}\`,
            lte: 'now'
          }
        }
      },
      aggs: {
        severity_breakdown: {
          terms: {
            field: 'event.severity'
          }
        },
        events_over_time: {
          date_histogram: {
            field: '@timestamp',
            calendar_interval: '1h'
          }
        }
      },
      size: 100,
      sort: [
        { '@timestamp': { order: 'desc' } }
      ]
    }
  });
  
  return response.body;
};`}</pre>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <h3 className="text-lg font-medium text-white">3. Integration with Dashboard</h3>
                  <p className="text-sm text-gray-300">Use React Query to fetch and display Elasticsearch data:</p>
                  <div className="bg-cyber-gray p-3 rounded-md font-mono text-sm relative group">
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => copyToClipboard(`import { useQuery } from '@tanstack/react-query';
import { createElasticsearchClient, fetchSecurityEvents } from '../utils/elasticsearch';

// In your dashboard component
const Dashboard = () => {
  const config = {
    host: 'https://elk-cluster-01.example.com:9200',
    apiKey: 'YOUR_API_KEY'
  };
  
  const client = createElasticsearchClient(config);
  
  const { data, isLoading, error } = useQuery({
    queryKey: ['securityEvents', '24h'],
    queryFn: () => fetchSecurityEvents(client, '24h'),
    refetchInterval: 30000,
  });
  
  // Render your dashboard using the fetched data
  // ...
}`)}
                    >
                      Copy
                    </Button>
                    <pre>{`import { useQuery } from '@tanstack/react-query';
import { createElasticsearchClient, fetchSecurityEvents } from '../utils/elasticsearch';

// In your dashboard component
const Dashboard = () => {
  const config = {
    host: 'https://elk-cluster-01.example.com:9200',
    apiKey: 'YOUR_API_KEY'
  };
  
  const client = createElasticsearchClient(config);
  
  const { data, isLoading, error } = useQuery({
    queryKey: ['securityEvents', '24h'],
    queryFn: () => fetchSecurityEvents(client, '24h'),
    refetchInterval: 30000,
  });
  
  // Render your dashboard using the fetched data
  // ...
}`}</pre>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <h3 className="text-lg font-medium text-white">4. Required Package</h3>
                  <p className="text-sm text-gray-300">Install the Elasticsearch JavaScript client:</p>
                  <div className="bg-cyber-gray p-3 rounded-md font-mono text-sm">
                    <code>npm install @elastic/elasticsearch</code>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <h3 className="text-lg font-medium text-white">5. Visualizing the Data</h3>
                  <p className="text-sm text-gray-300">Create dashboard widgets using the fetched data:</p>
                  <ul className="list-disc list-inside text-sm text-gray-300 space-y-2">
                    <li>Security events timeline using date histogram aggregation</li>
                    <li>Severity distribution pie chart or bar chart</li>
                    <li>Latest alerts table with filtering capabilities</li>
                    <li>Geographical map showing event origins (if location data available)</li>
                    <li>Technique usage correlation with MITRE ATT&CK framework</li>
                  </ul>
                </div>
                
                <div className="mt-4 p-4 bg-cyber-gray/30 border border-cyber-gray rounded-md">
                  <div className="flex items-center mb-2">
                    <AlertCircle className="h-5 w-5 text-cyber-accent mr-2" />
                    <h3 className="text-md font-medium text-white">Security Considerations</h3>
                  </div>
                  <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                    <li>Store API keys securely and never expose them in client-side code</li>
                    <li>Set up proper role-based access control in Elasticsearch</li>
                    <li>Use HTTPS for all communications</li>
                    <li>Consider implementing backend proxies for Elasticsearch requests</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </MainLayout>
  );
};

export default Elasticsearch;
