
import React from 'react';
import MainLayout from '@/components/layout/MainLayout';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertCircle, CheckCircle2, Search, Database, Server, Shield, ChartBar, Code, Layers } from 'lucide-react';
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";

const Opensearch = () => {
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
          <h1 className="text-3xl font-bold tracking-tight text-white">OpenSearch</h1>
          <p className="text-cyber-accent mt-2">Monitor and manage your OpenSearch deployment</p>
        </div>

        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="bg-cyber-dark border border-cyber-gray">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="dashboards">Dashboards</TabsTrigger>
            <TabsTrigger value="indices">Indices</TabsTrigger>
            <TabsTrigger value="security">Security</TabsTrigger>
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
                  <p className="text-xs text-cyber-accent mt-1">2 nodes online</p>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium">Documents</CardTitle>
                  <Database className="h-4 w-4 text-cyber-accent" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">18.7M</div>
                  <p className="text-xs text-cyber-accent mt-1">+7K in last 24h</p>
                </CardContent>
              </Card>
              
              <Card className="bg-cyber-darker border-cyber-gray text-white">
                <CardHeader className="flex flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm font-medium">Storage</CardTitle>
                  <Server className="h-4 w-4 text-cyber-accent" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">124GB</div>
                  <p className="text-xs text-cyber-accent mt-1">42% of capacity</p>
                </CardContent>
              </Card>
            </div>
            
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Stack Components</CardTitle>
                <CardDescription className="text-cyber-accent">Status of the OpenSearch ecosystem</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-cyber-gray pb-2">
                    <div className="flex items-center gap-2">
                      <Database className="h-5 w-5 text-cyber-accent" />
                      <span>OpenSearch</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm">v2.9.0</span>
                      <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between border-b border-cyber-gray pb-2">
                    <div className="flex items-center gap-2">
                      <Search className="h-5 w-5 text-cyber-accent" />
                      <span>OpenSearch Dashboards</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm">v2.9.0</span>
                      <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between border-b border-cyber-gray pb-2">
                    <div className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-cyber-accent" />
                      <span>Security Plugin</span>
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
                      <span className="text-sm">8 active</span>
                      <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                    </div>
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Layers className="h-5 w-5 text-cyber-accent" />
                      <span>Index Management</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm">3 policies</span>
                      <CheckCircle2 className="h-4 w-4 text-cyber-success" />
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Deployment Information</CardTitle>
                <CardDescription className="text-cyber-accent">Details about your OpenSearch deployment</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <h3 className="text-sm font-medium text-cyber-accent mb-1">Cluster URL</h3>
                    <p className="font-mono text-sm">https://opensearch-cluster.example.com:9200</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-cyber-accent mb-1">Dashboards URL</h3>
                    <p className="font-mono text-sm">https://opensearch-dashboards.example.com:5601</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-cyber-accent mb-1">Deployment Type</h3>
                    <p className="font-mono text-sm">AWS OpenSearch Service</p>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-cyber-accent mb-1">Region</h3>
                    <p className="font-mono text-sm">us-west-2</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="dashboards" className="space-y-4">
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>OpenSearch Dashboards</CardTitle>
                <CardDescription className="text-cyber-accent">Recent and saved dashboards</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="grid grid-cols-3 font-medium text-cyber-accent">
                    <div>Dashboard Name</div>
                    <div>Last Modified</div>
                    <div>Created By</div>
                  </div>
                  <div className="space-y-2">
                    <div className="grid grid-cols-3 border-b border-cyber-gray pb-2">
                      <div className="flex items-center gap-2">
                        <ChartBar className="h-4 w-4 text-cyber-accent" />
                        <span>Security Overview</span>
                      </div>
                      <div>Today, 08:24</div>
                      <div>admin</div>
                    </div>
                    <div className="grid grid-cols-3 border-b border-cyber-gray pb-2">
                      <div className="flex items-center gap-2">
                        <ChartBar className="h-4 w-4 text-cyber-accent" />
                        <span>Network Traffic</span>
                      </div>
                      <div>Yesterday, 15:30</div>
                      <div>soc_analyst</div>
                    </div>
                    <div className="grid grid-cols-3 border-b border-cyber-gray pb-2">
                      <div className="flex items-center gap-2">
                        <ChartBar className="h-4 w-4 text-cyber-accent" />
                        <span>System Metrics</span>
                      </div>
                      <div>2023-10-12</div>
                      <div>system</div>
                    </div>
                    <div className="grid grid-cols-3 border-b border-cyber-gray pb-2">
                      <div className="flex items-center gap-2">
                        <ChartBar className="h-4 w-4 text-cyber-accent" />
                        <span>Threat Hunting</span>
                      </div>
                      <div>2023-10-10</div>
                      <div>threat_hunter</div>
                    </div>
                    <div className="grid grid-cols-3">
                      <div className="flex items-center gap-2">
                        <ChartBar className="h-4 w-4 text-cyber-accent" />
                        <span>Audit Logs</span>
                      </div>
                      <div>2023-10-05</div>
                      <div>admin</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="indices" className="space-y-4">
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Indices Management</CardTitle>
                <CardDescription className="text-cyber-accent">Monitor and manage OpenSearch indices</CardDescription>
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
                      <div>logs-2023.10</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-cyber-success mr-2"></span>Open</div>
                      <div>4.2M</div>
                      <div>28GB</div>
                      <div>3p, 1r</div>
                    </div>
                    <div className="grid grid-cols-5 border-b border-cyber-gray pb-2">
                      <div>security-events</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-cyber-success mr-2"></span>Open</div>
                      <div>7.8M</div>
                      <div>42GB</div>
                      <div>3p, 1r</div>
                    </div>
                    <div className="grid grid-cols-5 border-b border-cyber-gray pb-2">
                      <div>metrics</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-cyber-success mr-2"></span>Open</div>
                      <div>6.4M</div>
                      <div>36GB</div>
                      <div>3p, 1r</div>
                    </div>
                    <div className="grid grid-cols-5 border-b border-cyber-gray pb-2">
                      <div>alerts</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-cyber-success mr-2"></span>Open</div>
                      <div>82K</div>
                      <div>1.8GB</div>
                      <div>2p, 1r</div>
                    </div>
                    <div className="grid grid-cols-5">
                      <div>.opensearch-dashboards</div>
                      <div className="flex items-center"><span className="h-2 w-2 rounded-full bg-cyber-success mr-2"></span>Open</div>
                      <div>124</div>
                      <div>8MB</div>
                      <div>1p, 1r</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="security" className="space-y-4">
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Security Settings</CardTitle>
                <CardDescription className="text-cyber-accent">Manage security for your OpenSearch deployment</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="grid grid-cols-2 border-b border-cyber-gray pb-2">
                    <div className="font-medium">Security Plugin</div>
                    <div className="flex items-center text-cyber-success">
                      <CheckCircle2 className="h-4 w-4 mr-2" />
                      Enabled
                    </div>
                  </div>
                  <div className="grid grid-cols-2 border-b border-cyber-gray pb-2">
                    <div className="font-medium">TLS</div>
                    <div className="flex items-center text-cyber-success">
                      <CheckCircle2 className="h-4 w-4 mr-2" />
                      Enabled (Node-to-node and clients)
                    </div>
                  </div>
                  <div className="grid grid-cols-2 border-b border-cyber-gray pb-2">
                    <div className="font-medium">Authentication</div>
                    <div className="flex items-center text-cyber-success">
                      <CheckCircle2 className="h-4 w-4 mr-2" />
                      Basic Auth + JWT
                    </div>
                  </div>
                  <div className="grid grid-cols-2 border-b border-cyber-gray pb-2">
                    <div className="font-medium">Audit Logging</div>
                    <div className="flex items-center text-cyber-success">
                      <CheckCircle2 className="h-4 w-4 mr-2" />
                      Enabled (Compliance mode)
                    </div>
                  </div>
                  <div className="grid grid-cols-2">
                    <div className="font-medium">Roles</div>
                    <div>8 custom roles configured</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="integration" className="space-y-4">
            <Card className="bg-cyber-darker border-cyber-gray text-white">
              <CardHeader>
                <CardTitle>Dashboard Integration Guide</CardTitle>
                <CardDescription className="text-cyber-accent">How to integrate OpenSearch data into your SOC dashboard</CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-3">
                  <h3 className="text-lg font-medium text-white">1. Configuration</h3>
                  <p className="text-sm text-gray-300">Configure your OpenSearch connection in the dashboard settings:</p>
                  <div className="bg-cyber-gray p-3 rounded-md font-mono text-sm relative group">
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => copyToClipboard(`{
  "opensearch": {
    "host": "https://opensearch-cluster.example.com:9200",
    "username": "admin",
    "password": "YOUR_PASSWORD",
    "index": "security-events",
    "refreshInterval": 30
  }
}`)}
                    >
                      Copy
                    </Button>
                    <pre>{`{
  "opensearch": {
    "host": "https://opensearch-cluster.example.com:9200",
    "username": "admin",
    "password": "YOUR_PASSWORD",
    "index": "security-events",
    "refreshInterval": 30
  }
}`}</pre>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <h3 className="text-lg font-medium text-white">2. Create a Data Source</h3>
                  <p className="text-sm text-gray-300">Add the following code to create an OpenSearch data source:</p>
                  <div className="bg-cyber-gray p-3 rounded-md font-mono text-sm relative group">
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => copyToClipboard(`import { Client } from '@opensearch-project/opensearch';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import createAwsOpensearchConnector from 'aws-opensearch-connector';

export const createOpensearchClient = async (config) => {
  // For AWS OpenSearch Service
  if (config.awsRegion) {
    const connector = createAwsOpensearchConnector({
      region: config.awsRegion,
      credentials: defaultProvider(),
    });
    
    return new Client({
      node: config.host,
      Connection: connector,
      ssl: { rejectUnauthorized: true }
    });
  }
  
  // For self-hosted OpenSearch
  return new Client({
    node: config.host,
    auth: {
      username: config.username,
      password: config.password
    },
    ssl: { rejectUnauthorized: false }
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
                    <pre>{`import { Client } from '@opensearch-project/opensearch';
import { defaultProvider } from '@aws-sdk/credential-provider-node';
import createAwsOpensearchConnector from 'aws-opensearch-connector';

export const createOpensearchClient = async (config) => {
  // For AWS OpenSearch Service
  if (config.awsRegion) {
    const connector = createAwsOpensearchConnector({
      region: config.awsRegion,
      credentials: defaultProvider(),
    });
    
    return new Client({
      node: config.host,
      Connection: connector,
      ssl: { rejectUnauthorized: true }
    });
  }
  
  // For self-hosted OpenSearch
  return new Client({
    node: config.host,
    auth: {
      username: config.username,
      password: config.password
    },
    ssl: { rejectUnauthorized: false }
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
                  <p className="text-sm text-gray-300">Use React Query to fetch and display OpenSearch data:</p>
                  <div className="bg-cyber-gray p-3 rounded-md font-mono text-sm relative group">
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => copyToClipboard(`import { useQuery } from '@tanstack/react-query';
import { createOpensearchClient, fetchSecurityEvents } from '../utils/opensearch';

// In your dashboard component
const Dashboard = () => {
  const config = {
    host: 'https://opensearch-cluster.example.com:9200',
    username: 'admin',
    password: 'YOUR_PASSWORD',
    // For AWS OpenSearch
    // awsRegion: 'us-west-2' 
  };
  
  const { data, isLoading, error } = useQuery({
    queryKey: ['opensearchEvents', '24h'],
    queryFn: async () => {
      const client = await createOpensearchClient(config);
      return fetchSecurityEvents(client, '24h');
    },
    refetchInterval: 30000,
  });
  
  // Render your dashboard using the fetched data
  // ...
}`)}
                    >
                      Copy
                    </Button>
                    <pre>{`import { useQuery } from '@tanstack/react-query';
import { createOpensearchClient, fetchSecurityEvents } from '../utils/opensearch';

// In your dashboard component
const Dashboard = () => {
  const config = {
    host: 'https://opensearch-cluster.example.com:9200',
    username: 'admin',
    password: 'YOUR_PASSWORD',
    // For AWS OpenSearch
    // awsRegion: 'us-west-2' 
  };
  
  const { data, isLoading, error } = useQuery({
    queryKey: ['opensearchEvents', '24h'],
    queryFn: async () => {
      const client = await createOpensearchClient(config);
      return fetchSecurityEvents(client, '24h');
    },
    refetchInterval: 30000,
  });
  
  // Render your dashboard using the fetched data
  // ...
}`}</pre>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <h3 className="text-lg font-medium text-white">4. Required Packages</h3>
                  <p className="text-sm text-gray-300">Install the OpenSearch JavaScript client and AWS connector:</p>
                  <div className="bg-cyber-gray p-3 rounded-md font-mono text-sm">
                    <code>npm install @opensearch-project/opensearch aws-opensearch-connector @aws-sdk/credential-provider-node</code>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <h3 className="text-lg font-medium text-white">5. Unified Dashboard View</h3>
                  <p className="text-sm text-gray-300">Create a unified view with both Elasticsearch and OpenSearch data:</p>
                  <div className="bg-cyber-gray p-3 rounded-md font-mono text-sm relative group">
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="absolute right-2 top-2 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => copyToClipboard(`import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { createElasticsearchClient, fetchSecurityEvents as fetchElasticsearchEvents } from '../utils/elasticsearch';
import { createOpensearchClient, fetchSecurityEvents as fetchOpensearchEvents } from '../utils/opensearch';

// Unified dashboard component
const UnifiedDashboard = () => {
  // Fetch Elasticsearch data
  const elasticsearchQuery = useQuery({
    queryKey: ['elasticsearchEvents'],
    queryFn: async () => {
      const client = createElasticsearchClient({
        host: 'https://elasticsearch-cluster.example.com:9200',
        apiKey: 'YOUR_ES_API_KEY'
      });
      return fetchElasticsearchEvents(client, '24h');
    },
    refetchInterval: 30000,
  });
  
  // Fetch OpenSearch data
  const opensearchQuery = useQuery({
    queryKey: ['opensearchEvents'],
    queryFn: async () => {
      const client = await createOpensearchClient({
        host: 'https://opensearch-cluster.example.com:9200',
        username: 'admin',
        password: 'YOUR_OS_PASSWORD'
      });
      return fetchOpensearchEvents(client, '24h');
    },
    refetchInterval: 30000,
  });
  
  // Combine and normalize data
  const combinedData = React.useMemo(() => {
    if (!elasticsearchQuery.data && !opensearchQuery.data) return null;
    
    // Combine alerts from both sources
    const combinedAlerts = [
      ...(elasticsearchQuery.data?.hits?.hits || []).map(hit => ({
        ...hit._source,
        source: 'elasticsearch'
      })),
      ...(opensearchQuery.data?.hits?.hits || []).map(hit => ({
        ...hit._source,
        source: 'opensearch'
      }))
    ];
    
    // Sort by timestamp
    combinedAlerts.sort((a, b) => 
      new Date(b['@timestamp']).getTime() - new Date(a['@timestamp']).getTime()
    );
    
    return {
      alerts: combinedAlerts,
      isLoading: elasticsearchQuery.isLoading || opensearchQuery.isLoading,
      error: elasticsearchQuery.error || opensearchQuery.error
    };
  }, [elasticsearchQuery.data, opensearchQuery.data, 
      elasticsearchQuery.isLoading, opensearchQuery.isLoading,
      elasticsearchQuery.error, opensearchQuery.error]);
  
  // Render your unified dashboard
  // ...
}`)}
                    >
                      Copy
                    </Button>
                    <pre>{`import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { createElasticsearchClient, fetchSecurityEvents as fetchElasticsearchEvents } from '../utils/elasticsearch';
import { createOpensearchClient, fetchSecurityEvents as fetchOpensearchEvents } from '../utils/opensearch';

// Unified dashboard component
const UnifiedDashboard = () => {
  // Fetch Elasticsearch data
  const elasticsearchQuery = useQuery({
    queryKey: ['elasticsearchEvents'],
    queryFn: async () => {
      const client = createElasticsearchClient({
        host: 'https://elasticsearch-cluster.example.com:9200',
        apiKey: 'YOUR_ES_API_KEY'
      });
      return fetchElasticsearchEvents(client, '24h');
    },
    refetchInterval: 30000,
  });
  
  // Fetch OpenSearch data
  const opensearchQuery = useQuery({
    queryKey: ['opensearchEvents'],
    queryFn: async () => {
      const client = await createOpensearchClient({
        host: 'https://opensearch-cluster.example.com:9200',
        username: 'admin',
        password: 'YOUR_OS_PASSWORD'
      });
      return fetchOpensearchEvents(client, '24h');
    },
    refetchInterval: 30000,
  });
  
  // Combine and normalize data
  const combinedData = React.useMemo(() => {
    if (!elasticsearchQuery.data && !opensearchQuery.data) return null;
    
    // Combine alerts from both sources
    const combinedAlerts = [
      ...(elasticsearchQuery.data?.hits?.hits || []).map(hit => ({
        ...hit._source,
        source: 'elasticsearch'
      })),
      ...(opensearchQuery.data?.hits?.hits || []).map(hit => ({
        ...hit._source,
        source: 'opensearch'
      }))
    ];
    
    // Sort by timestamp
    combinedAlerts.sort((a, b) => 
      new Date(b['@timestamp']).getTime() - new Date(a['@timestamp']).getTime()
    );
    
    return {
      alerts: combinedAlerts,
      isLoading: elasticsearchQuery.isLoading || opensearchQuery.isLoading,
      error: elasticsearchQuery.error || opensearchQuery.error
    };
  }, [elasticsearchQuery.data, opensearchQuery.data, 
      elasticsearchQuery.isLoading, opensearchQuery.isLoading,
      elasticsearchQuery.error, opensearchQuery.error]);
  
  // Render your unified dashboard
  // ...
}`}</pre>
                  </div>
                </div>
                
                <div className="mt-4 p-4 bg-cyber-gray/30 border border-cyber-gray rounded-md">
                  <div className="flex items-center mb-2">
                    <AlertCircle className="h-5 w-5 text-cyber-accent mr-2" />
                    <h3 className="text-md font-medium text-white">Security Considerations</h3>
                  </div>
                  <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                    <li>Store credentials securely and never expose them in client-side code</li>
                    <li>Implement proper authentication and authorization</li>
                    <li>For AWS OpenSearch Service, use IAM roles when possible</li>
                    <li>Always use HTTPS and proper TLS configuration</li>
                    <li>Consider using a backend proxy for secure search requests</li>
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

export default Opensearch;
