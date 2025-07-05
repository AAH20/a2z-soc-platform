import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { AlertCircle, CheckCircle, Save, Key, RefreshCcw } from 'lucide-react';
import { toast } from 'sonner';

const STORAGE_KEY = 'cloud-credentials';

interface CloudCredentials {
  aws: {
    accessKeyId: string;
    secretAccessKey: string;
    region: string;
  };
  azure: {
    clientId: string;
    clientSecret: string;
    tenantId: string;
    subscriptionId: string;
  };
  googleCloud: {
    projectId: string;
    credentials: string;
  };
}

const defaultCredentials: CloudCredentials = {
  aws: {
    accessKeyId: '',
    secretAccessKey: '',
    region: 'us-east-1',
  },
  azure: {
    clientId: '',
    tenantId: '',
    clientSecret: '',
    subscriptionId: '',
  },
  googleCloud: {
    projectId: '',
    credentials: '',
  },
};

const CloudCredentialsManager: React.FC = () => {
  const [credentials, setCredentials] = useState<CloudCredentials>(defaultCredentials);
  const [activeTab, setActiveTab] = useState('aws');
  const [isLoading, setIsLoading] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<{
    aws: 'connected' | 'not_configured' | 'error' | 'checking';
    azure: 'connected' | 'not_configured' | 'error' | 'checking';
    googleCloud: 'connected' | 'not_configured' | 'error' | 'checking';
  }>({
    aws: 'not_configured',
    azure: 'not_configured',
    googleCloud: 'not_configured',
  });

  // Load saved credentials on mount
  useEffect(() => {
    const savedCredentials = localStorage.getItem(STORAGE_KEY);
    if (savedCredentials) {
      try {
        setCredentials(JSON.parse(savedCredentials));
      } catch (error) {
        console.error('Failed to parse saved credentials', error);
      }
    }
    
    // Check connection status for saved credentials
    checkAllConnections();
  }, []);

  const saveCredentials = (provider: 'aws' | 'azure' | 'googleCloud') => {
    setIsLoading(true);
    // Save to localStorage
    localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
    
    // Check connection
    checkConnection(provider)
      .then(success => {
        if (success) {
          toast.success(`${provider.toUpperCase()} credentials saved and verified`);
        } else {
          toast.error(`${provider.toUpperCase()} credentials saved but failed to verify`);
        }
      })
      .finally(() => {
        setIsLoading(false);
      });
  };

  const checkConnection = async (provider: 'aws' | 'azure' | 'googleCloud'): Promise<boolean> => {
    setConnectionStatus(prev => ({ ...prev, [provider]: 'checking' }));
    
    try {
      // Check connection with the backend
      const response = await fetch(`/api/v1/cloud-infra/${provider}/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': 'fe137543d8e99aa75ab1d3b8812bc2042ddf53caa80934f687a9c98e93d176b0', // In production, get from secure storage
        },
        body: JSON.stringify({ credentials: credentials[provider] }),
      });
      
      const data = await response.json();
      
      if (data.success) {
        setConnectionStatus(prev => ({ ...prev, [provider]: 'connected' }));
        return true;
      } else {
        setConnectionStatus(prev => ({ ...prev, [provider]: 'error' }));
        return false;
      }
    } catch (error) {
      console.error(`Error checking ${provider} connection:`, error);
      setConnectionStatus(prev => ({ ...prev, [provider]: 'error' }));
      return false;
    }
  };

  const checkAllConnections = async () => {
    for (const provider of ['aws', 'azure', 'googleCloud'] as const) {
      await checkConnection(provider);
    }
  };

  const handleInputChange = (provider: 'aws' | 'azure' | 'googleCloud', field: string, value: string) => {
    setCredentials(prev => ({
      ...prev,
      [provider]: {
        ...prev[provider],
        [field]: value,
      },
    }));
  };

  const clearCredentials = (provider: 'aws' | 'azure' | 'googleCloud') => {
    setCredentials(prev => ({
      ...prev,
      [provider]: { ...defaultCredentials[provider] },
    }));
    
    // Update localStorage
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      ...credentials,
      [provider]: { ...defaultCredentials[provider] },
    }));
    
    setConnectionStatus(prev => ({ ...prev, [provider]: 'not_configured' }));
    toast.info(`${provider.toUpperCase()} credentials cleared`);
  };

  return (
    <Card className="bg-cyber-gray border-cyber-lightgray">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-medium text-white">Cloud Provider Credentials</CardTitle>
        <CardDescription className="text-gray-400">
          Configure your cloud provider credentials to enable the multi-cloud integration features
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="aws" value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-cyber-darker mb-4">
            <TabsTrigger 
              value="aws" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              AWS
              {connectionStatus.aws === 'connected' && (
                <CheckCircle className="ml-2 h-4 w-4 text-cyber-success" />
              )}
            </TabsTrigger>
            <TabsTrigger 
              value="azure" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Azure
              {connectionStatus.azure === 'connected' && (
                <CheckCircle className="ml-2 h-4 w-4 text-cyber-success" />
              )}
            </TabsTrigger>
            <TabsTrigger 
              value="googleCloud" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Google Cloud
              {connectionStatus.googleCloud === 'connected' && (
                <CheckCircle className="ml-2 h-4 w-4 text-cyber-success" />
              )}
            </TabsTrigger>
          </TabsList>
          
          {/* AWS Tab */}
          <TabsContent value="aws">
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <div className="flex items-center space-x-2">
                  <Key className="h-5 w-5 text-cyber-accent" />
                  <h3 className="text-md font-medium text-white">AWS Credentials</h3>
                </div>
                <Badge className={
                  connectionStatus.aws === 'connected' ? "bg-cyber-success" :
                  connectionStatus.aws === 'checking' ? "bg-cyber-warning" :
                  connectionStatus.aws === 'error' ? "bg-cyber-danger" :
                  "bg-cyber-gray"
                }>
                  {connectionStatus.aws === 'connected' ? "Connected" :
                   connectionStatus.aws === 'checking' ? "Checking..." :
                   connectionStatus.aws === 'error' ? "Connection Error" :
                   "Not Configured"}
                </Badge>
              </div>
              
              <div className="grid gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="aws-access-key" className="text-white">Access Key ID</Label>
                  <Input
                    id="aws-access-key"
                    value={credentials.aws.accessKeyId}
                    onChange={(e) => handleInputChange('aws', 'accessKeyId', e.target.value)}
                    placeholder="Enter your AWS Access Key ID"
                    className="bg-cyber-darker border-cyber-lightgray text-white"
                  />
                </div>
                
                <div className="grid gap-2">
                  <Label htmlFor="aws-secret-key" className="text-white">Secret Access Key</Label>
                  <Input
                    id="aws-secret-key"
                    type="password"
                    value={credentials.aws.secretAccessKey}
                    onChange={(e) => handleInputChange('aws', 'secretAccessKey', e.target.value)}
                    placeholder="Enter your AWS Secret Access Key"
                    className="bg-cyber-darker border-cyber-lightgray text-white"
                  />
                </div>
                
                <div className="grid gap-2">
                  <Label htmlFor="aws-region" className="text-white">Region</Label>
                  <Input
                    id="aws-region"
                    value={credentials.aws.region}
                    onChange={(e) => handleInputChange('aws', 'region', e.target.value)}
                    placeholder="us-east-1"
                    className="bg-cyber-darker border-cyber-lightgray text-white"
                  />
                </div>
                
                <div className="flex justify-between mt-2">
                  <Button 
                    variant="outline"
                    onClick={() => clearCredentials('aws')}
                    className="border-cyber-danger text-cyber-danger hover:bg-cyber-danger/20"
                  >
                    Clear
                  </Button>
                  <Button 
                    onClick={() => saveCredentials('aws')}
                    disabled={isLoading || !credentials.aws.accessKeyId || !credentials.aws.secretAccessKey}
                    className="bg-cyber-accent hover:bg-cyber-accent/80"
                  >
                    {isLoading ? (
                      <>
                        <RefreshCcw className="h-4 w-4 mr-2 animate-spin" />
                        Saving...
                      </>
                    ) : (
                      <>
                        <Save className="h-4 w-4 mr-2" />
                        Save & Verify
                      </>
                    )}
                  </Button>
                </div>
                
                {connectionStatus.aws === 'error' && (
                  <div className="flex items-center p-3 bg-cyber-danger/20 rounded-md text-cyber-danger text-sm mt-2">
                    <AlertCircle className="h-4 w-4 mr-2" />
                    Failed to connect to AWS. Please check your credentials and try again.
                  </div>
                )}
              </div>
            </div>
          </TabsContent>
          
          {/* Azure Tab */}
          <TabsContent value="azure">
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <div className="flex items-center space-x-2">
                  <Key className="h-5 w-5 text-cyber-accent" />
                  <h3 className="text-md font-medium text-white">Azure Credentials</h3>
                </div>
                <Badge className={
                  connectionStatus.azure === 'connected' ? "bg-cyber-success" :
                  connectionStatus.azure === 'checking' ? "bg-cyber-warning" :
                  connectionStatus.azure === 'error' ? "bg-cyber-danger" :
                  "bg-cyber-gray"
                }>
                  {connectionStatus.azure === 'connected' ? "Connected" :
                   connectionStatus.azure === 'checking' ? "Checking..." :
                   connectionStatus.azure === 'error' ? "Connection Error" :
                   "Not Configured"}
                </Badge>
              </div>
              
              <div className="grid gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="azure-client-id" className="text-white">Client ID</Label>
                  <Input
                    id="azure-client-id"
                    value={credentials.azure.clientId}
                    onChange={(e) => handleInputChange('azure', 'clientId', e.target.value)}
                    placeholder="Enter your Azure Client ID"
                    className="bg-cyber-darker border-cyber-lightgray text-white"
                  />
                </div>
                
                <div className="grid gap-2">
                  <Label htmlFor="azure-client-secret" className="text-white">Client Secret</Label>
                  <Input
                    id="azure-client-secret"
                    type="password"
                    value={credentials.azure.clientSecret}
                    onChange={(e) => handleInputChange('azure', 'clientSecret', e.target.value)}
                    placeholder="Enter your Azure Client Secret"
                    className="bg-cyber-darker border-cyber-lightgray text-white"
                  />
                </div>
                
                <div className="grid gap-2">
                  <Label htmlFor="azure-tenant-id" className="text-white">Tenant ID</Label>
                  <Input
                    id="azure-tenant-id"
                    value={credentials.azure.tenantId}
                    onChange={(e) => handleInputChange('azure', 'tenantId', e.target.value)}
                    placeholder="Enter your Azure Tenant ID"
                    className="bg-cyber-darker border-cyber-lightgray text-white"
                  />
                </div>
                
                <div className="grid gap-2">
                  <Label htmlFor="azure-subscription-id" className="text-white">Subscription ID</Label>
                  <Input
                    id="azure-subscription-id"
                    value={credentials.azure.subscriptionId}
                    onChange={(e) => handleInputChange('azure', 'subscriptionId', e.target.value)}
                    placeholder="Enter your Azure Subscription ID"
                    className="bg-cyber-darker border-cyber-lightgray text-white"
                  />
                </div>
                
                <div className="flex justify-between mt-2">
                  <Button 
                    variant="outline"
                    onClick={() => clearCredentials('azure')}
                    className="border-cyber-danger text-cyber-danger hover:bg-cyber-danger/20"
                  >
                    Clear
                  </Button>
                  <Button 
                    onClick={() => saveCredentials('azure')}
                    disabled={isLoading || !credentials.azure.clientId || !credentials.azure.clientSecret || !credentials.azure.tenantId || !credentials.azure.subscriptionId}
                    className="bg-cyber-accent hover:bg-cyber-accent/80"
                  >
                    {isLoading ? (
                      <>
                        <RefreshCcw className="h-4 w-4 mr-2 animate-spin" />
                        Saving...
                      </>
                    ) : (
                      <>
                        <Save className="h-4 w-4 mr-2" />
                        Save & Verify
                      </>
                    )}
                  </Button>
                </div>
                
                {connectionStatus.azure === 'error' && (
                  <div className="flex items-center p-3 bg-cyber-danger/20 rounded-md text-cyber-danger text-sm mt-2">
                    <AlertCircle className="h-4 w-4 mr-2" />
                    Failed to connect to Azure. Please check your credentials and try again.
                  </div>
                )}
              </div>
            </div>
          </TabsContent>
          
          {/* Google Cloud Tab */}
          <TabsContent value="googleCloud">
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <div className="flex items-center space-x-2">
                  <Key className="h-5 w-5 text-cyber-accent" />
                  <h3 className="text-md font-medium text-white">Google Cloud Credentials</h3>
                </div>
                <Badge className={
                  connectionStatus.googleCloud === 'connected' ? "bg-cyber-success" :
                  connectionStatus.googleCloud === 'checking' ? "bg-cyber-warning" :
                  connectionStatus.googleCloud === 'error' ? "bg-cyber-danger" :
                  "bg-cyber-gray"
                }>
                  {connectionStatus.googleCloud === 'connected' ? "Connected" :
                   connectionStatus.googleCloud === 'checking' ? "Checking..." :
                   connectionStatus.googleCloud === 'error' ? "Connection Error" :
                   "Not Configured"}
                </Badge>
              </div>
              
              <div className="grid gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="gcp-project-id" className="text-white">Project ID</Label>
                  <Input
                    id="gcp-project-id"
                    value={credentials.googleCloud.projectId}
                    onChange={(e) => handleInputChange('googleCloud', 'projectId', e.target.value)}
                    placeholder="Enter your GCP Project ID"
                    className="bg-cyber-darker border-cyber-lightgray text-white"
                  />
                </div>
                
                <div className="grid gap-2">
                  <Label htmlFor="gcp-credentials" className="text-white">Service Account Credentials (JSON)</Label>
                  <textarea
                    id="gcp-credentials"
                    value={credentials.googleCloud.credentials}
                    onChange={(e) => handleInputChange('googleCloud', 'credentials', e.target.value)}
                    placeholder="Paste your service account JSON credentials"
                    className="bg-cyber-darker border border-cyber-lightgray text-white h-48 p-2 rounded-md font-mono text-sm"
                  />
                  <p className="text-xs text-gray-400 mt-1">
                    Paste the entire JSON file content from your service account key
                  </p>
                </div>
                
                <div className="flex justify-between mt-2">
                  <Button 
                    variant="outline"
                    onClick={() => clearCredentials('googleCloud')}
                    className="border-cyber-danger text-cyber-danger hover:bg-cyber-danger/20"
                  >
                    Clear
                  </Button>
                  <Button 
                    onClick={() => saveCredentials('googleCloud')}
                    disabled={isLoading || !credentials.googleCloud.projectId || !credentials.googleCloud.credentials}
                    className="bg-cyber-accent hover:bg-cyber-accent/80"
                  >
                    {isLoading ? (
                      <>
                        <RefreshCcw className="h-4 w-4 mr-2 animate-spin" />
                        Saving...
                      </>
                    ) : (
                      <>
                        <Save className="h-4 w-4 mr-2" />
                        Save & Verify
                      </>
                    )}
                  </Button>
                </div>
                
                {connectionStatus.googleCloud === 'error' && (
                  <div className="flex items-center p-3 bg-cyber-danger/20 rounded-md text-cyber-danger text-sm mt-2">
                    <AlertCircle className="h-4 w-4 mr-2" />
                    Failed to connect to Google Cloud. Please check your credentials and try again.
                  </div>
                )}
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default CloudCredentialsManager; 