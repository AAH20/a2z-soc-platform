import React, { useState, useEffect } from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  DatabaseZap, 
  Search, 
  Shield, 
  FileText, 
  Globe, 
  RefreshCcw, 
  Settings,
  AlertTriangle,
  CheckCircle2,
  X,
  Zap,
  Link as LinkIcon,
  Clock,
  Cloud
} from 'lucide-react';
import { threatIntelligenceService } from '@/services/threatIntelligenceService';
import FileUpload from '@/components/threat-intel/FileUpload';
import ScanResults from '@/components/threat-intel/ScanResults';

const ThreatIntel: React.FC = () => {
  const [activeTab, setActiveTab] = useState("virustotal");
  const [searchInput, setSearchInput] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [searchResults, setSearchResults] = useState<any>(null);
  const [searchType, setSearchType] = useState<'file' | 'url' | 'domain' | 'ip'>('domain');
  const [apiHealth, setApiHealth] = useState<boolean | null>(null);
  const [isCheckingHealth, setIsCheckingHealth] = useState(false);

  useEffect(() => {
    checkApiHealth();
  }, []);

  const checkApiHealth = async () => {
    setIsCheckingHealth(true);
    try {
      const response = await threatIntelligenceService.checkVirusTotalHealth();
      setApiHealth(response.success);
    } catch (error) {
      setApiHealth(false);
      console.error('API health check failed:', error);
    } finally {
      setIsCheckingHealth(false);
    }
  };

  // Detect search type based on input
  useEffect(() => {
    if (!searchInput) return;
    
    // Check if it's a file hash (MD5, SHA1, SHA256)
    if (/^[a-fA-F0-9]{32}$/.test(searchInput) || /^[a-fA-F0-9]{40}$/.test(searchInput) || /^[a-fA-F0-9]{64}$/.test(searchInput)) {
      setSearchType('file');
      return;
    }
    
    // Check if it's a URL
    if (searchInput.startsWith('http') || searchInput.startsWith('www.') || /^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}(\/.*)?$/.test(searchInput)) {
      setSearchType('url');
      return;
    }
    
    // Check if it's an IP address
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(searchInput)) {
      setSearchType('ip');
      return;
    }
    
    // Default to domain
    setSearchType('domain');
  }, [searchInput]);

  const handleSearch = async () => {
    if (!searchInput.trim()) return;
    
    setIsSearching(true);
    setSearchResults(null);
    
    try {
      let response;
      
      switch (searchType) {
        case 'file':
          response = await threatIntelligenceService.getFileReport(searchInput);
          break;
        case 'url':
          response = await threatIntelligenceService.getUrlReport(searchInput);
          break;
        case 'ip':
          response = await threatIntelligenceService.getIpReport(searchInput);
          break;
        case 'domain':
          response = await threatIntelligenceService.getDomainReport(searchInput);
          break;
      }
      
      setSearchResults(response);
    } catch (error) {
      console.error('Search failed:', error);
      setSearchResults({
        success: false,
        data: null,
        timestamp: new Date().toISOString(),
        error: 'Failed to fetch results'
      });
    } finally {
      setIsSearching(false);
    }
  };

  const handleFileUploadComplete = (result: any) => {
    // Make sure to set the search type to 'file' for uploaded files
    setSearchType('file');
    
    // Log the response for debugging
    console.log('File upload completed with result:', JSON.stringify(result, null, 2));
    
    // Ensure the response is structured correctly
    setSearchResults({
      success: true,
      data: result,
      timestamp: new Date().toISOString()
    });
  };

  return (
      <div className="px-2">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Google Threat Intelligence</h1>
            <p className="text-gray-400">Integrated threat intelligence from Google's security ecosystem</p>
          </div>
          <div className="flex space-x-2">
            <Button 
              variant="outline" 
              className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20"
              onClick={checkApiHealth}
              disabled={isCheckingHealth}
            >
              <RefreshCcw className={`h-4 w-4 mr-2 ${isCheckingHealth ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button className="bg-cyber-accent hover:bg-cyber-accent/80">
              <Settings className="h-4 w-4 mr-2" />
              Configure
            </Button>
          </div>
        </div>

        <Tabs defaultValue="virustotal" value={activeTab} onValueChange={setActiveTab} className="w-full mb-6">
          <TabsList className="bg-cyber-darker mb-4">
            <TabsTrigger 
              value="virustotal" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              VirusTotal
            </TabsTrigger>
            <TabsTrigger 
              value="google-chronicle" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Google Chronicle
            </TabsTrigger>
          </TabsList>
          
          {/* VirusTotal Tab */}
          <TabsContent value="virustotal">
            <Card className="bg-cyber-gray border-cyber-lightgray mb-6">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Shield className="h-5 w-5 text-cyber-accent" />
                    <CardTitle className="text-lg font-medium text-white">VirusTotal API Integration</CardTitle>
                  </div>
                  <Badge className={apiHealth === null ? "bg-cyber-warning" : apiHealth ? "bg-cyber-success" : "bg-cyber-danger"}>
                    {apiHealth === null ? "Checking..." : apiHealth ? "Connected" : "Disconnected"}
                  </Badge>
                </div>
                <CardDescription className="text-gray-400">
                  Search for file hashes, URLs, domains, or IP addresses
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="mb-6">
                  <div className="flex space-x-2 mb-2">
                    <Input 
                      value={searchInput}
                      onChange={(e) => setSearchInput(e.target.value)}
                      placeholder="Enter hash, URL, domain, or IP address" 
                      className="bg-cyber-darker border-cyber-lightgray text-white"
                    />
                    <Button 
                      onClick={handleSearch}
                      disabled={isSearching || !searchInput.trim() || !apiHealth} 
                      className="bg-cyber-accent hover:bg-cyber-accent/80"
                    >
                      {isSearching ? (
                        <>
                          <RefreshCcw className="h-4 w-4 mr-2 animate-spin" />
                          Searching...
                        </>
                      ) : (
                        <>
                          <Search className="h-4 w-4 mr-2" />
                          Search
                        </>
                      )}
                    </Button>
                  </div>
                  <div className="text-xs text-gray-400 flex items-center">
                    <InfoIcon className="h-3 w-3 mr-1" />
                    Supported formats: MD5/SHA1/SHA256 hashes, URLs, Domains, IPv4/IPv6 addresses
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                  <div className="col-span-1">
                    <FileUpload onUploadComplete={handleFileUploadComplete} />
                  </div>
                  
                  {searchResults && (
                    <div className="col-span-1">
                      <ScanResults results={searchResults} type={searchType} />
                    </div>
                  )}
                </div>
                
                <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-cyber-darker p-3 rounded-md">
                    <div className="flex items-center space-x-2 mb-2">
                      <FileText className="h-4 w-4 text-cyber-accent" />
                      <h3 className="font-medium text-white text-sm">File Analysis</h3>
                    </div>
                    <p className="text-xs text-gray-400">
                      Analyze suspicious files using 70+ antivirus engines and file characterization tools
                    </p>
                  </div>
                  
                  <div className="bg-cyber-darker p-3 rounded-md">
                    <div className="flex items-center space-x-2 mb-2">
                      <Globe className="h-4 w-4 text-cyber-accent" />
                      <h3 className="font-medium text-white text-sm">URL Analysis</h3>
                    </div>
                    <p className="text-xs text-gray-400">
                      Scan suspicious URLs to detect phishing, malware, and other threats
                    </p>
                  </div>
                  
                  <div className="bg-cyber-darker p-3 rounded-md">
                    <div className="flex items-center space-x-2 mb-2">
                      <Zap className="h-4 w-4 text-cyber-accent" />
                      <h3 className="font-medium text-white text-sm">Automations</h3>
                    </div>
                    <p className="text-xs text-gray-400">
                      Automatically scan discovered IOCs from A2Z SOC detection events
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader className="pb-2">
                <div className="flex items-center space-x-2">
                  <DatabaseZap className="h-5 w-5 text-cyber-accent" />
                  <CardTitle className="text-lg font-medium text-white">Recent Scans</CardTitle>
                </div>
                <CardDescription className="text-gray-400">
                  Recently analyzed indicators of compromise
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    { 
                      type: "file", 
                      resource: "28f1d372a40c9a9548a0d6e1bbcf5c83", 
                      classification: "malicious", 
                      positives: 56, 
                      total: 68, 
                      timestamp: "10 mins ago" 
                    },
                    { 
                      type: "url", 
                      resource: "https://suspicious-domain.example/login.php", 
                      classification: "suspicious", 
                      positives: 12, 
                      total: 68, 
                      timestamp: "25 mins ago" 
                    },
                    { 
                      type: "domain", 
                      resource: "malware-distribution.example", 
                      classification: "malicious", 
                      positives: 45, 
                      total: 68, 
                      timestamp: "2 hours ago" 
                    },
                    { 
                      type: "ip", 
                      resource: "192.168.1.254", 
                      classification: "clean", 
                      positives: 0, 
                      total: 68, 
                      timestamp: "3 hours ago" 
                    },
                  ].map((scan) => (
                    <div key={scan.resource} className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex justify-between items-start">
                        <div>
                          <div className="flex items-center mb-1">
                            <Badge variant="outline" className="mr-2 bg-transparent border-cyber-accent text-cyber-accent">
                              {scan.type.toUpperCase()}
                            </Badge>
                            <Badge className={
                              scan.classification === "clean" ? "bg-cyber-success" :
                              scan.classification === "suspicious" ? "bg-cyber-warning" :
                              "bg-cyber-danger"
                            }>
                              {scan.classification.toUpperCase()}
                            </Badge>
                          </div>
                          <p className="text-sm text-white mb-1 font-mono">{scan.resource}</p>
                          <div className="flex items-center text-xs text-gray-400">
                            <span>{scan.positives}/{scan.total} detections</span>
                            <span className="mx-2">•</span>
                            <span>{scan.timestamp}</span>
                          </div>
                        </div>
                        <button className="text-gray-400 hover:text-white">
                          <Search className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          {/* Google Chronicle Tab */}
          <TabsContent value="google-chronicle">
            <Card className="bg-cyber-gray border-cyber-lightgray mb-6">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Cloud className="h-5 w-5 text-cyber-accent" />
                    <CardTitle className="text-lg font-medium text-white">Google Chronicle</CardTitle>
                  </div>
                  <Badge className="bg-cyber-success">Connected</Badge>
                </div>
                <CardDescription className="text-gray-400">
                  Google's cloud-native security analytics platform built on core Google infrastructure
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6 bg-slate-900 min-h-screen p-6">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-cyber-darker p-4 rounded-md flex flex-col">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-medium text-white">Active Detections</h3>
                        <Badge className="bg-cyber-danger">8</Badge>
                      </div>
                      <p className="text-xs text-gray-400 mb-2">3 high severity, 4 medium, 1 low</p>
                      <div className="mt-auto">
                        <Button variant="outline" size="sm" className="w-full border-cyber-accent text-cyber-accent hover:bg-cyber-accent/10">
                          View Detections
                        </Button>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-4 rounded-md flex flex-col">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-medium text-white">YARA Rules</h3>
                        <Badge className="bg-cyber-info">32</Badge>
                      </div>
                      <p className="text-xs text-gray-400 mb-2">12 custom, 20 Google templates</p>
                      <div className="mt-auto">
                        <Button variant="outline" size="sm" className="w-full border-cyber-accent text-cyber-accent hover:bg-cyber-accent/10">
                          Manage Rules
                        </Button>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-4 rounded-md flex flex-col">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-medium text-white">IOC Matches</h3>
                        <Badge className="bg-cyber-warning">15</Badge>
                      </div>
                      <p className="text-xs text-gray-400 mb-2">In the last 24 hours</p>
                      <div className="mt-auto">
                        <Button variant="outline" size="sm" className="w-full border-cyber-accent text-cyber-accent hover:bg-cyber-accent/10">
                          View Matches
                        </Button>
                      </div>
                    </div>
                  </div>
                  
                  <div className="bg-cyber-darker p-4 rounded-md">
                    <h3 className="text-sm font-medium text-white mb-3">Recent Detections</h3>
                    <div className="space-y-2">
                      {[
                        {
                          name: "Suspicious PowerShell execution",
                          severity: "High",
                          status: "Active",
                          created: "45 mins ago",
                          entities: "1 host, 1 user"
                        },
                        {
                          name: "Potential data exfiltration",
                          severity: "High",
                          status: "Active",
                          created: "2 hours ago",
                          entities: "3 hosts, 2 IPs"
                        },
                        {
                          name: "Suspicious Authentication Pattern",
                          severity: "Medium",
                          status: "Active",
                          created: "3 hours ago",
                          entities: "6 accounts, 2 IPs"
                        },
                        {
                          name: "Unusual Process Creation Chain",
                          severity: "Medium",
                          status: "Investigating",
                          created: "6 hours ago",
                          entities: "1 host, 4 processes"
                        }
                      ].map((detection, i) => (
                        <div key={i} className="p-3 bg-cyber-gray rounded-md border border-cyber-lightgray">
                          <div className="flex justify-between mb-1">
                            <span className="text-sm font-medium text-white">{detection.name}</span>
                            <Badge className={
                              detection.severity === "High" ? "bg-cyber-danger" :
                              detection.severity === "Medium" ? "bg-cyber-warning" :
                              "bg-cyber-info"
                            }>
                              {detection.severity}
                            </Badge>
                          </div>
                          <div className="flex justify-between items-center text-xs text-gray-400">
                            <span>{detection.entities}</span>
                            <span>{detection.created}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-cyber-darker p-4 rounded-md">
                      <h3 className="text-sm font-medium text-white mb-3">Data Sources</h3>
                      <div className="space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-300">Google Workspace Logs</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-success text-cyber-success">Connected</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-300">Google Cloud Logs</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-success text-cyber-success">Connected</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-300">Windows Event Logs</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-success text-cyber-success">Connected</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-300">Linux Syslogs</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-success text-cyber-success">Connected</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-300">Firewall Logs</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-success text-cyber-success">Connected</Badge>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-4 rounded-md">
                      <h3 className="text-sm font-medium text-white mb-3">Advanced Features</h3>
                      <div className="space-y-2">
                        <div className="p-2 bg-cyber-gray rounded-md flex justify-between items-center">
                          <div>
                            <span className="text-xs font-medium text-white block">UDM Search</span>
                            <span className="text-xs text-gray-400">Unified Data Model for normalized search</span>
                          </div>
                          <Button variant="ghost" size="sm" className="h-6 px-2">
                            <Search className="h-3 w-3" />
                          </Button>
                        </div>
                        <div className="p-2 bg-cyber-gray rounded-md flex justify-between items-center">
                          <div>
                            <span className="text-xs font-medium text-white block">Rule Engine</span>
                            <span className="text-xs text-gray-400">YARA-L for detection rules</span>
                          </div>
                          <Button variant="ghost" size="sm" className="h-6 px-2">
                            <FileText className="h-3 w-3" />
                          </Button>
                        </div>
                        <div className="p-2 bg-cyber-gray rounded-md flex justify-between items-center">
                          <div>
                            <span className="text-xs font-medium text-white block">Retrohunting</span>
                            <span className="text-xs text-gray-400">Search 1 year of data in seconds</span>
                          </div>
                          <Button variant="ghost" size="sm" className="h-6 px-2">
                            <Clock className="h-3 w-3" />
                          </Button>
                        </div>
                        <div className="p-2 bg-cyber-gray rounded-md flex justify-between items-center">
                          <div>
                            <span className="text-xs font-medium text-white block">IoC Management</span>
                            <span className="text-xs text-gray-400">Manage and track IoCs</span>
                          </div>
                          <Button variant="ghost" size="sm" className="h-6 px-2">
                            <Shield className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
  );
};

// Small info icon component
const InfoIcon: React.FC<{ className?: string }> = ({ className }) => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <circle cx="12" cy="12" r="10" />
    <line x1="12" y1="16" x2="12" y2="12" />
    <line x1="12" y1="8" x2="12.01" y2="8" />
  </svg>
);

export default ThreatIntel;
