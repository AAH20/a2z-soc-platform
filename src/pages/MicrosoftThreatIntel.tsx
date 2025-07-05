
import React, { useState } from 'react';
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

const MicrosoftThreatIntel: React.FC = () => {
  const [activeTab, setActiveTab] = useState("microsoft");
  const [searchInput, setSearchInput] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [searchResults, setSearchResults] = useState<any>(null);

  // Mock search function for Microsoft Threat Intelligence
  const handleSearch = () => {
    if (!searchInput.trim()) return;
    
    setIsSearching(true);
    
    // Simulate API call with timeout
    setTimeout(() => {
      // Mock search results
      setSearchResults({
        resource: searchInput,
        positives: 12,
        total: 55,
        scan_date: "2023-12-19 10:45:12",
        permalink: "https://security.microsoft.com/threatanalytics/" + searchInput,
        scans: {
          "Microsoft Defender": { detected: true, result: "Trojan:Win32/Emotet.AB" },
          "Microsoft ATP": { detected: true, result: "HackTool:Win32/Mimikatz" },
          "Microsoft Security": { detected: true, result: "VirTool:Win32/CeeInject.gen!A" },
          "Azure Defender": { detected: true, result: "TrojanDropper:Win32/Dridex.TA!MTB" },
          "Windows Defender": { detected: true, result: "PWS:Win32/Fareit.C!MTB" },
        },
        classification: "malicious"
      });
      
      setIsSearching(false);
    }, 1500);
  };

  return (
      <div className="px-2">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Microsoft Threat Intelligence</h1>
            <p className="text-gray-400">Advanced threat detection with Microsoft security ecosystem</p>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20">
              <RefreshCcw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            <Button className="bg-cyber-accent hover:bg-cyber-accent/80">
              <Settings className="h-4 w-4 mr-2" />
              Configure
            </Button>
          </div>
        </div>

        <Tabs defaultValue="microsoft" value={activeTab} onValueChange={setActiveTab} className="w-full mb-6">
          <TabsList className="bg-cyber-darker mb-4">
            <TabsTrigger 
              value="microsoft" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Microsoft Threat Intelligence
            </TabsTrigger>
            <TabsTrigger 
              value="azure-sentinel" 
              className="data-[state=active]:bg-cyber-accent data-[state=active]:text-white"
            >
              Azure Sentinel
            </TabsTrigger>
          </TabsList>
          
          {/* Microsoft Threat Intelligence Tab */}
          <TabsContent value="microsoft">
            <Card className="bg-cyber-gray border-cyber-lightgray mb-6">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Shield className="h-5 w-5 text-cyber-accent" />
                    <CardTitle className="text-lg font-medium text-white">Microsoft Threat Intelligence API</CardTitle>
                  </div>
                  <Badge className="bg-cyber-success">Connected</Badge>
                </div>
                <CardDescription className="text-gray-400">
                  Search for file hashes, URLs, domains, or IP addresses in Microsoft's threat database
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
                      disabled={isSearching || !searchInput.trim()} 
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

                {searchResults && (
                  <div className="mt-4 bg-cyber-darker p-4 rounded-md border border-cyber-lightgray">
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <h3 className="text-lg font-medium text-white">{searchResults.resource}</h3>
                        <div className="flex items-center text-xs text-gray-400 mt-1">
                          <Clock className="h-3 w-3 mr-1" />
                          <span>Scanned on {searchResults.scan_date}</span>
                        </div>
                      </div>
                      <Badge className={
                        searchResults.classification === "clean" ? "bg-cyber-success" :
                        searchResults.classification === "suspicious" ? "bg-cyber-warning" :
                        "bg-cyber-danger"
                      }>
                        {searchResults.classification.toUpperCase()}
                      </Badge>
                    </div>
                    
                    <div className="mb-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm text-gray-300">Detection Rate</span>
                        <span className="text-sm text-white">
                          {searchResults.positives}/{searchResults.total} engines
                        </span>
                      </div>
                      <div className="h-2 bg-cyber-gray rounded-full overflow-hidden">
                        <div 
                          className={`h-full ${
                            searchResults.positives / searchResults.total < 0.2 ? "bg-cyber-success" :
                            searchResults.positives / searchResults.total < 0.5 ? "bg-cyber-warning" :
                            "bg-cyber-danger"
                          }`}
                          style={{ width: `${(searchResults.positives / searchResults.total) * 100}%` }}
                        ></div>
                      </div>
                    </div>
                    
                    <div className="mb-4">
                      <h4 className="text-sm font-medium text-white mb-2">Engine Results</h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {Object.entries(searchResults.scans).map(([engine, data]: [string, any]) => (
                          <div key={engine} className="flex items-center justify-between p-2 bg-cyber-gray rounded-md">
                            <div className="flex items-center">
                              {data.detected ? (
                                <AlertTriangle className="h-4 w-4 text-cyber-danger mr-2" />
                              ) : (
                                <CheckCircle2 className="h-4 w-4 text-cyber-success mr-2" />
                              )}
                              <span className="text-sm text-white">{engine}</span>
                            </div>
                            <span className="text-xs text-gray-300 truncate max-w-32">
                              {data.detected ? data.result : "Clean"}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div className="flex justify-end">
                      <Button 
                        variant="outline" 
                        className="text-cyber-accent border-cyber-accent hover:bg-cyber-accent/10"
                        onClick={() => window.open(searchResults.permalink, "_blank")}
                      >
                        <LinkIcon className="h-4 w-4 mr-2" />
                        View Full Report
                      </Button>
                    </div>
                  </div>
                )}
                
                <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-cyber-darker p-3 rounded-md">
                    <div className="flex items-center space-x-2 mb-2">
                      <FileText className="h-4 w-4 text-cyber-accent" />
                      <h3 className="font-medium text-white text-sm">Threat Analysis</h3>
                    </div>
                    <p className="text-xs text-gray-400">
                      Deep analysis of threats using Microsoft's global threat intelligence network
                    </p>
                  </div>
                  
                  <div className="bg-cyber-darker p-3 rounded-md">
                    <div className="flex items-center space-x-2 mb-2">
                      <Globe className="h-4 w-4 text-cyber-accent" />
                      <h3 className="font-medium text-white text-sm">Advanced Hunting</h3>
                    </div>
                    <p className="text-xs text-gray-400">
                      Query-based hunting across Microsoft 365 Defender data
                    </p>
                  </div>
                  
                  <div className="bg-cyber-darker p-3 rounded-md">
                    <div className="flex items-center space-x-2 mb-2">
                      <Zap className="h-4 w-4 text-cyber-accent" />
                      <h3 className="font-medium text-white text-sm">Threat & Vulnerability Mgmt</h3>
                    </div>
                    <p className="text-xs text-gray-400">
                      Continuously discover, prioritize, and remediate vulnerabilities and misconfigurations
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
            
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader className="pb-2">
                <div className="flex items-center space-x-2">
                  <DatabaseZap className="h-5 w-5 text-cyber-accent" />
                  <CardTitle className="text-lg font-medium text-white">Recent Intelligence</CardTitle>
                </div>
                <CardDescription className="text-gray-400">
                  Latest threat actor campaigns and insights from Microsoft
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {[
                    { 
                      title: "Emerging Ransomware Group: DEV-0401", 
                      category: "Ransomware", 
                      severity: "Critical", 
                      timestamp: "2 hours ago" 
                    },
                    { 
                      title: "Supply Chain Attack Targeting Financial Sector", 
                      category: "APT", 
                      severity: "High", 
                      timestamp: "Yesterday" 
                    },
                    { 
                      title: "Zero-day Vulnerability in Windows Print Spooler", 
                      category: "Vulnerability", 
                      severity: "Critical", 
                      timestamp: "3 days ago" 
                    },
                    { 
                      title: "AI-Generated Phishing Campaign Detection", 
                      category: "Phishing", 
                      severity: "Medium", 
                      timestamp: "1 week ago" 
                    },
                  ].map((intel) => (
                    <div key={intel.title} className="bg-cyber-darker p-3 rounded-md">
                      <div className="flex justify-between items-start">
                        <div>
                          <div className="flex items-center mb-1">
                            <Badge variant="outline" className="mr-2 bg-transparent border-cyber-accent text-cyber-accent">
                              {intel.category}
                            </Badge>
                            <Badge className={
                              intel.severity === "Critical" ? "bg-cyber-danger" :
                              intel.severity === "High" ? "bg-cyber-warning" :
                              "bg-cyber-info"
                            }>
                              {intel.severity}
                            </Badge>
                          </div>
                          <p className="text-sm text-white mb-1">{intel.title}</p>
                          <div className="flex items-center text-xs text-gray-400">
                            <span>{intel.timestamp}</span>
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
          
          {/* Azure Sentinel Tab */}
          <TabsContent value="azure-sentinel">
            <Card className="bg-cyber-gray border-cyber-lightgray mb-6">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Cloud className="h-5 w-5 text-cyber-accent" />
                    <CardTitle className="text-lg font-medium text-white">Azure Sentinel SIEM</CardTitle>
                  </div>
                  <Badge className="bg-cyber-success">Connected</Badge>
                </div>
                <CardDescription className="text-gray-400">
                  Microsoft's cloud-native security information and event management (SIEM) solution
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-cyber-darker p-4 rounded-md flex flex-col">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-medium text-white">Active Incidents</h3>
                        <Badge className="bg-cyber-danger">12</Badge>
                      </div>
                      <p className="text-xs text-gray-400 mb-2">4 high severity, 6 medium, 2 low</p>
                      <div className="mt-auto">
                        <Button variant="outline" size="sm" className="w-full border-cyber-accent text-cyber-accent hover:bg-cyber-accent/10">
                          View Incidents
                        </Button>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-4 rounded-md flex flex-col">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-medium text-white">Hunting Queries</h3>
                        <Badge className="bg-cyber-info">47</Badge>
                      </div>
                      <p className="text-xs text-gray-400 mb-2">8 custom, 39 Microsoft templates</p>
                      <div className="mt-auto">
                        <Button variant="outline" size="sm" className="w-full border-cyber-accent text-cyber-accent hover:bg-cyber-accent/10">
                          Run Queries
                        </Button>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-4 rounded-md flex flex-col">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-medium text-white">Analytics Rules</h3>
                        <Badge className="bg-cyber-success">68</Badge>
                      </div>
                      <p className="text-xs text-gray-400 mb-2">52 active, 16 disabled</p>
                      <div className="mt-auto">
                        <Button variant="outline" size="sm" className="w-full border-cyber-accent text-cyber-accent hover:bg-cyber-accent/10">
                          Manage Rules
                        </Button>
                      </div>
                    </div>
                  </div>
                  
                  <div className="bg-cyber-darker p-4 rounded-md">
                    <h3 className="text-sm font-medium text-white mb-3">Recent Incidents</h3>
                    <div className="space-y-2">
                      {[
                        {
                          name: "Multiple failed login attempts",
                          severity: "High",
                          status: "Active",
                          created: "30 mins ago",
                          entities: "14 accounts, 3 IPs"
                        },
                        {
                          name: "Suspicious PowerShell commands",
                          severity: "High",
                          status: "Active",
                          created: "1 hour ago",
                          entities: "2 hosts, 1 user"
                        },
                        {
                          name: "Unusual network traffic pattern",
                          severity: "Medium",
                          status: "Active",
                          created: "3 hours ago",
                          entities: "5 IPs, 2 hosts"
                        },
                        {
                          name: "Suspicious outbound traffic to rare domain",
                          severity: "Medium",
                          status: "Investigating",
                          created: "5 hours ago",
                          entities: "1 host, 1 domain"
                        }
                      ].map((incident, i) => (
                        <div key={i} className="p-3 bg-cyber-gray rounded-md border border-cyber-lightgray">
                          <div className="flex justify-between mb-1">
                            <span className="text-sm font-medium text-white">{incident.name}</span>
                            <Badge className={
                              incident.severity === "High" ? "bg-cyber-danger" :
                              incident.severity === "Medium" ? "bg-cyber-warning" :
                              "bg-cyber-info"
                            }>
                              {incident.severity}
                            </Badge>
                          </div>
                          <div className="flex justify-between items-center text-xs text-gray-400">
                            <span>{incident.entities}</span>
                            <span>{incident.created}</span>
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
                          <span className="text-xs text-gray-300">Microsoft 365 Defender</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-success text-cyber-success">Connected</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-300">Azure AD</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-success text-cyber-success">Connected</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-300">Azure Activity</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-success text-cyber-success">Connected</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-300">Office 365</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-success text-cyber-success">Connected</Badge>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-xs text-gray-300">AWS CloudTrail</span>
                          <Badge variant="outline" className="bg-transparent border-cyber-danger text-cyber-danger">Not Connected</Badge>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-cyber-darker p-4 rounded-md">
                      <h3 className="text-sm font-medium text-white mb-3">Workbooks</h3>
                      <div className="space-y-2">
                        <div className="p-2 bg-cyber-gray rounded-md">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium text-white">Security Operations</span>
                            <Button variant="ghost" size="sm" className="h-6 px-2">
                              <FileText className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="p-2 bg-cyber-gray rounded-md">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium text-white">Identity & Access</span>
                            <Button variant="ghost" size="sm" className="h-6 px-2">
                              <FileText className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="p-2 bg-cyber-gray rounded-md">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium text-white">Threat Intelligence</span>
                            <Button variant="ghost" size="sm" className="h-6 px-2">
                              <FileText className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="p-2 bg-cyber-gray rounded-md">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium text-white">Network Analysis</span>
                            <Button variant="ghost" size="sm" className="h-6 px-2">
                              <FileText className="h-3 w-3" />
                            </Button>
                          </div>
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

export default MicrosoftThreatIntel;
