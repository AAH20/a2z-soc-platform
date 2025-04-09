import React, { useState } from 'react';
import MainLayout from '@/components/layout/MainLayout';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { useQuery } from '@tanstack/react-query';
import { Search, Filter, Info, ExternalLink, Zap } from 'lucide-react';

// MITRE ATT&CK Data Types
interface Technique {
  id: string;
  name: string;
  description: string;
  tactic: string;
  platforms: string[];
  dataSource: string[];
  procedure: string;
  detection: string;
  mitigation: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

interface TacticGroup {
  name: string;
  techniques: Technique[];
}

// Updated mock API fetch function for MITRE ATT&CK techniques with popular APT techniques
const fetchTechniques = async (): Promise<TacticGroup[]> => {
  // In a real application, this would be an API call
  // For now, we'll use mock data
  console.log('Fetching MITRE ATT&CK techniques...');
  
  // Simulating API delay
  await new Promise(resolve => setTimeout(resolve, 800));
  
  const tactics: TacticGroup[] = [
    {
      name: 'Initial Access',
      techniques: [
        {
          id: 'T1566',
          name: 'Phishing',
          description: 'Adversaries may send phishing messages to gain access to victim systems. Used by APT29 (Cozy Bear), APT28 (Fancy Bear), and APT40.',
          tactic: 'Initial Access',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Email Gateway', 'User Reporting'],
          procedure: 'APT29 uses spear-phishing emails with web links to credential harvesting websites. APT28 uses targeted spear-phishing campaigns with malicious attachments.',
          detection: 'Monitor for suspicious email attachments and links. Train users to identify phishing attempts. Analyze email headers and message content for known indicators.',
          mitigation: 'Implement email filtering, user training, attachment sandboxing, and multi-factor authentication.',
          severity: 'high'
        },
        {
          id: 'T1190',
          name: 'Exploit Public-Facing Application',
          description: 'Adversaries may exploit vulnerabilities in public-facing applications. Common for APT41, APT40, and APT18 (Wekby).',
          tactic: 'Initial Access',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Web Application Firewall', 'Application Logs', 'Network Traffic'],
          procedure: 'APT41 exploits vulnerabilities in web applications like Zoho, Citrix, and Microsoft SharePoint. APT40 exploits vulnerabilities in internet-facing systems.',
          detection: 'Monitor application logs for suspicious activity and failed authentication attempts. Deploy web application firewalls with updated signatures.',
          mitigation: 'Implement regular patching, WAF, security testing, and network segmentation for public-facing services.',
          severity: 'critical'
        },
        {
          id: 'T1133',
          name: 'External Remote Services',
          description: 'Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Common for APT29, Lazarus Group, and APT34.',
          tactic: 'Initial Access',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Authentication Logs', 'VPN Logs', 'Network Traffic'],
          procedure: 'APT29 targets organizations\' VPN infrastructure and leverages valid credentials to access the victim environment. The Lazarus Group has targeted VPN vulnerabilities.',
          detection: 'Monitor for unusual authentication patterns, login times, and connection locations. Review VPN logs for anomalous behavior.',
          mitigation: 'Implement multi-factor authentication, limit VPN access, and regularly audit remote service configurations.',
          severity: 'high'
        }
      ]
    },
    {
      name: 'Execution',
      techniques: [
        {
          id: 'T1059',
          name: 'Command and Scripting Interpreter',
          description: 'Adversaries may abuse command and script interpreters to execute commands. Used extensively by APT28, APT29, APT41, and others.',
          tactic: 'Execution',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Process Monitoring', 'Command Line Logging', 'Script Logs'],
          procedure: 'APT29 uses PowerShell scripts for execution and data collection. APT28 uses PowerShell and VBScript to execute malicious code. APT41 leverages PowerShell and native Windows commands.',
          detection: 'Monitor process execution and command-line parameters. Implement PowerShell logging and script block logging.',
          mitigation: 'Restrict script execution, implement application control, and use PowerShell constrained language mode.',
          severity: 'high'
        },
        {
          id: 'T1204',
          name: 'User Execution',
          description: 'Adversaries may rely upon user interaction for execution. Common tactic for APT28, Lazarus Group, and Kimsuky.',
          tactic: 'Execution',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Process Monitoring', 'Email Logs', 'Endpoint Detection'],
          procedure: 'APT28 entices victims to open malicious Microsoft Office documents. Lazarus Group uses weaponized documents with embedded macros. Kimsuky sends malicious documents posing as legitimate organizations.',
          detection: 'Monitor for suspicious file executions, particularly Office applications spawning unusual processes. Detect unexpected child processes.',
          mitigation: 'User security awareness training, application whitelisting, and disabling macros.',
          severity: 'medium'
        },
        {
          id: 'T1047',
          name: 'Windows Management Instrumentation',
          description: 'Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands locally or remotely. Used by APT29, APT41, and FIN8.',
          tactic: 'Execution',
          platforms: ['Windows'],
          dataSource: ['Process Monitoring', 'WMI Logs', 'PowerShell Logs'],
          procedure: 'APT29 uses WMI to execute commands and maintain persistence. APT41 leverages WMI for lateral movement and remote execution.',
          detection: 'Monitor for WMI process creation events (wmic.exe) and suspicious WMI queries, particularly those executed remotely.',
          mitigation: 'Restrict WMI usage where possible, audit WMI access, and implement proper access controls.',
          severity: 'high'
        }
      ]
    },
    {
      name: 'Persistence',
      techniques: [
        {
          id: 'T1547',
          name: 'Boot or Logon Autostart Execution',
          description: 'Adversaries may configure system settings to automatically execute at startup. Commonly used by APT41, APT29, and Lazarus Group.',
          tactic: 'Persistence',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Registry', 'File Monitoring', 'Process Monitoring'],
          procedure: 'APT29 adds registry keys in Run and RunOnce keys to maintain persistence. APT41 uses registry run keys and startup folder items. Lazarus Group modifies registry keys for persistence.',
          detection: 'Monitor changes to autostart locations, registry keys, and startup directories. Compare changes against known good baselines.',
          mitigation: 'Restrict registry/file write access, implement application whitelisting, and regularly audit autostart locations.',
          severity: 'high'
        },
        {
          id: 'T1136',
          name: 'Create Account',
          description: 'Adversaries may create accounts to maintain access to victim systems. Used by APT28, APT29, and Dragonfly.',
          tactic: 'Persistence',
          platforms: ['Windows', 'macOS', 'Linux', 'Cloud'],
          dataSource: ['Account Creation Logs', 'Active Directory Logs', 'Authentication Logs'],
          procedure: 'APT28 creates local and domain accounts for persistence. APT29 creates additional accounts with admin privileges. Dragonfly creates specialized admin accounts.',
          detection: 'Monitor for new account creation, especially those with administrative privileges or created outside normal business hours.',
          mitigation: 'Enforce strong account management policies, audit account creation, and limit privileges.',
          severity: 'medium'
        },
        {
          id: 'T1505.003',
          name: 'Web Shell',
          description: 'Adversaries may create web shells to maintain access to compromised web servers. Common tactic for APT40, APT41, and multiple Chinese APT groups.',
          tactic: 'Persistence',
          platforms: ['Windows', 'Linux'],
          dataSource: ['File Monitoring', 'Web Server Logs', 'Process Monitoring'],
          procedure: 'APT41 deploys multiple web shells to maintain persistence. APT40 uses web shells like China Chopper. Chinese APTs known for ASPX and PHP web shells.',
          detection: 'Monitor web directories for unexpected file changes. Scan for known web shell signatures and unusual web server process behavior.',
          mitigation: 'Implement web application firewalls, regular file integrity monitoring, and secure web server configurations.',
          severity: 'critical'
        }
      ]
    },
    {
      name: 'Privilege Escalation',
      techniques: [
        {
          id: 'T1068',
          name: 'Exploitation for Privilege Escalation',
          description: 'Adversaries may exploit software vulnerabilities to escalate privileges. Used by APT41, APT28, and FIN7.',
          tactic: 'Privilege Escalation',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Process Monitoring', 'Kernel Logs', 'Vulnerability Scanning'],
          procedure: 'APT41 exploits local privilege escalation vulnerabilities. APT28 uses Windows kernel exploits to elevate privileges. FIN7 leverages known Windows vulnerabilities.',
          detection: 'Monitor for unusual process activity, permission changes, and exploit indicators. Look for unexpected child processes with elevated privileges.',
          mitigation: 'Keep systems patched, implement principle of least privilege, and use exploit prevention tools.',
          severity: 'critical'
        },
        {
          id: 'T1078',
          name: 'Valid Accounts',
          description: 'Adversaries may obtain and abuse credentials of existing accounts. Common for APT29, APT40, and FIN10.',
          tactic: 'Privilege Escalation',
          platforms: ['Windows', 'macOS', 'Linux', 'Cloud'],
          dataSource: ['Authentication Logs', 'Account Usage', 'Command History'],
          procedure: 'APT29 steals credentials and utilizes administrative accounts. APT40 steals privileged account credentials through various methods.',
          detection: 'Monitor for unexpected privileged account usage, unusual login times or locations, and privilege changes.',
          mitigation: 'Implement the principle of least privilege, multi-factor authentication, and privileged access management.',
          severity: 'high'
        },
        {
          id: 'T1053',
          name: 'Scheduled Task/Job',
          description: 'Adversaries may abuse task scheduling functionality to facilitate privilege escalation. Used by APT32, APT28, and APT41.',
          tactic: 'Privilege Escalation',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Task Scheduler Logs', 'File Monitoring', 'Process Monitoring'],
          procedure: 'APT32 creates scheduled tasks for privilege escalation. APT28 uses scheduled tasks to execute privileged commands. APT41 leverages scheduled tasks to launch malware with higher privileges.',
          detection: 'Monitor for creation of new scheduled tasks, especially those running with SYSTEM privileges or from unusual locations.',
          mitigation: 'Monitor and audit scheduled tasks, and limit who can create scheduled tasks.',
          severity: 'medium'
        }
      ]
    },
    {
      name: 'Defense Evasion',
      techniques: [
        {
          id: 'T1027',
          name: 'Obfuscated Files or Information',
          description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze. Used by APT29, APT28, and Lazarus Group.',
          tactic: 'Defense Evasion',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['File Monitoring', 'Malware Analysis', 'Static File Analysis'],
          procedure: 'APT29 uses steganography and custom encoders. APT28 uses custom obfuscation methods to hide payloads. Lazarus Group implements custom encryption algorithms.',
          detection: 'Use behavioral analysis and multiple detection methods. Analyze files for encryption, encoding, and obfuscation indicators.',
          mitigation: 'Deploy anti-malware capabilities with multiple detection techniques and behavior monitoring.',
          severity: 'high'
        },
        {
          id: 'T1140',
          name: 'Deobfuscate/Decode Files or Information',
          description: 'Adversaries may use encoded or obfuscated information during execution to hide artifacts. Common for APT41, Lazarus Group, and APT28.',
          tactic: 'Defense Evasion',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Process Monitoring', 'Script Monitoring', 'File Monitoring'],
          procedure: 'APT41 uses custom decoders to reveal payloads at runtime. Lazarus Group decrypts payloads using custom algorithms. APT28 uses multi-layer encoded commands.',
          detection: 'Monitor for suspicious decoding/deobfuscation activities such as use of common encoding utilities or suspicious script execution.',
          mitigation: 'Implement application control and monitor script execution for deobfuscation techniques.',
          severity: 'medium'
        },
        {
          id: 'T1055',
          name: 'Process Injection',
          description: 'Adversaries may inject code into processes to evade process-based defenses. Used extensively by APT29, APT28, and FIN7.',
          tactic: 'Defense Evasion',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Process Monitoring', 'Memory Analysis', 'API Monitoring'],
          procedure: 'APT29 injects into legitimate Windows processes. APT28 uses various process injection techniques to hide malicious code. FIN7 uses process hollowing and DLL injection.',
          detection: 'Monitor for suspicious API calls related to process manipulation, unexpected thread creation, and memory modifications.',
          mitigation: 'Implement exploit prevention capabilities, application control, and behavior monitoring.',
          severity: 'critical'
        }
      ]
    },
    {
      name: 'Credential Access',
      techniques: [
        {
          id: 'T1110',
          name: 'Brute Force',
          description: 'Adversaries may use brute force techniques to gain access to accounts. Common technique for APT28, Lazarus Group, and APT41.',
          tactic: 'Credential Access',
          platforms: ['Windows', 'macOS', 'Linux', 'Cloud'],
          dataSource: ['Authentication Logs', 'Failed Login Attempts', 'Network Traffic'],
          procedure: 'APT28 targets VPN, OWA, and remote access interfaces. Lazarus Group performs password spraying against internet-facing services. APT41 performs brute force attacks against public services.',
          detection: 'Monitor for multiple failed authentication attempts, especially from the same source IP or targeting multiple accounts.',
          mitigation: 'Implement account lockout policies, multi-factor authentication, and CAPTCHA mechanisms.',
          severity: 'high'
        },
        {
          id: 'T1003',
          name: 'OS Credential Dumping',
          description: 'Adversaries may attempt to dump credentials to obtain account login information. Used by APT29, APT28, and many other APTs.',
          tactic: 'Credential Access',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Process Monitoring', 'Memory Analysis', 'Registry Access'],
          procedure: 'APT29 uses custom tools to extract credentials from LSASS. APT28 uses Mimikatz variants for credential harvesting. Most APTs target Windows credential storage.',
          detection: 'Monitor for suspicious access to LSASS process, Security Account Manager database, and specific API calls related to credential access.',
          mitigation: 'Implement credential guard, privileged access workstations, and password management solutions.',
          severity: 'critical'
        },
        {
          id: 'T1056',
          name: 'Input Capture',
          description: 'Adversaries may use methods of capturing user input to obtain credentials. Common for FIN7, APT28, and Kimsuky.',
          tactic: 'Credential Access',
          platforms: ['Windows', 'macOS', 'Linux'],
          dataSource: ['Process Monitoring', 'API Monitoring', 'Keyboard Event Logs'],
          procedure: 'FIN7 deploys keyloggers to capture credentials. APT28 uses keylogging capabilities in their malware. Kimsuky deploys keyloggers targeting specific applications.',
          detection: 'Monitor for suspicious processes accessing keyboard interfaces, hooking APIs, or creating screenshots.',
          mitigation: 'Implement application control, use credential managers, and deploy anti-malware with behavioral detection.',
          severity: 'medium'
        }
      ]
    }
  ];
  
  return tactics;
};

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical': return 'bg-red-600 hover:bg-red-700';
    case 'high': return 'bg-orange-500 hover:bg-orange-600';
    case 'medium': return 'bg-yellow-500 hover:bg-yellow-600';
    case 'low': return 'bg-blue-500 hover:bg-blue-600';
    default: return 'bg-gray-500 hover:bg-gray-600';
  }
};

const TechniquesPage: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<Technique | null>(null);

  const { data: tacticGroups, isLoading, error } = useQuery({
    queryKey: ['techniques'],
    queryFn: fetchTechniques,
  });

  // Filter techniques based on search and tactic selection
  const filteredTactics = React.useMemo(() => {
    if (!tacticGroups) return [];
    
    return tacticGroups
      .map(tacticGroup => {
        // Skip filtering if no search query and no tactic selected
        if (!searchQuery && !selectedTactic) return tacticGroup;
        
        // Filter by tactic if selected
        if (selectedTactic && tacticGroup.name !== selectedTactic) {
          return { ...tacticGroup, techniques: [] };
        }
        
        // Filter by search query
        if (searchQuery) {
          const filtered = tacticGroup.techniques.filter(technique => 
            technique.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
            technique.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
            technique.description.toLowerCase().includes(searchQuery.toLowerCase())
          );
          return { ...tacticGroup, techniques: filtered };
        }
        
        return tacticGroup;
      })
      .filter(group => group.techniques.length > 0);
  }, [tacticGroups, searchQuery, selectedTactic]);

  return (
    <MainLayout>
      <div className="container mx-auto space-y-6">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold text-white">MITRE ATT&CK Techniques</h1>
          <a 
            href="https://attack.mitre.org" 
            target="_blank" 
            rel="noopener noreferrer"
            className="flex items-center text-cyber-accent hover:underline"
          >
            Visit MITRE ATT&CK <ExternalLink className="ml-1 h-4 w-4" />
          </a>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left panel - Tactics and Techniques list */}
          <div className="col-span-1">
            <Card className="bg-cyber-gray border-cyber-lightgray h-full">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle>Tactics & Techniques</CardTitle>
                  <div className="flex">
                    <Badge 
                      className="cursor-pointer mr-2"
                      variant={!selectedTactic ? "default" : "outline"}
                      onClick={() => setSelectedTactic(null)}
                    >
                      All
                    </Badge>
                    <Badge 
                      className={`cursor-pointer ${selectedTechnique ? 'bg-cyber-accent' : 'bg-cyber-gray'}`}
                      variant="outline"
                      onClick={() => setSelectedTechnique(null)}
                    >
                      <Filter className="h-3.5 w-3.5 mr-1" />
                      Clear
                    </Badge>
                  </div>
                </div>
                <div className="relative w-full mt-2">
                  <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    type="text"
                    placeholder="Search techniques by ID, name, or description"
                    className="w-full pl-8 bg-cyber-darker border-cyber-gray"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="flex justify-center items-center h-96">
                    <div className="text-cyber-accent animate-pulse">Loading techniques...</div>
                  </div>
                ) : error ? (
                  <div className="text-cyber-danger p-4">
                    <p>Error loading techniques. Please try again later.</p>
                  </div>
                ) : (
                  <ScrollArea className="h-[calc(100vh-320px)]">
                    <div className="space-y-6 pr-3">
                      {filteredTactics.map((tacticGroup) => (
                        <div key={tacticGroup.name} className="space-y-2">
                          <div 
                            className="font-semibold text-cyber-accent cursor-pointer flex items-center"
                            onClick={() => setSelectedTactic(selectedTactic === tacticGroup.name ? null : tacticGroup.name)}
                          >
                            {tacticGroup.name}
                            <Badge className="ml-2 bg-cyber-darker text-xs">
                              {tacticGroup.techniques.length}
                            </Badge>
                          </div>
                          <div className="space-y-1">
                            {tacticGroup.techniques.map((technique) => (
                              <div 
                                key={technique.id}
                                className={`px-2 py-1.5 rounded-md cursor-pointer flex items-center justify-between ${
                                  selectedTechnique?.id === technique.id 
                                    ? 'bg-cyber-accent text-white' 
                                    : 'hover:bg-cyber-darker'
                                }`}
                                onClick={() => setSelectedTechnique(technique)}
                              >
                                <div className="flex items-center">
                                  <span className="font-mono text-xs mr-2 opacity-70">{technique.id}</span>
                                  <span>{technique.name}</span>
                                </div>
                                <Badge className={`${getSeverityColor(technique.severity)} text-white text-xs`}>
                                  {technique.severity}
                                </Badge>
                              </div>
                            ))}
                          </div>
                          <Separator className="bg-cyber-lightgray" />
                        </div>
                      ))}
                      {filteredTactics.length === 0 && (
                        <div className="text-center py-4 text-gray-400">
                          No techniques found matching your filters.
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Right panel - Technique details */}
          <div className="col-span-1 lg:col-span-2">
            <Card className="bg-cyber-gray border-cyber-lightgray h-full">
              {selectedTechnique ? (
                <React.Fragment>
                  <CardHeader className="pb-2 border-b border-cyber-lightgray">
                    <div className="flex justify-between items-start">
                      <div>
                        <div className="flex items-center space-x-2">
                          <CardTitle>{selectedTechnique.name}</CardTitle>
                          <Badge className="font-mono">{selectedTechnique.id}</Badge>
                          <Badge className={`${getSeverityColor(selectedTechnique.severity)} text-white`}>
                            {selectedTechnique.severity}
                          </Badge>
                        </div>
                        <CardDescription className="mt-1">
                          {selectedTechnique.tactic} Tactic - Affects: {selectedTechnique.platforms.join(', ')}
                        </CardDescription>
                      </div>
                      <a 
                        href={`https://attack.mitre.org/techniques/${selectedTechnique.id.replace('.', '/')}/`}
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-cyber-accent hover:underline flex items-center text-sm"
                      >
                        View on MITRE <ExternalLink className="ml-1 h-3 w-3" />
                      </a>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-4">
                    <Tabs defaultValue="overview" className="w-full">
                      <TabsList className="bg-cyber-darker border-cyber-lightgray mb-4">
                        <TabsTrigger value="overview">Overview</TabsTrigger>
                        <TabsTrigger value="detection">Detection</TabsTrigger>
                        <TabsTrigger value="mitigation">Mitigation</TabsTrigger>
                        <TabsTrigger value="procedure">Procedure Examples</TabsTrigger>
                      </TabsList>
                      <TabsContent value="overview">
                        <div className="space-y-4">
                          <div>
                            <h3 className="text-sm uppercase text-gray-400 mb-1">Description</h3>
                            <p className="text-white">{selectedTechnique.description}</p>
                          </div>
                          <div>
                            <h3 className="text-sm uppercase text-gray-400 mb-1">Data Sources</h3>
                            <div className="flex flex-wrap gap-2">
                              {selectedTechnique.dataSource.map(source => (
                                <Badge key={source} variant="outline" className="bg-cyber-darker">
                                  {source}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        </div>
                      </TabsContent>
                      <TabsContent value="detection">
                        <div className="space-y-4">
                          <div className="flex items-start space-x-2">
                            <Info className="h-5 w-5 text-cyber-accent mt-0.5" />
                            <p className="text-white">{selectedTechnique.detection}</p>
                          </div>
                        </div>
                      </TabsContent>
                      <TabsContent value="mitigation">
                        <div className="space-y-4">
                          <div className="flex items-start space-x-2">
                            <Info className="h-5 w-5 text-cyber-accent mt-0.5" />
                            <p className="text-white">{selectedTechnique.mitigation}</p>
                          </div>
                        </div>
                      </TabsContent>
                      <TabsContent value="procedure">
                        <div className="space-y-4">
                          <div className="flex items-start space-x-2">
                            <Info className="h-5 w-5 text-cyber-accent mt-0.5" />
                            <p className="text-white">{selectedTechnique.procedure}</p>
                          </div>
                        </div>
                      </TabsContent>
                    </Tabs>
                  </CardContent>
                </React.Fragment>
              ) : (
                <div className="flex flex-col items-center justify-center h-[calc(100vh-240px)] text-center p-6">
                  <Zap className="h-16 w-16 text-cyber-accent mb-4 opacity-50" />
                  <h3 className="text-xl font-medium text-white mb-2">Select a Technique</h3>
                  <p className="text-gray-400 max-w-md">
                    Choose a technique from the list to view detailed information about attack vectors, detection methods, and mitigation strategies.
                  </p>
                </div>
              )}
            </Card>
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

export default TechniquesPage;
