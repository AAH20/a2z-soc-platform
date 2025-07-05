import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Code, Wand2, Eye, Save, TestTube, Copy, FileText, 
  AlertTriangle, Shield, Network, Lock, Globe, Activity,
  Package, BarChart3, Settings, Play, Pause
} from 'lucide-react';

interface RuleCondition {
  field: string;
  operator: string;
  value: string;
  enabled: boolean;
}

interface PacketStats {
  totalProcessed: number;
  matched: number;
  dropped: number;
  passed: number;
  avgProcessingTime: number;
  peakThroughput: number;
}

interface RuleBuilderProps {
  onSave: (rule: any) => void;
  onCancel: () => void;
  initialRule?: any;
}

const RuleBuilder: React.FC<RuleBuilderProps> = ({ onSave, onCancel, initialRule }) => {
  const [activeTab, setActiveTab] = useState('rules');
  const [ruleMode, setRuleMode] = useState<'guided' | 'manual'>('guided');
  const [ruleName, setRuleName] = useState(initialRule?.name || '');
  const [ruleDescription, setRuleDescription] = useState(initialRule?.description || '');
  const [ruleCategory, setRuleCategory] = useState(initialRule?.category || 'custom');
  const [ruleSeverity, setRuleSeverity] = useState(initialRule?.severity || 'medium');
  const [ruleAction, setRuleAction] = useState(initialRule?.action || 'alert');
  const [isEngineRunning, setIsEngineRunning] = useState(true);
  
  // Mock packet statistics
  const [packetStats, setPacketStats] = useState<PacketStats>({
    totalProcessed: 1247832,
    matched: 2453,
    dropped: 124,
    passed: 1245255,
    avgProcessingTime: 0.023,
    peakThroughput: 850000
  });

  // Guided rule builder state
  const [protocol, setProtocol] = useState('tcp');
  const [sourceNetwork, setSourceNetwork] = useState('any');
  const [sourcePort, setSourcePort] = useState('any');
  const [destNetwork, setDestNetwork] = useState('$HOME_NET');
  const [destPort, setDestPort] = useState('any');
  const [direction, setDirection] = useState('->');
  const [conditions, setConditions] = useState<RuleCondition[]>([
    { field: 'content', operator: 'contains', value: '', enabled: false }
  ]);
  
  // Manual rule content
  const [manualRuleContent, setManualRuleContent] = useState(initialRule?.rule_content || '');
  
  // Generated rule preview
  const [generatedRule, setGeneratedRule] = useState('');

  const protocolOptions = [
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
    { value: 'icmp', label: 'ICMP' },
    { value: 'ip', label: 'IP' },
    { value: 'http', label: 'HTTP' },
    { value: 'tls', label: 'TLS/SSL' },
    { value: 'dns', label: 'DNS' },
    { value: 'ftp', label: 'FTP' },
    { value: 'ssh', label: 'SSH' }
  ];

  const conditionFields = [
    { value: 'content', label: 'Content (payload contains)' },
    { value: 'uricontent', label: 'URI Content' },
    { value: 'pcre', label: 'Regular Expression' },
    { value: 'flags', label: 'TCP Flags' },
    { value: 'flow', label: 'Flow Direction' },
    { value: 'dsize', label: 'Data Size' },
    { value: 'ttl', label: 'Time To Live' },
    { value: 'tos', label: 'Type of Service' },
    { value: 'ipopts', label: 'IP Options' },
    { value: 'fragbits', label: 'Fragment Bits' },
    { value: 'seq', label: 'Sequence Number' },
    { value: 'ack', label: 'Acknowledgment Number' },
    { value: 'http_method', label: 'HTTP Method' },
    { value: 'http_header', label: 'HTTP Header' },
    { value: 'ssl_version', label: 'SSL Version' },
    { value: 'ja3', label: 'JA3 Fingerprint' }
  ];

  const operators = {
    content: ['contains', 'equals', 'starts_with', 'ends_with', 'regex'],
    dsize: ['equals', 'greater_than', 'less_than', 'between'],
    ttl: ['equals', 'greater_than', 'less_than'],
    flags: ['has', 'not_has', 'equals'],
    default: ['equals', 'not_equals', 'contains', 'greater_than', 'less_than']
  };

  const ruleTemplates = [
    {
      name: 'SSH Brute Force',
      description: 'Detect multiple SSH login failures',
      category: 'bruteforce',
      severity: 'high',
      rule: 'alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"Failed password"; detection_filter:track by_src, count 5, seconds 60; classtype:attempted-dos; priority:2; sid:1001; rev:1;)'
    },
    {
      name: 'Port Scan Detection',
      description: 'Detect port scanning activity',
      category: 'portscan',
      severity: 'medium',
      rule: 'alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; detection_filter:track by_src, count 10, seconds 5; classtype:attempted-recon; priority:3; sid:1002; rev:1;)'
    },
    {
      name: 'Web SQL Injection',
      description: 'Detect SQL injection attempts in web traffic',
      category: 'web-attack',
      severity: 'high',
      rule: 'alert tcp any any -> $HOME_NET [80,443] (msg:"SQL Injection Attempt"; flow:to_server,established; content:"union select"; nocase; http_uri; classtype:web-application-attack; priority:2; sid:1003; rev:1;)'
    },
    {
      name: 'Malware C&C',
      description: 'Detect malware command and control traffic',
      category: 'malware',
      severity: 'critical',
      rule: 'alert tcp $HOME_NET any -> !$HOME_NET any (msg:"Possible Malware C&C"; flow:to_server,established; content:"|deadbeef|"; classtype:trojan-activity; priority:1; sid:1004; rev:1;)'
    },
    {
      name: 'DDoS Detection',
      description: 'Detect distributed denial of service attacks',
      category: 'dos',
      severity: 'high',
      rule: 'alert tcp any any -> $HOME_NET any (msg:"Possible DDoS Attack"; flags:S; detection_filter:track by_dst, count 50, seconds 10; classtype:attempted-dos; priority:2; sid:1005; rev:1;)'
    },
    {
      name: 'DNS Tunneling',
      description: 'Detect DNS tunneling attempts',
      category: 'exfiltration',
      severity: 'medium',
      rule: 'alert udp any any -> any 53 (msg:"Possible DNS Tunneling"; content:"|01 00 00 01|"; offset:2; depth:4; dsize:>100; classtype:policy-violation; priority:3; sid:1006; rev:1;)'
    }
  ];

  const generateRule = () => {
    if (ruleMode === 'manual') {
      setGeneratedRule(manualRuleContent);
      return;
    }

    let rule = `${ruleAction} ${protocol} ${sourceNetwork} ${sourcePort} ${direction} ${destNetwork} ${destPort}`;
    
    const ruleOptions = [`msg:"${ruleName || 'Custom Rule'}"`];
    
    // Add conditions
    conditions.forEach((condition, index) => {
      if (condition.enabled && condition.value) {
        switch (condition.field) {
          case 'content':
            if (condition.operator === 'contains') {
              ruleOptions.push(`content:"${condition.value}"`);
            } else if (condition.operator === 'regex') {
              ruleOptions.push(`pcre:"/${condition.value}/i"`);
            }
            break;
          case 'uricontent':
            ruleOptions.push(`content:"${condition.value}"; http_uri`);
            break;
          case 'pcre':
            ruleOptions.push(`pcre:"${condition.value}"`);
            break;
          case 'flags':
            ruleOptions.push(`flags:${condition.value}`);
            break;
          case 'flow':
            ruleOptions.push(`flow:${condition.value}`);
            break;
          case 'dsize':
            if (condition.operator === 'equals') {
              ruleOptions.push(`dsize:${condition.value}`);
            } else if (condition.operator === 'greater_than') {
              ruleOptions.push(`dsize:>${condition.value}`);
            } else if (condition.operator === 'less_than') {
              ruleOptions.push(`dsize:<${condition.value}`);
            }
            break;
          case 'http_method':
            ruleOptions.push(`http_method; content:"${condition.value}"`);
            break;
          case 'http_header':
            ruleOptions.push(`http_header; content:"${condition.value}"`);
            break;
          default:
            ruleOptions.push(`${condition.field}:${condition.value}`);
        }
      }
    });

    // Add classification
    ruleOptions.push(`classtype:${ruleCategory}-activity`);
    
    // Add priority based on severity
    const priorityMap = { critical: 1, high: 2, medium: 3, low: 4 };
    ruleOptions.push(`priority:${priorityMap[ruleSeverity as keyof typeof priorityMap] || 3}`);
    
    // Add unique SID (timestamp-based)
    ruleOptions.push(`sid:${Date.now()}`);
    ruleOptions.push('rev:1');

    const finalRule = `${rule} (${ruleOptions.join('; ')};)`;
    setGeneratedRule(finalRule);
  };

  const addCondition = () => {
    setConditions([...conditions, { field: 'content', operator: 'contains', value: '', enabled: false }]);
  };

  const updateCondition = (index: number, field: keyof RuleCondition, value: any) => {
    const newConditions = [...conditions];
    newConditions[index] = { ...newConditions[index], [field]: value };
    setConditions(newConditions);
  };

  const removeCondition = (index: number) => {
    setConditions(conditions.filter((_, i) => i !== index));
  };

  const loadTemplate = (template: any) => {
    setRuleName(template.name);
    setRuleDescription(template.description);
    setRuleCategory(template.category);
    setRuleSeverity(template.severity);
    setManualRuleContent(template.rule);
    setRuleMode('manual');
    setGeneratedRule(template.rule);
  };

  const testRule = () => {
    // Mock rule testing
    console.log('Testing rule:', generatedRule);
  };

  const handleSave = () => {
    const rule = {
      name: ruleName,
      description: ruleDescription,
      category: ruleCategory,
      severity: ruleSeverity,
      rule_content: ruleMode === 'manual' ? manualRuleContent : generatedRule,
      enabled: true
    };
    onSave(rule);
  };

  const formatNumber = (num: number) => {
    return new Intl.NumberFormat().format(num);
  };

  const formatTime = (ms: number) => {
    return `${ms.toFixed(3)}ms`;
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="bg-gray-800 rounded-lg shadow-lg p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center">
                <Shield className="w-8 h-8 text-blue-400 mr-3" />
                A2Z IDS/IPS Engine
              </h1>
              <p className="text-gray-400 mt-1">Advanced intrusion detection and prevention system</p>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={() => setIsEngineRunning(!isEngineRunning)}
                className={`flex items-center space-x-2 px-4 py-2 rounded-md font-medium transition-colors ${
                  isEngineRunning ? 'bg-green-600 hover:bg-green-700 text-white' : 'bg-red-600 hover:bg-red-700 text-white'
                }`}
              >
                {isEngineRunning ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                <span>{isEngineRunning ? 'Engine Running' : 'Engine Stopped'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* Engine Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Package className="w-6 h-6 text-blue-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Packets Processed</p>
                <p className="text-2xl font-semibold text-blue-400">{formatNumber(packetStats.totalProcessed)}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <AlertTriangle className="w-6 h-6 text-yellow-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Rules Matched</p>
                <p className="text-2xl font-semibold text-yellow-400">{formatNumber(packetStats.matched)}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Shield className="w-6 h-6 text-red-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Packets Dropped</p>
                <p className="text-2xl font-semibold text-red-400">{formatNumber(packetStats.dropped)}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Activity className="w-6 h-6 text-green-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Packets Passed</p>
                <p className="text-2xl font-semibold text-green-400">{formatNumber(packetStats.passed)}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <BarChart3 className="w-6 h-6 text-purple-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Avg Process Time</p>
                <p className="text-2xl font-semibold text-purple-400">{formatTime(packetStats.avgProcessingTime)}</p>
              </div>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg shadow-lg p-4 border border-gray-700">
            <div className="flex items-center">
              <Network className="w-6 h-6 text-cyan-400 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-400">Peak Throughput</p>
                <p className="text-2xl font-semibold text-cyan-400">{formatNumber(packetStats.peakThroughput)}/s</p>
              </div>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="bg-gray-800 rounded-lg shadow-lg border border-gray-700">
          <div className="flex border-b border-gray-700">
            {[
              { id: 'rules', label: 'Rule Builder', icon: Code },
              { id: 'templates', label: 'Rule Templates', icon: FileText },
              { id: 'analytics', label: 'Rule Analytics', icon: BarChart3 },
              { id: 'processing', label: 'Packet Processing', icon: Package }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-6 py-4 font-medium transition-colors ${
                  activeTab === tab.id
                    ? 'text-blue-400 border-b-2 border-blue-400 bg-gray-750'
                    : 'text-gray-400 hover:text-white hover:bg-gray-750'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            ))}
          </div>

          <div className="p-6">
            {activeTab === 'rules' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-white">Custom Rule Builder</h3>
                  <div className="flex items-center space-x-3">
                    <button
                      onClick={() => setRuleMode(ruleMode === 'guided' ? 'manual' : 'guided')}
                      className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
                    >
                      {ruleMode === 'guided' ? 'Switch to Manual' : 'Switch to Guided'}
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Rule Configuration */}
                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h4 className="font-semibold text-white mb-4">Rule Configuration</h4>
                    <div className="space-y-4">
                      <div>
                        <Label className="text-gray-300">Rule Name</Label>
                        <Input
                          value={ruleName}
                          onChange={(e) => setRuleName(e.target.value)}
                          placeholder="Enter rule name"
                          className="bg-gray-700 border-gray-600 text-white"
                        />
                      </div>
                      
                      <div>
                        <Label className="text-gray-300">Description</Label>
                        <Textarea
                          value={ruleDescription}
                          onChange={(e) => setRuleDescription(e.target.value)}
                          placeholder="Describe what this rule detects"
                          className="bg-gray-700 border-gray-600 text-white"
                          rows={3}
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <Label className="text-gray-300">Category</Label>
                          <Select value={ruleCategory} onValueChange={setRuleCategory}>
                            <SelectTrigger className="bg-gray-700 border-gray-600 text-white">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent className="bg-gray-700 border-gray-600">
                              <SelectItem value="web-attack">Web Attack</SelectItem>
                              <SelectItem value="malware">Malware</SelectItem>
                              <SelectItem value="bruteforce">Brute Force</SelectItem>
                              <SelectItem value="dos">DoS/DDoS</SelectItem>
                              <SelectItem value="portscan">Port Scan</SelectItem>
                              <SelectItem value="exfiltration">Data Exfiltration</SelectItem>
                              <SelectItem value="custom">Custom</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        
                        <div>
                          <Label className="text-gray-300">Severity</Label>
                          <Select value={ruleSeverity} onValueChange={setRuleSeverity}>
                            <SelectTrigger className="bg-gray-700 border-gray-600 text-white">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent className="bg-gray-700 border-gray-600">
                              <SelectItem value="critical">Critical</SelectItem>
                              <SelectItem value="high">High</SelectItem>
                              <SelectItem value="medium">Medium</SelectItem>
                              <SelectItem value="low">Low</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Rule Preview */}
                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h4 className="font-semibold text-white mb-4">Generated Rule</h4>
                    <div className="space-y-4">
                      <div className="bg-gray-800 rounded p-3 border border-gray-700">
                        <pre className="text-sm text-green-400 font-mono whitespace-pre-wrap">
                          {generatedRule || 'Configure rule parameters to see preview...'}
                        </pre>
                      </div>
                      
                      <div className="flex space-x-2">
                        <Button 
                          onClick={generateRule} 
                          className="bg-blue-600 hover:bg-blue-700"
                        >
                          <Wand2 className="w-4 h-4 mr-2" />
                          Generate Rule
                        </Button>
                        <Button 
                          onClick={testRule} 
                          variant="outline"
                          className="border-gray-600 text-gray-300 hover:bg-gray-700"
                        >
                          <TestTube className="w-4 h-4 mr-2" />
                          Test Rule
                        </Button>
                        <Button 
                          onClick={handleSave} 
                          className="bg-green-600 hover:bg-green-700"
                          disabled={!generatedRule}
                        >
                          <Save className="w-4 h-4 mr-2" />
                          Save Rule
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>

                {ruleMode === 'guided' && (
                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h4 className="font-semibold text-white mb-4">Rule Conditions</h4>
                    <div className="grid grid-cols-5 gap-4 mb-4">
                      <div>
                        <Label className="text-gray-300">Protocol</Label>
                        <Select value={protocol} onValueChange={setProtocol}>
                          <SelectTrigger className="bg-gray-700 border-gray-600 text-white">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent className="bg-gray-700 border-gray-600">
                            {protocolOptions.map(option => (
                              <SelectItem key={option.value} value={option.value}>
                                {option.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      
                      <div>
                        <Label className="text-gray-300">Source Network</Label>
                        <Input
                          value={sourceNetwork}
                          onChange={(e) => setSourceNetwork(e.target.value)}
                          placeholder="any"
                          className="bg-gray-700 border-gray-600 text-white"
                        />
                      </div>
                      
                      <div>
                        <Label className="text-gray-300">Source Port</Label>
                        <Input
                          value={sourcePort}
                          onChange={(e) => setSourcePort(e.target.value)}
                          placeholder="any"
                          className="bg-gray-700 border-gray-600 text-white"
                        />
                      </div>
                      
                      <div>
                        <Label className="text-gray-300">Destination Network</Label>
                        <Input
                          value={destNetwork}
                          onChange={(e) => setDestNetwork(e.target.value)}
                          placeholder="$HOME_NET"
                          className="bg-gray-700 border-gray-600 text-white"
                        />
                      </div>
                      
                      <div>
                        <Label className="text-gray-300">Destination Port</Label>
                        <Input
                          value={destPort}
                          onChange={(e) => setDestPort(e.target.value)}
                          placeholder="any"
                          className="bg-gray-700 border-gray-600 text-white"
                        />
                      </div>
                    </div>

                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h5 className="font-medium text-white">Advanced Conditions</h5>
                        <Button onClick={addCondition} size="sm" variant="outline" className="border-gray-600 text-gray-300">
                          Add Condition
                        </Button>
                      </div>
                      
                      {conditions.map((condition, index) => (
                        <div key={index} className="grid grid-cols-5 gap-3 items-end">
                          <div>
                            <Select 
                              value={condition.field} 
                              onValueChange={(value) => updateCondition(index, 'field', value)}
                            >
                              <SelectTrigger className="bg-gray-700 border-gray-600 text-white">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent className="bg-gray-700 border-gray-600">
                                {conditionFields.map(field => (
                                  <SelectItem key={field.value} value={field.value}>
                                    {field.label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                          
                          <div>
                            <Select 
                              value={condition.operator} 
                              onValueChange={(value) => updateCondition(index, 'operator', value)}
                            >
                              <SelectTrigger className="bg-gray-700 border-gray-600 text-white">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent className="bg-gray-700 border-gray-600">
                                {((operators as any)[condition.field] || operators.default).map((op: string) => (
                                  <SelectItem key={op} value={op}>
                                    {op.replace('_', ' ')}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                          
                          <div>
                            <Input
                              value={condition.value}
                              onChange={(e) => updateCondition(index, 'value', e.target.value)}
                              placeholder="Value"
                              className="bg-gray-700 border-gray-600 text-white"
                            />
                          </div>
                          
                          <div className="flex items-center justify-center">
                            <Switch
                              checked={condition.enabled}
                              onCheckedChange={(checked) => updateCondition(index, 'enabled', checked)}
                            />
                          </div>
                          
                          <div>
                            <Button 
                              onClick={() => removeCondition(index)} 
                              size="sm" 
                              variant="destructive"
                            >
                              Remove
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {ruleMode === 'manual' && (
                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h4 className="font-semibold text-white mb-4">Manual Rule Editor</h4>
                    <Textarea
                      value={manualRuleContent}
                      onChange={(e) => setManualRuleContent(e.target.value)}
                      placeholder="Enter Suricata rule syntax..."
                      className="bg-gray-700 border-gray-600 text-white font-mono"
                      rows={8}
                    />
                  </div>
                )}
              </div>
            )}

            {activeTab === 'templates' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white">Pre-built Rule Templates</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {ruleTemplates.map((template, index) => (
                    <div key={index} className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h4 className="font-semibold text-white">{template.name}</h4>
                          <p className="text-sm text-gray-400 mt-1">{template.description}</p>
                        </div>
                        <Badge 
                          variant={template.severity === 'critical' ? 'destructive' : 
                                  template.severity === 'high' ? 'default' : 'secondary'}
                          className={
                            template.severity === 'critical' ? 'bg-red-900 text-red-400' :
                            template.severity === 'high' ? 'bg-orange-900 text-orange-400' :
                            template.severity === 'medium' ? 'bg-yellow-900 text-yellow-400' :
                            'bg-green-900 text-green-400'
                          }
                        >
                          {template.severity}
                        </Badge>
                      </div>
                      
                      <div className="bg-gray-800 rounded p-3 border border-gray-700 mb-4">
                        <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap">
                          {template.rule}
                        </pre>
                      </div>
                      
                      <div className="flex space-x-2">
                        <Button 
                          onClick={() => loadTemplate(template)} 
                          size="sm"
                          className="bg-blue-600 hover:bg-blue-700"
                        >
                          <Copy className="w-4 h-4 mr-2" />
                          Use Template
                        </Button>
                        <Button 
                          size="sm" 
                          variant="outline"
                          className="border-gray-600 text-gray-300 hover:bg-gray-700"
                        >
                          <Eye className="w-4 h-4 mr-2" />
                          Preview
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'analytics' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white mb-4">Rule Performance Analytics</h3>
                
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h4 className="font-semibold text-white mb-4">Processing Efficiency</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Match Rate:</span>
                        <span className="text-green-400">{((packetStats.matched / packetStats.totalProcessed) * 100).toFixed(3)}%</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Drop Rate:</span>
                        <span className="text-red-400">{((packetStats.dropped / packetStats.totalProcessed) * 100).toFixed(3)}%</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Pass Rate:</span>
                        <span className="text-blue-400">{((packetStats.passed / packetStats.totalProcessed) * 100).toFixed(2)}%</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                    <h4 className="font-semibold text-white mb-4">Performance Metrics</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Avg Processing:</span>
                        <span className="text-purple-400">{formatTime(packetStats.avgProcessingTime)}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Peak Throughput:</span>
                        <span className="text-cyan-400">{formatNumber(packetStats.peakThroughput)} pps</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Engine Status:</span>
                        <span className={isEngineRunning ? 'text-green-400' : 'text-red-400'}>
                          {isEngineRunning ? 'Running' : 'Stopped'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'processing' && (
              <div className="space-y-6">
                <h3 className="text-lg font-semibold text-white mb-4">Real-time Packet Processing</h3>
                
                <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                  <h4 className="font-semibold text-white mb-4">Processing Pipeline Status</h4>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="bg-gray-700 rounded p-3 border border-gray-600">
                      <div className="flex items-center space-x-2 mb-2">
                        <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
                        <span className="text-sm font-medium text-white">Packet Capture</span>
                      </div>
                      <p className="text-lg font-semibold text-green-400">{formatNumber(packetStats.totalProcessed)}</p>
                      <p className="text-xs text-gray-400">Packets/sec: {formatNumber(packetStats.peakThroughput)}</p>
                    </div>

                    <div className="bg-gray-700 rounded p-3 border border-gray-600">
                      <div className="flex items-center space-x-2 mb-2">
                        <div className="w-3 h-3 bg-blue-400 rounded-full animate-pulse"></div>
                        <span className="text-sm font-medium text-white">Rule Matching</span>
                      </div>
                      <p className="text-lg font-semibold text-blue-400">{formatNumber(packetStats.matched)}</p>
                      <p className="text-xs text-gray-400">Match rate: {((packetStats.matched / packetStats.totalProcessed) * 100).toFixed(3)}%</p>
                    </div>

                    <div className="bg-gray-700 rounded p-3 border border-gray-600">
                      <div className="flex items-center space-x-2 mb-2">
                        <div className="w-3 h-3 bg-red-400 rounded-full animate-pulse"></div>
                        <span className="text-sm font-medium text-white">Threat Detection</span>
                      </div>
                      <p className="text-lg font-semibold text-red-400">{formatNumber(packetStats.dropped)}</p>
                      <p className="text-xs text-gray-400">Block rate: {((packetStats.dropped / packetStats.totalProcessed) * 100).toFixed(3)}%</p>
                    </div>

                    <div className="bg-gray-700 rounded p-3 border border-gray-600">
                      <div className="flex items-center space-x-2 mb-2">
                        <div className="w-3 h-3 bg-purple-400 rounded-full animate-pulse"></div>
                        <span className="text-sm font-medium text-white">Performance</span>
                      </div>
                      <p className="text-lg font-semibold text-purple-400">{formatTime(packetStats.avgProcessingTime)}</p>
                      <p className="text-xs text-gray-400">Avg latency per packet</p>
                    </div>
                  </div>
                </div>

                <div className="bg-gray-750 rounded-lg p-4 border border-gray-600">
                  <h4 className="font-semibold text-white mb-4">Rule Engine Configuration</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Active Rules:</span>
                        <span className="text-green-400">247</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Disabled Rules:</span>
                        <span className="text-gray-400">12</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Custom Rules:</span>
                        <span className="text-blue-400">18</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Last Updated:</span>
                        <span className="text-white">2 hours ago</span>
                      </div>
                    </div>
                    
                    <div className="space-y-4">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Signature Version:</span>
                        <span className="text-green-400">6.0.8</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Rule Categories:</span>
                        <span className="text-blue-400">42</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">Memory Usage:</span>
                        <span className="text-yellow-400">2.3 GB</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-400">CPU Usage:</span>
                        <span className="text-orange-400">15.2%</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default RuleBuilder; 