import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { 
  BarChart3, 
  ShieldAlert, 
  Network, 
  Target, 
  Users, 
  AlertCircle, 
  Settings, 
  Zap, 
  ActivitySquare,
  Shield,
  DatabaseZap,
  FileCheck,
  Cloud,
  Database,
  Search,
  Brain,
  FileText,
  CreditCard,
  Building2,
  Server,
  TrendingUp,
  ShieldCheck,
  Monitor,
  Radar,
  BarChart,
  FileCode
} from 'lucide-react';

const navItems = [
  // Main Dashboards
  { name: 'Security Dashboard', path: '/dashboard', icon: <BarChart3 className="h-5 w-5" /> },
  { name: 'ROI Analytics', path: '/roi-dashboard', icon: <TrendingUp className="h-5 w-5" /> },
  
  // Network Agent Section
  { name: 'Network Agent', path: '/network-agent', icon: <Monitor className="h-5 w-5" /> },
  { name: 'Network Monitoring', path: '/network-monitoring', icon: <Network className="h-5 w-5" /> },
  { name: 'Threat Detection', path: '/threat-detection', icon: <Radar className="h-5 w-5" /> },
  { name: 'System Metrics', path: '/system-metrics', icon: <BarChart className="h-5 w-5" /> },
  { name: 'Agent Config', path: '/agent-config', icon: <Settings className="h-5 w-5" /> },
  { name: 'Agent Logs', path: '/agent-logs', icon: <FileCode className="h-5 w-5" /> },
  
  // Security Operations
  { name: 'Campaigns', path: '/campaigns', icon: <Target className="h-5 w-5" /> },
  { name: 'Agents', path: '/agents', icon: <Users className="h-5 w-5" /> },
  { name: 'Techniques', path: '/techniques', icon: <Zap className="h-5 w-5" /> },
  { name: 'Alerts', path: '/alerts', icon: <AlertCircle className="h-5 w-5" /> },
  
  // Security Tools
  { name: 'A2Z IDS/IPS', path: '/ids-ips', icon: <ShieldCheck className="h-5 w-5" /> },
  { name: 'Wazuh SIEM', path: '/wazuh', icon: <ShieldAlert className="h-5 w-5" /> },
  { name: 'Snort IDS', path: '/snort', icon: <ActivitySquare className="h-5 w-5" /> },
  { name: 'Suricata IPS', path: '/suricata', icon: <Shield className="h-5 w-5" /> },
  
  // Data & Analytics
  { name: 'Elasticsearch', path: '/elasticsearch', icon: <Database className="h-5 w-5" /> },
  { name: 'OpenSearch', path: '/opensearch', icon: <Search className="h-5 w-5" /> },
  
  // Threat Intelligence
  { name: 'Threat Intel Hub', path: '/threats', icon: <DatabaseZap className="h-5 w-5" /> },
  
  // Cloud & Infrastructure
  { name: 'Cloud Infrastructure', path: '/cloud-infra', icon: <Cloud className="h-5 w-5" /> },
  { name: 'Microsoft Security', path: '/microsoft-threat-intel', icon: <Building2 className="h-5 w-5" /> },
  { name: 'AWS Security', path: '/aws-threat-intel', icon: <Server className="h-5 w-5" /> },
  
  // Compliance & Auditing
  { name: 'Security Audits', path: '/infosec-audits', icon: <FileCheck className="h-5 w-5" /> },
  { name: 'Compliance Reports', path: '/compliance-reporting', icon: <FileText className="h-5 w-5" /> },
  
  // AI & Management
  { name: 'AI Insights', path: '/ai-insights', icon: <Brain className="h-5 w-5" /> },
  { name: 'Billing', path: '/billing', icon: <CreditCard className="h-5 w-5" /> },
  { name: 'Settings', path: '/settings', icon: <Settings className="h-5 w-5" /> },
];

const Sidebar: React.FC = () => {
  const location = useLocation();
  
  return (
    <div className="w-64 h-full bg-slate-800 border-r border-slate-700 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-slate-700 flex-shrink-0">
        <div className="flex items-center space-x-2">
          <Shield className="h-8 w-8 text-blue-400 flex-shrink-0" />
          <div className="min-w-0 flex-1">
            <h1 className="text-xl font-bold text-white truncate">A2Z SOC</h1>
            <div className="text-xs text-blue-400 truncate">Security Operations Platform</div>
          </div>
        </div>
      </div>
      
      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            title={item.name}
            className={cn(
              "flex items-center space-x-3 px-3 py-2 rounded-md transition-colors group",
              location.pathname === item.path
                ? "bg-blue-600 text-white"
                : "text-gray-300 hover:bg-slate-700 hover:text-white"
            )}
          >
            <div className="flex-shrink-0">
              {item.icon}
            </div>
            <span className="text-sm truncate min-w-0">{item.name}</span>
          </Link>
        ))}
      </nav>
      
      {/* Footer */}
      <div className="p-4 border-t border-slate-700 flex-shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2 min-w-0">
            <div className="h-2 w-2 bg-green-400 rounded-full animate-pulse flex-shrink-0"></div>
            <span className="text-sm text-gray-300 truncate">System Online</span>
          </div>
          <span className="text-xs text-gray-400 flex-shrink-0">v1.0.0</span>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
