
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
  User,
  Database,
  Search,
  Brain,
  FileText
} from 'lucide-react';

const navItems = [
  { name: 'Dashboard', path: '/', icon: <BarChart3 className="h-5 w-5" /> },
  { name: 'Campaigns', path: '/campaigns', icon: <Target className="h-5 w-5" /> },
  { name: 'Agents', path: '/agents', icon: <Users className="h-5 w-5" /> },
  { name: 'Techniques', path: '/techniques', icon: <Zap className="h-5 w-5" /> },
  { name: 'Network', path: '/network', icon: <Network className="h-5 w-5" /> },
  { name: 'Wazuh', path: '/wazuh', icon: <ShieldAlert className="h-5 w-5" /> },
  { name: 'Snort', path: '/snort', icon: <ActivitySquare className="h-5 w-5" /> },
  { name: 'Suricata', path: '/suricata', icon: <Shield className="h-5 w-5" /> },
  { name: 'Elasticsearch', path: '/elasticsearch', icon: <Database className="h-5 w-5" /> },
  { name: 'Opensearch', path: '/opensearch', icon: <Search className="h-5 w-5" /> },
  { name: 'Google Threat Intel', path: '/threat-intel', icon: <DatabaseZap className="h-5 w-5" /> },
  { name: 'Microsoft Threat Intel', path: '/microsoft-threat-intel', icon: <Cloud className="h-5 w-5" /> },
  { name: 'AWS Threat Intel', path: '/aws-threat-intel', icon: <Cloud className="h-5 w-5" /> },
  { name: 'InfoSec Audits', path: '/infosec-audits', icon: <FileCheck className="h-5 w-5" /> },
  { name: 'Compliance Reporting', path: '/compliance-reporting', icon: <FileText className="h-5 w-5" /> },
  { name: 'Alerts', path: '/alerts', icon: <AlertCircle className="h-5 w-5" /> },
  { name: 'AI Insights', path: '/ai-insights', icon: <Brain className="h-5 w-5" /> },
  { name: 'Contact', path: '/contact', icon: <User className="h-5 w-5" /> },
  { name: 'Settings', path: '/settings', icon: <Settings className="h-5 w-5" /> },
];

const Sidebar: React.FC = () => {
  const location = useLocation();
  
  return (
    <div className="w-64 h-full bg-cyber-darker border-r border-cyber-gray flex flex-col overflow-hidden lg:w-64 md:w-20 sm:w-20">
      <div className="p-4 border-b border-cyber-gray">
        <div className="flex items-center space-x-2">
          <Shield className="h-8 w-8 text-cyber-accent" />
          <h1 className="text-xl font-bold text-white md:hidden lg:block">A2Z SOC</h1>
        </div>
        <div className="text-xs text-cyber-accent mt-1 md:hidden lg:block">Security Operations Platform</div>
      </div>
      
      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={cn(
              "flex items-center space-x-3 px-3 py-2 rounded-md transition-colors",
              location.pathname === item.path
                ? "bg-cyber-accent text-white"
                : "text-gray-300 hover:bg-cyber-gray hover:text-white"
            )}
          >
            {item.icon}
            <span className="md:hidden lg:block">{item.name}</span>
          </Link>
        ))}
      </nav>
      
      <div className="p-4 border-t border-cyber-gray">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="h-2 w-2 bg-cyber-success rounded-full animate-pulse"></div>
            <span className="text-sm text-gray-300 md:hidden lg:block">System Online</span>
          </div>
          <span className="text-xs text-gray-400 md:hidden lg:block">v1.0.0</span>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
