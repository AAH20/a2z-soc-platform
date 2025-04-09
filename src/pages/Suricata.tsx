
import React, { useState } from 'react';
import MainLayout from '@/components/layout/MainLayout';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { 
  Shield, 
  RefreshCcw, 
  Settings, 
  Network,
  BarChart,
  CheckCircle2
} from 'lucide-react';

// Suricata mock data
const suricataStatus = {
  status: 'not connected',
  version: '6.0.1',
  lastUpdate: 'Never',
  availableRules: 5421,
  enabledRules: 0,
  signature: {
    total: 5421,
    enabled: 0,
    drop: 0,
    alert: 0
  },
  interfaces: ['eth0', 'eth1'],
  engines: 4
};

const Suricata: React.FC = () => {
  return (
    <MainLayout>
      <div className="px-2">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">Suricata Integration</h1>
            <p className="text-gray-400">Connect to Suricata intrusion detection system</p>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent/20">
              <RefreshCcw className="h-4 w-4 mr-2" />
              Refresh Status
            </Button>
            <Button className="bg-cyber-accent hover:bg-cyber-accent/80">
              <Settings className="h-4 w-4 mr-2" />
              Configure
            </Button>
          </div>
        </div>
        
        <div className="bg-cyber-darker border border-cyber-gray rounded-md p-6 mb-6">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h2 className="text-xl font-semibold text-white">Suricata Configuration</h2>
              <p className="text-gray-400">Configure and connect to Suricata IDS</p>
            </div>
            <div>
              <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                suricataStatus.status === 'connected' ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'
              }`}>
                {suricataStatus.status === 'connected' ? 'Connected' : 'Not Connected'}
              </span>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm text-gray-400">Suricata Server Address</label>
                <div className="flex">
                  <input 
                    type="text" 
                    placeholder="e.g. 192.168.1.10" 
                    className="flex-1 px-3 py-2 bg-cyber-gray border border-cyber-gray text-white rounded-l-md focus:outline-none focus:ring-1 focus:ring-cyber-accent"
                  />
                  <input 
                    type="text" 
                    placeholder="Port" 
                    className="w-24 px-3 py-2 bg-cyber-gray border border-cyber-gray text-white rounded-r-md focus:outline-none focus:ring-1 focus:ring-cyber-accent"
                    defaultValue="9090"
                  />
                </div>
              </div>
              
              <div className="space-y-2">
                <label className="text-sm text-gray-400">API Key</label>
                <input 
                  type="password" 
                  placeholder="Enter your Suricata API key" 
                  className="w-full px-3 py-2 bg-cyber-gray border border-cyber-gray text-white rounded-md focus:outline-none focus:ring-1 focus:ring-cyber-accent"
                />
              </div>
              
              <div className="space-y-2">
                <label className="text-sm text-gray-400">Monitored Interfaces</label>
                <div className="grid grid-cols-2 gap-2">
                  {suricataStatus.interfaces.map((iface) => (
                    <div key={iface} className="flex items-center">
                      <input 
                        type="checkbox" 
                        id={`interface-${iface}`} 
                        className="mr-2 rounded border-cyber-gray text-cyber-accent focus:ring-cyber-accent"
                      />
                      <label htmlFor={`interface-${iface}`} className="text-white">{iface}</label>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            
            <div className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm text-gray-400">Engine Settings</label>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-white">Detect Engine Count</span>
                    <input 
                      type="number" 
                      className="w-16 px-2 py-1 bg-cyber-gray border border-cyber-gray text-white rounded-md focus:outline-none focus:ring-1 focus:ring-cyber-accent"
                      defaultValue={suricataStatus.engines}
                      min="1" 
                      max="16"
                    />
                  </div>
                  <div className="flex justify-between">
                    <span className="text-white">Alert Mode</span>
                    <select className="bg-cyber-gray border border-cyber-gray text-white rounded-md focus:outline-none focus:ring-1 focus:ring-cyber-accent">
                      <option>Alert Only</option>
                      <option>Alert and Drop</option>
                      <option>IPS Mode</option>
                    </select>
                  </div>
                </div>
              </div>
              
              <div className="space-y-2">
                <label className="text-sm text-gray-400">Rule Management</label>
                <button className="w-full px-3 py-2 bg-cyber-dark border border-cyber-gray text-white rounded-md hover:bg-cyber-gray transition">
                  Update Ruleset
                </button>
              </div>
            </div>
          </div>
          
          <div className="flex justify-end mt-6 space-x-3">
            <button className="px-4 py-2 border border-cyber-accent text-cyber-accent rounded-md hover:bg-cyber-accent/10 transition">
              Test Connection
            </button>
            <button className="px-4 py-2 bg-cyber-accent text-white rounded-md hover:bg-cyber-accent/90 transition">
              Connect
            </button>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-cyber-darker border border-cyber-gray rounded-md p-4">
            <h3 className="text-lg font-medium text-white mb-3">Rule Statistics</h3>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-400">Total Rules</span>
                <span className="text-white">{suricataStatus.signature.total}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Enabled</span>
                <span className="text-white">{suricataStatus.signature.enabled}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Alert Rules</span>
                <span className="text-white">{suricataStatus.signature.alert}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Drop Rules</span>
                <span className="text-white">{suricataStatus.signature.drop}</span>
              </div>
            </div>
          </div>
          
          <div className="bg-cyber-darker border border-cyber-gray rounded-md p-4">
            <h3 className="text-lg font-medium text-white mb-3">Performance</h3>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-400">Avg. Processing Time</span>
                <span className="text-white">235 μs</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Max Processing Time</span>
                <span className="text-white">782 μs</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Packets Processed</span>
                <span className="text-white">1.2M/s</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Drops</span>
                <span className="text-white">0.02%</span>
              </div>
            </div>
          </div>
          
          <div className="bg-cyber-darker border border-cyber-gray rounded-md p-4">
            <h3 className="text-lg font-medium text-white mb-3">Status</h3>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-400">Version</span>
                <span className="text-white">{suricataStatus.version}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Last Update</span>
                <span className="text-white">{suricataStatus.lastUpdate}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Uptime</span>
                <span className="text-white">Not running</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Memory Usage</span>
                <span className="text-white">N/A</span>
              </div>
            </div>
          </div>
        </div>
        
        <Card className="bg-cyber-gray border-cyber-lightgray mt-6">
          <CardHeader className="pb-2">
            <div className="flex items-center space-x-2">
              <Shield className="h-5 w-5 text-cyber-accent" />
              <CardTitle className="text-lg font-medium text-white">Integration Notes</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <p className="text-gray-300">
                The Suricata integration allows A2Z SOC to leverage Suricata's intrusion detection and prevention capabilities. Benefits include:
              </p>
              <ul className="list-disc pl-5 space-y-1 text-gray-300">
                <li>High-performance network traffic analysis</li>
                <li>Protocol detection and parser</li>
                <li>TLS/SSL certificate parsing and validation</li>
                <li>File extraction and identification</li>
                <li>Advanced correlation with other security systems</li>
              </ul>
              <div className="flex justify-between items-center bg-cyber-darker p-3 rounded-md">
                <div className="flex items-center space-x-2">
                  <CheckCircle2 className="h-5 w-5 text-cyber-accent" />
                  <span className="text-white">Alerts from Suricata are automatically correlated with other security events</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </MainLayout>
  );
};

export default Suricata;
