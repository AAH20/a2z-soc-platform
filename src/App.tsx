import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from '@/components/ui/sonner';

// Auth Components
import AuthProvider from '@/components/auth/AuthProvider';
import ProtectedRoute from '@/components/auth/ProtectedRoute';

// Auth Pages
import Login from '@/pages/Auth/Login';
import Register from '@/pages/Auth/Register';
import Onboarding from '@/pages/Onboarding';
import BillingSettings from '@/pages/BillingSettings';

// Main App Pages
import Dashboard from '@/pages/Dashboard';
import ThreatIntel from '@/pages/ThreatIntel';
import AiInsights from '@/pages/AiInsights';
import Settings from '@/pages/Settings';
import NotFound from '@/pages/NotFound';

// SIEM and SOAR Pages
import { SIEM } from '@/pages/SIEM';
import { SOAR } from '@/pages/SOAR';

// Additional Pages
import ROIDashboard from '@/pages/ROIDashboard';
import Campaigns from '@/pages/Campaigns';
import Agents from '@/pages/Agents';
import Techniques from '@/pages/Techniques';
import Network from '@/pages/Network';
import IdsIps from '@/pages/IdsIps';
import Wazuh from '@/pages/Wazuh';
import Snort from '@/pages/Snort';
import Suricata from '@/pages/Suricata';
import Elasticsearch from '@/pages/Elasticsearch';
import Opensearch from '@/pages/Opensearch';
import MicrosoftThreatIntel from '@/pages/MicrosoftThreatIntel';
import AwsThreatIntel from '@/pages/AwsThreatIntel';
import CloudInfra from '@/pages/CloudInfra';
import InfoSecAudits from '@/pages/InfoSecAudits';
import ComplianceReporting from '@/pages/ComplianceReporting';
import Alerts from '@/pages/Alerts';

// Network Agent Components
import { Dashboard as NetworkAgentDashboard } from '@/components/network-agent/Dashboard';
import { NetworkMonitoring } from '@/components/network-agent/NetworkMonitoring';
import { ThreatDetection } from '@/components/network-agent/ThreatDetection';
import { SystemMetrics } from '@/components/network-agent/SystemMetrics';
import { Configuration as AgentConfiguration } from '@/components/network-agent/Configuration';
import { Logs as AgentLogs } from '@/components/network-agent/Logs';

// Layout
import MainLayout from '@/components/layout/MainLayout';

import './App.css';

// Create a client for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 3,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

function App() {
  return (
    <Router>
      <AuthProvider>
        <QueryClientProvider client={queryClient}>
          <div className="App h-screen w-full bg-slate-900">
            <Routes>
              {/* Public Routes */}
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />

              {/* Onboarding Route */}
              <Route
                path="/onboarding"
                element={
                  <ProtectedRoute requireOnboarding>
                    <Onboarding />
                  </ProtectedRoute>
                }
              />

              {/* Protected Routes with Layout */}
              <Route
                path="/*"
                element={
                  <ProtectedRoute>
                    <MainLayout>
                      <Routes>
                        {/* Dashboard - Default Route */}
                        <Route index element={<Navigate to="/dashboard" replace />} />
                        <Route path="/dashboard" element={<Dashboard />} />
                        <Route path="/roi-dashboard" element={<ROIDashboard />} />

                        {/* SIEM and SOAR Routes */}
                        <Route path="/siem" element={<SIEM />} />
                        <Route path="/soar" element={<SOAR />} />

                        {/* Core Features */}
                        <Route path="/threats" element={<ThreatIntel />} />
                        <Route path="/ai-insights" element={<AiInsights />} />
                        <Route path="/campaigns" element={<Campaigns />} />
                        <Route path="/agents" element={<Agents />} />
                        <Route path="/techniques" element={<Techniques />} />
                        <Route path="/network" element={<Network />} />
                        <Route path="/alerts" element={<Alerts />} />
                        
                        {/* Network Agent Features */}
                        <Route path="/network-agent" element={<NetworkAgentDashboard />} />
                        <Route path="/network-monitoring" element={<NetworkMonitoring />} />
                        <Route path="/threat-detection" element={<ThreatDetection />} />
                        <Route path="/system-metrics" element={<SystemMetrics />} />
                        <Route path="/agent-config" element={<AgentConfiguration />} />
                        <Route path="/agent-logs" element={<AgentLogs />} />
                        
                        {/* Account Management */}
                        <Route path="/billing" element={<BillingSettings />} />
                        <Route path="/settings" element={<Settings />} />

                        {/* Integration Pages */}
                        <Route path="/ids-ips" element={<IdsIps />} />
                        <Route path="/wazuh" element={<Wazuh />} />
                        <Route path="/snort" element={<Snort />} />
                        <Route path="/suricata" element={<Suricata />} />
                        <Route path="/elasticsearch" element={<Elasticsearch />} />
                        <Route path="/opensearch" element={<Opensearch />} />
                        <Route path="/cloud-infra" element={<CloudInfra />} />

                        {/* Threat Intelligence */}
                        <Route path="/microsoft-threat-intel" element={<MicrosoftThreatIntel />} />
                        <Route path="/aws-threat-intel" element={<AwsThreatIntel />} />

                        {/* Compliance & Audits */}
                        <Route path="/infosec-audits" element={<InfoSecAudits />} />
                        <Route path="/compliance-reporting" element={<ComplianceReporting />} />

                        {/* Catch all - 404 */}
                        <Route path="*" element={<NotFound />} />
                      </Routes>
                    </MainLayout>
                  </ProtectedRoute>
                }
              />
            </Routes>

            {/* Global Toast Notifications */}
            <Toaster position="top-right" />
          </div>
        </QueryClientProvider>
      </AuthProvider>
    </Router>
  );
}

export default App;
