import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Layout } from '@/components/Layout';
import { Dashboard } from '@/components/Dashboard';
import { NetworkMonitoring } from '@/components/NetworkMonitoring';
import { ThreatDetection } from '@/components/ThreatDetection';
import { SystemMetrics } from '@/components/SystemMetrics';
import { Configuration } from '@/components/Configuration';
import { Logs } from '@/components/Logs';
import { NotificationProvider } from '@/components/NotificationProvider';
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
    <QueryClientProvider client={queryClient}>
      <NotificationProvider>
        <Router>
          <div className="min-h-screen bg-gray-50">
            <Routes>
              <Route path="/" element={<Layout />}>
                <Route index element={<Navigate to="/dashboard" replace />} />
                <Route path="dashboard" element={<Dashboard />} />
                <Route path="network" element={<NetworkMonitoring />} />
                <Route path="threats" element={<ThreatDetection />} />
                <Route path="metrics" element={<SystemMetrics />} />
                <Route path="config" element={<Configuration />} />
                <Route path="logs" element={<Logs />} />
              </Route>
            </Routes>
          </div>
        </Router>
      </NotificationProvider>
    </QueryClientProvider>
  );
}

export default App; 