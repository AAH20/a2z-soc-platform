import React, { useState } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  Network,
  AlertTriangle,
  BarChart3,
  Settings,
  FileText,
  Menu,
  X,
  Activity,
  Server,
} from 'lucide-react';
import { api } from '@/services/api';
import { StatusIndicator } from './StatusIndicator';
import { AgentStatus } from '@/types';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: BarChart3 },
  { name: 'Network Monitoring', href: '/network', icon: Network },
  { name: 'Threat Detection', href: '/threats', icon: AlertTriangle },
  { name: 'System Metrics', href: '/metrics', icon: Activity },
  { name: 'Configuration', href: '/config', icon: Settings },
  { name: 'Logs', href: '/logs', icon: FileText },
];

export function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();

  const { data: agentStatus } = useQuery<AgentStatus>({
    queryKey: ['agentStatus'],
    queryFn: () => api.getAgentStatus(),
    refetchInterval: 30000, // Refetch every 30 seconds
  });

  const currentPage = navigation.find(item => item.href === location.pathname);

  return (
    <div className="flex h-screen bg-gray-100">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        >
          <div className="absolute inset-0 bg-gray-600 opacity-75" />
        </div>
      )}

      {/* Sidebar */}
      <div
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-white shadow-lg transform ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        } transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0`}
      >
        <div className="flex items-center justify-between h-16 px-6 border-b border-gray-200">
          <div className="flex items-center space-x-2">
            <Shield className="w-8 h-8 text-primary-600" />
            <span className="text-xl font-bold text-gray-900">A2Z Agent</span>
          </div>
          <button
            className="lg:hidden"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="w-6 h-6 text-gray-400" />
          </button>
        </div>

        {/* Agent Status */}
        <div className="p-4 border-b border-gray-200">
          <div className="flex items-center space-x-3">
            <Server className="w-5 h-5 text-gray-400" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 truncate">
                {agentStatus?.agentId || 'Unknown Agent'}
              </p>
              <div className="flex items-center mt-1">
                <StatusIndicator status={agentStatus?.status || 'offline'} />
                <span className="ml-2 text-xs text-gray-500">
                  {agentStatus?.status || 'Offline'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-4 py-4 space-y-1">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href;
            return (
              <Link
                key={item.name}
                to={item.href}
                className={`group flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                  isActive
                    ? 'bg-primary-100 text-primary-700 border-r-2 border-primary-700'
                    : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
                }`}
              >
                <item.icon
                  className={`flex-shrink-0 w-5 h-5 mr-3 ${
                    isActive ? 'text-primary-500' : 'text-gray-400 group-hover:text-gray-500'
                  }`}
                />
                {item.name}
              </Link>
            );
          })}
        </nav>

        {/* Agent Info */}
        {agentStatus && (
          <div className="p-4 border-t border-gray-200">
            <div className="text-xs text-gray-500 space-y-1">
              <div>Version: {agentStatus.version}</div>
              <div>Platform: {agentStatus.systemInfo.platform}</div>
              <div>
                Uptime: {Math.floor(agentStatus.uptime / 3600)}h{' '}
                {Math.floor((agentStatus.uptime % 3600) / 60)}m
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main content */}
      <div className="flex flex-col flex-1 lg:pl-0">
        {/* Top header */}
        <header className="bg-white shadow-sm border-b border-gray-200">
          <div className="flex items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
            <div className="flex items-center">
              <button
                className="text-gray-500 hover:text-gray-700 lg:hidden"
                onClick={() => setSidebarOpen(true)}
              >
                <Menu className="w-6 h-6" />
              </button>
              <h1 className="ml-4 text-2xl font-semibold text-gray-900 lg:ml-0">
                {currentPage?.name || 'A2Z Network Agent'}
              </h1>
            </div>

            <div className="flex items-center space-x-4">
              {agentStatus && (
                <div className="hidden sm:flex items-center space-x-2 text-sm text-gray-500">
                  <div className="flex items-center">
                    <div className="w-2 h-2 bg-green-500 rounded-full mr-1" />
                    Last heartbeat: {new Date(agentStatus.lastHeartbeat).toLocaleTimeString()}
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-auto">
          <div className="p-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
} 