import React, { useState, useEffect } from 'react';
import Sidebar from './Sidebar';
import { Toaster } from '@/components/ui/toaster';
import { Button } from '@/components/ui/button';
import { Menu, X, Shield } from 'lucide-react';

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  // Check if we're on mobile
  useEffect(() => {
    const checkScreenSize = () => {
      setIsMobile(window.innerWidth < 1024); // lg breakpoint
    };

    checkScreenSize();
    window.addEventListener('resize', checkScreenSize);
    return () => window.removeEventListener('resize', checkScreenSize);
  }, []);

  // Close mobile sidebar when screen becomes desktop
  useEffect(() => {
    if (!isMobile) {
      setSidebarOpen(false);
    }
  }, [isMobile]);

  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  const closeSidebar = () => {
    setSidebarOpen(false);
  };

  return (
    <div className="h-screen flex overflow-hidden bg-slate-900">
      {/* Mobile sidebar overlay */}
      {isMobile && sidebarOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black bg-opacity-50 transition-opacity"
          onClick={closeSidebar}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <div className={`
        ${isMobile ? 'fixed' : 'relative'} 
        ${isMobile && !sidebarOpen ? '-translate-x-full' : 'translate-x-0'}
        ${isMobile ? 'z-50' : 'z-10'}
        transition-transform duration-300 ease-in-out
        ${isMobile ? 'inset-y-0 left-0' : ''}
      `}>
        {isMobile && sidebarOpen && (
          <div className="absolute top-4 right-4 z-10">
            <Button
              variant="ghost"
              size="sm"
              onClick={closeSidebar}
              className="text-white hover:bg-slate-700 p-2"
            >
              <X className="h-5 w-5" />
            </Button>
          </div>
        )}
        <Sidebar />
      </div>

      {/* Main content area */}
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        {/* Mobile header */}
        {isMobile && (
          <header className="bg-slate-800 border-b border-slate-700 px-4 py-3 flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={toggleSidebar}
                className="text-white hover:bg-slate-700 p-2"
              >
                <Menu className="h-6 w-6" />
              </Button>
              <div className="flex items-center space-x-2">
                <Shield className="h-6 w-6 text-blue-400" />
                <span className="text-lg font-semibold text-white">A2Z SOC</span>
              </div>
            </div>
          </header>
        )}

        {/* Main content */}
        <main className="flex-1 overflow-auto bg-slate-900">
          {children}
        </main>
      </div>

      {/* Toast notifications */}
      <Toaster />
    </div>
  );
};

export default MainLayout;
