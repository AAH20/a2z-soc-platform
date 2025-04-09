
import React, { useState } from 'react';
import Sidebar from './Sidebar';
import { Toaster } from '@/components/ui/toaster';
import { Button } from '@/components/ui/button';
import { Menu } from 'lucide-react';

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <div className="flex h-screen overflow-hidden bg-cyber-dark text-white">
      {/* Mobile sidebar */}
      <div className={`fixed inset-0 z-40 lg:hidden ${sidebarOpen ? 'block' : 'hidden'}`}>
        <div className="absolute inset-0 bg-cyber-dark opacity-80" onClick={toggleSidebar}></div>
        <div className="absolute inset-y-0 left-0 z-50">
          <Sidebar />
        </div>
      </div>
      
      {/* Desktop sidebar */}
      <div className="hidden lg:block">
        <Sidebar />
      </div>
      
      <div className="flex flex-col flex-1 overflow-hidden">
        {/* Mobile header with menu button */}
        <div className="lg:hidden flex items-center p-4 border-b border-cyber-gray">
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleSidebar}
            className="mr-2 text-white hover:bg-cyber-gray"
          >
            <Menu className="h-6 w-6" />
          </Button>
          <h1 className="text-xl font-bold">A2Z SOC</h1>
        </div>
        
        <main className="flex-1 overflow-auto p-4">
          {children}
        </main>
      </div>
      <Toaster />
    </div>
  );
};

export default MainLayout;
