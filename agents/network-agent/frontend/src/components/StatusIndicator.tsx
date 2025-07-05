import React from 'react';
import { StatusColor } from '@/types';

interface StatusIndicatorProps {
  status: 'online' | 'offline' | 'connecting' | 'error';
  size?: 'sm' | 'md' | 'lg';
  showPulse?: boolean;
}

const statusColors: Record<string, StatusColor> = {
  online: 'green',
  connecting: 'yellow',
  error: 'red',
  offline: 'gray',
};

const sizeClasses = {
  sm: 'w-2 h-2',
  md: 'w-3 h-3',
  lg: 'w-4 h-4',
};

export function StatusIndicator({ status, size = 'md', showPulse = true }: StatusIndicatorProps) {
  const color = statusColors[status];
  const sizeClass = sizeClasses[size];
  
  const baseClasses = `rounded-full ${sizeClass}`;
  const colorClasses = {
    green: 'bg-green-500',
    yellow: 'bg-yellow-500',
    red: 'bg-red-500',
    gray: 'bg-gray-400',
  };
  
  const pulseClasses = {
    green: 'animate-pulse',
    yellow: 'animate-pulse',
    red: '',
    gray: '',
  };

  return (
    <div className="relative flex items-center">
      <div
        className={`${baseClasses} ${colorClasses[color]} ${
          showPulse && status === 'connecting' ? pulseClasses[color] : ''
        }`}
      />
      {status === 'online' && showPulse && (
        <div className={`absolute ${baseClasses} ${colorClasses[color]} animate-ping opacity-75`} />
      )}
    </div>
  );
} 