
import React from 'react';
import { Progress } from '@/components/ui/progress';
import { cn } from '@/lib/utils';

interface CustomProgressProps {
  value: number;
  className?: string;
  indicatorColor?: string;
}

const CustomProgress: React.FC<CustomProgressProps> = ({
  value,
  className,
  indicatorColor,
}) => {
  return (
    <div className={cn("relative", className)}>
      <Progress 
        value={value} 
        className="h-2"
        style={indicatorColor ? { 
          '--progress-foreground': indicatorColor 
        } as React.CSSProperties : undefined}
      />
    </div>
  );
};

export default CustomProgress;
