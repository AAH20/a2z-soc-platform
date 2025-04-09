
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface MetricsCardProps {
  title: string;
  value: string | number;
  description?: string;
  icon: React.ReactNode;
  trend?: number;
  className?: string;
}

const MetricsCard: React.FC<MetricsCardProps> = ({
  title,
  value,
  description,
  icon,
  trend,
  className
}) => {
  return (
    <Card className={cn("bg-cyber-gray border-cyber-lightgray overflow-hidden", className)}>
      <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
        <CardTitle className="text-sm font-medium text-gray-300">{title}</CardTitle>
        <div className="text-cyber-accent">{icon}</div>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold text-white">{value}</div>
        {description && <p className="text-xs text-gray-400 mt-1">{description}</p>}
        {trend !== undefined && (
          <div className={cn(
            "flex items-center mt-2 text-xs",
            trend >= 0 ? "text-cyber-success" : "text-cyber-danger"
          )}>
            <span className="mr-1">
              {trend >= 0 ? '↑' : '↓'}
            </span>
            <span>{Math.abs(trend)}% from previous period</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default MetricsCard;
