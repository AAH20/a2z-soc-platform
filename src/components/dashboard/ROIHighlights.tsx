import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { TrendingUp, TrendingDown, DollarSign, Users, Clock, Shield } from 'lucide-react';

interface ROIMetric {
  title: string;
  value: string;
  change: number;
  changeType: 'increase' | 'decrease';
  description: string;
  icon: React.ReactNode;
}

interface ROIHighlightsProps {
  className?: string;
}

const ROIHighlights: React.FC<ROIHighlightsProps> = ({ className }) => {
  // Mock ROI data - this would come from the API in a real implementation
  const roiMetrics: ROIMetric[] = [
    {
      title: 'Annual Cost Savings',
      value: '$2.4M',
      change: 15.3,
      changeType: 'increase',
      description: 'Compared to traditional SOC operations',
      icon: <DollarSign className="h-4 w-4" />
    },
    {
      title: 'ROI Percentage',
      value: '240%',
      change: 12.5,
      changeType: 'increase',
      description: 'Return on investment in 12 months',
      icon: <TrendingUp className="h-4 w-4" />
    },
    {
      title: 'Staff Reduction',
      value: '15 FTEs',
      change: 8.2,
      changeType: 'increase',
      description: 'Equivalent analyst positions automated',
      icon: <Users className="h-4 w-4" />
    },
    {
      title: 'Response Time',
      value: '85% faster',
      change: 22.1,
      changeType: 'increase',
      description: 'Average incident response improvement',
      icon: <Clock className="h-4 w-4" />
    },
    {
      title: 'Risk Reduction',
      value: '68%',
      change: 5.7,
      changeType: 'increase',
      description: 'Security risk profile improvement',
      icon: <Shield className="h-4 w-4" />
    },
    {
      title: 'Tool Consolidation',
      value: '12 tools',
      change: 33.3,
      changeType: 'decrease',
      description: 'Replaced by A2Z SOC platform',
      icon: <TrendingDown className="h-4 w-4" />
    }
  ];

  const getTrendIcon = (changeType: 'increase' | 'decrease') => {
    return changeType === 'increase' ? (
      <TrendingUp className="h-3 w-3 text-green-400" />
    ) : (
      <TrendingDown className="h-3 w-3 text-red-400" />
    );
  };

  const getTrendColor = (changeType: 'increase' | 'decrease') => {
    return changeType === 'increase' ? 'text-green-400' : 'text-red-400';
  };

  return (
    <div className={`space-y-6 ${className}`}>
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">ROI Highlights</h2>
        <Badge variant="secondary" className="bg-green-500/20 text-green-400">
          240% ROI Achieved
        </Badge>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {roiMetrics.map((metric, index) => (
          <Card key={index} className="bg-cyber-darker border-cyber-gray hover:shadow-lg transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-gray-300">
                {metric.title}
              </CardTitle>
              <div className="h-8 w-8 rounded-lg bg-blue-500/20 flex items-center justify-center text-blue-400">
                {metric.icon}
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <div className="text-2xl font-bold text-white">
                  {metric.value}
                </div>
                
                <div className="flex items-center space-x-1">
                  {getTrendIcon(metric.changeType)}
                  <span className={`text-xs font-medium ${getTrendColor(metric.changeType)}`}>
                    {metric.change}% from last period
                  </span>
                </div>
                
                <p className="text-xs text-gray-400">
                  {metric.description}
                </p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Summary Card */}
      <Card className="border-green-500/30 bg-green-500/10">
        <CardHeader>
          <CardTitle className="text-green-400 flex items-center space-x-2">
            <TrendingUp className="h-5 w-5" />
            <span>ROI Summary</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-center">
            <div>
              <div className="text-3xl font-bold text-white">$2.4M</div>
              <div className="text-sm text-green-400">Annual Savings</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-white">5 months</div>
              <div className="text-sm text-green-400">Payback Period</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-white">240%</div>
              <div className="text-sm text-green-400">ROI in Year 1</div>
            </div>
          </div>
          <div className="mt-4 pt-4 border-t border-green-500/30">
            <p className="text-sm text-gray-300 text-center">
              A2Z SOC has delivered exceptional value by automating security operations, 
              reducing manual effort by 85%, and improving threat detection capabilities 
              while significantly lowering operational costs.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ROIHighlights; 