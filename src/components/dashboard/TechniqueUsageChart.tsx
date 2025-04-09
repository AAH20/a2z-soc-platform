
import React from 'react';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  Cell
} from 'recharts';

interface Technique {
  name: string;
  count: number;
  description?: string;
}

interface TechniqueUsageChartProps {
  data: Technique[];
}

const TechniqueUsageChart: React.FC<TechniqueUsageChartProps> = ({ data }) => {
  // Add a null/undefined check to avoid the error
  const chartData = data || [];
  
  return (
    <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-medium text-white">Top ATT&CK Techniques</CardTitle>
        <CardDescription className="text-gray-400">
          Most frequently detected attack techniques
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={chartData}
              margin={{
                top: 5,
                right: 10,
                left: 20,
                bottom: 5,
              }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis 
                dataKey="name" 
                tick={{ fill: '#94a3b8' }} 
                axisLine={{ stroke: '#334155' }}
              />
              <YAxis 
                tick={{ fill: '#94a3b8' }} 
                axisLine={{ stroke: '#334155' }}
              />
              <Tooltip
                contentStyle={{ 
                  backgroundColor: '#0F172A', 
                  border: '1px solid #334155',
                  borderRadius: '4px',
                  color: '#E2E8F0'
                }}
                itemStyle={{ color: '#E2E8F0' }}
                cursor={{ fill: '#1E293B', opacity: 0.3 }}
              />
              <Bar dataKey="count" maxBarSize={50}>
                {chartData.map((_, index) => (
                  <Cell key={`cell-${index}`} fill="#0EA5E9" />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
};

export default TechniqueUsageChart;
