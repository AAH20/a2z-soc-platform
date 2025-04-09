
import React, { useState } from 'react';
import {
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart as RechartsBarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Sector,
  ScatterChart,
  Scatter,
  ZAxis,
  Brush,
  ReferenceLine,
} from 'recharts';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { Download, ZoomIn, ZoomOut, RefreshCw } from 'lucide-react';

interface ChartData {
  [key: string]: string | number;
}

interface AdvancedChartProps {
  title: string;
  description?: string;
  data: ChartData[];
  type?: 'bar' | 'line' | 'area' | 'pie' | 'scatter' | 'heatmap';
  xAxisKey: string;
  series: {
    name: string;
    dataKey: string;
    color?: string;
  }[];
  stacked?: boolean;
  height?: number;
  allowExport?: boolean;
  allowZoom?: boolean;
  allowTypeChange?: boolean;
}

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8', '#82ca9d'];

const AdvancedChart: React.FC<AdvancedChartProps> = ({
  title,
  description,
  data,
  type = 'line',
  xAxisKey,
  series,
  stacked = false,
  height = 300,
  allowExport = true,
  allowZoom = true,
  allowTypeChange = true,
}) => {
  const [chartType, setChartType] = useState(type);
  const [activeIndex, setActiveIndex] = useState(0);
  const [zoomLevel, setZoomLevel] = useState(1);

  const handleTypeChange = (value: string) => {
    setChartType(value as 'bar' | 'line' | 'area' | 'pie' | 'scatter' | 'heatmap');
  };

  const handleExport = () => {
    // Create and download CSV
    const headers = [xAxisKey, ...series.map(s => s.name)].join(',');
    const rows = data.map(item => {
      return [item[xAxisKey], ...series.map(s => item[s.dataKey])].join(',');
    });
    const csv = [headers, ...rows].join('\n');
    
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${title.replace(/\s+/g, '_').toLowerCase()}_data.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleZoom = (direction: 'in' | 'out') => {
    if (direction === 'in') {
      setZoomLevel(prev => Math.min(prev + 0.25, 2));
    } else {
      setZoomLevel(prev => Math.max(prev - 0.25, 0.5));
    }
  };

  const onPieEnter = (_: any, index: number) => {
    setActiveIndex(index);
  };

  const renderActiveShape = (props: any) => {
    const RADIAN = Math.PI / 180;
    const { cx, cy, midAngle, innerRadius, outerRadius, startAngle, endAngle, fill, payload, percent, value } = props;
    const sin = Math.sin(-RADIAN * midAngle);
    const cos = Math.cos(-RADIAN * midAngle);
    const sx = cx + (outerRadius + 10) * cos;
    const sy = cy + (outerRadius + 10) * sin;
    const mx = cx + (outerRadius + 30) * cos;
    const my = cy + (outerRadius + 30) * sin;
    const ex = mx + (cos >= 0 ? 1 : -1) * 22;
    const ey = my;
    const textAnchor = cos >= 0 ? 'start' : 'end';

    return (
      <g>
        <text x={cx} y={cy} dy={8} textAnchor="middle" fill={fill}>
          {payload[xAxisKey]}
        </text>
        <Sector
          cx={cx}
          cy={cy}
          innerRadius={innerRadius}
          outerRadius={outerRadius}
          startAngle={startAngle}
          endAngle={endAngle}
          fill={fill}
        />
        <Sector
          cx={cx}
          cy={cy}
          startAngle={startAngle}
          endAngle={endAngle}
          innerRadius={outerRadius + 6}
          outerRadius={outerRadius + 10}
          fill={fill}
        />
        <path d={`M${sx},${sy}L${mx},${my}L${ex},${ey}`} stroke={fill} fill="none" />
        <circle cx={ex} cy={ey} r={2} fill={fill} stroke="none" />
        <text x={ex + (cos >= 0 ? 1 : -1) * 12} y={ey} textAnchor={textAnchor} fill="#999">{`${payload[series[0].dataKey]}`}</text>
        <text x={ex + (cos >= 0 ? 1 : -1) * 12} y={ey} dy={18} textAnchor={textAnchor} fill="#999">
          {`(${(percent * 100).toFixed(2)}%)`}
        </text>
      </g>
    );
  };

  const renderChart = () => {
    switch (chartType) {
      case 'bar':
        return (
          <ResponsiveContainer width="100%" height={height}>
            <RechartsBarChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 50 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey={xAxisKey} tick={{ fill: '#94a3b8' }} angle={-45} textAnchor="end" height={70} />
              <YAxis tick={{ fill: '#94a3b8' }} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #334155', borderRadius: '4px', color: '#E2E8F0' }}
                itemStyle={{ color: '#E2E8F0' }}
              />
              <Legend wrapperStyle={{ color: '#E2E8F0', paddingTop: '10px' }} />
              <Brush dataKey={xAxisKey} height={30} stroke="#8884d8" />
              {series.map((s, index) => (
                <Bar 
                  key={s.name} 
                  dataKey={s.dataKey} 
                  name={s.name} 
                  fill={s.color || COLORS[index % COLORS.length]} 
                  stackId={stacked ? 'stack' : undefined}
                />
              ))}
            </RechartsBarChart>
          </ResponsiveContainer>
        );
      case 'line':
        return (
          <ResponsiveContainer width="100%" height={height}>
            <LineChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 50 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey={xAxisKey} tick={{ fill: '#94a3b8' }} angle={-45} textAnchor="end" height={70} />
              <YAxis tick={{ fill: '#94a3b8' }} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #334155', borderRadius: '4px', color: '#E2E8F0' }}
                itemStyle={{ color: '#E2E8F0' }}
              />
              <Legend wrapperStyle={{ color: '#E2E8F0', paddingTop: '10px' }} />
              <Brush dataKey={xAxisKey} height={30} stroke="#8884d8" />
              {series.map((s, index) => (
                <Line 
                  key={s.name} 
                  type="monotone" 
                  dataKey={s.dataKey} 
                  name={s.name} 
                  stroke={s.color || COLORS[index % COLORS.length]} 
                  strokeWidth={2}
                  dot={{ r: 3 }}
                  activeDot={{ r: 5 }}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        );
      case 'area':
        return (
          <ResponsiveContainer width="100%" height={height}>
            <AreaChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 50 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey={xAxisKey} tick={{ fill: '#94a3b8' }} angle={-45} textAnchor="end" height={70} />
              <YAxis tick={{ fill: '#94a3b8' }} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #334155', borderRadius: '4px', color: '#E2E8F0' }}
                itemStyle={{ color: '#E2E8F0' }}
              />
              <Legend wrapperStyle={{ color: '#E2E8F0', paddingTop: '10px' }} />
              <Brush dataKey={xAxisKey} height={30} stroke="#8884d8" />
              {series.map((s, index) => (
                <Area 
                  key={s.name} 
                  type="monotone" 
                  dataKey={s.dataKey} 
                  name={s.name} 
                  stroke={s.color || COLORS[index % COLORS.length]}
                  fill={s.color || COLORS[index % COLORS.length]}
                  fillOpacity={0.3}
                  stackId={stacked ? 'stack' : undefined}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        );
      case 'pie':
        return (
          <ResponsiveContainer width="100%" height={height}>
            <PieChart>
              <Pie
                activeIndex={activeIndex}
                activeShape={renderActiveShape}
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                dataKey={series[0].dataKey}
                nameKey={xAxisKey}
                onMouseEnter={onPieEnter}
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #334155', borderRadius: '4px', color: '#E2E8F0' }}
                itemStyle={{ color: '#E2E8F0' }}
              />
              <Legend wrapperStyle={{ color: '#E2E8F0', paddingTop: '10px' }} />
            </PieChart>
          </ResponsiveContainer>
        );
      case 'scatter':
        return (
          <ResponsiveContainer width="100%" height={height}>
            <ScatterChart margin={{ top: 20, right: 30, left: 20, bottom: 50 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis 
                dataKey={xAxisKey} 
                type="number" 
                name={xAxisKey}
                tick={{ fill: '#94a3b8' }}
              />
              <YAxis 
                dataKey={series[0].dataKey} 
                name={series[0].name}
                tick={{ fill: '#94a3b8' }}
              />
              {series.length > 1 && (
                <ZAxis 
                  dataKey={series[1].dataKey} 
                  range={[50, 400]} 
                  name={series[1].name}
                />
              )}
              <Tooltip 
                contentStyle={{ backgroundColor: '#0F172A', border: '1px solid #334155', borderRadius: '4px', color: '#E2E8F0' }}
                itemStyle={{ color: '#E2E8F0' }}
                cursor={{ strokeDasharray: '3 3' }}
              />
              <Legend wrapperStyle={{ color: '#E2E8F0', paddingTop: '10px' }} />
              <Scatter 
                name={series[0].name} 
                data={data} 
                fill={series[0].color || COLORS[0]}
              />
            </ScatterChart>
          </ResponsiveContainer>
        );
      case 'heatmap':
        // Simplified heatmap implementation using recharts
        // For a real heatmap, you might need a specialized library
        const rows = [...new Set(data.map(item => item[xAxisKey]))];
        const columns = series.map(s => s.name);
        
        return (
          <div className="h-full w-full flex items-center justify-center">
            <div className="grid" style={{ gridTemplateColumns: `repeat(${columns.length + 1}, 1fr)` }}>
              <div className="p-2 font-bold"></div>
              {columns.map(col => (
                <div key={col} className="p-2 font-bold text-xs">{col}</div>
              ))}
              
              {rows.map((row, rowIndex) => (
                <React.Fragment key={`row-${row}`}>
                  <div className="p-2 font-bold text-xs">{row}</div>
                  {series.map((s, colIndex) => {
                    const value = data.find(d => d[xAxisKey] === row)?.[s.dataKey] as number || 0;
                    const intensity = Math.min(Math.max(value / 100, 0), 1);
                    const bgColor = s.color || COLORS[colIndex % COLORS.length];
                    
                    return (
                      <div 
                        key={`cell-${row}-${s.name}`}
                        className="p-2 text-xs text-center" 
                        style={{ 
                          backgroundColor: `rgba(${parseInt(bgColor.substring(1, 3), 16)}, ${parseInt(bgColor.substring(3, 5), 16)}, ${parseInt(bgColor.substring(5, 7), 16)}, ${intensity})`,
                          color: intensity > 0.5 ? 'white' : 'black'
                        }}
                      >
                        {value}
                      </div>
                    );
                  })}
                </React.Fragment>
              ))}
            </div>
          </div>
        );
      default:
        return <div>Unsupported chart type</div>;
    }
  };

  return (
    <Card className="bg-cyber-gray border-cyber-lightgray overflow-hidden">
      <CardHeader className="pb-2">
        <div className="flex justify-between items-center">
          <div>
            <CardTitle className="text-lg font-medium text-white">{title}</CardTitle>
            {description && <CardDescription className="text-gray-400">{description}</CardDescription>}
          </div>
          <div className="flex gap-2">
            {allowTypeChange && (
              <Select value={chartType} onValueChange={handleTypeChange}>
                <SelectTrigger className="w-[100px] bg-cyber-darker text-xs h-8">
                  <SelectValue placeholder="Chart Type" />
                </SelectTrigger>
                <SelectContent className="bg-cyber-darker border-cyber-gray">
                  <SelectItem value="bar">Bar</SelectItem>
                  <SelectItem value="line">Line</SelectItem>
                  <SelectItem value="area">Area</SelectItem>
                  <SelectItem value="pie">Pie</SelectItem>
                  <SelectItem value="scatter">Scatter</SelectItem>
                  <SelectItem value="heatmap">Heatmap</SelectItem>
                </SelectContent>
              </Select>
            )}
            {allowZoom && (
              <div className="flex">
                <Button variant="outline" size="icon" className="h-8 w-8 bg-cyber-darker" onClick={() => handleZoom('in')}>
                  <ZoomIn className="h-4 w-4" />
                </Button>
                <Button variant="outline" size="icon" className="h-8 w-8 bg-cyber-darker" onClick={() => handleZoom('out')}>
                  <ZoomOut className="h-4 w-4" />
                </Button>
              </div>
            )}
            {allowExport && (
              <Button variant="outline" size="icon" className="h-8 w-8 bg-cyber-darker" onClick={handleExport}>
                <Download className="h-4 w-4" />
              </Button>
            )}
            <Button variant="outline" size="icon" className="h-8 w-8 bg-cyber-darker">
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent style={{ height: height + 70 }}>
        <div style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'center', height: '100%', transition: 'transform 0.3s ease' }}>
          {renderChart()}
        </div>
      </CardContent>
    </Card>
  );
};

export default AdvancedChart;
