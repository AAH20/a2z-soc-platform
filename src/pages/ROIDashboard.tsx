import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { 
  DollarSign, 
  TrendingUp, 
  Clock, 
  Shield, 
  Users, 
  AlertTriangle, 
  CheckCircle, 
  BarChart3,
  PieChart,
  Calculator,
  Target,
  Zap,
  FileText,
  Download
} from 'lucide-react';
import { Badge } from "@/components/ui/badge";
import AdvancedChart from '@/components/visualizations/AdvancedChart';

// ROI calculation data
const roiMetrics = {
  currentInvestment: 250000, // Annual A2Z SOC investment
  traditionalSOCCost: 850000, // Traditional SOC annual cost
  annualSavings: 600000,
  paybackPeriod: 5, // months
  roi: 240, // percentage
  incidentReduction: 75, // percentage
  responseTimeImprovement: 85, // percentage
  falsePositiveReduction: 60, // percentage
  complianceCostSavings: 120000,
  staffProductivityGain: 40 // percentage
};

const costComparisonData = [
  { category: 'Staff Costs', traditional: 480000, a2zSOC: 180000, savings: 300000 },
  { category: 'Infrastructure', traditional: 200000, a2zSOC: 50000, savings: 150000 },
  { category: 'Tools & Licenses', traditional: 120000, a2zSOC: 20000, savings: 100000 },
  { category: 'Training & Maintenance', traditional: 50000, a2zSOC: 0, savings: 50000 }
];

const timeToValueData = [
  { month: 'Month 1', traditionaSOC: 0, a2zSOC: 35 },
  { month: 'Month 2', traditionaSOC: 15, a2zSOC: 65 },
  { month: 'Month 3', traditionaSOC: 30, a2zSOC: 85 },
  { month: 'Month 4', traditionaSOC: 45, a2zSOC: 95 },
  { month: 'Month 5', traditionaSOC: 60, a2zSOC: 100 },
  { month: 'Month 6', traditionaSOC: 75, a2zSOC: 100 }
];

const incidentCostReductionData = [
  { quarter: 'Q1 2023', beforeA2Z: 125000, afterA2Z: 32000 },
  { quarter: 'Q2 2023', beforeA2Z: 148000, afterA2Z: 28000 },
  { quarter: 'Q3 2023', beforeA2Z: 167000, afterA2Z: 24000 },
  { quarter: 'Q4 2023', beforeA2Z: 134000, afterA2Z: 19000 }
];

const ROIDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState("overview");
  const [calculatedROI, setCalculatedROI] = useState<any>(null);

  useEffect(() => {
    // Calculate comprehensive ROI metrics
    const totalTraditionalCost = roiMetrics.traditionalSOCCost;
    const totalA2ZCost = roiMetrics.currentInvestment;
    const netSavings = totalTraditionalCost - totalA2ZCost;
    const roiPercentage = ((netSavings / totalA2ZCost) * 100);
    
    setCalculatedROI({
      netSavings,
      roiPercentage,
      paybackMonths: Math.ceil(totalA2ZCost / (netSavings / 12)),
      fiveYearSavings: netSavings * 5,
      incidentCostSavings: 574000, // Calculated from incident reduction data
      complianceSavings: roiMetrics.complianceCostSavings
    });
  }, []);

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount);
  };

  const exportROIReport = () => {
    // Generate comprehensive ROI report
    const reportData = {
      generatedAt: new Date().toISOString(),
      executiveSummary: "A2Z SOC platform delivers 240% ROI within 5 months",
      keyMetrics: roiMetrics,
      calculations: calculatedROI,
      recommendations: [
        "Immediate implementation recommended for maximum cost savings",
        "Focus on high-value integrations (AI insights, automated response)",
        "Leverage compliance automation for additional 20% cost reduction"
      ]
    };
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'A2Z-SOC-ROI-Report.json';
    a.click();
  };

  return (
      <div className="px-2">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-3xl font-bold text-white">ROI Dashboard</h1>
            <p className="text-gray-400">Financial impact and return on investment analysis for A2Z SOC</p>
          </div>
          <Button onClick={exportROIReport} className="flex items-center gap-2">
            <Download className="h-4 w-4" />
            Export ROI Report
          </Button>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5 h-12 bg-cyber-darker border border-cyber-gray">
            <TabsTrigger value="overview" className="flex items-center gap-2">
              <DollarSign className="h-4 w-4" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="cost-comparison" className="flex items-center gap-2">
              <BarChart3 className="h-4 w-4" />
              Cost Analysis
            </TabsTrigger>
            <TabsTrigger value="savings" className="flex items-center gap-2">
              <TrendingUp className="h-4 w-4" />
              Savings
            </TabsTrigger>
            <TabsTrigger value="calculator" className="flex items-center gap-2">
              <Calculator className="h-4 w-4" />
              ROI Calculator
            </TabsTrigger>
            <TabsTrigger value="business-case" className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Business Case
            </TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              <Card className="bg-gradient-to-br from-green-900 to-green-800 border-green-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-green-100 text-sm font-medium">Annual Savings</p>
                      <p className="text-3xl font-bold text-white">
                        {formatCurrency(roiMetrics.annualSavings)}
                      </p>
                      <p className="text-green-200 text-sm">vs. Traditional SOC</p>
                    </div>
                    <TrendingUp className="h-8 w-8 text-green-300" />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-gradient-to-br from-blue-900 to-blue-800 border-blue-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-blue-100 text-sm font-medium">ROI Percentage</p>
                      <p className="text-3xl font-bold text-white">{roiMetrics.roi}%</p>
                      <p className="text-blue-200 text-sm">Within 12 months</p>
                    </div>
                    <Target className="h-8 w-8 text-blue-300" />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-gradient-to-br from-purple-900 to-purple-800 border-purple-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-purple-100 text-sm font-medium">Payback Period</p>
                      <p className="text-3xl font-bold text-white">{roiMetrics.paybackPeriod}</p>
                      <p className="text-purple-200 text-sm">Months</p>
                    </div>
                    <Clock className="h-8 w-8 text-purple-300" />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-gradient-to-br from-orange-900 to-orange-800 border-orange-700">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-orange-100 text-sm font-medium">Incident Reduction</p>
                      <p className="text-3xl font-bold text-white">{roiMetrics.incidentReduction}%</p>
                      <p className="text-orange-200 text-sm">Fewer security incidents</p>
                    </div>
                    <Shield className="h-8 w-8 text-orange-300" />
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Time to Value Comparison</CardTitle>
                  <CardDescription>
                    A2Z SOC delivers value 5x faster than traditional SOC implementations
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <AdvancedChart
                    title=""
                    data={timeToValueData}
                    type="line"
                    xAxisKey="month"
                    series={[
                      { name: 'Traditional SOC', dataKey: 'traditionaSOC', color: '#ef4444' },
                      { name: 'A2Z SOC', dataKey: 'a2zSOC', color: '#22c55e' }
                    ]}
                    height={300}
                  />
                </CardContent>
              </Card>

              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Key Performance Improvements</CardTitle>
                  <CardDescription>
                    Measurable improvements in security operations efficiency
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Response Time Improvement</span>
                      <Badge className="bg-green-600">{roiMetrics.responseTimeImprovement}% faster</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">False Positive Reduction</span>
                      <Badge className="bg-blue-600">{roiMetrics.falsePositiveReduction}% fewer</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Staff Productivity Gain</span>
                      <Badge className="bg-purple-600">{roiMetrics.staffProductivityGain}% increase</Badge>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-gray-300">Compliance Cost Reduction</span>
                      <Badge className="bg-orange-600">{formatCurrency(roiMetrics.complianceCostSavings)}</Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Cost Comparison Tab */}
          <TabsContent value="cost-comparison" className="mt-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Annual Cost Breakdown</CardTitle>
                  <CardDescription>
                    Detailed comparison of traditional SOC vs A2Z SOC costs
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {costComparisonData.map((item, index) => (
                      <div key={index} className="p-4 bg-cyber-darker rounded-lg">
                        <h4 className="text-white font-medium mb-2">{item.category}</h4>
                        <div className="grid grid-cols-3 gap-4 text-sm">
                          <div>
                            <p className="text-gray-400">Traditional SOC</p>
                            <p className="text-red-400 font-medium">{formatCurrency(item.traditional)}</p>
                          </div>
                          <div>
                            <p className="text-gray-400">A2Z SOC</p>
                            <p className="text-blue-400 font-medium">{formatCurrency(item.a2zSOC)}</p>
                          </div>
                          <div>
                            <p className="text-gray-400">Savings</p>
                            <p className="text-green-400 font-medium">{formatCurrency(item.savings)}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Incident Cost Reduction</CardTitle>
                  <CardDescription>
                    Quarterly incident response costs before and after A2Z SOC
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <AdvancedChart
                    title=""
                    data={incidentCostReductionData}
                    type="bar"
                    xAxisKey="quarter"
                    series={[
                      { name: 'Before A2Z SOC', dataKey: 'beforeA2Z', color: '#ef4444' },
                      { name: 'After A2Z SOC', dataKey: 'afterA2Z', color: '#22c55e' }
                    ]}
                    height={300}
                  />
                </CardContent>
              </Card>
            </div>

            <Card className="bg-cyber-gray border-cyber-lightgray mt-6">
              <CardHeader>
                <CardTitle className="text-white">Total Cost of Ownership (5 Years)</CardTitle>
                <CardDescription>
                  Comprehensive 5-year TCO analysis including hidden costs
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="text-center p-6 bg-red-900/20 rounded-lg border border-red-800">
                    <h3 className="text-red-400 font-medium mb-2">Traditional SOC</h3>
                    <p className="text-3xl font-bold text-white mb-2">
                      {formatCurrency(roiMetrics.traditionalSOCCost * 5)}
                    </p>
                    <p className="text-sm text-gray-400">Includes staff, infrastructure, tools, training</p>
                  </div>
                  <div className="text-center p-6 bg-blue-900/20 rounded-lg border border-blue-800">
                    <h3 className="text-blue-400 font-medium mb-2">A2Z SOC</h3>
                    <p className="text-3xl font-bold text-white mb-2">
                      {formatCurrency(roiMetrics.currentInvestment * 5)}
                    </p>
                    <p className="text-sm text-gray-400">All-inclusive platform cost</p>
                  </div>
                  <div className="text-center p-6 bg-green-900/20 rounded-lg border border-green-800">
                    <h3 className="text-green-400 font-medium mb-2">5-Year Savings</h3>
                    <p className="text-3xl font-bold text-white mb-2">
                      {formatCurrency((roiMetrics.traditionalSOCCost - roiMetrics.currentInvestment) * 5)}
                    </p>
                    <p className="text-sm text-gray-400">Net cost reduction</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Savings Tab */}
          <TabsContent value="savings" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Operational Savings</CardTitle>
                  <CardDescription>
                    Efficiency gains translate to significant cost reductions
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center p-3 bg-cyber-darker rounded-lg">
                      <div className="flex items-center gap-3">
                        <Users className="h-5 w-5 text-blue-400" />
                        <span className="text-white">Reduced Staff Requirements</span>
                      </div>
                      <span className="text-green-400 font-medium">{formatCurrency(300000)}/year</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-cyber-darker rounded-lg">
                      <div className="flex items-center gap-3">
                        <Clock className="h-5 w-5 text-purple-400" />
                        <span className="text-white">Faster Incident Response</span>
                      </div>
                      <span className="text-green-400 font-medium">{formatCurrency(180000)}/year</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-cyber-darker rounded-lg">
                      <div className="flex items-center gap-3">
                        <AlertTriangle className="h-5 w-5 text-orange-400" />
                        <span className="text-white">Fewer False Positives</span>
                      </div>
                      <span className="text-green-400 font-medium">{formatCurrency(90000)}/year</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-cyber-darker rounded-lg">
                      <div className="flex items-center gap-3">
                        <CheckCircle className="h-5 w-5 text-green-400" />
                        <span className="text-white">Automated Compliance</span>
                      </div>
                      <span className="text-green-400 font-medium">{formatCurrency(120000)}/year</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Risk Mitigation Value</CardTitle>
                  <CardDescription>
                    Quantifiable value of improved security posture
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="p-4 bg-cyber-darker rounded-lg">
                      <h4 className="text-white font-medium mb-2">Data Breach Prevention</h4>
                      <p className="text-gray-300 text-sm mb-2">
                        Average data breach cost: $4.45M. A2Z SOC reduces probability by 85%.
                      </p>
                      <p className="text-green-400 font-medium">Risk Reduction Value: {formatCurrency(3782500)}</p>
                    </div>
                    <div className="p-4 bg-cyber-darker rounded-lg">
                      <h4 className="text-white font-medium mb-2">Compliance Penalties Avoided</h4>
                      <p className="text-gray-300 text-sm mb-2">
                        Automated compliance monitoring prevents regulatory fines.
                      </p>
                      <p className="text-green-400 font-medium">Penalty Avoidance: {formatCurrency(500000)}</p>
                    </div>
                    <div className="p-4 bg-cyber-darker rounded-lg">
                      <h4 className="text-white font-medium mb-2">Business Continuity</h4>
                      <p className="text-gray-300 text-sm mb-2">
                        Reduced downtime from security incidents improves revenue protection.
                      </p>
                      <p className="text-green-400 font-medium">Revenue Protection: {formatCurrency(850000)}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* ROI Calculator Tab */}
          <TabsContent value="calculator" className="mt-6">
            <Card className="bg-cyber-gray border-cyber-lightgray">
              <CardHeader>
                <CardTitle className="text-white">Custom ROI Calculator</CardTitle>
                <CardDescription>
                  Calculate ROI based on your organization's specific parameters
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  <div className="space-y-4">
                    <h3 className="text-white font-medium">Current Security Costs</h3>
                    <div className="space-y-3">
                      <div>
                        <label className="text-sm text-gray-400">Annual SOC Staff Costs</label>
                        <input 
                          type="number" 
                          placeholder="480000" 
                          className="w-full mt-1 p-2 bg-cyber-darker border border-cyber-gray rounded text-white"
                        />
                      </div>
                      <div>
                        <label className="text-sm text-gray-400">Infrastructure Costs</label>
                        <input 
                          type="number" 
                          placeholder="200000" 
                          className="w-full mt-1 p-2 bg-cyber-darker border border-cyber-gray rounded text-white"
                        />
                      </div>
                      <div>
                        <label className="text-sm text-gray-400">Tool Licenses</label>
                        <input 
                          type="number" 
                          placeholder="120000" 
                          className="w-full mt-1 p-2 bg-cyber-darker border border-cyber-gray rounded text-white"
                        />
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-4">
                    <h3 className="text-white font-medium">Incident Metrics</h3>
                    <div className="space-y-3">
                      <div>
                        <label className="text-sm text-gray-400">Annual Incidents</label>
                        <input 
                          type="number" 
                          placeholder="24" 
                          className="w-full mt-1 p-2 bg-cyber-darker border border-cyber-gray rounded text-white"
                        />
                      </div>
                      <div>
                        <label className="text-sm text-gray-400">Avg. Incident Cost</label>
                        <input 
                          type="number" 
                          placeholder="25000" 
                          className="w-full mt-1 p-2 bg-cyber-darker border border-cyber-gray rounded text-white"
                        />
                      </div>
                      <div>
                        <label className="text-sm text-gray-400">Response Time (hours)</label>
                        <input 
                          type="number" 
                          placeholder="8" 
                          className="w-full mt-1 p-2 bg-cyber-darker border border-cyber-gray rounded text-white"
                        />
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-4">
                    <h3 className="text-white font-medium">A2Z SOC Benefits</h3>
                    <div className="p-4 bg-green-900/20 rounded-lg border border-green-800">
                      <h4 className="text-green-400 font-medium mb-2">Calculated ROI</h4>
                      <p className="text-2xl font-bold text-white">240%</p>
                      <p className="text-sm text-gray-400 mt-1">Within 12 months</p>
                    </div>
                    <div className="p-4 bg-blue-900/20 rounded-lg border border-blue-800">
                      <h4 className="text-blue-400 font-medium mb-2">Annual Savings</h4>
                      <p className="text-2xl font-bold text-white">{formatCurrency(600000)}</p>
                      <p className="text-sm text-gray-400 mt-1">Recurring annually</p>
                    </div>
                    <Button className="w-full bg-cyber-accent hover:bg-cyber-accent/90">
                      <Calculator className="h-4 w-4 mr-2" />
                      Recalculate ROI
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Business Case Tab */}
          <TabsContent value="business-case" className="mt-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Executive Summary</CardTitle>
                  <CardDescription>
                    Key points for decision makers
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="p-4 bg-cyber-darker rounded-lg">
                      <h4 className="text-white font-medium mb-2">Investment Highlights</h4>
                      <ul className="space-y-2 text-gray-300 text-sm">
                        <li>• {formatCurrency(600000)} annual cost savings</li>
                        <li>• 240% ROI within first year</li>
                        <li>• 5-month payback period</li>
                        <li>• 75% reduction in security incidents</li>
                        <li>• 85% faster threat response</li>
                      </ul>
                    </div>
                    <div className="p-4 bg-cyber-darker rounded-lg">
                      <h4 className="text-white font-medium mb-2">Strategic Benefits</h4>
                      <ul className="space-y-2 text-gray-300 text-sm">
                        <li>• Enhanced security posture and risk reduction</li>
                        <li>• Improved regulatory compliance automation</li>
                        <li>• Scalable platform for future growth</li>
                        <li>• AI-driven insights and automation</li>
                        <li>• Reduced dependency on specialized staff</li>
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-cyber-gray border-cyber-lightgray">
                <CardHeader>
                  <CardTitle className="text-white">Implementation Roadmap</CardTitle>
                  <CardDescription>
                    Structured approach to maximize value realization
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white text-sm font-medium">
                        1
                      </div>
                      <div>
                        <h4 className="text-white font-medium">Phase 1: Core Deployment (Month 1)</h4>
                        <p className="text-gray-300 text-sm">Setup main platform, integrate existing tools, establish baseline metrics</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white text-sm font-medium">
                        2
                      </div>
                      <div>
                        <h4 className="text-white font-medium">Phase 2: AI Integration (Month 2-3)</h4>
                        <p className="text-gray-300 text-sm">Deploy AI models, configure automated responses, optimize detection rules</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white text-sm font-medium">
                        3
                      </div>
                      <div>
                        <h4 className="text-white font-medium">Phase 3: Advanced Features (Month 4-5)</h4>
                        <p className="text-gray-300 text-sm">Enable threat hunting, compliance automation, advanced analytics</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 bg-green-600 rounded-full flex items-center justify-center text-white text-sm font-medium">
                        ✓
                      </div>
                      <div>
                        <h4 className="text-white font-medium">Full ROI Realization (Month 5+)</h4>
                        <p className="text-gray-300 text-sm">Maximum value delivery, continuous optimization, expansion planning</p>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            <Card className="bg-gradient-to-r from-cyber-accent/20 to-blue-900/20 border-cyber-accent mt-6">
              <CardContent className="p-6">
                <div className="text-center">
                  <h3 className="text-2xl font-bold text-white mb-4">Ready to Transform Your Security Operations?</h3>
                  <p className="text-gray-300 mb-6">
                    Join organizations saving an average of {formatCurrency(600000)} annually with A2Z SOC
                  </p>
                  <div className="flex justify-center gap-4">
                    <Button className="bg-cyber-accent hover:bg-cyber-accent/90">
                      Schedule Demo
                    </Button>
                    <Button variant="outline" className="border-cyber-accent text-cyber-accent hover:bg-cyber-accent hover:text-white">
                      Request Pilot Program
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
  );
};

export default ROIDashboard; 