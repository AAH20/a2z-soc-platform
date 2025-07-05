import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  CreditCard,
  Download,
  Users,
  Zap,
  Database,
  Link as LinkIcon,
  CheckCircle,
  AlertCircle,
  TrendingUp,
  Calendar,
  Shield,
  Crown,
  Loader2,
  Plus,
  Edit3,
  Trash2,
  ExternalLink,
  DollarSign
} from 'lucide-react';
import { apiService } from '@/services/api';

interface Subscription {
  id: string;
  plan_name: string;
  status: 'active' | 'canceled' | 'past_due' | 'trialing';
  current_period_start: string;
  current_period_end: string;
  cancel_at_period_end: boolean;
  amount: number;
  currency: string;
  trial_end?: string;
  features: string[];
  limits: {
    users: number;
    api_requests: number;
    storage_gb: number;
    integrations: number;
  };
}

interface Usage {
  api_requests: {
    current: number;
    limit: number;
    percentage: number;
  };
  users: {
    current: number;
    limit: number;
    percentage: number;
  };
  storage: {
    current: number;
    limit: number;
    percentage: number;
  };
  integrations: {
    current: number;
    limit: number;
    percentage: number;
  };
}

interface Invoice {
  id: string;
  amount: number;
  currency: string;
  status: 'paid' | 'pending' | 'failed';
  created: string;
  period_start: string;
  period_end: string;
  invoice_pdf?: string;
  description: string;
}

interface PaymentMethod {
  id: string;
  type: 'card';
  card: {
    brand: string;
    last4: string;
    exp_month: number;
    exp_year: number;
  };
  is_default: boolean;
}

interface AvailablePlan {
  id: string;
  name: string;
  description: string;
  price: number;
  currency: string;
  interval: string;
  features: string[];
  limits: {
    users: number;
    api_requests: number;
    storage_gb: number;
    integrations: number;
  };
  popular?: boolean;
}

const BillingSettings: React.FC = () => {
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [usage, setUsage] = useState<Usage | null>(null);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [paymentMethods, setPaymentMethods] = useState<PaymentMethod[]>([]);
  const [availablePlans, setAvailablePlans] = useState<AvailablePlan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchBillingData();
  }, []);

  const fetchBillingData = async () => {
    try {
      setLoading(true);
      setError('');
      
      // Fetch real billing data from our API
      const [subscriptionRes, usageRes, invoicesRes, plansRes] = await Promise.all([
        apiService.get('/api/billing/subscription'),
        apiService.get('/api/billing/usage'),
        apiService.get('/api/billing/invoices'),
        apiService.get('/api/billing/plans')
      ]);
      
      if (subscriptionRes.data?.success) {
        setSubscription(subscriptionRes.data.data);
      }
      
      if (usageRes.data?.success) {
        setUsage(usageRes.data.data);
      }
      
      if (invoicesRes.data?.success) {
        setInvoices(invoicesRes.data.data);
      }
      
      if (plansRes.data?.success) {
        setAvailablePlans(plansRes.data.data);
      }
      
    } catch (err) {
      console.error('Failed to fetch billing data:', err);
      setError('Failed to load billing information.');
      // Only use fallback data in development or as last resort
      if (import.meta.env.DEV) {
        loadFallbackData();
      }
    } finally {
      setLoading(false);
    }
  };

  const loadFallbackData = () => {
    // Minimal fallback data for development only
    setSubscription({
      id: 'dev_subscription',
      plan_name: 'Development',
      status: 'active',
      current_period_start: new Date().toISOString(),
      current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      cancel_at_period_end: false,
      amount: 0,
      currency: 'USD',
      features: ['Development Features'],
      limits: {
        users: 10,
        api_requests: 10000,
        storage_gb: 100,
        integrations: 10
      }
    });

    setUsage({
      api_requests: { current: 0, limit: 10000, percentage: 0 },
      users: { current: 1, limit: 10, percentage: 10 },
      storage: { current: 0, limit: 100, percentage: 0 },
      integrations: { current: 0, limit: 10, percentage: 0 }
    });

    setInvoices([]);
    setAvailablePlans([]);
  };

  const formatCurrency = (amount: number, currency: string = 'USD') => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency,
    }).format(amount / 100);
  };

  const formatDate = (dateString: string) => {
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    }).format(new Date(dateString));
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800';
      case 'trialing':
        return 'bg-blue-100 text-blue-800';
      case 'past_due':
        return 'bg-red-100 text-red-800';
      case 'canceled':
        return 'bg-slate-600 text-slate-200';
      case 'paid':
        return 'bg-green-100 text-green-800';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-slate-600 text-slate-200';
    }
  };

  const getUsageColor = (percentage: number) => {
    if (percentage >= 90) return 'text-red-600';
    if (percentage >= 75) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getUsageProgressColor = (percentage: number) => {
    if (percentage >= 90) return 'bg-red-500';
    if (percentage >= 75) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const changePlan = async (planId: string) => {
    try {
      // Mock plan change behavior
      const selectedPlan = availablePlans.find(plan => plan.id === planId);
      if (selectedPlan && subscription) {
        setSubscription({
          ...subscription,
          plan_name: selectedPlan.name,
          amount: selectedPlan.price * 100, // Convert to cents
          features: selectedPlan.features,
          limits: selectedPlan.limits
        });
        
        // Show success message (you could add a toast here)
        console.log(`Plan changed to ${selectedPlan.name}`);
      }
    } catch (err) {
      setError('Failed to change plan. Please try again.');
    }
  };

  const downloadInvoice = async (invoiceId: string) => {
    try {
      // Mock invoice download
      const invoice = invoices.find(inv => inv.id === invoiceId);
      if (invoice) {
        // Create a simple text file as a mock invoice
        const content = `Invoice ${invoice.id}\nAmount: ${formatCurrency(invoice.amount)}\nStatus: ${invoice.status}\nDate: ${formatDate(invoice.created)}`;
        const blob = new Blob([content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `invoice-${invoiceId}.txt`;
        a.click();
        window.URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error('Failed to download invoice:', err);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-blue-400" />
          <p className="text-slate-400">Loading billing information...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <div className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <CreditCard className="w-8 h-8 text-blue-400 mr-3" />
              <span className="text-xl font-bold text-white">Billing & Subscription</span>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && (
          <Alert className="mb-6 border-red-600 bg-red-900/50">
            <AlertCircle className="h-4 w-4 text-red-400" />
            <AlertDescription className="text-red-200">
              {error}
            </AlertDescription>
          </Alert>
        )}

        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="grid w-full grid-cols-4 bg-slate-800">
            <TabsTrigger value="overview" className="data-[state=active]:bg-slate-700 text-slate-300">Overview</TabsTrigger>
            <TabsTrigger value="plans" className="data-[state=active]:bg-slate-700 text-slate-300">Plans</TabsTrigger>
            <TabsTrigger value="invoices" className="data-[state=active]:bg-slate-700 text-slate-300">Invoices</TabsTrigger>
            <TabsTrigger value="payment" className="data-[state=active]:bg-slate-700 text-slate-300">Payment</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            {/* Current Subscription */}
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2 text-white">
                  <Crown className="w-5 h-5 text-yellow-500" />
                  <span>Current Subscription</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {subscription ? (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-2xl font-bold text-white">{subscription.plan_name} Plan</h3>
                        <p className="text-slate-400">
                          {formatCurrency(subscription.amount)} / month
                        </p>
                      </div>
                      <Badge className={getStatusColor(subscription.status)}>
                        {subscription.status.charAt(0).toUpperCase() + subscription.status.slice(1)}
                      </Badge>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm text-slate-400">Current Period</p>
                        <p className="font-medium text-white">
                          {formatDate(subscription.current_period_start)} - {formatDate(subscription.current_period_end)}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-slate-400">Next Billing</p>
                        <p className="font-medium text-white">
                          {formatDate(subscription.current_period_end)}
                        </p>
                      </div>
                    </div>

                    <Separator className="bg-slate-700" />

                    <div>
                      <h4 className="font-medium mb-3 text-white">Plan Features</h4>
                      <div className="grid grid-cols-2 gap-2">
                        {subscription.features.map((feature, index) => (
                          <div key={index} className="flex items-center space-x-2">
                            <CheckCircle className="w-4 h-4 text-green-500" />
                            <span className="text-sm text-slate-300">{feature}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <p className="text-slate-400">No active subscription found.</p>
                    <Button className="mt-4">Choose a Plan</Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Usage Statistics */}
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2 text-white">
                  <TrendingUp className="w-5 h-5 text-blue-500" />
                  <span>Usage Statistics</span>
                </CardTitle>
                <CardDescription className="text-slate-400">
                  Current usage for this billing period
                </CardDescription>
              </CardHeader>
              <CardContent>
                {usage ? (
                  <div className="space-y-6">
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <Users className="w-4 h-4 text-slate-400" />
                            <span className="text-sm font-medium text-white">Users</span>
                          </div>
                          <span className={`text-sm font-medium ${getUsageColor(usage.users.percentage)}`}>
                            {usage.users.current}/{usage.users.limit}
                          </span>
                        </div>
                        <Progress 
                          value={usage.users.percentage} 
                          className="h-2"
                        />
                        <span className="text-xs text-slate-400 mt-1">
                          {usage.users.percentage.toFixed(1)}% used
                        </span>
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <Zap className="w-4 h-4 text-slate-400" />
                            <span className="text-sm font-medium text-white">API Requests</span>
                          </div>
                          <span className={`text-sm font-medium ${getUsageColor(usage.api_requests.percentage)}`}>
                            {usage.api_requests.current.toLocaleString()}/{usage.api_requests.limit.toLocaleString()}
                          </span>
                        </div>
                        <Progress 
                          value={usage.api_requests.percentage} 
                          className="h-2"
                        />
                        <span className="text-xs text-slate-400 mt-1">
                          {usage.api_requests.percentage.toFixed(1)}% used
                        </span>
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <Database className="w-4 h-4 text-slate-400" />
                            <span className="text-sm font-medium text-white">Storage</span>
                          </div>
                          <span className={`text-sm font-medium ${getUsageColor(usage.storage.percentage)}`}>
                            {usage.storage.current}GB/{usage.storage.limit}GB
                          </span>
                        </div>
                        <Progress 
                          value={usage.storage.percentage} 
                          className="h-2"
                        />
                        <span className="text-xs text-slate-400 mt-1">
                          {usage.storage.percentage.toFixed(1)}% used
                        </span>
                      </div>

                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <LinkIcon className="w-4 h-4 text-slate-400" />
                            <span className="text-sm font-medium text-white">Integrations</span>
                          </div>
                          <span className={`text-sm font-medium ${getUsageColor(usage.integrations.percentage)}`}>
                            {usage.integrations.current}/{usage.integrations.limit}
                          </span>
                        </div>
                        <Progress 
                          value={usage.integrations.percentage} 
                          className="h-2"
                        />
                        <span className="text-xs text-slate-400 mt-1">
                          {usage.integrations.percentage.toFixed(1)}% used
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <p className="text-slate-400">No usage data available.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="plans" className="space-y-6">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold mb-2 text-white">Choose Your Plan</h2>
              <p className="text-slate-400">Select the plan that best fits your security operations needs</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {availablePlans.map((plan) => (
                <Card
                  key={plan.id}
                  className={`relative bg-slate-800 border-slate-700 ${
                    plan.popular ? 'ring-2 ring-blue-500 border-blue-500' : ''
                  } ${subscription?.plan_name.toLowerCase() === plan.name.toLowerCase() ? 'bg-blue-900/50' : ''}`}
                >
                  {plan.popular && (
                    <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                      <Badge className="bg-blue-600 text-white">Most Popular</Badge>
                    </div>
                  )}
                  
                  <CardHeader className="text-center">
                    <CardTitle className="text-xl text-white">{plan.name}</CardTitle>
                    <CardDescription className="text-slate-400">{plan.description}</CardDescription>
                    <div className="mt-4">
                      <span className="text-3xl font-bold text-white">${plan.price}</span>
                      <span className="text-slate-400">/{plan.interval}</span>
                    </div>
                  </CardHeader>
                  
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      {plan.features.map((feature, index) => (
                        <div key={index} className="flex items-center text-sm text-slate-300">
                          <CheckCircle className="w-4 h-4 text-green-500 mr-2 flex-shrink-0" />
                          {feature}
                        </div>
                      ))}
                    </div>

                    <Separator className="bg-slate-700" />

                    <div className="space-y-1 text-xs text-slate-400">
                      <div>Up to {plan.limits.users} users</div>
                      <div>{plan.limits.api_requests.toLocaleString()} API requests</div>
                      <div>{plan.limits.storage_gb}GB storage</div>
                      <div>{plan.limits.integrations} integrations</div>
                    </div>

                    <Button
                      className="w-full"
                      variant={subscription?.plan_name.toLowerCase() === plan.name.toLowerCase() ? "secondary" : "default"}
                      onClick={() => changePlan(plan.id)}
                      disabled={subscription?.plan_name.toLowerCase() === plan.name.toLowerCase()}
                    >
                      {subscription?.plan_name.toLowerCase() === plan.name.toLowerCase() 
                        ? 'Current Plan' 
                        : plan.price === 0 
                        ? 'Start Free Trial' 
                        : 'Upgrade'
                      }
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          </TabsContent>

          <TabsContent value="invoices" className="space-y-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Billing History</CardTitle>
                <CardDescription className="text-slate-400">
                  View and download your past invoices
                </CardDescription>
              </CardHeader>
              <CardContent>
                {invoices.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Invoice</TableHead>
                        <TableHead>Description</TableHead>
                        <TableHead>Amount</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Date</TableHead>
                        <TableHead>Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {invoices.map((invoice) => (
                        <TableRow key={invoice.id}>
                          <TableCell className="font-medium">
                            #{invoice.id.slice(-8)}
                          </TableCell>
                          <TableCell>{invoice.description}</TableCell>
                          <TableCell>{formatCurrency(invoice.amount)}</TableCell>
                          <TableCell>
                            <Badge className={getStatusColor(invoice.status)}>
                              {invoice.status.charAt(0).toUpperCase() + invoice.status.slice(1)}
                            </Badge>
                          </TableCell>
                          <TableCell>{formatDate(invoice.created)}</TableCell>
                          <TableCell>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => downloadInvoice(invoice.id)}
                            >
                              <Download className="w-4 h-4 mr-1" />
                              Download
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <div className="text-center py-8">
                    <p className="text-slate-400">No invoices found.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="payment" className="space-y-6">
            <Card className="bg-slate-800 border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Payment Methods</CardTitle>
                <CardDescription className="text-slate-400">
                  Manage your payment methods and billing information
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {paymentMethods.length > 0 ? (
                    paymentMethods.map((method) => (
                      <div key={method.id} className="flex items-center justify-between p-4 border border-slate-700 rounded-lg bg-slate-700/50">
                        <div className="flex items-center space-x-3">
                          <CreditCard className="w-5 h-5 text-slate-400" />
                          <div>
                            <p className="font-medium text-white">
                              {method.card.brand.toUpperCase()} •••• {method.card.last4}
                            </p>
                            <p className="text-sm text-slate-400">
                              Expires {method.card.exp_month}/{method.card.exp_year}
                            </p>
                          </div>
                          {method.is_default && (
                            <Badge variant="secondary">Default</Badge>
                          )}
                        </div>
                        <div className="flex space-x-2">
                          <Button variant="ghost" size="sm">
                            <Edit3 className="w-4 h-4" />
                          </Button>
                          <Button variant="ghost" size="sm">
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8">
                      <CreditCard className="w-12 h-12 text-slate-400 mx-auto mb-4" />
                      <p className="text-slate-400 mb-4">No payment methods on file.</p>
                      <Button>
                        <Plus className="w-4 h-4 mr-2" />
                        Add Payment Method
                      </Button>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default BillingSettings; 