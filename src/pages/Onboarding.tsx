import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { CheckCircle, AlertCircle, CreditCard, Users, Shield, Zap } from 'lucide-react';

interface SubscriptionTier {
  id: string;
  name: string;
  price: number;
  endpoints: number;
  features: string[];
  recommended?: boolean;
}

interface Customer {
  id: string;
  company: string;
  email: string;
  firstName: string;
  lastName: string;
  status: string;
  trialEndsAt: string;
  apiKey: string;
}

interface OnboardingStep {
  step: number;
  title: string;
  status: 'completed' | 'pending' | 'current';
  description?: string;
}

const Onboarding: React.FC = () => {
  const [activeTab, setActiveTab] = useState('register');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [customer, setCustomer] = useState<Customer | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('a2z_token'));
  const [tiers, setTiers] = useState<SubscriptionTier[]>([]);
  const [onboardingSteps, setOnboardingSteps] = useState<OnboardingStep[]>([]);

  // Registration form
  const [regForm, setRegForm] = useState({
    company: '',
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: '',
    phone: ''
  });

  // Login form
  const [loginForm, setLoginForm] = useState({
    email: '',
    password: ''
  });

  useEffect(() => {
    fetchTiers();
    if (token) {
      fetchOnboardingStatus();
    }
  }, [token]);

  const fetchTiers = async () => {
    try {
      const response = await fetch('/api/onboarding/tiers');
      const data = await response.json();
      setTiers(data.tiers);
    } catch (err) {
      console.error('Failed to fetch tiers:', err);
    }
  };

  const fetchOnboardingStatus = async () => {
    try {
      const response = await fetch('/api/onboarding/onboarding', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const data = await response.json();
        setOnboardingSteps(data.onboarding.steps);
      }
    } catch (err) {
      console.error('Failed to fetch onboarding status:', err);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (regForm.password !== regForm.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      const response = await fetch('/api/onboarding/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          company: regForm.company,
          email: regForm.email,
          password: regForm.password,
          firstName: regForm.firstName,
          lastName: regForm.lastName,
          phone: regForm.phone
        })
      });

      const data = await response.json();

      if (response.ok) {
        setCustomer(data.customer);
        setToken(data.token);
        localStorage.setItem('a2z_token', data.token);
        setOnboardingSteps(data.onboardingSteps);
        setSuccess('Registration successful! Welcome to A2Z SOC.');
        setActiveTab('dashboard');
      } else {
        setError(data.error || 'Registration failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/onboarding/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(loginForm)
      });

      const data = await response.json();

      if (response.ok) {
        setCustomer(data.customer);
        setToken(data.token);
        localStorage.setItem('a2z_token', data.token);
        setSuccess('Login successful!');
        setActiveTab('dashboard');
        fetchOnboardingStatus();
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleUpgrade = async (tierId: string) => {
    if (!token) return;
    
    setLoading(true);
    try {
      const response = await fetch('/api/onboarding/upgrade', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          tier: tierId,
          paymentMethod: 'demo' // In production, integrate with Stripe/PayPal
        })
      });

      const data = await response.json();
      if (response.ok) {
        setSuccess('Subscription upgraded successfully!');
      } else {
        setError(data.error || 'Upgrade failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('a2z_token');
    setToken(null);
    setCustomer(null);
    setActiveTab('register');
  };

  if (customer && token) {
    return (
      <div className="container mx-auto p-6 max-w-6xl">
        <div className="mb-6 flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">Welcome to A2Z SOC</h1>
            <p className="text-gray-600">Hi {customer.firstName}, let's get your security monitoring set up!</p>
          </div>
          <Button variant="outline" onClick={logout}>Logout</Button>
        </div>

        {success && (
          <Alert className="mb-6">
            <CheckCircle className="h-4 w-4" />
            <AlertDescription>{success}</AlertDescription>
          </Alert>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Onboarding Progress */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle>Getting Started</CardTitle>
              <CardDescription>Complete these steps to activate your security monitoring</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {onboardingSteps.map((step) => (
                  <div key={step.step} className="flex items-center space-x-4 p-4 border rounded-lg">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                      step.status === 'completed' 
                        ? 'bg-green-100 text-green-600' 
                        : 'bg-gray-100 text-gray-400'
                    }`}>
                      {step.status === 'completed' ? (
                        <CheckCircle className="w-5 h-5" />
                      ) : (
                        <span className="text-sm font-semibold">{step.step}</span>
                      )}
                    </div>
                    <div className="flex-1">
                      <h3 className="font-semibold">{step.title}</h3>
                      {step.description && (
                        <p className="text-sm text-gray-600">{step.description}</p>
                      )}
                    </div>
                    <Badge variant={step.status === 'completed' ? 'default' : 'secondary'}>
                      {step.status}
                    </Badge>
                  </div>
                ))}
              </div>

              <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <h3 className="font-semibold text-blue-900 mb-2">Quick Start Links</h3>
                <div className="space-y-2">
                  <a href="/dashboard" className="block text-blue-600 hover:underline">
                    📊 Go to Security Dashboard
                  </a>
                  <a href="/api/docs" className="block text-blue-600 hover:underline">
                    📚 API Documentation
                  </a>
                  <a href="mailto:support@a2zsoc.com" className="block text-blue-600 hover:underline">
                    💬 Contact Support
                  </a>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Account Info */}
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Account Status</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Status</span>
                    <Badge variant={customer.status === 'trial' ? 'secondary' : 'default'}>
                      {customer.status.toUpperCase()}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">Company</span>
                    <span className="text-sm font-medium">{customer.company}</span>
                  </div>
                  {customer.status === 'trial' && (
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Trial Ends</span>
                      <span className="text-sm font-medium">
                        {new Date(customer.trialEndsAt).toLocaleDateString()}
                      </span>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>API Access</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <Label className="text-sm text-gray-600">Your API Key</Label>
                  <div className="p-2 bg-gray-100 rounded text-xs font-mono break-all">
                    {customer.apiKey}
                  </div>
                  <p className="text-xs text-gray-500">
                    Use this key to integrate with our APIs
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Subscription Tiers */}
        <Card className="mt-6">
          <CardHeader>
            <CardTitle>Upgrade Your Plan</CardTitle>
            <CardDescription>Scale your security monitoring with advanced features</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {tiers.map((tier) => (
                <div key={tier.id} className={`p-4 border rounded-lg ${tier.recommended ? 'border-blue-500 bg-blue-50' : ''}`}>
                  {tier.recommended && (
                    <Badge className="mb-2">Recommended</Badge>
                  )}
                  <h3 className="text-lg font-semibold">{tier.name}</h3>
                  <div className="text-2xl font-bold text-blue-600">
                    ${tier.price}<span className="text-sm text-gray-500">/month</span>
                  </div>
                  <p className="text-sm text-gray-600 mb-3">
                    Up to {tier.endpoints.toLocaleString()} endpoints
                  </p>
                  <ul className="space-y-1 mb-4">
                    {tier.features.map((feature, idx) => (
                      <li key={idx} className="text-sm flex items-center">
                        <CheckCircle className="w-4 h-4 text-green-500 mr-2" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                  <Button 
                    className="w-full" 
                    onClick={() => handleUpgrade(tier.id)}
                    disabled={loading}
                  >
                    {loading ? 'Processing...' : 'Upgrade Now'}
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto w-12 h-12 bg-blue-600 rounded-lg flex items-center justify-center mb-4">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <CardTitle className="text-2xl">A2Z SOC Platform</CardTitle>
          <CardDescription>Enterprise Security Operations Center</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="register">Sign Up</TabsTrigger>
              <TabsTrigger value="login">Sign In</TabsTrigger>
            </TabsList>

            {error && (
              <Alert className="mt-4" variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <TabsContent value="register">
              <form onSubmit={handleRegister} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="firstName">First Name</Label>
                    <Input
                      id="firstName"
                      value={regForm.firstName}
                      onChange={(e) => setRegForm({...regForm, firstName: e.target.value})}
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="lastName">Last Name</Label>
                    <Input
                      id="lastName"
                      value={regForm.lastName}
                      onChange={(e) => setRegForm({...regForm, lastName: e.target.value})}
                      required
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="company">Company</Label>
                  <Input
                    id="company"
                    value={regForm.company}
                    onChange={(e) => setRegForm({...regForm, company: e.target.value})}
                    required
                  />
                </div>

                <div>
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    value={regForm.email}
                    onChange={(e) => setRegForm({...regForm, email: e.target.value})}
                    required
                  />
                </div>

                <div>
                  <Label htmlFor="phone">Phone (Optional)</Label>
                  <Input
                    id="phone"
                    type="tel"
                    value={regForm.phone}
                    onChange={(e) => setRegForm({...regForm, phone: e.target.value})}
                  />
                </div>

                <div>
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    value={regForm.password}
                    onChange={(e) => setRegForm({...regForm, password: e.target.value})}
                    required
                  />
                </div>

                <div>
                  <Label htmlFor="confirmPassword">Confirm Password</Label>
                  <Input
                    id="confirmPassword"
                    type="password"
                    value={regForm.confirmPassword}
                    onChange={(e) => setRegForm({...regForm, confirmPassword: e.target.value})}
                    required
                  />
                </div>

                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? 'Creating Account...' : 'Start Free Trial'}
                </Button>

                <p className="text-xs text-center text-gray-600">
                  14-day free trial • No credit card required
                </p>
              </form>
            </TabsContent>

            <TabsContent value="login">
              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <Label htmlFor="loginEmail">Email</Label>
                  <Input
                    id="loginEmail"
                    type="email"
                    value={loginForm.email}
                    onChange={(e) => setLoginForm({...loginForm, email: e.target.value})}
                    required
                  />
                </div>

                <div>
                  <Label htmlFor="loginPassword">Password</Label>
                  <Input
                    id="loginPassword"
                    type="password"
                    value={loginForm.password}
                    onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                    required
                  />
                </div>

                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? 'Signing In...' : 'Sign In'}
                </Button>
              </form>
            </TabsContent>
          </Tabs>

          {/* Features showcase */}
          <div className="mt-6 pt-6 border-t">
            <h3 className="text-sm font-semibold mb-3">Why choose A2Z SOC?</h3>
            <div className="space-y-2">
              <div className="flex items-center text-sm">
                <Zap className="w-4 h-4 text-blue-500 mr-2" />
                Real-time threat detection
              </div>
              <div className="flex items-center text-sm">
                <Users className="w-4 h-4 text-blue-500 mr-2" />
                Multi-tenant architecture
              </div>
              <div className="flex items-center text-sm">
                <CreditCard className="w-4 h-4 text-blue-500 mr-2" />
                Flexible pricing plans
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Onboarding; 