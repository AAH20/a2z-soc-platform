import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { Checkbox } from '@/components/ui/checkbox';
import { useAuth } from '@/components/auth/AuthProvider';
import { apiCall } from '@/lib/api';
import { 
  Shield, 
  Mail, 
  Lock, 
  AlertCircle, 
  Loader2, 
  Eye, 
  EyeOff,
  ArrowRight,
  Zap,
  Users,
  BarChart3,
  AlertTriangle
} from 'lucide-react';

const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { login } = useAuth();

  const fillCredentials = (email: string, password: string) => {
    setEmail(email);
    setPassword(password);
    setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const data = await apiCall('/api/onboarding/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });

      // Transform the response to match expected format
      const user = {
        id: data.user.id,
        email: data.user.email,
        firstName: data.user.firstName,
        lastName: data.user.lastName,
        role: data.user.role,
        emailVerified: true, // Always true since we bypass email verification
        tenantId: data.organization.id
      };

      const tenant = {
        id: data.organization.id,
        name: data.organization.name,
        subdomain: data.organization.name.toLowerCase().replace(/[^a-z0-9]/g, ''),
        status: data.organization.subscriptionStatus,
        onboarding_status: 'completed',
        plan: data.subscription.tier
      };

      // Store token and user data
      login(data.token, user, tenant);
      
      // Redirect to dashboard
      navigate('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const features = [
    {
      icon: <Shield className="w-6 h-6 text-blue-500" />,
      title: "Enterprise Security",
      description: "Bank-grade encryption and SOC 2 compliance"
    },
    {
      icon: <Zap className="w-6 h-6 text-purple-500" />,
      title: "AI-Powered Insights",
      description: "Automated threat detection and response"
    },
    {
      icon: <Users className="w-6 h-6 text-green-500" />,
      title: "Team Collaboration",
      description: "Unified security operations workflow"
    },
    {
      icon: <BarChart3 className="w-6 h-6 text-orange-500" />,
      title: "Real-time Analytics",
      description: "Advanced threat intelligence dashboard"
    }
  ];

  return (
    <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2 mb-4">
            <Shield className="h-8 w-8 text-blue-400" />
            <h1 className="text-2xl font-bold text-white">A2Z SOC</h1>
          </div>
          <p className="text-slate-400">Sign in to your security operations center</p>
        </div>

        {/* Demo Credentials Section */}
        <Card className="bg-gradient-to-r from-blue-900 to-purple-900 border-blue-700 mb-6">
          <CardHeader>
            <CardTitle className="text-white flex items-center gap-2">
              <Zap className="h-5 w-5 text-yellow-400" />
              Demo Credentials
            </CardTitle>
            <CardDescription className="text-blue-200">
              Use these credentials to explore the A2Z SOC platform
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div 
                className="bg-slate-800/50 p-3 rounded-lg border border-slate-600 cursor-pointer hover:bg-slate-700/50 hover:border-green-500 transition-all"
                onClick={() => fillCredentials('admin@demo.com', 'demo123')}
              >
                <div className="text-green-400 font-semibold mb-1">👑 Admin Access</div>
                <div className="text-slate-300 text-sm">
                  <div><span className="text-slate-400">Email:</span> admin@demo.com</div>
                  <div><span className="text-slate-400">Password:</span> demo123</div>
                </div>
              </div>
              <div 
                className="bg-slate-800/50 p-3 rounded-lg border border-slate-600 cursor-pointer hover:bg-slate-700/50 hover:border-blue-500 transition-all"
                onClick={() => fillCredentials('analyst@demo.com', 'demo123')}
              >
                <div className="text-blue-400 font-semibold mb-1">🔍 SOC Analyst</div>
                <div className="text-slate-300 text-sm">
                  <div><span className="text-slate-400">Email:</span> analyst@demo.com</div>
                  <div><span className="text-slate-400">Password:</span> demo123</div>
                </div>
              </div>
              <div 
                className="bg-slate-800/50 p-3 rounded-lg border border-slate-600 cursor-pointer hover:bg-slate-700/50 hover:border-purple-500 transition-all"
                onClick={() => fillCredentials('manager@demo.com', 'demo123')}
              >
                <div className="text-purple-400 font-semibold mb-1">📊 SOC Manager</div>
                <div className="text-slate-300 text-sm">
                  <div><span className="text-slate-400">Email:</span> manager@demo.com</div>
                  <div><span className="text-slate-400">Password:</span> demo123</div>
                </div>
              </div>
              <div 
                className="bg-slate-800/50 p-3 rounded-lg border border-slate-600 cursor-pointer hover:bg-slate-700/50 hover:border-orange-500 transition-all"
                onClick={() => fillCredentials('viewer@demo.com', 'demo123')}
              >
                <div className="text-orange-400 font-semibold mb-1">👀 Viewer</div>
                <div className="text-slate-300 text-sm">
                  <div><span className="text-slate-400">Email:</span> viewer@demo.com</div>
                  <div><span className="text-slate-400">Password:</span> demo123</div>
                </div>
              </div>
            </div>
            <div className="mt-4 p-3 bg-yellow-900/20 rounded-lg border border-yellow-700">
              <div className="text-yellow-400 text-sm font-medium">💡 Pro Tip</div>
              <div className="text-yellow-200 text-xs mt-1">
                Click on any credential above to auto-fill the login form
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-800 border-slate-700">
          <CardHeader>
            <CardTitle className="text-white">Welcome back</CardTitle>
            <CardDescription className="text-slate-400">
              Enter your credentials to access your account
            </CardDescription>
          </CardHeader>
          <CardContent>
            {error && (
              <Alert className="mb-4 bg-red-900 border-red-700">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                <AlertDescription className="text-red-300">
                  {error}
                </AlertDescription>
              </Alert>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email" className="text-white">Email address</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email"
                  required
                  className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password" className="text-white">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    required
                    className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-400 pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-slate-300"
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <input
                    id="remember"
                    type="checkbox"
                    className="rounded border-slate-600 text-blue-500 focus:ring-blue-500 bg-slate-700"
                  />
                  <Label htmlFor="remember" className="text-sm text-slate-300">
                    Remember me
                  </Label>
                </div>
                <span className="text-sm text-slate-500 cursor-not-allowed">
                  Forgot password?
                </span>
              </div>

              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white"
              >
                {loading ? 'Signing in...' : 'Sign in'}
              </Button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-slate-400">
                Don't have an account?{' '}
                <Link
                  to="/register"
                  className="text-blue-400 hover:text-blue-300 hover:underline font-medium"
                >
                  Sign up
                </Link>
              </p>
            </div>
          </CardContent>
        </Card>

        <div className="mt-8 text-center">
          <p className="text-xs text-slate-500">
            By signing in, you agree to our{' '}
            <a href="#" className="text-blue-400 hover:underline">Terms of Service</a>
            {' '}and{' '}
            <a href="#" className="text-blue-400 hover:underline">Privacy Policy</a>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login; 