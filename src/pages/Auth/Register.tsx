import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Shield, Users, Zap, CheckCircle, AlertCircle, Loader2, Eye, EyeOff, AlertTriangle, Check } from 'lucide-react';
import { Progress } from '@/components/ui/progress';
import { useAuth } from '@/components/auth/AuthProvider';

interface RegistrationData {
  tenantName: string;
  subdomain: string;
  contactEmail: string;
  firstName: string;
  lastName: string;
  password: string;
  confirmPassword: string;
  phone?: string;
  industry?: string;
  companySize?: string;
  planId: string;
}

const Register: React.FC = () => {
  const navigate = useNavigate();
  const [currentStep, setCurrentStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState<RegistrationData>({
    tenantName: '',
    subdomain: '',
    contactEmail: '',
    firstName: '',
    lastName: '',
    password: '',
    confirmPassword: '',
    planId: 'trial'
  });
  const [showPassword, setShowPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);
  const { login } = useAuth();

  const plans = [
    {
      id: 'trial',
      name: 'Free Trial',
      price: '$0',
      duration: '14 days',
      features: ['Up to 5 users', '1,000 API requests', '10GB storage', 'Basic support'],
      recommended: false,
      color: 'bg-slate-700 border-slate-700'
    },
    {
      id: 'starter',
      name: 'Starter',
      price: '$49',
      duration: 'per month',
      features: ['Up to 10 users', '10,000 API requests', '50GB storage', 'Email support'],
      recommended: false,
      color: 'bg-blue-50 border-blue-200'
    },
    {
      id: 'professional',
      name: 'Professional',
      price: '$149',
      duration: 'per month',
      features: ['Up to 50 users', '100,000 API requests', '500GB storage', 'Priority support', 'Advanced AI features'],
      recommended: true,
      color: 'bg-purple-50 border-purple-200'
    }
  ];

  const handleInputChange = (field: keyof RegistrationData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    
    // Auto-generate subdomain from tenant name
    if (field === 'tenantName') {
      const subdomain = value.toLowerCase()
        .replace(/[^a-z0-9]/g, '')
        .substring(0, 20);
      setFormData(prev => ({ ...prev, subdomain }));
    }
    if (field === 'password') {
      setPasswordStrength(calculatePasswordStrength(value));
    }
    setError('');
  };

  const validateStep = (step: number): boolean => {
    setError('');
    
    switch (step) {
      case 1:
        if (!formData.tenantName || !formData.subdomain || !formData.contactEmail) {
          setError('Please fill in all required company information.');
          return false;
        }
        if (formData.subdomain.length < 3) {
          setError('Subdomain must be at least 3 characters long.');
          return false;
        }
        if (!/^[a-z0-9]+$/.test(formData.subdomain)) {
          setError('Subdomain can only contain lowercase letters and numbers.');
          return false;
        }
        break;
      
      case 2:
        if (!formData.firstName || !formData.lastName || !formData.password || !formData.confirmPassword) {
          setError('Please fill in all required personal information.');
          return false;
        }
        if (formData.password.length < 8) {
          setError('Password must be at least 8 characters long.');
          return false;
        }
        if (formData.password !== formData.confirmPassword) {
          setError('Passwords do not match.');
          return false;
        }
        break;
    }
    return true;
  };

  const handleNext = () => {
    if (validateStep(currentStep)) {
      setCurrentStep(prev => prev + 1);
    }
  };

  const handleBack = () => {
    setCurrentStep(prev => prev - 1);
  };

  const handleSubmit = async () => {
    if (!validateStep(currentStep)) return;

    setLoading(true);
    try {
      const response = await fetch('http://localhost:3001/api/onboarding/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          company: formData.tenantName,
          email: formData.contactEmail,
          password: formData.password,
          firstName: formData.firstName,
          lastName: formData.lastName
        }),
      });

      const data = await response.json();

      if (response.ok) {
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
          subdomain: formData.subdomain,
          status: data.organization.subscriptionStatus,
          onboarding_status: 'completed',
          plan: data.subscription.tier
        };

        // Store token and redirect to dashboard (skip onboarding since no email verification)
        login(data.token, user, tenant);
        navigate('/dashboard');
      } else {
        setError(data.message || 'Registration failed. Please try again.');
      }
    } catch (err) {
      setError('Network error. Please check your connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  const calculatePasswordStrength = (password: string) => {
    let strength = 0;
    if (password.length >= 8) strength += 25;
    if (/[a-z]/.test(password)) strength += 25;
    if (/[A-Z]/.test(password)) strength += 25;
    if (/[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) strength += 25;
    return strength;
  };

  const getPasswordStrengthColor = () => {
    if (passwordStrength < 25) return 'bg-red-500';
    if (passwordStrength < 50) return 'bg-orange-500';
    if (passwordStrength < 75) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const getPasswordStrengthText = () => {
    if (passwordStrength < 25) return 'Weak';
    if (passwordStrength < 50) return 'Fair';
    if (passwordStrength < 75) return 'Good';
    return 'Strong';
  };

  const renderStepIndicator = () => (
    <div className="flex items-center justify-center mb-8">
      {[1, 2, 3].map((step) => (
        <React.Fragment key={step}>
          <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
            step <= currentStep 
              ? 'bg-blue-600 text-white' 
              : 'bg-slate-500 text-slate-400'
          }`}>
            {step < currentStep ? <CheckCircle className="w-4 h-4" /> : step}
          </div>
          {step < 3 && (
            <div className={`w-12 h-0.5 ${
              step < currentStep ? 'bg-blue-600' : 'bg-slate-500'
            }`} />
          )}
        </React.Fragment>
      ))}
    </div>
  );

  const renderStep1 = () => (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-white">Company Information</h2>
        <p className="text-slate-400 mt-2">Set up your organization's security operations center</p>
      </div>

      <div className="space-y-4">
        <div>
          <Label htmlFor="tenantName">Company Name *</Label>
          <Input
            id="tenantName"
            value={formData.tenantName}
            onChange={(e) => handleInputChange('tenantName', e.target.value)}
            placeholder="Enter your company name"
            className="mt-1"
          />
        </div>

        <div>
          <Label htmlFor="subdomain">Subdomain *</Label>
          <div className="flex items-center mt-1">
            <Input
              id="subdomain"
              value={formData.subdomain}
              onChange={(e) => handleInputChange('subdomain', e.target.value)}
              placeholder="yourcompany"
              className="rounded-r-none"
            />
            <span className="px-3 py-2 bg-slate-700 border border-l-0 border-slate-600 rounded-r-md text-slate-400">
              .a2zsoc.com
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            This will be your unique URL: {formData.subdomain || 'yourcompany'}.a2zsoc.com
          </p>
        </div>

        <div>
          <Label htmlFor="contactEmail">Business Email *</Label>
          <Input
            id="contactEmail"
            type="email"
            value={formData.contactEmail}
            onChange={(e) => handleInputChange('contactEmail', e.target.value)}
            placeholder="admin@yourcompany.com"
            className="mt-1"
          />
        </div>

        <div>
          <Label htmlFor="phone">Phone Number</Label>
          <Input
            id="phone"
            value={formData.phone || ''}
            onChange={(e) => handleInputChange('phone', e.target.value)}
            placeholder="+1 (555) 123-4567"
            className="mt-1"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label htmlFor="industry">Industry</Label>
            <select
              id="industry"
              value={formData.industry || ''}
              onChange={(e) => handleInputChange('industry', e.target.value)}
              className="mt-1 w-full px-3 py-2 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select industry</option>
              <option value="technology">Technology</option>
              <option value="finance">Finance</option>
              <option value="healthcare">Healthcare</option>
              <option value="manufacturing">Manufacturing</option>
              <option value="retail">Retail</option>
              <option value="government">Government</option>
              <option value="other">Other</option>
            </select>
          </div>

          <div>
            <Label htmlFor="companySize">Company Size</Label>
            <select
              id="companySize"
              value={formData.companySize || ''}
              onChange={(e) => handleInputChange('companySize', e.target.value)}
              className="mt-1 w-full px-3 py-2 border border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">Select size</option>
              <option value="1-10">1-10 employees</option>
              <option value="11-50">11-50 employees</option>
              <option value="51-200">51-200 employees</option>
              <option value="201-1000">201-1000 employees</option>
              <option value="1000+">1000+ employees</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );

  const renderStep2 = () => (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-white">Admin Account</h2>
        <p className="text-slate-400 mt-2">Create your administrator account</p>
      </div>

      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label htmlFor="firstName">First Name *</Label>
            <Input
              id="firstName"
              value={formData.firstName}
              onChange={(e) => handleInputChange('firstName', e.target.value)}
              placeholder="John"
              className="mt-1"
            />
          </div>

          <div>
            <Label htmlFor="lastName">Last Name *</Label>
            <Input
              id="lastName"
              value={formData.lastName}
              onChange={(e) => handleInputChange('lastName', e.target.value)}
              placeholder="Doe"
              className="mt-1"
            />
          </div>
        </div>

        <div>
          <Label htmlFor="password">Password *</Label>
          <div className="relative">
            <Input
              id="password"
              type={showPassword ? 'text' : 'password'}
              value={formData.password}
              onChange={(e) => handleInputChange('password', e.target.value)}
              placeholder="Enter a secure password"
              className="mt-1 pr-10"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400 hover:text-slate-300"
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Password must be at least 8 characters long
          </p>
        </div>

        <div>
          <Label htmlFor="confirmPassword">Confirm Password *</Label>
          <Input
            id="confirmPassword"
            type="password"
            value={formData.confirmPassword}
            onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
            placeholder="Confirm your password"
            className="mt-1"
          />
        </div>
      </div>
    </div>
  );

  const renderStep3 = () => (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-white">Choose Your Plan</h2>
        <p className="text-slate-400 mt-2">Select the plan that best fits your security needs</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {plans.map((plan) => (
          <Card
            key={plan.id}
            className={`cursor-pointer transition-all hover:shadow-lg ${
              formData.planId === plan.id 
                ? 'ring-2 ring-blue-500 border-blue-500' 
                : plan.color
            } ${plan.recommended ? 'relative' : ''}`}
            onClick={() => handleInputChange('planId', plan.id)}
          >
            {plan.recommended && (
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2">
                <Badge className="bg-purple-600 text-white">Recommended</Badge>
              </div>
            )}
            
            <CardHeader className="text-center">
              <CardTitle className="text-xl">{plan.name}</CardTitle>
              <div className="mt-2">
                <span className="text-3xl font-bold">{plan.price}</span>
                <span className="text-slate-400 ml-1">/{plan.duration}</span>
              </div>
            </CardHeader>
            
            <CardContent>
              <ul className="space-y-2">
                {plan.features.map((feature, index) => (
                  <li key={index} className="flex items-center text-sm">
                    <CheckCircle className="w-4 h-4 text-green-500 mr-2 flex-shrink-0" />
                    {feature}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex items-start">
          <Shield className="w-5 h-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0" />
          <div>
            <h4 className="font-medium text-blue-900">Security First</h4>
            <p className="text-sm text-blue-700 mt-1">
              All plans include enterprise-grade security, 99.9% uptime SLA, and SOC 2 compliance.
            </p>
          </div>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-blue-400 mr-3" />
            <span className="text-3xl font-bold text-white">A2Z SOC</span>
          </div>
          <h1 className="text-2xl font-semibold text-gray-200">
            Start Your Security Operations Center
          </h1>
          <p className="text-gray-400 mt-2">
            Deploy enterprise-grade security in minutes, not months
          </p>
        </div>

        <Card className="bg-slate-800/95 backdrop-blur-sm shadow-xl">
          <CardContent className="p-8">
            {renderStepIndicator()}

            {error && (
              <Alert className="mb-6 border-red-200 bg-red-50">
                <AlertCircle className="h-4 w-4 text-red-600" />
                <AlertDescription className="text-red-700">
                  {error}
                </AlertDescription>
              </Alert>
            )}

            {currentStep === 1 && renderStep1()}
            {currentStep === 2 && renderStep2()}
            {currentStep === 3 && renderStep3()}

            <Separator className="my-8" />

            <div className="flex justify-between">
              {currentStep > 1 ? (
                <Button
                  variant="outline"
                  onClick={handleBack}
                  disabled={loading}
                >
                  Back
                </Button>
              ) : (
                <div />
              )}

              {currentStep < 3 ? (
                <Button onClick={handleNext} disabled={loading}>
                  Next
                </Button>
              ) : (
                <Button
                  onClick={handleSubmit}
                  disabled={loading}
                  className="bg-blue-600 hover:bg-blue-700"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Creating Account...
                    </>
                  ) : (
                    'Create Account'
                  )}
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        <div className="text-center mt-6">
          <p className="text-gray-400">
            Already have an account?{' '}
            <Link to="/login" className="text-blue-400 hover:text-blue-300">
              Sign in here
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register; 