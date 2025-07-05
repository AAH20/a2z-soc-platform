// Update this page (the content is just a fallback if you fail to update the page)

import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { 
  Shield, 
  Zap, 
  Eye, 
  Brain, 
  Cloud, 
  Lock, 
  ArrowRight,
  CheckCircle,
  Star,
  Users,
  Globe
} from 'lucide-react';

const Index: React.FC = () => {
  const features = [
    {
      icon: <Shield className="h-6 w-6 text-blue-400" />,
      title: "Advanced Threat Detection",
      description: "Real-time monitoring with AI-powered threat intelligence and automated response capabilities."
    },
    {
      icon: <Brain className="h-6 w-6 text-purple-400" />,
      title: "AI-Powered Analytics",
      description: "Machine learning algorithms analyze patterns and predict potential security threats."
    },
    {
      icon: <Cloud className="h-6 w-6 text-green-400" />,
      title: "Multi-Cloud Security",
      description: "Unified security operations across AWS, Azure, and Google Cloud platforms."
    },
    {
      icon: <Eye className="h-6 w-6 text-orange-400" />,
      title: "24/7 Monitoring",
      description: "Continuous surveillance with real-time alerts and incident response automation."
    },
    {
      icon: <Lock className="h-6 w-6 text-red-400" />,
      title: "Compliance Ready",
      description: "Built-in compliance frameworks for SOC 2, ISO 27001, and industry standards."
    },
    {
      icon: <Zap className="h-6 w-6 text-yellow-400" />,
      title: "Rapid Deployment",
      description: "Get up and running in minutes with our streamlined onboarding process."
    }
  ];

  const stats = [
    { label: "Security Events Processed", value: "10M+", subtext: "per day" },
    { label: "Response Time", value: "<30s", subtext: "average" },
    { label: "Threat Detection", value: "99.7%", subtext: "accuracy" },
    { label: "Uptime", value: "99.9%", subtext: "guaranteed" }
  ];

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Header */}
      <header className="bg-slate-800 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center gap-2">
              <Shield className="h-8 w-8 text-blue-400" />
              <span className="text-2xl font-bold text-white">A2Z SOC</span>
            </div>
            <nav className="hidden md:flex items-center gap-8">
              <a href="#features" className="text-slate-300 hover:text-white transition-colors">Features</a>
              <a href="#pricing" className="text-slate-300 hover:text-white transition-colors">Pricing</a>
              <a href="#about" className="text-slate-300 hover:text-white transition-colors">About</a>
              <Link to="/auth/login" className="text-slate-300 hover:text-white transition-colors">Login</Link>
              <Button asChild className="bg-blue-600 hover:bg-blue-700">
                <Link to="/auth/register">Get Started</Link>
              </Button>
            </nav>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto text-center">
          <Badge className="mb-4 bg-blue-600 text-white">Next-Generation SOC Platform</Badge>
          <h1 className="text-4xl md:text-6xl font-bold text-white mb-6">
            Comprehensive Security
            <br />
            <span className="text-blue-400">Operations Center</span>
          </h1>
          <p className="text-xl text-slate-400 mb-8 max-w-3xl mx-auto">
            Empower your organization with AI-driven threat detection, real-time monitoring, 
            and automated incident response. Built for modern security teams.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
            <Button asChild size="lg" className="bg-blue-600 hover:bg-blue-700">
              <Link to="/auth/register">
                Start Free Trial
                <ArrowRight className="ml-2 h-4 w-4" />
              </Link>
            </Button>
            <Button asChild variant="outline" size="lg" className="border-slate-600 text-slate-300 hover:bg-slate-800">
              <Link to="/demo">
                Watch Demo
              </Link>
            </Button>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 max-w-4xl mx-auto">
            {stats.map((stat, index) => (
              <div key={index} className="text-center">
                <div className="text-3xl font-bold text-white mb-1">{stat.value}</div>
                <div className="text-sm text-slate-400">{stat.label}</div>
                <div className="text-xs text-slate-500">{stat.subtext}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4 sm:px-6 lg:px-8 bg-slate-800">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Everything you need for modern security operations
            </h2>
            <p className="text-xl text-slate-400 max-w-2xl mx-auto">
              Comprehensive security tools and integrations to protect your organization
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <Card key={index} className="bg-slate-700 border-slate-600 hover:bg-slate-600 transition-colors">
                <CardHeader>
                  <div className="mb-2">{feature.icon}</div>
                  <CardTitle className="text-white">{feature.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-slate-300">
                    {feature.description}
                  </CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Ready to secure your organization?
          </h2>
          <p className="text-xl text-slate-400 mb-8">
            Join thousands of security teams already using A2Z SOC
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button asChild size="lg" className="bg-blue-600 hover:bg-blue-700">
              <Link to="/auth/register">
                Get Started Free
                <ArrowRight className="ml-2 h-4 w-4" />
              </Link>
            </Button>
            <Button asChild variant="outline" size="lg" className="border-slate-600 text-slate-300 hover:bg-slate-800">
              <Link to="/contact">
                Contact Sales
              </Link>
            </Button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-slate-800 border-t border-slate-700 py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="flex items-center gap-2 mb-4 md:mb-0">
              <Shield className="h-6 w-6 text-blue-400" />
              <span className="text-xl font-bold text-white">A2Z SOC</span>
            </div>
            <div className="flex items-center gap-6 text-slate-400">
              <a href="#" className="hover:text-white transition-colors">Privacy Policy</a>
              <a href="#" className="hover:text-white transition-colors">Terms of Service</a>
              <a href="#" className="hover:text-white transition-colors">Support</a>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t border-slate-700 text-center text-slate-500">
            <p>&copy; 2024 A2Z SOC. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
