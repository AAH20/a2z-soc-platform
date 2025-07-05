import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Home, ArrowLeft, Shield } from 'lucide-react';

const NotFound: React.FC = () => {
  return (
    <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md text-center">
        <div className="mb-8">
          <div className="flex items-center justify-center gap-2 mb-6">
            <Shield className="h-12 w-12 text-blue-400" />
            <h1 className="text-3xl font-bold text-white">A2Z SOC</h1>
          </div>
          
          <div className="text-8xl font-bold text-blue-400 mb-4">404</div>
          <h2 className="text-2xl font-semibold text-white mb-2">Page Not Found</h2>
          <p className="text-slate-400 mb-8">
            The page you're looking for doesn't exist or has been moved.
          </p>
        </div>

        <Card className="bg-slate-800 border-slate-700 mb-6">
          <CardContent className="p-6">
            <div className="space-y-4">
              <p className="text-slate-300">
                You might want to check the URL or navigate back to a safe place.
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <Button
                  asChild
                  className="flex-1 bg-blue-600 hover:bg-blue-700 text-white"
                >
                  <Link to="/dashboard">
                    <Home className="h-4 w-4 mr-2" />
                    Go to Dashboard
                  </Link>
                </Button>
                <Button
                  asChild
                  variant="outline"
                  className="flex-1 border-slate-600 text-slate-300 hover:bg-slate-700"
                >
                  <Link to="javascript:history.back()">
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Go Back
                  </Link>
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="text-xs text-slate-500">
          If you believe this is an error, please{' '}
          <Link to="/contact" className="text-blue-400 hover:underline">
            contact support
          </Link>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
