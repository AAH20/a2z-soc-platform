import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Shield, Mail, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';

const VerifyEmail: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [isSuccess, setIsSuccess] = useState(false);

  const resendVerification = async () => {
    setLoading(true);
    setMessage('');

    try {
      // This would call your resend verification API
      setTimeout(() => {
        setMessage('Verification email sent! Please check your inbox.');
        setIsSuccess(true);
        setLoading(false);
      }, 1000);
    } catch (error) {
      setMessage('Failed to send verification email. Please try again.');
      setIsSuccess(false);
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-blue-400 mr-3" />
            <span className="text-3xl font-bold text-white">A2Z SOC</span>
          </div>
          <h1 className="text-2xl font-semibold text-gray-200 mb-2">
            Verify Your Email
          </h1>
          <p className="text-gray-400">
            Check your email for a verification link
          </p>
        </div>

        <Card className="bg-slate-800/95 backdrop-blur-sm shadow-xl">
          <CardHeader className="space-y-1 text-center">
            <div className="mx-auto w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
              <Mail className="w-8 h-8 text-blue-600" />
            </div>
            <CardTitle className="text-2xl font-bold">Check Your Email</CardTitle>
            <CardDescription>
              We've sent a verification link to your email address. Please check your inbox and click the link to verify your account.
            </CardDescription>
          </CardHeader>
          
          <CardContent className="space-y-6">
            {message && (
              <Alert className={isSuccess ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"}>
                {isSuccess ? (
                  <CheckCircle className="h-4 w-4 text-green-600" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-red-600" />
                )}
                <AlertDescription className={isSuccess ? "text-green-700" : "text-red-700"}>
                  {message}
                </AlertDescription>
              </Alert>
            )}

            <div className="space-y-4">
              <div className="text-center">
                <p className="text-sm text-slate-400 mb-4">
                  Didn't receive the email? Check your spam folder or request a new one.
                </p>
                
                <Button
                  onClick={resendVerification}
                  disabled={loading}
                  variant="outline"
                  className="w-full"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Sending...
                    </>
                  ) : (
                    'Resend Verification Email'
                  )}
                </Button>
              </div>

              <div className="text-center">
                <Link
                  to="/login"
                  className="text-sm text-blue-600 hover:text-blue-800"
                >
                  Back to Login
                </Link>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Security Notice */}
        <div className="mt-6 text-center">
          <div className="inline-flex items-center text-sm text-gray-400">
            <Shield className="w-4 h-4 mr-2" />
            <span>Secure email verification process</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default VerifyEmail; 