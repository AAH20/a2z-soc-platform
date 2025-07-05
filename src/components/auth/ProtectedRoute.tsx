import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './AuthProvider';
import { Loader2 } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requireOnboarding?: boolean;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requireOnboarding = false 
}) => {
  const { isAuthenticated, isLoading, user, tenant } = useAuth();
  const location = useLocation();

  console.log('🛡️ ProtectedRoute check:', { 
    isAuthenticated, 
    isLoading, 
    path: location.pathname,
    userEmail: user?.email,
    tenantName: tenant?.name,
    onboardingStatus: tenant?.onboarding_status,
    requireOnboarding
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-blue-600" />
          <p className="text-gray-600">Verifying authentication...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    console.log('❌ Not authenticated, redirecting to login');
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check if email verification is required - DISABLED for A2Z SOC
  // Email verification is bypassed in our registration process
  
  // if (user && !user.emailVerified && requireEmailVerification) {
  //   console.log('📧 Email not verified, redirecting to verify-email');
  //   return <Navigate to="/verify-email" replace />;
  // }

  // Check onboarding status (only if the column exists and has a value)
  const needsOnboarding = tenant?.onboarding_status === 'pending' || tenant?.onboarding_status === 'in_progress';
  
  if (needsOnboarding) {
    if (!requireOnboarding && location.pathname !== '/onboarding') {
      console.log('📋 Needs onboarding, redirecting to onboarding');
      return <Navigate to="/onboarding" replace />;
    }
  } else if (requireOnboarding && location.pathname === '/onboarding') {
    // User has completed onboarding but is trying to access onboarding page
    console.log('✅ Onboarding completed, redirecting to dashboard');
    return <Navigate to="/dashboard" replace />;
  }

  console.log('✅ ProtectedRoute: Access granted to', location.pathname);
  return <>{children}</>;
};

export default ProtectedRoute; 