import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';

interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  emailVerified: boolean;
  tenantId: string;
}

interface Tenant {
  id: string;
  name: string;
  subdomain: string;
  status: string;
  onboarding_status?: string;
  plan: string;
}

interface AuthContextType {
  user: User | null;
  tenant: Tenant | null;
  token: string | null;
  login: (token: string, user: User, tenant: Tenant) => void;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    // Check for existing authentication on mount
    const storedToken = localStorage.getItem('token');
    const storedUser = localStorage.getItem('user');
    const storedTenant = localStorage.getItem('tenant');

    console.log('🔍 AuthProvider: Checking stored auth data', { 
      hasToken: !!storedToken, 
      hasUser: !!storedUser, 
      hasTenant: !!storedTenant 
    });

    if (storedToken && storedUser && storedTenant) {
      try {
        const parsedUser = JSON.parse(storedUser);
        const parsedTenant = JSON.parse(storedTenant);
        
        console.log('📱 AuthProvider: Restoring auth from localStorage', { 
          user: parsedUser.email, 
          tenant: parsedTenant.name 
        });
        
        // Set authentication state from localStorage
        // Token validation will happen naturally during API calls
        setToken(storedToken);
        setUser(parsedUser);
        setTenant(parsedTenant);
        setIsLoading(false);
        
        console.log('✅ AuthProvider: Auth state restored');
      } catch (error) {
        console.error('❌ AuthProvider: Error parsing stored auth data:', error);
        logout();
      }
    } else {
      console.log('ℹ️ AuthProvider: No stored auth data found');
      setIsLoading(false);
    }
  }, []);

  const verifyToken = async (token: string, user: User, tenant: Tenant) => {
    try {
      const response = await fetch('http://localhost:3001/api/v1/auth/verify', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        setToken(token);
        setUser(user);
        setTenant(tenant);
      } else {
        // Token is invalid
        logout();
      }
    } catch (error) {
      console.error('Token verification failed:', error);
      logout();
    } finally {
      setIsLoading(false);
    }
  };

  const login = (newToken: string, newUser: User, newTenant: Tenant) => {
    console.log('🔐 AuthProvider: Login called', { user: newUser.email, tenant: newTenant.name });
    
    setToken(newToken);
    setUser(newUser);
    setTenant(newTenant);
    
    // Store in localStorage
    localStorage.setItem('token', newToken);
    localStorage.setItem('user', JSON.stringify(newUser));
    localStorage.setItem('tenant', JSON.stringify(newTenant));
    
    console.log('✅ AuthProvider: Authentication state updated, isAuthenticated:', !!(newToken && newUser));
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    setTenant(null);
    
    // Clear localStorage
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('tenant');
    localStorage.removeItem('rememberMe');
    
    // Redirect to login
    navigate('/login');
  };

  const isAuthenticated = !!token && !!user;

  const value = {
    user,
    tenant,
    token,
    login,
    logout,
    isAuthenticated,
    isLoading
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthProvider; 