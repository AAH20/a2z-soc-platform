import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  CheckCircle, 
  Circle, 
  ArrowRight, 
  ArrowLeft, 
  Skip, 
  Clock,
  AlertCircle,
  Trophy
} from 'lucide-react';

// Import step components
import ProfileSetupStep from './steps/ProfileSetupStep';
import SecurityConfigStep from './steps/SecurityConfigStep';
import IntegrationSetupStep from './steps/IntegrationSetupStep';
import TeamInvitationStep from './steps/TeamInvitationStep';
import TrialConfigStep from './steps/TrialConfigStep';
import FirstScanStep from './steps/FirstScanStep';
import DashboardTourStep from './steps/DashboardTourStep';

interface OnboardingStep {
  step_number: number;
  title: string;
  description: string;
  status: 'pending' | 'completed' | 'skipped';
  completed_at?: string;
  estimated_time: number;
}

interface OnboardingProgress {
  id: string;
  status: 'in_progress' | 'completed' | 'abandoned';
  current_step: number;
  steps_completed: number[];
  steps: OnboardingStep[];
}

const OnboardingWizard: React.FC = () => {
  const navigate = useNavigate();
  const [progress, setProgress] = useState<OnboardingProgress | null>(null);
  const [currentStep, setCurrentStep] = useState<number>(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stepData, setStepData] = useState<Record<number, any>>({});

  useEffect(() => {
    fetchOnboardingProgress();
  }, []);

  const fetchOnboardingProgress = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/onboarding/progress', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to fetch onboarding progress');
      }

      const data = await response.json();
      setProgress(data);
      setCurrentStep(data.current_step);
    } catch (error) {
      console.error('Error fetching onboarding progress:', error);
      setError('Failed to load onboarding progress');
    } finally {
      setLoading(false);
    }
  };

  const completeStep = async (stepNumber: number, data: any) => {
    try {
      setLoading(true);
      const response = await fetch(`/api/onboarding/steps/${stepNumber}/complete`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(data)
      });

      if (!response.ok) {
        throw new Error('Failed to complete step');
      }

      const result = await response.json();
      
      // Update step data
      setStepData(prev => ({ ...prev, [stepNumber]: data }));
      
      // Refresh progress
      await fetchOnboardingProgress();
      
      // Move to next step or complete onboarding
      if (result.next_step) {
        setCurrentStep(result.next_step);
      } else {
        // Onboarding completed
        navigate('/dashboard');
      }
    } catch (error) {
      console.error('Error completing step:', error);
      setError('Failed to complete step');
    } finally {
      setLoading(false);
    }
  };

  const skipStep = async (stepNumber: number) => {
    try {
      setLoading(true);
      const response = await fetch(`/api/onboarding/steps/${stepNumber}/skip`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to skip step');
      }

      await fetchOnboardingProgress();
    } catch (error) {
      console.error('Error skipping step:', error);
      setError('Failed to skip step');
    } finally {
      setLoading(false);
    }
  };

  const goToStep = (stepNumber: number) => {
    if (stepNumber <= currentStep) {
      setCurrentStep(stepNumber);
    }
  };

  const renderStepComponent = () => {
    const stepProps = {
      onComplete: (data: any) => completeStep(currentStep, data),
      onSkip: () => skipStep(currentStep),
      stepData: stepData[currentStep] || {},
      loading
    };

    switch (currentStep) {
      case 1:
        return <ProfileSetupStep {...stepProps} />;
      case 2:
        return <SecurityConfigStep {...stepProps} />;
      case 3:
        return <IntegrationSetupStep {...stepProps} />;
      case 4:
        return <TeamInvitationStep {...stepProps} />;
      case 5:
        return <TrialConfigStep {...stepProps} />;
      case 6:
        return <FirstScanStep {...stepProps} />;
      case 7:
        return <DashboardTourStep {...stepProps} />;
      default:
        return <div>Unknown step</div>;
    }
  };

  const getProgressPercentage = () => {
    if (!progress) return 0;
    return Math.round((progress.steps_completed.length / progress.steps.length) * 100);
  };

  const getTotalEstimatedTime = () => {
    if (!progress) return 0;
    return progress.steps.reduce((total, step) => total + step.estimated_time, 0);
  };

  const getRemainingTime = () => {
    if (!progress) return 0;
    const remainingSteps = progress.steps.filter(step => step.status === 'pending');
    return remainingSteps.reduce((total, step) => total + step.estimated_time, 0);
  };

  if (loading && !progress) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading onboarding...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Alert className="max-w-md">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (!progress) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Alert className="max-w-md">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>No onboarding progress found</AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-semibold text-gray-900">Welcome to A2Z SOC</h1>
              <Badge variant="outline" className="ml-3">
                Setup in Progress
              </Badge>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center text-sm text-gray-500">
                <Clock className="h-4 w-4 mr-1" />
                {getRemainingTime()} min remaining
              </div>
              <Button 
                variant="ghost" 
                onClick={() => navigate('/dashboard')}
              >
                Skip Setup
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Sidebar - Progress Overview */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Setup Progress</CardTitle>
                <div className="space-y-2">
                  <Progress value={getProgressPercentage()} className="w-full" />
                  <p className="text-sm text-gray-600">
                    {progress.steps_completed.length} of {progress.steps.length} steps completed
                  </p>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {progress.steps.map((step) => (
                    <div 
                      key={step.step_number}
                      className={`flex items-center space-x-3 p-2 rounded-lg cursor-pointer transition-colors ${
                        step.step_number === currentStep 
                          ? 'bg-blue-50 border border-blue-200' 
                          : step.status === 'completed' 
                            ? 'hover:bg-green-50' 
                            : 'hover:bg-gray-50'
                      }`}
                      onClick={() => goToStep(step.step_number)}
                    >
                      <div className="flex-shrink-0">
                        {step.status === 'completed' ? (
                          <CheckCircle className="h-5 w-5 text-green-500" />
                        ) : step.status === 'skipped' ? (
                          <Skip className="h-5 w-5 text-yellow-500" />
                        ) : step.step_number === currentStep ? (
                          <Circle className="h-5 w-5 text-blue-500 fill-current" />
                        ) : (
                          <Circle className="h-5 w-5 text-gray-300" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className={`text-sm font-medium ${
                          step.step_number === currentStep ? 'text-blue-900' : 'text-gray-900'
                        }`}>
                          {step.title}
                        </p>
                        <div className="flex items-center space-x-2">
                          <p className="text-xs text-gray-500">
                            {step.estimated_time} min
                          </p>
                          {step.status === 'completed' && (
                            <Badge variant="secondary" className="text-xs">
                              Done
                            </Badge>
                          )}
                          {step.status === 'skipped' && (
                            <Badge variant="outline" className="text-xs">
                              Skipped
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                <Separator className="my-4" />

                <div className="space-y-2 text-sm text-gray-600">
                  <div className="flex justify-between">
                    <span>Total time:</span>
                    <span>{getTotalEstimatedTime()} minutes</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Remaining:</span>
                    <span>{getRemainingTime()} minutes</span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Quick Tips */}
            <Card className="mt-6">
              <CardHeader>
                <CardTitle className="text-sm font-medium flex items-center">
                  <Trophy className="h-4 w-4 mr-2" />
                  Quick Tips
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="text-sm text-gray-600 space-y-2">
                  <p>• Complete all steps for the best experience</p>
                  <p>• You can always return to setup later</p>
                  <p>• Skip optional steps if needed</p>
                  <p>• Your progress is automatically saved</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-xl">
                      Step {currentStep}: {progress.steps.find(s => s.step_number === currentStep)?.title}
                    </CardTitle>
                    <p className="text-gray-600 mt-1">
                      {progress.steps.find(s => s.step_number === currentStep)?.description}
                    </p>
                  </div>
                  <Badge variant="outline">
                    {progress.steps.find(s => s.step_number === currentStep)?.estimated_time} min
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                {renderStepComponent()}
              </CardContent>
            </Card>

            {/* Navigation */}
            <div className="flex items-center justify-between mt-6">
              <Button
                variant="outline"
                onClick={() => setCurrentStep(Math.max(1, currentStep - 1))}
                disabled={currentStep === 1}
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Previous
              </Button>

              <div className="flex items-center space-x-2">
                <span className="text-sm text-gray-500">
                  Step {currentStep} of {progress.steps.length}
                </span>
              </div>

              <Button
                variant="outline"
                onClick={() => skipStep(currentStep)}
                disabled={loading}
              >
                Skip Step
                <ArrowRight className="h-4 w-4 ml-2" />
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OnboardingWizard; 