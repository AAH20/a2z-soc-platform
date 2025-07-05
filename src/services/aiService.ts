// AI service for handling model interactions

import { ModelType } from '@/components/ai/ModelInterface';

// Mock model configurations
export const modelConfigurations = {
  'gpt': {
    type: 'gpt' as ModelType,
    name: 'GPT-4',
    description: 'OpenAI\'s GPT-4 model for general analysis and recommendations',
    endpoint: 'https://api.openai.com/v1/chat/completions',
    maxTokens: 8192,
    temperature: 0.7,
    status: 'disconnected' as const,
  },
  'claude': {
    type: 'claude' as ModelType,
    name: 'Claude 3.7 Sonnet',
    description: 'Anthropic\'s Claude model focused on security log analysis',
    endpoint: 'https://api.anthropic.com/v1/messages',
    maxTokens: 100000,
    temperature: 0.5,
    status: 'disconnected' as const,
  },
  'gemini': {
    type: 'gemini' as ModelType,
    name: 'Gemini 2.5 Pro',
    description: 'Google\'s Gemini model for multimodal security data analysis',
    endpoint: 'https://generativelanguage.googleapis.com/v1',
    maxTokens: 32768,
    temperature: 0.2,
    status: 'disconnected' as const,
  },
  'security-copilot': {
    type: 'security-copilot' as ModelType,
    name: 'Microsoft Security Copilot',
    description: 'Specialized AI for security operations and threat analysis',
    maxTokens: 16000,
    temperature: 0.3,
    status: 'disconnected' as const,
  },
  'deepseek': {
    type: 'deepseek' as ModelType,
    name: 'DeepSeek Coder',
    description: 'DeepSeek\'s specialized model for code analysis and security review',
    endpoint: 'https://api.deepseek.com/v1/chat/completions',
    maxTokens: 16000,
    temperature: 0.4,
    status: 'connected' as const,
  }
};

// Preset prompts for security analysis
export const securityPrompts = {
  general: [
    {
      title: 'System Health Assessment',
      prompt: 'Analyze the current health of all security systems. Identify any degraded services or components requiring attention.',
      description: 'Get a comprehensive overview of system status and health metrics'
    },
    {
      title: 'Threat Pattern Analysis',
      prompt: 'Identify patterns in recent security alerts. Look for correlated events that might indicate a coordinated attack.',
      description: 'Detect attack patterns and coordinated threats across systems'
    },
    {
      title: 'Compliance Verification',
      prompt: 'Evaluate the current security configuration against industry best practices and compliance frameworks (NIST, CIS).',
      description: 'Verify compliance with security standards and best practices'
    },
    {
      title: 'Performance Optimization',
      prompt: 'Analyze system performance metrics and recommend optimizations for the security infrastructure.',
      description: 'Improve system performance and resource utilization'
    }
  ],
  logs: [
    {
      title: 'Critical Log Analysis',
      prompt: 'Analyze critical severity logs from the past 24 hours. Identify potential false positives and recommend alert tuning.',
      description: 'Deep analysis of critical security events'
    },
    {
      title: 'Anomaly Detection',
      prompt: 'Identify statistical anomalies in authentication logs across all systems.',
      description: 'Detect unusual patterns in authentication attempts'
    },
    {
      title: 'Lateral Movement Detection',
      prompt: 'Analyze network logs for signs of lateral movement between systems following the initial compromise.',
      description: 'Identify attackers moving between systems'
    }
  ],
  recommendations: [
    {
      title: 'Security Posture Improvement',
      prompt: 'Based on recent alerts and system configurations, provide actionable recommendations to improve overall security posture.',
      description: 'Get actionable steps to enhance security'
    },
    {
      title: 'Alert Reduction Strategy',
      prompt: 'Analyze alert volume and suggest strategies to reduce false positives while maintaining detection coverage.',
      description: 'Reduce alert fatigue and focus on real threats'
    },
    {
      title: 'Detection Gap Analysis',
      prompt: 'Identify potential gaps in current detection capabilities based on recent threat intelligence.',
      description: 'Find blind spots in your security monitoring'
    }
  ],
  codeAnalysis: [
    {
      title: 'API Security Review',
      prompt: 'Review the API endpoints for common security vulnerabilities like CSRF, injection attacks, and authorization flaws.',
      description: 'Find security issues in API implementations'
    },
    {
      title: 'Authentication Mechanism Audit',
      prompt: 'Analyze the authentication system for potential weaknesses, password storage methods, and session management issues.',
      description: 'Identify authentication security risks'
    },
    {
      title: 'Dependency Vulnerability Scan',
      prompt: 'Examine the project dependencies for known vulnerabilities and recommend secure alternatives where needed.',
      description: 'Find vulnerable dependencies in your codebase'
    },
    {
      title: 'OWASP Top 10 Assessment',
      prompt: 'Evaluate the codebase against the OWASP Top 10 vulnerabilities and provide specific remediation steps.',
      description: 'Check code against industry-standard security risks'
    }
  ]
};

// Mock function to run analysis with a model
export const runModelAnalysis = async (modelType: ModelType, prompt: string): Promise<string> => {
  console.log(`Running analysis with ${modelType} using prompt: ${prompt}`);
  
  try {
    const response = await fetch('/api/ai/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
      },
      body: JSON.stringify({
        model: modelType,
        prompt,
        temperature: 0.7,
        max_tokens: 2000
      })
    });

    const result = await response.json();
    
    if (result.success) {
      return result.data.response;
    } else {
      throw new Error(result.error || 'AI analysis failed');
    }
  } catch (error) {
    console.error('AI service error:', error);
    throw new Error('Failed to generate AI analysis. Please check your connection and try again.');
  }
};

// Real function to save model configuration
export const saveModelConfiguration = async (config: any): Promise<boolean> => {
  console.log('Saving model configuration:', config);
  
  try {
    const response = await fetch('/api/ai/config', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
      },
      body: JSON.stringify(config)
    });

    const result = await response.json();
    return result.success;
  } catch (error) {
    console.error('Error saving model configuration:', error);
    return false;
  }
};
