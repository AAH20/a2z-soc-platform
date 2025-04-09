
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
  ]
};

// Mock function to run analysis with a model
export const runModelAnalysis = async (modelType: ModelType, prompt: string): Promise<string> => {
  console.log(`Running analysis with ${modelType} using prompt: ${prompt}`);
  
  // In a real implementation, this would call the appropriate API
  return new Promise((resolve) => {
    // Simulate API call delay
    setTimeout(() => {
      resolve(generateMockResponse(modelType, prompt));
    }, 3000);
  });
};

// Mock function to save model configuration
export const saveModelConfiguration = async (config: any): Promise<boolean> => {
  console.log('Saving model configuration:', config);
  // In a real implementation, this would save to a backend or local storage
  return Promise.resolve(true);
};

// Helper function to generate mock responses
const generateMockResponse = (modelType: ModelType, prompt: string): string => {
  // Generate different responses based on model and prompt content
  if (prompt.toLowerCase().includes('health')) {
    return `## System Health Assessment
    
Overall health: 87% (Good)

**Components requiring attention:**
- Threat Intelligence Feed: Performance degraded (API rate limiting)
- Elasticsearch Node 3: High CPU utilization (92%)

**Recommendations:**
1. Implement rate limiting controls for the Threat Intel API
2. Evaluate resource allocation for Elasticsearch cluster
3. Consider implementing load balancing for high-traffic services

All other systems operating within normal parameters.`;
  }
  
  if (prompt.toLowerCase().includes('threat') || prompt.toLowerCase().includes('attack')) {
    return `## Threat Pattern Analysis

Identified 3 potential coordinated attack patterns:

**Pattern A: Credential Stuffing**
- 247 failed authentication attempts across 18 systems
- Source IP ranges suggest botnet activity
- Recommend: Implement progressive rate limiting and CAPTCHA

**Pattern B: API Scanning**
- Unusual API endpoint probing from 5 source IPs
- Targeting known vulnerabilities in web services
- Recommend: Review WAF rules and API throttling policies

**Pattern C: Data Exfiltration Attempt**
- Unusual outbound traffic patterns from Database Server
- Destination matches known C2 infrastructure
- HIGH PRIORITY: Isolate affected system for forensic analysis`;
  }
  
  if (prompt.toLowerCase().includes('compliance') || prompt.toLowerCase().includes('framework')) {
    return `## Compliance Assessment

**NIST CSF Compliance: 73%**
- Identity Management: 65% ⚠️
- Access Control: 82% ✓
- Data Protection: 78% ✓
- Monitoring: 89% ✓
- Response Planning: 52% ❌

**Critical Gaps:**
1. Incident response procedures not regularly tested
2. Multi-factor authentication not enforced on all admin accounts
3. Data classification policy implementation incomplete

**Recommended Actions:**
- Schedule quarterly tabletop exercises for IR team
- Complete MFA rollout for remaining admin accounts (6 identified)
- Finalize data classification across cloud storage services`;
  }
  
  // Default response
  return `## Analysis Results

Based on the requested analysis, I've identified several key findings:

1. System performance metrics show optimal operation at 94% efficiency
2. Alert categorization accuracy has improved by 12% over the past month
3. Current detection coverage maps to approximately 85% of MITRE ATT&CK framework

**Recommendations:**
- Consider implementing additional monitoring for the identified gap in credential access techniques
- Review and update alert thresholds for network traffic analysis
- Enhance log correlation rules between endpoint and network data sources

Additional context and metrics are available in the full report.`;
};
