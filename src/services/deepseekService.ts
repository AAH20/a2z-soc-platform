import axios from 'axios';

interface DeepSeekMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface DeepSeekCompletionRequest {
  model: string;
  messages: DeepSeekMessage[];
  temperature?: number;
  max_tokens?: number;
  stream?: boolean;
}

interface DeepSeekCompletionResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: {
    index: number;
    message: DeepSeekMessage;
    finish_reason: string;
  }[];
  usage: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

interface DeepSeekCodeAnalysisResult {
  summary: string;
  vulnerabilities: {
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    description: string;
    location?: string;
    recommendation: string;
  }[];
  recommendations: string[];
  securityScore: number;
}

// Enhanced report interfaces
interface SecurityAssessmentReport {
  id: string;
  title: string;
  generatedAt: string;
  executiveSummary: string;
  overallRiskScore: number;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  keyFindings: {
    finding: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    impact: string;
    recommendation: string;
  }[];
  vulnerabilityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  complianceStatus: {
    framework: string;
    status: 'Compliant' | 'Non-Compliant' | 'Partially Compliant';
    score: number;
    gaps: string[];
  }[];
  threatLandscape: {
    activeThreatActors: string[];
    relevantTTPsIdentified: string[];
    industryTrends: string[];
  };
  recommendations: {
    priority: 'immediate' | 'short-term' | 'medium-term' | 'long-term';
    category: string;
    description: string;
    effort: 'Low' | 'Medium' | 'High';
    impact: 'Low' | 'Medium' | 'High';
  }[];
  nextSteps: string[];
  appendices: {
    technicalDetails: string;
    methodologyUsed: string;
    toolsAndTechniques: string[];
  };
}

interface IncidentAnalysisReport {
  id: string;
  incidentId: string;
  title: string;
  generatedAt: string;
  incidentTimeline: {
    timestamp: string;
    event: string;
    source: string;
    impact: string;
  }[];
  rootCauseAnalysis: {
    primaryCause: string;
    contributingFactors: string[];
    systemsAffected: string[];
  };
  impactAssessment: {
    dataCompromised: boolean;
    systemsDown: string[];
    estimatedDowntime: string;
    businessImpact: string;
    financialImpact?: string;
  };
  attackVectorAnalysis: {
    initialAccess: string;
    persistence: string[];
    privilegeEscalation: string[];
    defensiveEvasion: string[];
    credentialAccess: string[];
    discovery: string[];
    lateralMovement: string[];
    collection: string[];
    exfiltration: string[];
    impact: string[];
  };
  lessonsLearned: string[];
  recommendedActions: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
  };
  preventiveMeasures: string[];
}

interface ComplianceReport {
  id: string;
  framework: string;
  title: string;
  generatedAt: string;
  overallCompliance: number;
  status: 'Compliant' | 'Non-Compliant' | 'Partially Compliant';
  controlsAssessment: {
    controlId: string;
    controlName: string;
    status: 'Compliant' | 'Non-Compliant' | 'Partially Compliant';
    evidence: string[];
    gaps: string[];
    recommendations: string[];
    riskRating: 'Critical' | 'High' | 'Medium' | 'Low';
  }[];
  riskAssessment: {
    highRiskControls: string[];
    mediumRiskControls: string[];
    lowRiskControls: string[];
  };
  remediationPlan: {
    priority: number;
    control: string;
    action: string;
    owner: string;
    timeline: string;
    status: 'Not Started' | 'In Progress' | 'Completed';
  }[];
  executiveSummary: string;
  nextAuditDate: string;
}

interface ThreatIntelligenceReport {
  id: string;
  title: string;
  generatedAt: string;
  threatLandscape: {
    activeCampaigns: {
      name: string;
      actor: string;
      targets: string[];
      ttps: string[];
      indicators: string[];
    }[];
    emergingThreats: {
      threat: string;
      description: string;
      severity: 'Critical' | 'High' | 'Medium' | 'Low';
      affectedSectors: string[];
      mitigations: string[];
    }[];
  };
  organizationalRelevance: {
    applicableThreats: string[];
    riskAssessment: string;
    priorityActions: string[];
  };
  indicatorsOfCompromise: {
    type: 'hash' | 'ip' | 'domain' | 'url' | 'email';
    value: string;
    context: string;
    confidence: 'High' | 'Medium' | 'Low';
    source: string;
  }[];
  recommendedActions: {
    defensive: string[];
    monitoring: string[];
    hunting: string[];
  };
}

// Enhanced report interfaces
interface SecurityAssessmentReport {
  id: string;
  title: string;
  generatedAt: string;
  executiveSummary: string;
  overallRiskScore: number;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  keyFindings: {
    finding: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    impact: string;
    recommendation: string;
  }[];
  vulnerabilityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  complianceStatus: {
    framework: string;
    status: 'Compliant' | 'Non-Compliant' | 'Partially Compliant';
    score: number;
    gaps: string[];
  }[];
  threatLandscape: {
    activeThreatActors: string[];
    relevantTTPsIdentified: string[];
    industryTrends: string[];
  };
  recommendations: {
    priority: 'immediate' | 'short-term' | 'medium-term' | 'long-term';
    category: string;
    description: string;
    effort: 'Low' | 'Medium' | 'High';
    impact: 'Low' | 'Medium' | 'High';
  }[];
  nextSteps: string[];
  appendices: {
    technicalDetails: string;
    methodologyUsed: string;
    toolsAndTechniques: string[];
  };
}

interface IncidentAnalysisReport {
  id: string;
  incidentId: string;
  title: string;
  generatedAt: string;
  incidentTimeline: {
    timestamp: string;
    event: string;
    source: string;
    impact: string;
  }[];
  rootCauseAnalysis: {
    primaryCause: string;
    contributingFactors: string[];
    systemsAffected: string[];
  };
  impactAssessment: {
    dataCompromised: boolean;
    systemsDown: string[];
    estimatedDowntime: string;
    businessImpact: string;
    financialImpact?: string;
  };
  attackVectorAnalysis: {
    initialAccess: string;
    persistence: string[];
    privilegeEscalation: string[];
    defensiveEvasion: string[];
    credentialAccess: string[];
    discovery: string[];
    lateralMovement: string[];
    collection: string[];
    exfiltration: string[];
    impact: string[];
  };
  lessonsLearned: string[];
  recommendedActions: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
  };
  preventiveMeasures: string[];
}

interface ComplianceReport {
  id: string;
  framework: string;
  title: string;
  generatedAt: string;
  overallCompliance: number;
  status: 'Compliant' | 'Non-Compliant' | 'Partially Compliant';
  controlsAssessment: {
    controlId: string;
    controlName: string;
    status: 'Compliant' | 'Non-Compliant' | 'Partially Compliant';
    evidence: string[];
    gaps: string[];
    recommendations: string[];
    riskRating: 'Critical' | 'High' | 'Medium' | 'Low';
  }[];
  riskAssessment: {
    highRiskControls: string[];
    mediumRiskControls: string[];
    lowRiskControls: string[];
  };
  remediationPlan: {
    priority: number;
    control: string;
    action: string;
    owner: string;
    timeline: string;
    status: 'Not Started' | 'In Progress' | 'Completed';
  }[];
  executiveSummary: string;
  nextAuditDate: string;
}

interface ThreatIntelligenceReport {
  id: string;
  title: string;
  generatedAt: string;
  threatLandscape: {
    activeCampaigns: {
      name: string;
      actor: string;
      targets: string[];
      ttps: string[];
      indicators: string[];
    }[];
    emergingThreats: {
      threat: string;
      description: string;
      severity: 'Critical' | 'High' | 'Medium' | 'Low';
      affectedSectors: string[];
      mitigations: string[];
    }[];
  };
  organizationalRelevance: {
    applicableThreats: string[];
    riskAssessment: string;
    priorityActions: string[];
  };
  indicatorsOfCompromise: {
    type: 'hash' | 'ip' | 'domain' | 'url' | 'email';
    value: string;
    context: string;
    confidence: 'High' | 'Medium' | 'Low';
    source: string;
  }[];
  recommendedActions: {
    defensive: string[];
    monitoring: string[];
    hunting: string[];
  };
}

// API client configuration - will be initialized with proper auth header later
const deepseekClient = axios.create({
  baseURL: 'https://api.deepseek.com/v1',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Get API key from backend for security
const getApiKey = async (): Promise<string> => {
  try {
    const response = await axios.get('/api/v1/ai-insights/deepseek/key');
    return response.data.key;
  } catch (error) {
    console.error('Failed to fetch DeepSeek API key:', error);
    throw error;
  }
};

export const deepseekService = {
  // Initialize with API key from backend
  initialize: async () => {
    try {
      const apiKey = await getApiKey();
      deepseekClient.defaults.headers.common['Authorization'] = `Bearer ${apiKey}`;
      return true;
    } catch (error) {
      console.error('Failed to initialize DeepSeek service:', error);
      return false;
    }
  },

  // Check API connectivity
  checkConnection: async (): Promise<boolean> => {
    try {
      const response = await deepseekClient.get('/models');
      return response.status === 200;
    } catch (error) {
      console.error('DeepSeek API connection check failed:', error);
      return false;
    }
  },

  // Generate chat completions
  generateCompletion: async (prompt: string, systemPrompt: string = '', temperature: number = 0.4, maxTokens: number = 4000): Promise<string> => {
    try {
      const messages: DeepSeekMessage[] = [];
      
      if (systemPrompt) {
        messages.push({
          role: 'system',
          content: systemPrompt
        });
      }
      
      messages.push({
        role: 'user',
        content: prompt
      });
      
      const request: DeepSeekCompletionRequest = {
        model: 'deepseek-coder',
        messages,
        temperature,
        max_tokens: maxTokens
      };
      
      const response = await deepseekClient.post<DeepSeekCompletionResponse>('/chat/completions', request);
      
      return response.data.choices[0].message.content;
    } catch (error) {
      console.error('Error generating DeepSeek completion:', error);
      throw error;
    }
  },
  
  // Analyze code for security vulnerabilities
  analyzeCodeSecurity: async (code: string, language: string): Promise<DeepSeekCodeAnalysisResult> => {
    try {
      const systemPrompt = `You are a cybersecurity expert specializing in code security analysis. 
      Analyze the provided ${language} code for security vulnerabilities. 
      Focus on identifying security issues like injection vulnerabilities, authentication problems, 
      sensitive data exposure, broken access control, security misconfiguration, and other OWASP Top 10 issues.
      Format your response as a JSON object with the following structure:
      {
        "summary": "A brief summary of the security analysis",
        "vulnerabilities": [
          {
            "severity": "critical|high|medium|low|info",
            "description": "Detailed description of the vulnerability",
            "location": "File/line number or function name where the issue was found",
            "recommendation": "How to fix this specific issue"
          }
        ],
        "recommendations": ["General recommendation 1", "General recommendation 2"],
        "securityScore": 85 // A score from 0-100 indicating the overall security
      }`;
      
      const result = await this.generateCompletion(code, systemPrompt, 0.2, 4000);
      
      // Extract JSON from the response (handling potential text before/after the JSON)
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('Invalid response format from DeepSeek');
      }
      
      return JSON.parse(jsonMatch[0]) as DeepSeekCodeAnalysisResult;
    } catch (error) {
      console.error('Error analyzing code security with DeepSeek:', error);
      throw error;
    }
  },
  
  // Analyze logs for security insights
  analyzeSecurityLogs: async (logs: string): Promise<string> => {
    const systemPrompt = `You are a security log analysis expert. Analyze the provided security logs
    to identify potential security incidents, anomalies, or patterns that might indicate a security breach.
    Focus on identifying suspicious activities, potential attack patterns, unusual access patterns, and
    potential indicators of compromise. Provide a detailed analysis with specific findings and recommendations.`;
    
    return this.generateCompletion(logs, systemPrompt, 0.3, 8000);
  },

  // Generate comprehensive security assessment report
  generateSecurityAssessmentReport: async (
    organizationName: string,
    assessmentData: {
      vulnerabilities: any[];
      systemsScanned: string[];
      complianceFrameworks: string[];
      businessContext: string;
    }
  ): Promise<SecurityAssessmentReport> => {
    try {
      const systemPrompt = `You are a senior cybersecurity consultant generating a comprehensive security assessment report for ${organizationName}. 
      Create a detailed, professional security assessment report based on the provided data. The report should be suitable for both technical teams and executive leadership.
      Focus on providing actionable insights, clear risk prioritization, and strategic recommendations.
      Format your response as a valid JSON object matching the SecurityAssessmentReport interface structure.`;

      const prompt = `Generate a comprehensive security assessment report for ${organizationName}.

      Assessment Data:
      - Vulnerabilities Found: ${JSON.stringify(assessmentData.vulnerabilities, null, 2)}
      - Systems Scanned: ${assessmentData.systemsScanned.join(', ')}
      - Compliance Frameworks: ${assessmentData.complianceFrameworks.join(', ')}
      - Business Context: ${assessmentData.businessContext}

      Include:
      1. Executive summary with key findings and overall risk assessment
      2. Detailed vulnerability breakdown with risk scores
      3. Compliance status for each framework
      4. Threat landscape analysis relevant to the organization
      5. Prioritized recommendations with implementation timelines
      6. Next steps and action items

      Ensure the report is comprehensive, professional, and actionable.`;

      const result = await this.generateCompletion(prompt, systemPrompt, 0.3, 16000);
      
      // Extract JSON from the response
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('Invalid response format from DeepSeek');
      }
      
      const report = JSON.parse(jsonMatch[0]) as SecurityAssessmentReport;
      
      // Add metadata
      report.id = `SA-${Date.now()}`;
      report.generatedAt = new Date().toISOString();
      
      return report;
    } catch (error) {
      console.error('Error generating security assessment report:', error);
      throw error;
    }
  },

  // Generate incident analysis report
  generateIncidentAnalysisReport: async (
    incidentData: {
      incidentId: string;
      description: string;
      timelineEvents: any[];
      affectedSystems: string[];
      logData: string;
      initialFindings: string;
    }
  ): Promise<IncidentAnalysisReport> => {
    try {
      const systemPrompt = `You are a senior incident response analyst generating a comprehensive incident analysis report. 
      Analyze the provided incident data and create a detailed forensic report suitable for technical teams, management, and potential legal review.
      Focus on root cause analysis, attack vector identification, impact assessment, and prevention recommendations.
      Format your response as a valid JSON object matching the IncidentAnalysisReport interface structure.`;

      const prompt = `Analyze the following security incident and generate a comprehensive incident analysis report:

      Incident ID: ${incidentData.incidentId}
      Description: ${incidentData.description}
      
      Timeline Events: ${JSON.stringify(incidentData.timelineEvents, null, 2)}
      Affected Systems: ${incidentData.affectedSystems.join(', ')}
      Initial Findings: ${incidentData.initialFindings}
      
      Log Data Sample:
      ${incidentData.logData}

      Include:
      1. Detailed incident timeline reconstruction
      2. Root cause analysis with contributing factors
      3. Impact assessment (technical and business)
      4. Attack vector mapping to MITRE ATT&CK framework
      5. Lessons learned and gaps identified
      6. Recommended immediate, short-term, and long-term actions
      7. Preventive measures to avoid similar incidents

      Ensure the analysis is thorough, evidence-based, and actionable.`;

      const result = await this.generateCompletion(prompt, systemPrompt, 0.2, 16000);
      
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('Invalid response format from DeepSeek');
      }
      
      const report = JSON.parse(jsonMatch[0]) as IncidentAnalysisReport;
      
      // Add metadata
      report.id = `IA-${Date.now()}`;
      report.incidentId = incidentData.incidentId;
      report.generatedAt = new Date().toISOString();
      
      return report;
    } catch (error) {
      console.error('Error generating incident analysis report:', error);
      throw error;
    }
  },

  // Generate compliance report
  generateComplianceReport: async (
    framework: string,
    organizationName: string,
    controlsData: {
      controlId: string;
      status: string;
      evidence: string[];
      gaps: string[];
    }[]
  ): Promise<ComplianceReport> => {
    try {
      const systemPrompt = `You are a compliance auditor generating a comprehensive compliance assessment report for ${framework}. 
      Analyze the provided controls data and create a detailed compliance report suitable for auditors, management, and regulatory bodies.
      Focus on control effectiveness, gap analysis, risk assessment, and remediation planning.
      Format your response as a valid JSON object matching the ComplianceReport interface structure.`;

      const prompt = `Generate a comprehensive compliance assessment report for ${organizationName} against the ${framework} framework.

      Controls Assessment Data:
      ${JSON.stringify(controlsData, null, 2)}

      Include:
      1. Overall compliance status and score
      2. Detailed assessment of each control with evidence and gaps
      3. Risk assessment highlighting high-risk areas
      4. Prioritized remediation plan with timelines
      5. Executive summary for leadership
      6. Next audit preparation recommendations

      Ensure the report meets regulatory standards and provides clear guidance for compliance improvement.`;

      const result = await this.generateCompletion(prompt, systemPrompt, 0.2, 16000);
      
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('Invalid response format from DeepSeek');
      }
      
      const report = JSON.parse(jsonMatch[0]) as ComplianceReport;
      
      // Add metadata
      report.id = `CR-${Date.now()}`;
      report.framework = framework;
      report.generatedAt = new Date().toISOString();
      
      return report;
    } catch (error) {
      console.error('Error generating compliance report:', error);
      throw error;
    }
  },

  // Generate threat intelligence report
  generateThreatIntelligenceReport: async (
    organizationProfile: {
      industry: string;
      size: string;
      geographicLocation: string;
      technologyStack: string[];
      criticalAssets: string[];
    },
    threatData: {
      activeCampaigns: any[];
      emergingThreats: any[];
      indicators: any[];
    }
  ): Promise<ThreatIntelligenceReport> => {
    try {
      const systemPrompt = `You are a threat intelligence analyst generating a comprehensive threat intelligence report. 
      Analyze the current threat landscape and provide organization-specific threat intelligence based on the organization's profile.
      Focus on relevant threats, actionable intelligence, and defensive recommendations.
      Format your response as a valid JSON object matching the ThreatIntelligenceReport interface structure.`;

      const prompt = `Generate a comprehensive threat intelligence report for an organization with the following profile:

      Organization Profile:
      - Industry: ${organizationProfile.industry}
      - Size: ${organizationProfile.size}
      - Geographic Location: ${organizationProfile.geographicLocation}
      - Technology Stack: ${organizationProfile.technologyStack.join(', ')}
      - Critical Assets: ${organizationProfile.criticalAssets.join(', ')}

      Threat Intelligence Data:
      - Active Campaigns: ${JSON.stringify(threatData.activeCampaigns, null, 2)}
      - Emerging Threats: ${JSON.stringify(threatData.emergingThreats, null, 2)}
      - Indicators of Compromise: ${JSON.stringify(threatData.indicators, null, 2)}

      Include:
      1. Current threat landscape analysis
      2. Organization-specific threat relevance assessment
      3. Priority threat actors and campaigns
      4. Actionable indicators of compromise
      5. Recommended defensive actions and monitoring
      6. Threat hunting recommendations

      Ensure the intelligence is actionable, relevant, and prioritized based on the organization's risk profile.`;

      const result = await this.generateCompletion(prompt, systemPrompt, 0.3, 16000);
      
      const jsonMatch = result.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        throw new Error('Invalid response format from DeepSeek');
      }
      
      const report = JSON.parse(jsonMatch[0]) as ThreatIntelligenceReport;
      
      // Add metadata
      report.id = `TI-${Date.now()}`;
      report.generatedAt = new Date().toISOString();
      
      return report;
    } catch (error) {
      console.error('Error generating threat intelligence report:', error);
      throw error;
    }
  },

  // Export report to different formats
  exportReport: async (
    report: SecurityAssessmentReport | IncidentAnalysisReport | ComplianceReport | ThreatIntelligenceReport,
    format: 'pdf' | 'docx' | 'html' | 'json'
  ): Promise<Blob> => {
    try {
      if (format === 'json') {
        const jsonData = JSON.stringify(report, null, 2);
        return new Blob([jsonData], { type: 'application/json' });
      }

      // For other formats, generate formatted content
      const systemPrompt = `You are a technical writer converting a security report into ${format.toUpperCase()} format. 
      Create well-formatted, professional document content suitable for ${format} export.
      Include proper headings, sections, tables, and formatting appropriate for the target format.`;

      const prompt = `Convert the following security report into ${format.toUpperCase()} format:

      ${JSON.stringify(report, null, 2)}

      Create a well-structured document with:
      1. Title page and executive summary
      2. Table of contents
      3. Detailed sections with proper headings
      4. Tables and charts where appropriate
      5. Professional formatting and layout
      6. Appendices with technical details

      Return the formatted content ready for ${format} export.`;

      const formattedContent = await this.generateCompletion(prompt, systemPrompt, 0.2, 16000);
      
      const mimeTypes = {
        pdf: 'application/pdf',
        docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        html: 'text/html'
      };

      return new Blob([formattedContent], { type: mimeTypes[format] });
    } catch (error) {
      console.error(`Error exporting report to ${format}:`, error);
      throw error;
    }
  },

  // Generate executive summary from detailed report
  generateExecutiveSummary: async (
    detailedReport: SecurityAssessmentReport | IncidentAnalysisReport | ComplianceReport | ThreatIntelligenceReport
  ): Promise<string> => {
    try {
      const systemPrompt = `You are an executive communications specialist creating a concise executive summary. 
      Transform the detailed technical report into a clear, actionable summary suitable for C-level executives and board members.
      Focus on business impact, risk, and strategic recommendations. Use clear, non-technical language.`;

      const prompt = `Create an executive summary for the following detailed security report:

      ${JSON.stringify(detailedReport, null, 2)}

      The summary should include:
      1. Key findings and overall risk assessment
      2. Business impact and implications
      3. Priority actions required
      4. Resource requirements and timelines
      5. Strategic recommendations

      Keep it concise (max 2 pages), executive-friendly, and action-oriented.`;

      return await this.generateCompletion(prompt, systemPrompt, 0.4, 8000);
    } catch (error) {
      console.error('Error generating executive summary:', error);
      throw error;
    }
  }
};

// Export report types for use in other components
export type {
  SecurityAssessmentReport,
  IncidentAnalysisReport,
  ComplianceReport,
  ThreatIntelligenceReport,
  DeepSeekCodeAnalysisResult
};