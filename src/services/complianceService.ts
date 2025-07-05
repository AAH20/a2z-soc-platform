// Dynamic Compliance Service for A2Z SOC Platform
import { useAuth } from '@/components/auth/AuthProvider';
import { apiService } from './api';

export interface NetworkResource {
  id: string;
  name: string;
  type: string;
  provider: string;
  region: string;
  status: string;
  securityGroups: string[];
  publicIpAddress?: string;
  privateIpAddress: string;
  tags: Record<string, string>;
  compliance: {
    encrypted: boolean;
    backupConfigured: boolean;
    monitoringEnabled: boolean;
    accessControlsConfigured: boolean;
    patchingUpToDate: boolean;
    vulnerabilityScanCompleted: boolean;
  };
  lastAssessed: string;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  requirements: ComplianceRequirement[];
}

export interface ComplianceRequirement {
  id: string;
  title: string;
  description: string;
  category: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  status: 'compliant' | 'non-compliant' | 'not-applicable' | 'pending';
  evidence?: string[];
  recommendations?: string[];
}

export interface ComplianceAssessment {
  id: string;
  frameworkId: string;
  frameworkName: string;
  tenantId: string;
  generatedAt: string;
  overallScore: number;
  status: 'compliant' | 'partially-compliant' | 'non-compliant';
  totalControls: number;
  compliantControls: number;
  nonCompliantControls: number;
  notApplicableControls: number;
  findings: ComplianceFinding[];
  recommendations: ComplianceRecommendation[];
  resourceSummary: {
    totalResources: number;
    assessedResources: number;
    compliantResources: number;
    nonCompliantResources: number;
    resourceBreakdown: Record<string, number>;
  };
  riskScore: number;
  nextAssessmentDue: string;
}

export interface ComplianceFinding {
  id: string;
  controlId: string;
  controlName: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'resolved' | 'acknowledged';
  description: string;
  impact: string;
  remediation: string;
  affectedResources: string[];
  discoveredAt: string;
  dueDate?: string;
}

export interface ComplianceRecommendation {
  id: string;
  title: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  estimatedEffort: string;
  implementation: string[];
  benefits: string[];
  affectedControls: string[];
}

export interface ComplianceReport {
  id: string;
  tenantId: string;
  frameworkId: string;
  reportName: string;
  generatedAt: string;
  generatedBy: string;
  executiveSummary: string;
  assessment: ComplianceAssessment;
  detailedFindings: ComplianceFinding[];
  recommendations: ComplianceRecommendation[];
  actionPlan: {
    immediateActions: string[];
    shortTermActions: string[];
    longTermActions: string[];
  };
  appendices: {
    resourceInventory: NetworkResource[];
    evidenceFiles: string[];
    screenshots: string[];
    configurations: string[];
  };
  metadata: {
    assessmentDuration: string;
    toolsUsed: string[];
    assessorName: string;
    approvalStatus: 'draft' | 'review' | 'approved' | 'published';
  };
}

class ComplianceService {
  private baseUrl: string;
  private apiKey: string;

  constructor() {
    this.baseUrl = '/api';
    this.apiKey = localStorage.getItem('auth_token') || '';
  }

  // Get network resources from cloud inventory
  async getNetworkResources(tenantId: string): Promise<NetworkResource[]> {
    try {
      const response = await apiService.get('/cloud-infra/resources', {
        params: { tenant_id: tenantId }
      });

      if (response.data.success) {
        return response.data.data;
      }

      return [];
    } catch (error) {
      console.error('Error fetching network resources:', error);
      return [];
    }
  }

  // Get compliance frameworks
  async getComplianceFrameworks(): Promise<ComplianceFramework[]> {
    try {
      const response = await apiService.get('/compliance/frameworks');
      return response.data.data || [];
    } catch (error) {
      console.error('Error fetching compliance frameworks:', error);
        return [];
    }
  }

  // Get compliance framework by ID
  async getComplianceFramework(frameworkId: string): Promise<ComplianceFramework | null> {
    try {
      const response = await apiService.get(`/compliance/frameworks/${frameworkId}`);
      return response.data.data || null;
    } catch (error) {
      console.error('Error fetching compliance framework:', error);
      return null;
    }
  }

  // Generate dynamic compliance assessment
  async generateComplianceAssessment(tenantId: string, frameworkId: string): Promise<ComplianceAssessment> {
    try {
      const response = await apiService.post('/compliance/assess', {
        tenantId,
        frameworkId
      });

      if (response.data.success) {
        return response.data.data;
      }

      throw new Error('Assessment generation failed');
    } catch (error) {
      console.error('Error generating compliance assessment:', error);
      throw error;
    }
  }

  // Generate compliance report
  async generateComplianceReport(tenantId: string, frameworkId: string, reportName: string): Promise<ComplianceReport> {
    try {
      const response = await apiService.post('/compliance/report', {
        tenantId,
        frameworkId, 
        reportName
      });

      if (response.data.success) {
        return response.data.data;
      }

      throw new Error('Report generation failed');
    } catch (error) {
      console.error('Error generating compliance report:', error);
      throw error;
    }
  }

  // Get existing assessments
  async getAssessments(tenantId: string): Promise<ComplianceAssessment[]> {
    try {
      const response = await apiService.get('/compliance/assessments', {
        params: { tenant_id: tenantId }
      });
      return response.data.data || [];
    } catch (error) {
      console.error('Error fetching assessments:', error);
      return [];
    }
  }

  // Get existing reports
  async getReports(tenantId: string): Promise<ComplianceReport[]> {
    try {
      const response = await apiService.get('/compliance/reports', {
        params: { tenant_id: tenantId }
      });
      return response.data.data || [];
    } catch (error) {
      console.error('Error fetching reports:', error);
      return [];
    }
  }

  // Submit evidence for a finding
  async submitEvidence(findingId: string, evidence: File[], description: string): Promise<boolean> {
    try {
      const formData = new FormData();
      formData.append('finding_id', findingId);
      formData.append('description', description);
      
      evidence.forEach((file, index) => {
        formData.append(`evidence_${index}`, file);
      });

      const response = await apiService.post('/compliance/evidence', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      return response.data.success;
    } catch (error) {
      console.error('Error submitting evidence:', error);
      return false;
    }
  }

  // Update finding status
  async updateFindingStatus(findingId: string, status: string, notes?: string): Promise<boolean> {
    try {
      const response = await apiService.put(`/compliance/findings/${findingId}`, {
        status,
        notes
      });
      return response.data.success;
    } catch (error) {
      console.error('Error updating finding status:', error);
      return false;
    }
  }

  // Schedule assessment
  async scheduleAssessment(tenantId: string, frameworkId: string, schedule: any): Promise<boolean> {
    try {
      const response = await apiService.post('/compliance/schedule', {
        tenantId,
        frameworkId,
        schedule
      });
      return response.data.success;
    } catch (error) {
      console.error('Error scheduling assessment:', error);
      return false;
    }
  }

  // New method to run assessment (for compatibility)
  async runAssessment(frameworkId: string): Promise<ComplianceAssessment> {
    try {
      const tenantId = localStorage.getItem('tenantId') || 'default';
      return await this.generateComplianceAssessment(tenantId, frameworkId);
    } catch (error) {
      console.error('Error running assessment:', error);
      throw error;
    }
  }
}

// Create singleton instance
const complianceService = new ComplianceService();

// Export both named and default exports
export { ComplianceService, complianceService };
export default complianceService; 

export type {
  NetworkResource,
  ComplianceFramework,
  ComplianceRequirement,
  ComplianceAssessment,
  ComplianceFinding,
  ComplianceRecommendation,
  ComplianceReport
}; 