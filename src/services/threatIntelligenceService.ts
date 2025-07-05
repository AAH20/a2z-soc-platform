import axios from 'axios';

const API_BASE_URL = 'http://localhost:3001/api/v1';
const API_KEY = 'fe137543d8e99aa75ab1d3b8812bc2042ddf53caa80934f687a9c98e93d176b0';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
    'x-api-key': API_KEY
  }
});

export interface VirusTotalResponse {
  success: boolean;
  data: any;
  timestamp: string;
}

export const threatIntelligenceService = {
  // Check VirusTotal API health
  checkVirusTotalHealth: async (): Promise<VirusTotalResponse> => {
    const response = await apiClient.get('/threat-intelligence/virustotal/health');
    return response.data;
  },

  // Search for an indicator in VirusTotal
  searchVirusTotal: async (query: string, type?: string): Promise<VirusTotalResponse> => {
    const response = await apiClient.get('/threat-intelligence/virustotal/search', {
      params: { query, type }
    });
    return response.data;
  },

  // Get a file report from VirusTotal
  getFileReport: async (hash: string): Promise<VirusTotalResponse> => {
    const response = await apiClient.get(`/threat-intelligence/virustotal/file/${hash}`);
    return response.data;
  },

  // Get a URL report from VirusTotal
  getUrlReport: async (url: string): Promise<VirusTotalResponse> => {
    const response = await apiClient.get('/threat-intelligence/virustotal/url', {
      params: { url }
    });
    return response.data;
  },

  // Get an IP report from VirusTotal
  getIpReport: async (ip: string): Promise<VirusTotalResponse> => {
    const response = await apiClient.get(`/threat-intelligence/virustotal/ip/${ip}`);
    return response.data;
  },

  // Get a domain report from VirusTotal
  getDomainReport: async (domain: string): Promise<VirusTotalResponse> => {
    const response = await apiClient.get(`/threat-intelligence/virustotal/domain/${domain}`);
    return response.data;
  },

  // Get upload URL for large files (>32MB, up to 650MB)
  getLargeFileUploadUrl: async (): Promise<VirusTotalResponse> => {
    const response = await apiClient.get('/threat-intelligence/virustotal/file/upload-url');
    return response.data;
  },

  // Upload file to a specific URL (for large files)
  uploadFileToUrl: async (file: File, uploadUrl: string): Promise<VirusTotalResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await axios.post(uploadUrl, formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
    
    return {
      success: true,
      data: response.data,
      timestamp: new Date().toISOString()
    };
  },

  // Upload a file to VirusTotal (standard method for files <= 32MB)
  uploadFile: async (file: File): Promise<VirusTotalResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await apiClient.post('/threat-intelligence/virustotal/file/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
    
    return response.data;
  },

  // Get Google Security Command Center alerts
  getSecurityCommandCenterAlerts: async () => {
    const response = await apiClient.get('/threat-intelligence/google-scc/alerts');
    return response.data;
  },

  // Get Mandiant threat intelligence
  getMandiantIntelligence: async () => {
    const response = await apiClient.get('/threat-intelligence/mandiant');
    return response.data;
  }
};

export default threatIntelligenceService; 