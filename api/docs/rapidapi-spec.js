module.exports = {
  name: 'A2Z SOC API',
  description: 'Comprehensive Security Operations Center API for threat detection, analysis, and response',
  
  endpoints: [
    // InfoSec Audits Endpoints
    {
      name: 'Get All Compliance Frameworks',
      description: 'Retrieve a list of all compliance frameworks',
      method: 'GET',
      path: '/audits',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      response: {
        success: true,
        count: 4,
        data: [
          {
            id: 'iso27001',
            name: 'ISO 27001',
            description: 'Information Security Management System (ISMS) standard',
            status: 'Certified',
            lastAudit: '2023-10-15',
            nextAudit: '2024-10-15'
          },
          // Additional items would appear here
        ]
      }
    },
    {
      name: 'Get Compliance Framework by ID',
      description: 'Retrieve details for a specific compliance framework',
      method: 'GET',
      path: '/audits/{id}',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      pathParams: {
        id: {
          type: 'string',
          required: true,
          description: 'Framework ID (e.g., iso27001, soc2, gdpr, hipaa)'
        }
      },
      response: {
        success: true,
        data: {
          id: 'iso27001',
          name: 'ISO 27001',
          description: 'Information Security Management System (ISMS) standard...',
          status: 'Certified',
          lastAudit: '2023-10-15',
          nextAudit: '2024-10-15',
          controls: [
            // Array of controls
          ],
          certificationDocument: "https://example.com/certs/iso27001.pdf",
          certificationAuthority: "Bureau Veritas",
          certificationNumber: "ISMS-12345-2023"
        }
      }
    },
    {
      name: 'Get Compliance Summary',
      description: 'Retrieve summary statistics for compliance',
      method: 'GET',
      path: '/audits/summary',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      response: {
        success: true,
        data: {
          totalControls: 24,
          compliantControls: 20,
          minorFindingControls: 4,
          majorFindingControls: 0,
          complianceRate: '83.33',
          frameworksCount: 4,
          nextAuditDate: '2024-09-05'
        }
      }
    },
    
    // AI Insights Endpoints
    {
      name: 'Get AI Insights Overview',
      description: 'Retrieve overview dashboard data for AI insights',
      method: 'GET',
      path: '/ai-insights/overview',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      response: {
        success: true,
        data: {
          insights: {
            total: 4,
            critical: 1,
            high: 1,
            warning: 1,
            info: 1,
            latest: {
              // Latest insight details
            }
          },
          recommendations: {
            total: 8,
            implemented: 3,
            implementationRate: '37.50',
            pending: 5
          },
          coverageSummary: {
            average: '72.50',
            benchmark: '75.58',
            delta: '-3.08',
            lowestCoverage: {
              technique: 'Defense Evasion',
              coverage: 58,
              benchmarkCoverage: 72
            }
          },
          modelStatus: [
            // Model status information
          ],
          logProcessing: [
            // Log processing status
          ]
        }
      }
    },
    {
      name: 'Get AI Insights',
      description: 'Retrieve all AI-generated insights with optional filtering',
      method: 'GET',
      path: '/ai-insights/insights',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      query: {
        severity: {
          type: 'string',
          required: false,
          description: 'Filter by severity (critical, high, warning, info)',
          default: 'all'
        },
        source: {
          type: 'string',
          required: false,
          description: 'Filter by AI model source (GPT-4, Claude, Gemini, Security Copilot)',
          default: 'all'
        }
      },
      response: {
        success: true,
        count: 4,
        data: [
          // Array of insights
        ]
      }
    },
    {
      name: 'Get AI Recommendations',
      description: 'Retrieve all AI-generated security recommendations with optional filtering',
      method: 'GET',
      path: '/ai-insights/recommendations',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      query: {
        category: {
          type: 'string',
          required: false,
          description: 'Filter by category (Detection, Prevention, Response, Configuration, Monitoring)',
          default: 'all'
        },
        priority: {
          type: 'string',
          required: false,
          description: 'Filter by priority (high, medium, low)',
          default: 'all'
        },
        implemented: {
          type: 'boolean',
          required: false,
          description: 'Filter by implementation status',
          default: null
        },
        source: {
          type: 'string',
          required: false,
          description: 'Filter by AI model source',
          default: 'all'
        }
      },
      response: {
        success: true,
        count: 8,
        data: [
          // Array of recommendations
        ]
      }
    },
    {
      name: 'Get MITRE ATT&CK Coverage',
      description: 'Retrieve security coverage data mapped to MITRE ATT&CK framework',
      method: 'GET',
      path: '/ai-insights/coverage',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      response: {
        success: true,
        count: 12,
        data: [
          // Array of coverage data
        ]
      }
    },
    {
      name: 'Get Analytics Trends',
      description: 'Retrieve time-series data for security analytics',
      method: 'GET',
      path: '/ai-insights/trends',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      query: {
        startDate: {
          type: 'string',
          required: false,
          description: 'Start date for trends (YYYY-MM-DD)',
          default: '14 days ago'
        },
        endDate: {
          type: 'string',
          required: false,
          description: 'End date for trends (YYYY-MM-DD)',
          default: 'today'
        }
      },
      response: {
        success: true,
        count: 14,
        data: [
          // Array of trend data
        ]
      }
    },
    
    // Google Threat Intelligence Endpoints
    {
      name: 'Check VirusTotal API Health',
      description: 'Check the health status of the VirusTotal API connection',
      method: 'GET',
      path: '/threat-intelligence/virustotal/health',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      response: {
        success: true,
        status: 'healthy',
        timestamp: '2024-03-16T12:30:00Z'
      }
    },
    {
      name: 'Search VirusTotal',
      description: 'Search for indicators in VirusTotal (IP, domain, file hash, URL)',
      method: 'GET',
      path: '/threat-intelligence/virustotal/search',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      query: {
        query: {
          type: 'string',
          required: true,
          description: 'The search query (IP, domain, file hash, URL)'
        },
        type: {
          type: 'string',
          required: false,
          description: 'Type of the query (ip, domain, file, url, general)',
          default: 'general'
        }
      },
      response: {
        success: true,
        data: {
          // VirusTotal response data
        },
        query: 'example.com',
        type: 'domain',
        timestamp: '2024-03-16T12:30:00Z'
      }
    },
    {
      name: 'Get File Report from VirusTotal',
      description: 'Get a file analysis report from VirusTotal',
      method: 'GET',
      path: '/threat-intelligence/virustotal/file/{hash}',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      pathParams: {
        hash: {
          type: 'string',
          required: true,
          description: 'The hash of the file (MD5, SHA-1, SHA-256)'
        }
      },
      response: {
        success: true,
        data: {
          // VirusTotal file report data
        },
        hash: '44d88612fea8a8f36de82e1278abb02f',
        timestamp: '2024-03-16T12:30:00Z'
      }
    },
    {
      name: 'Get URL Report from VirusTotal',
      description: 'Get a URL analysis report from VirusTotal',
      method: 'GET',
      path: '/threat-intelligence/virustotal/url',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      query: {
        url: {
          type: 'string',
          required: true,
          description: 'The URL to analyze'
        }
      },
      response: {
        success: true,
        data: {
          // VirusTotal URL report data
        },
        url: 'https://example.com',
        timestamp: '2024-03-16T12:30:00Z'
      }
    },
    {
      name: 'Get IP Report from VirusTotal',
      description: 'Get an IP address analysis report from VirusTotal',
      method: 'GET',
      path: '/threat-intelligence/virustotal/ip/{ip}',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      pathParams: {
        ip: {
          type: 'string',
          required: true,
          description: 'The IP address to analyze'
        }
      },
      response: {
        success: true,
        data: {
          // VirusTotal IP report data
        },
        ip: '8.8.8.8',
        timestamp: '2024-03-16T12:30:00Z'
      }
    },
    {
      name: 'Get Domain Report from VirusTotal',
      description: 'Get a domain analysis report from VirusTotal',
      method: 'GET',
      path: '/threat-intelligence/virustotal/domain/{domain}',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      pathParams: {
        domain: {
          type: 'string',
          required: true,
          description: 'The domain to analyze'
        }
      },
      response: {
        success: true,
        data: {
          // VirusTotal domain report data
        },
        domain: 'example.com',
        timestamp: '2024-03-16T12:30:00Z'
      }
    },
    {
      name: 'Get Google Security Command Center Alerts',
      description: 'Get security alerts from Google Security Command Center',
      method: 'GET',
      path: '/threat-intelligence/google-scc/alerts',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      response: {
        success: true,
        count: 3,
        data: [
          // Array of Google Security Command Center alerts
        ]
      }
    },
    {
      name: 'Get Mandiant Threat Intelligence',
      description: 'Get threat intelligence data from Mandiant',
      method: 'GET',
      path: '/threat-intelligence/mandiant',
      headers: {
        'x-api-key': {
          type: 'string',
          required: true,
          description: 'Your API key'
        }
      },
      response: {
        success: true,
        data: {
          activeThreats: [
            // Array of active threats
          ],
          recentCampaigns: [
            // Array of recent campaigns
          ]
        }
      }
    }
  ],
  
  pricing: {
    basic: {
      price: 'Free',
      rateLimit: '100 requests per 15 minutes',
      features: ['Read-only access to AI insights summary', 'Basic compliance framework listings', 'Limited historical data (14 days)', 'Basic VirusTotal search (10 requests per day)']
    },
    professional: {
      price: '$99/month',
      rateLimit: '1,000 requests per 15 minutes',
      features: ['Full read access to all endpoints', 'Detailed AI insights and recommendations', 'Historical data up to 30 days', 'Filter and search capabilities', 'Full VirusTotal API access (100 requests per day)']
    },
    enterprise: {
      price: '$499/month',
      rateLimit: '5,000 requests per 15 minutes',
      features: ['Full read access with premium rate limits', 'Advanced AI-powered security insights', 'Historical data up to 1 year', 'Priority support', 'Unlimited VirusTotal API access', 'Full Google Security Command Center integration', 'Access to Mandiant threat intelligence']
    }
  }
}; 