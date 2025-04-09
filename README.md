
# A2Z SOC - Security Operations Center Platform

## Project Overview

A2Z SOC is a comprehensive Security Operations Center (SOC) platform designed to integrate multiple security tools and data sources into a unified dashboard for enhanced threat detection, analysis, and response capabilities.

## Key Features

- **Centralized Dashboard**: Monitor all security systems and alerts from a single interface
- **Multiple Security Integrations**:
  - **Wazuh**: Security monitoring and threat detection
  - **Snort & Suricata**: Network intrusion detection systems
  - **Elasticsearch & Opensearch**: Powerful search and analytics engines for security data
  - **Multiple Threat Intelligence Sources**: Google, Microsoft, AWS
- **Customizable Alerts**: Configure and prioritize alerts based on severity and source
- **Real-time Monitoring**: Track security events as they happen across your infrastructure
- **Compliance Reporting**: Generate reports for security compliance requirements
- **Agent Management**: Monitor and manage security agents deployed across your environment

## Technologies Used

- **Frontend**: React, TypeScript, Vite
- **UI Components**: shadcn-ui, Tailwind CSS
- **State Management**: React Context API
- **Data Fetching**: TanStack Query (React Query)
- **Visualization**: Recharts
- **Icons**: Lucide React

## Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm (v7 or higher)

### Installation

```bash
# Clone the repository
git clone <YOUR_GIT_URL>

# Navigate to the project directory
cd a2z-soc

# Install dependencies
npm install

# Start the development server
npm run dev
```

## System Integrations

### Wazuh Integration

The platform integrates with Wazuh for comprehensive security monitoring, including:
- Real-time security event monitoring with Wazuh agents
- Correlation between simulated attacks and detected events
- Validation of detection rules and policies
- Enhanced visibility across your security infrastructure

### Elasticsearch Integration

Elasticsearch provides powerful search and analytics capabilities:
- Centralized log management and analysis
- Fast full-text search across security data
- Advanced data visualization through Kibana
- Anomaly detection and machine learning capabilities

### Opensearch Integration

Opensearch offers an alternative search and analytics engine:
- Community-driven, open-source search and analytics suite
- Compatible with Elasticsearch APIs
- Enhanced security features and access controls
- Customizable dashboards for security monitoring

### Threat Intelligence

Multiple threat intelligence sources are integrated:
- **Google Threat Intelligence**: VirusTotal and Google Chronicle
- **Microsoft Threat Intelligence**: Azure Sentinel and Microsoft Defender
- **AWS Threat Intelligence**: Amazon GuardDuty and AWS Security Hub

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Project URL

**URL**: https://lovable.dev/projects/4c3bb595-6a1b-4f2f-874b-8124bcdd1c19

For more information on how to edit and deploy this project, see the original README instructions.
