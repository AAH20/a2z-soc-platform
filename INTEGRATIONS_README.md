# Security Integrations - A2Z SOC Platform

This document provides comprehensive information about the security tool integrations implemented in the A2Z SOC platform.

## Overview

The A2Z SOC platform integrates with the following security tools and platforms:

- **Wazuh** - Open-source security monitoring and SIEM
- **Elasticsearch** - Search and analytics engine for security data
- **OpenSearch** - Open-source search and analytics suite
- **Snort** - Network intrusion detection system (IDS)
- **Suricata** - Network IDS/IPS and security monitoring

## 🛡️ Wazuh Integration

### Features
- **Agent Management**: Monitor and manage Wazuh agents across your infrastructure
- **Real-time Alerts**: Receive and analyze security alerts from Wazuh manager
- **Rule Management**: View and manage detection rules and decoders
- **Compliance Monitoring**: Track compliance with various security standards
- **Vulnerability Detection**: Monitor system vulnerabilities across agents
- **File Integrity Monitoring**: Track file changes and modifications
- **Security Analytics**: Advanced security event analysis and reporting

### API Endpoints
```
GET    /api/integrations/wazuh/health
GET    /api/integrations/wazuh/manager/info
GET    /api/integrations/wazuh/agents
GET    /api/integrations/wazuh/alerts
GET    /api/integrations/wazuh/rules
GET    /api/integrations/wazuh/overview
```

### Configuration
```env
WAZUH_API_URL=https://localhost:55000
WAZUH_USERNAME=wazuh-wui
WAZUH_PASSWORD=wazuh-wui
```

## 🔍 Elasticsearch Integration

### Features
- **Cluster Management**: Monitor Elasticsearch cluster health and performance
- **Index Operations**: Create, manage, and query security indices
- **Advanced Search**: Powerful search capabilities across security data
- **Alert Analytics**: Statistical analysis of security alerts and events
- **Log Management**: Centralized logging and log analysis
- **Performance Monitoring**: Track cluster performance and resource usage

### API Endpoints
```
GET    /api/integrations/elasticsearch/health
GET    /api/integrations/elasticsearch/cluster/status
GET    /api/integrations/elasticsearch/indices
POST   /api/integrations/elasticsearch/search
GET    /api/integrations/elasticsearch/security/events
```

### Configuration
```env
ELASTICSEARCH_URL=https://localhost:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=changeme
```

## 🔎 OpenSearch Integration

### Features
- **Security Plugin**: Advanced security features and user management
- **Anomaly Detection**: ML-based anomaly detection for security events
- **Index State Management**: Automated index lifecycle management
- **Dashboards Integration**: Integration with OpenSearch Dashboards
- **Performance Analytics**: Built-in performance monitoring
- **Multi-tenancy**: Support for tenant isolation and security

### API Endpoints
```
GET    /api/integrations/opensearch/health
GET    /api/integrations/opensearch/security/config
GET    /api/integrations/opensearch/anomaly/detectors
GET    /api/integrations/opensearch/dashboards/info
POST   /api/integrations/opensearch/search
```

### Configuration
```env
OPENSEARCH_URL=https://localhost:9200
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=admin
OPENSEARCH_DASHBOARDS_URL=http://localhost:5601
```

## 🚨 Snort Integration

### Features
- **Service Management**: Start, stop, and restart Snort IDS
- **Rule Management**: Manage and update Snort detection rules
- **Alert Processing**: Real-time processing of Snort alerts
- **Performance Monitoring**: Track Snort performance and packet processing
- **Configuration Validation**: Validate Snort configuration files
- **Rule Categories**: Organize rules by threat categories

### API Endpoints
```
GET    /api/integrations/snort/health
GET    /api/integrations/snort/status
POST   /api/integrations/snort/start
POST   /api/integrations/snort/stop
GET    /api/integrations/snort/rules
GET    /api/integrations/snort/alerts
```

### Configuration
```env
SNORT_PATH=/usr/local/bin/snort
SNORT_CONFIG_PATH=/etc/snort/snort.conf
SNORT_RULES_PATH=/etc/snort/rules
SNORT_LOG_PATH=/var/log/snort
```

## ⚡ Suricata Integration

### Features
- **IDS/IPS Mode**: Support for both intrusion detection and prevention
- **Eve JSON Output**: Structured JSON logging for advanced analytics
- **Rule Management**: Advanced rule management with multiple sources
- **Flow Analysis**: Network flow monitoring and analysis
- **Protocol Detection**: HTTP, DNS, TLS, and file extraction
- **Performance Monitoring**: Real-time performance metrics

### API Endpoints
```
GET    /api/integrations/suricata/health
GET    /api/integrations/suricata/status
POST   /api/integrations/suricata/start
GET    /api/integrations/suricata/alerts
GET    /api/integrations/suricata/flows
GET    /api/integrations/suricata/http
GET    /api/integrations/suricata/dns
```

### Configuration
```env
SURICATA_PATH=/usr/bin/suricata
SURICATA_CONFIG_PATH=/etc/suricata/suricata.yaml
SURICATA_RULES_PATH=/var/lib/suricata/rules
SURICATA_LOG_PATH=/var/log/suricata
```

## 🏗️ Architecture

### Service Layer
Each integration follows a consistent service architecture:

```javascript
class SecurityService {
  constructor() {
    // Service initialization
  }
  
  async testConnection() {
    // Health check implementation
  }
  
  async getServiceHealth() {
    // Service health monitoring
  }
  
  // Service-specific methods...
}
```

### API Layer
All integrations expose RESTful APIs with consistent patterns:

- **Health Checks**: `/health` endpoints for service monitoring
- **CRUD Operations**: Standard create, read, update, delete operations
- **Real-time Data**: Live data streaming where applicable
- **Error Handling**: Consistent error responses and logging

### Data Flow
```
Frontend → API Routes → Service Layer → External Tools → Database/Cache
```

## 🚀 Getting Started

### Prerequisites
1. Node.js 18+ and npm/yarn
2. PostgreSQL database
3. Redis for caching
4. Target security tools installed and configured

### Installation
1. Install dependencies:
```bash
cd api
npm install
```

2. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Start the API server:
```bash
npm run dev
```

### Testing Integrations
Use the health check endpoints to verify connectivity:

```bash
# Test all integrations
curl http://localhost:3001/api/integrations/status/all

# Test specific integration
curl http://localhost:3001/api/integrations/wazuh/health
```

## 📊 Monitoring and Observability

### Health Checks
All integrations provide health check endpoints that return:
```json
{
  "status": "connected|error",
  "version": "tool-version",
  "timestamp": "2024-01-15T10:30:00Z",
  "message": "Status description"
}
```

### Performance Metrics
Performance data is collected for:
- API response times
- Service connectivity status
- Data processing rates
- Error rates and patterns

### Logging
Structured logging includes:
- Integration connection status
- API request/response logs
- Error tracking and debugging
- Security event processing logs

## 🔒 Security Considerations

### Authentication
- JWT-based authentication for API access
- Service-specific authentication for integrations
- Token refresh mechanisms

### Authorization
- Role-based access control (RBAC)
- Tenant isolation for multi-tenancy
- API rate limiting and throttling

### Data Protection
- Encryption in transit (TLS/SSL)
- Sensitive data masking in logs
- Secure credential management

## 🔧 Troubleshooting

### Common Issues

1. **Connection Timeouts**
   - Check network connectivity
   - Verify service endpoints
   - Review firewall configurations

2. **Authentication Failures**
   - Validate credentials in environment variables
   - Check service-specific authentication requirements
   - Verify certificate configurations

3. **Service Unavailable**
   - Confirm target services are running
   - Check service health endpoints
   - Review service logs

### Debug Mode
Enable debug logging:
```env
LOG_LEVEL=debug
```

### Health Dashboard
Monitor all integrations from:
```
http://localhost:3000/integrations/status
```

## 📈 Performance Optimization

### Caching Strategy
- Redis caching for frequently accessed data
- Response caching with TTL
- Connection pooling for database operations

### Rate Limiting
- API rate limiting per tenant
- Service-specific rate limits
- Graceful degradation under load

### Scaling Considerations
- Horizontal scaling support
- Load balancing between API instances
- Database connection pooling

## 🤝 Contributing

### Adding New Integrations

1. Create service class in `api/services/`
2. Implement standard methods (testConnection, getServiceHealth)
3. Add API routes in `api/routes/integrations.js`
4. Update environment configuration
5. Add documentation and tests

### Code Standards
- Follow existing service patterns
- Implement comprehensive error handling
- Add input validation and sanitization
- Include unit and integration tests

## 📚 Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Elasticsearch Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [OpenSearch Documentation](https://opensearch.org/docs/)
- [Snort User Manual](https://snort.org/documents)
- [Suricata Documentation](https://suricata.readthedocs.io/)

## 📞 Support

For integration support:
- Check the troubleshooting section
- Review service logs
- Submit issues with detailed error information
- Contact the A2Z SOC development team

---

*Last updated: January 2024* 