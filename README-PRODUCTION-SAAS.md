# A2Z SOC SaaS Platform - Production Deployment Guide

## 🚀 Production-Ready SaaS Platform with Fixed Components

This guide covers the deployment and management of the A2Z SOC platform as a production-ready SaaS solution with fully functional IDS/IPS and Network Monitoring components.

### ✅ What's Fixed and Ready

- **🔧 IDS/IPS Core Engine (Rust)**: Fully functional with real packet capture, threat detection, and macOS compatibility
- **🌐 Network Monitoring Agent (Node.js)**: Complete with system integration, log collection, and cross-platform support
- **🏗️ Production Docker Configuration**: Multi-service architecture with Traefik, monitoring, and scaling
- **🔐 Enterprise Security**: Multi-tenancy, encryption, audit logging, and compliance features
- **📊 Comprehensive Monitoring**: Prometheus, Grafana, Jaeger for full observability
- **⚡ Auto-scaling & Load Balancing**: Production-ready infrastructure with health checks

---

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Quick Start](#quick-start)
3. [Production Configuration](#production-configuration)
4. [Security Setup](#security-setup)
5. [Monitoring & Observability](#monitoring--observability)
6. [Scaling & Performance](#scaling--performance)
7. [Backup & Recovery](#backup--recovery)
8. [Troubleshooting](#troubleshooting)
9. [API Documentation](#api-documentation)
10. [Maintenance](#maintenance)

---

## 🖥️ System Requirements

### Minimum Requirements (Small Deployment)
- **CPU**: 4 cores (8 threads)
- **Memory**: 8GB RAM
- **Storage**: 100GB SSD
- **Network**: 1Gbps connection
- **OS**: Ubuntu 20.04+, CentOS 8+, or RHEL 8+

### Recommended Requirements (Production)
- **CPU**: 8+ cores (16+ threads)
- **Memory**: 16-32GB RAM
- **Storage**: 500GB+ NVMe SSD
- **Network**: 10Gbps connection
- **OS**: Ubuntu 22.04 LTS (preferred)

### Enterprise Requirements (High Scale)
- **CPU**: 16+ cores (32+ threads)
- **Memory**: 64-128GB RAM
- **Storage**: 1TB+ NVMe SSD with RAID
- **Network**: Multiple 10Gbps+ connections
- **Load Balancer**: External (F5, HAProxy, etc.)

---

## 🚀 Quick Start

### 1. Clone and Prepare
```bash
git clone <repository-url>
cd a2z-soc-main

# Copy production environment template
cp .env.production .env.production.local
```

### 2. Configure Environment
```bash
# Edit production configuration
nano .env.production.local

# CRITICAL: Change these default values
POSTGRES_PASSWORD=your_secure_postgres_password
REDIS_PASSWORD=your_secure_redis_password
JWT_SECRET=your_jwt_secret_key_64_chars_minimum
API_KEY_SECRET=your_api_key_secret
ENCRYPTION_KEY=your_32_character_encryption_key
```

### 3. Deploy Platform
```bash
# Make deployment script executable
chmod +x deploy-production.sh

# Run production deployment
./deploy-production.sh
```

### 4. Verify Deployment
```bash
# Check all services are healthy
./deploy-production.sh --health

# View logs
docker-compose -f docker-compose.unified.yml logs -f
```

---

## ⚙️ Production Configuration

### Environment Variables

#### Core Security
```bash
# Database passwords (REQUIRED)
POSTGRES_PASSWORD=your_secure_password_here
REDIS_PASSWORD=your_secure_password_here
CLICKHOUSE_PASSWORD=your_secure_password_here
ELASTIC_PASSWORD=your_secure_password_here

# Application secrets (REQUIRED)
JWT_SECRET=your_jwt_secret_minimum_64_characters_for_security
API_KEY_SECRET=your_api_key_secret_32_characters_minimum
ENCRYPTION_KEY=your_32_character_encryption_key_exactly
SESSION_SECRET=your_session_secret_for_additional_security
```

#### Multi-Tenancy Settings
```bash
MULTI_TENANT_MODE=true
TENANT_ISOLATION=strict
DEFAULT_TENANT_TIER=enterprise
MAX_TENANTS_PER_INSTANCE=100
TENANT_DATABASE_ISOLATION=true
TENANT_DATA_ENCRYPTION=true
```

#### Performance Tuning
```bash
MAX_CONCURRENT_REQUESTS=10000
RATE_LIMIT_REQUESTS_PER_MINUTE=1000
NODE_OPTIONS=--max-old-space-size=4096
UV_THREADPOOL_SIZE=16
GOMAXPROCS=8
```

### Domain Configuration

Set up your domains in `.env.production.local`:
```bash
DOMAIN_NAME=yourdomain.com
FRONTEND_URL=https://app.yourdomain.com
API_URL=https://api.yourdomain.com
AGENT_URL=https://agent.yourdomain.com
IDS_URL=https://ids.yourdomain.com
DASHBOARD_URL=https://dashboard.yourdomain.com
```

### SSL/TLS Configuration

Automatic SSL certificates via Let's Encrypt:
```bash
LETSENCRYPT_EMAIL=admin@yourdomain.com
ENABLE_HTTPS=true
FORCE_HTTPS=true
```

---

## 🔐 Security Setup

### 1. Firewall Configuration
```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow SSH (adjust port as needed)
sudo ufw allow 22/tcp

# Block all other incoming
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
```

### 2. Docker Security
```bash
# Add current user to docker group
sudo usermod -aG docker $USER

# Configure Docker daemon security
sudo tee /etc/docker/daemon.json << EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  },
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true
}
EOF

sudo systemctl restart docker
```

### 3. Secret Management
```bash
# Use Docker secrets for sensitive data
echo "your_postgres_password" | docker secret create postgres_password -
echo "your_jwt_secret" | docker secret create jwt_secret -
```

### 4. Network Security
- Enable VPC/private networking
- Use security groups/firewalls
- Implement network segmentation
- Regular security scans

---

## 📊 Monitoring & Observability

### Access Monitoring Dashboards

| Service | URL | Purpose |
|---------|-----|---------|
| Grafana | `https://dashboard.yourdomain.com` | Main monitoring dashboard |
| Prometheus | `https://metrics.yourdomain.com` | Metrics collection |
| Jaeger | `https://tracing.yourdomain.com` | Distributed tracing |
| Traefik | `https://traefik.yourdomain.com` | Load balancer dashboard |

### Key Metrics to Monitor

#### Application Metrics
- Request rates and response times
- Error rates and success ratios
- Database connection pools
- Memory and CPU usage
- Disk I/O and network traffic

#### Security Metrics
- Authentication failures
- Suspicious network activity
- Threat detection events
- IDS/IPS alerts
- Failed login attempts

#### Business Metrics
- Active users and tenants
- API usage per tenant
- Feature utilization
- Revenue metrics
- SLA compliance

### Alerting Setup

Configure alerts in Grafana for:
- High CPU/Memory usage (>80%)
- High error rates (>5%)
- Database connection issues
- Disk space (>85% used)
- Security incidents
- Service downtime

---

## ⚡ Scaling & Performance

### Horizontal Scaling

#### Database Scaling
```bash
# PostgreSQL read replicas
docker-compose -f docker-compose.scaled.yml up -d postgres-replica

# Redis clustering
docker-compose -f docker-compose.scaled.yml up -d redis-cluster
```

#### Application Scaling
```bash
# Scale platform instances
docker-compose -f docker-compose.unified.yml up -d --scale a2z-soc-platform=3
```

### Vertical Scaling

Update resource limits in `docker-compose.unified.yml`:
```yaml
services:
  a2z-soc-platform:
    deploy:
      resources:
        limits:
          cpus: '8.0'
          memory: 16G
        reservations:
          cpus: '4.0'
          memory: 8G
```

### Performance Optimization

#### Database Optimization
```sql
-- PostgreSQL tuning
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET effective_cache_size = '8GB';
ALTER SYSTEM SET work_mem = '64MB';
ALTER SYSTEM SET maintenance_work_mem = '512MB';
SELECT pg_reload_conf();
```

#### Application Optimization
- Enable connection pooling
- Use Redis caching effectively
- Optimize database queries
- Implement CDN for static assets
- Enable gzip compression

---

## 💾 Backup & Recovery

### Automated Backups

Backups are automatically configured and run daily at 2 AM:

```bash
# Manual backup
./deploy-production.sh --backup

# Restore from backup
./scripts/restore.sh backup_date_20240101_020000
```

### Backup Components

1. **Database Backups**
   - PostgreSQL: SQL dumps
   - Redis: RDB snapshots
   - ClickHouse: Native backups
   - Elasticsearch: Snapshots

2. **Application Data**
   - Configuration files
   - Uploaded files
   - Log files
   - IDS/IPS rules and models

3. **System Configuration**
   - Docker configurations
   - Environment settings
   - SSL certificates

### Disaster Recovery

#### RTO (Recovery Time Objective): 4 hours
#### RPO (Recovery Point Objective): 1 hour

```bash
# Emergency restore procedure
./scripts/emergency-restore.sh

# Restore specific service
./scripts/restore-service.sh database
./scripts/restore-service.sh application
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Service Won't Start
```bash
# Check service logs
docker-compose -f docker-compose.unified.yml logs service_name

# Check system resources
docker stats
df -h
free -h
```

#### 2. Database Connection Issues
```bash
# Check database health
docker-compose -f docker-compose.unified.yml exec postgres pg_isready

# Reset database connection
docker-compose -f docker-compose.unified.yml restart postgres
```

#### 3. High Memory Usage
```bash
# Check memory usage by service
docker stats --format "table {{.Container}}\t{{.MemUsage}}\t{{.MemPerc}}"

# Restart memory-heavy services
docker-compose -f docker-compose.unified.yml restart service_name
```

#### 4. SSL Certificate Issues
```bash
# Check Traefik logs
docker logs a2z-soc-traefik

# Force certificate renewal
docker-compose -f docker-compose.unified.yml restart traefik
```

### Debug Commands

```bash
# Service health checks
./deploy-production.sh --health

# View all logs
docker-compose -f docker-compose.unified.yml logs -f

# Container resource usage
docker stats

# Network connectivity
docker network ls
docker network inspect a2z-internal

# Volume usage
docker volume ls
docker system df
```

### Log Locations

- **Application Logs**: `/opt/a2z-soc/logs/`
- **Database Logs**: Docker container logs
- **System Logs**: `/var/log/`
- **Deployment Logs**: `/opt/a2z-soc/deployment.log`

---

## 📚 API Documentation

### Core APIs

#### Authentication API
```bash
# Login
curl -X POST https://api.yourdomain.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# Get user profile
curl -X GET https://api.yourdomain.com/auth/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Network Agent API
```bash
# Get agent status
curl -X GET https://agent.yourdomain.com/api/status

# Get network statistics
curl -X GET https://agent.yourdomain.com/api/network/stats

# Get security events
curl -X GET https://agent.yourdomain.com/api/security/events
```

#### IDS/IPS Management API
```bash
# Get IDS status
curl -X GET https://ids.yourdomain.com/api/status

# Get threat alerts
curl -X GET https://ids.yourdomain.com/api/alerts

# Update rules
curl -X POST https://ids.yourdomain.com/api/rules \
  -H "Content-Type: application/json" \
  -d '{"rule": "alert tcp any any -> any any"}'
```

### WebSocket APIs

#### Real-time Events
```javascript
const ws = new WebSocket('wss://api.yourdomain.com/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Real-time event:', data);
};
```

### Rate Limiting

All APIs are rate-limited:
- **Free Tier**: 100 requests/minute
- **Pro Tier**: 1,000 requests/minute
- **Enterprise Tier**: 10,000 requests/minute

---

## 🔄 Maintenance

### Regular Maintenance Tasks

#### Daily
- Monitor system health
- Check backup completion
- Review security alerts
- Verify SSL certificate status

#### Weekly
- Update threat intelligence feeds
- Review performance metrics
- Check disk space usage
- Update IDS/IPS rules

#### Monthly
- Security patching
- Database maintenance
- Performance tuning
- Capacity planning review

### Update Procedures

#### Platform Updates
```bash
# Update to latest version
./deploy-production.sh --update

# Rollback if needed
./scripts/rollback.sh previous_version
```

#### Security Updates
```bash
# Update base images
docker-compose -f docker-compose.unified.yml pull

# Apply security patches
./scripts/security-update.sh
```

### Maintenance Windows

Schedule regular maintenance windows:
- **Duration**: 2-4 hours
- **Frequency**: Monthly
- **Time**: During lowest traffic periods
- **Notification**: 48-hour advance notice

---

## 📈 SaaS Features

### Multi-Tenancy

The platform supports strict tenant isolation:
- **Database Isolation**: Separate schemas per tenant
- **Data Encryption**: Tenant-specific encryption keys
- **Resource Limits**: Configurable per tenant tier
- **Feature Flags**: Granular feature control

### Billing Integration

Built-in billing with Stripe:
```bash
# Configure billing
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

### Compliance

- **SOC 2 Type II** compliance ready
- **GDPR** compliant data handling
- **HIPAA** ready for healthcare
- **Audit logging** for all actions

### Analytics

Built-in analytics dashboard:
- User engagement metrics
- Feature usage statistics
- Performance analytics
- Security incident reports

---

## 🆘 Support & Contact

### Documentation
- **API Docs**: https://docs.yourdomain.com
- **User Guide**: https://help.yourdomain.com
- **Videos**: https://training.yourdomain.com

### Support Channels
- **Email**: support@yourdomain.com
- **Slack**: [Support Channel]
- **Emergency**: +1-xxx-xxx-xxxx

### Community
- **GitHub**: [Issues & Discussions]
- **Discord**: [Community Server]
- **Forum**: [Community Forum]

---

## 📄 License & Legal

- **License**: Enterprise License
- **Privacy Policy**: https://yourdomain.com/privacy
- **Terms of Service**: https://yourdomain.com/terms
- **Security Policy**: https://yourdomain.com/security

---

## 🎯 Next Steps

After successful deployment:

1. **Configure DNS** for your domains
2. **Set up monitoring alerts**
3. **Configure backup destinations**
4. **Implement CI/CD pipelines**
5. **Set up staging environment**
6. **Configure external integrations**
7. **Train your team**
8. **Plan scaling strategy**

---

**🎉 Congratulations! Your A2Z SOC SaaS platform is now production-ready with fully functional IDS/IPS and Network Monitoring components!** 