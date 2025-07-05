# 🚀 A2Z SOC Unified Platform

**Complete Security Operations Center in a Single Container**

The A2Z SOC Unified Platform consolidates all security monitoring, threat detection, and network analysis capabilities into a single, easy-to-deploy container. This unified approach simplifies deployment, reduces resource overhead, and provides seamless integration between all platform components.

## 🏗️ **Architecture Overview**

### **Unified Container Components**
```
┌─────────────────────────────────────────────────────────────┐
│                A2Z SOC Unified Container                    │
├─────────────────────────────────────────────────────────────┤
│ 🌐 Nginx Web Server (Port 80)                              │
│   ├── React Frontend Dashboard                             │
│   ├── IDS/IPS Web Interface (/ids/)                       │
│   └── API Routing & Load Balancing                        │
├─────────────────────────────────────────────────────────────┤
│ 🔌 Core APIs                                               │
│   ├── Main API Server (Port 3001)                         │
│   ├── IDS/IPS Management API (Port 8080)                  │
│   └── Network Agent API (Port 3002)                       │
├─────────────────────────────────────────────────────────────┤
│ 🛡️ Security Services                                       │
│   ├── IDS/IPS Core Engine (Rust)                          │
│   ├── Threat Detection Engine                             │
│   └── ML-based Anomaly Detection                          │
├─────────────────────────────────────────────────────────────┤
│ 📡 Agent Services                                          │
│   ├── Network Monitoring Agent                            │
│   ├── Cloud Connector                                     │
│   ├── Endpoint Agent Manager                              │
│   └── Log Collector                                       │
├─────────────────────────────────────────────────────────────┤
│ ⚙️ Background Workers                                       │
│   ├── AI Processing Worker                                │
│   ├── Alert Processing Worker                             │
│   └── Compliance Worker                                   │
└─────────────────────────────────────────────────────────────┘
```

### **External Dependencies**
```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   PostgreSQL    │  │     Redis       │  │   ClickHouse    │
│   Database      │  │     Cache       │  │   Analytics     │
│   Port 5432     │  │   Port 6379     │  │   Port 9000     │
└─────────────────┘  └─────────────────┘  └─────────────────┘

┌─────────────────┐  ┌─────────────────┐
│ Elasticsearch   │  │    Grafana      │
│    Search       │  │  Monitoring     │
│   Port 9200     │  │   Port 3000     │
└─────────────────┘  └─────────────────┘
```

## 🚀 **Quick Start**

### **Prerequisites**
- Docker 20.10+
- Docker Compose 2.0+
- 8GB+ RAM (recommended)
- 20GB+ disk space

### **1. Build the Unified Platform**
```bash
# Clone the repository
git clone <repository-url>
cd a2z-soc-main

# Build the unified container
./build-unified.sh
```

### **2. Configure Environment**
```bash
# Copy environment template
cp .env.unified .env

# Edit configuration (IMPORTANT: Change security secrets!)
nano .env
```

### **3. Deploy the Platform**
```bash
# Deploy all services
./deploy-unified.sh

# Or manually:
docker-compose -f docker-compose.unified.yml up -d
```

### **4. Access the Platform**
- **Main Dashboard**: http://localhost
- **IDS/IPS Interface**: http://localhost/ids/
- **API Documentation**: http://localhost:3001/docs
- **Grafana Monitoring**: http://localhost:3000 (admin/admin123)

## 📋 **Configuration**

### **Environment Variables**

#### **Security Settings** (REQUIRED)
```bash
# Change these in production!
JWT_SECRET=your-jwt-secret-here-32-characters
API_KEY_SECRET=your-api-key-secret-here
ENCRYPTION_KEY=your-encryption-key-32-chars-min
```

#### **Network Configuration**
```bash
# Network interface for packet capture
NETWORK_INTERFACE=any  # or eth0, ens33, etc.

# Deployment mode
DEPLOYMENT_MODE=passive  # or inline, bridge
```

#### **External Integrations** (Optional)
```bash
# Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your-virustotal-key
DEEPSEEK_API_KEY=your-deepseek-key
OPENAI_API_KEY=your-openai-key

# Cloud Provider Credentials
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
AZURE_CLIENT_ID=your-azure-client-id
GCP_PROJECT_ID=your-gcp-project
```

#### **Email Notifications** (Optional)
```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@domain.com
SMTP_PASS=your-app-password
```

## 🔧 **Management Commands**

### **Service Management**
```bash
# Start all services
docker-compose -f docker-compose.unified.yml up -d

# Stop all services
docker-compose -f docker-compose.unified.yml down

# Restart services
docker-compose -f docker-compose.unified.yml restart

# View service status
docker-compose -f docker-compose.unified.yml ps

# View logs
docker-compose -f docker-compose.unified.yml logs -f

# View logs for specific service
docker-compose -f docker-compose.unified.yml logs -f a2z-soc-unified
```

### **Container Management**
```bash
# Enter the unified container
docker exec -it a2z-soc-unified bash

# View running processes inside container
docker exec -it a2z-soc-unified supervisorctl status

# Restart specific service inside container
docker exec -it a2z-soc-unified supervisorctl restart api
docker exec -it a2z-soc-unified supervisorctl restart ids-core
docker exec -it a2z-soc-unified supervisorctl restart network-agent
```

### **Database Management**
```bash
# Access PostgreSQL
docker exec -it a2z-unified-postgres psql -U a2zsoc -d a2zsoc

# Backup database
docker exec a2z-unified-postgres pg_dump -U a2zsoc a2zsoc > backup.sql

# Restore database
docker exec -i a2z-unified-postgres psql -U a2zsoc -d a2zsoc < backup.sql
```

## 📊 **Monitoring & Health Checks**

### **Health Endpoints**
- **Platform Health**: http://localhost/health
- **API Health**: http://localhost:3001/health
- **IDS/IPS Health**: http://localhost:8080/health
- **Network Agent Health**: http://localhost:3002/health

### **System Monitoring**
```bash
# Check overall system health
curl http://localhost/health

# Monitor resource usage
docker stats a2z-soc-unified

# Monitor database connections
docker exec a2z-unified-postgres psql -U a2zsoc -d a2zsoc -c "SELECT count(*) FROM pg_stat_activity;"

# Monitor Redis memory usage
docker exec a2z-unified-redis redis-cli info memory
```

### **Log Locations**
```bash
# Application logs
docker exec a2z-soc-unified ls -la /var/log/a2z-soc/

# Service logs
docker exec a2z-soc-unified ls -la /var/log/supervisor/

# Nginx logs
docker exec a2z-soc-unified ls -la /var/log/nginx/
```

## 🔐 **Security Configuration**

### **Network Security**
```bash
# The unified container requires privileged mode for:
# - Network packet capture (IDS/IPS)
# - Raw socket access
# - Network interface monitoring

# Capabilities required:
# - NET_ADMIN: Network administration
# - NET_RAW: Raw socket access
# - SYS_NICE: Process priority modification
```

### **Firewall Configuration**
```bash
# Allow required ports
sudo ufw allow 80/tcp    # Web interface
sudo ufw allow 3001/tcp  # API (if external access needed)
sudo ufw allow 3000/tcp  # Grafana (optional)
```

### **SSL/TLS Configuration** (Production)
To enable SSL in production, modify the nginx configuration:

```bash
# Generate SSL certificates
sudo certbot certonly --standalone -d your-domain.com

# Update nginx configuration to use SSL
# Edit: /etc/nginx/nginx.conf inside the container
```

## 🚨 **Troubleshooting**

### **Common Issues**

#### **Container Won't Start**
```bash
# Check Docker daemon
sudo systemctl status docker

# Check available resources
docker system df
docker system prune  # Clean up if needed

# Check port conflicts
sudo netstat -tlnp | grep -E ':(80|3001|3002|8080)'
```

#### **Database Connection Issues**
```bash
# Check database container
docker logs a2z-unified-postgres

# Test database connection
docker exec a2z-unified-postgres pg_isready -U a2zsoc

# Reset database password
docker exec -it a2z-unified-postgres psql -U a2zsoc -c "ALTER USER a2zsoc PASSWORD 'new_password';"
```

#### **IDS/IPS Not Detecting Traffic**
```bash
# Check network interface
docker exec a2z-soc-unified ip link show

# Check IDS core status
docker exec a2z-soc-unified supervisorctl status ids-core

# Verify packet capture permissions
docker exec a2z-soc-unified tcpdump -i any -c 10
```

#### **High Resource Usage**
```bash
# Monitor resource usage by service
docker exec a2z-soc-unified supervisorctl status
docker exec a2z-soc-unified htop

# Adjust service priorities or disable non-essential services
docker exec a2z-soc-unified supervisorctl stop cloud-connector
docker exec a2z-soc-unified supervisorctl stop endpoint-agent
```

### **Performance Tuning**

#### **Database Optimization**
```sql
-- Connect to PostgreSQL and run:
VACUUM ANALYZE;
REINDEX DATABASE a2zsoc;

-- Adjust configuration for better performance:
-- shared_buffers = 25% of RAM
-- effective_cache_size = 75% of RAM
```

#### **Redis Optimization**
```bash
# Monitor Redis performance
docker exec a2z-unified-redis redis-cli --latency-history

# Adjust memory limits if needed
# Edit docker-compose.unified.yml:
# command: redis-server --maxmemory 1gb --maxmemory-policy allkeys-lru
```

## 📈 **Scaling & High Availability**

### **Horizontal Scaling**
For larger deployments, consider:

1. **Database Clustering**: Use PostgreSQL with read replicas
2. **Redis Clustering**: Configure Redis cluster mode
3. **Load Balancing**: Use external load balancer for multiple instances
4. **Storage**: Use external storage for persistent volumes

### **Resource Requirements**

#### **Minimum Requirements**
- CPU: 4 cores
- RAM: 8GB
- Disk: 20GB SSD
- Network: 1Gbps

#### **Recommended Production**
- CPU: 8+ cores
- RAM: 16GB+
- Disk: 100GB+ SSD
- Network: 10Gbps

#### **High-Traffic Production**
- CPU: 16+ cores
- RAM: 32GB+
- Disk: 500GB+ NVMe SSD
- Network: 10Gbps+

## 🔄 **Updates & Maintenance**

### **Updating the Platform**
```bash
# Pull latest changes
git pull origin main

# Rebuild unified container
./build-unified.sh

# Deploy updates with zero downtime
docker-compose -f docker-compose.unified.yml up -d --no-deps a2z-soc-unified
```

### **Backup Strategy**
```bash
# Create backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)

# Backup database
docker exec a2z-unified-postgres pg_dump -U a2zsoc a2zsoc > "backup_db_${DATE}.sql"

# Backup volumes
docker run --rm -v a2z-logs:/data -v $(pwd):/backup alpine tar czf /backup/logs_${DATE}.tar.gz -C /data .
docker run --rm -v a2z-pcap:/data -v $(pwd):/backup alpine tar czf /backup/pcap_${DATE}.tar.gz -C /data .

# Backup configuration
cp .env "env_backup_${DATE}"
cp -r a2z-ids-ips/config "config_backup_${DATE}"
```

### **Monitoring Alerts**
Set up monitoring alerts for:
- Container health status
- Database connection issues
- High CPU/memory usage
- Disk space utilization
- Failed authentication attempts
- Threat detection spikes

## 📚 **Additional Resources**

- **API Documentation**: http://localhost:3001/docs
- **Security Best Practices**: [Security Guide](./docs/security.md)
- **Performance Tuning**: [Performance Guide](./docs/performance.md)
- **Integration Examples**: [Integration Guide](./docs/integrations.md)

## 🆘 **Support**

For technical support:
1. Check the troubleshooting section above
2. Review logs: `docker-compose -f docker-compose.unified.yml logs`
3. Open an issue with detailed logs and configuration
4. Join our community Discord/Slack for real-time help

---

**🎯 A2Z SOC Unified Platform - Complete Security in One Container**

*Simplifying cybersecurity infrastructure deployment and management* 