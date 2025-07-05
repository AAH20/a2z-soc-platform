# 🐳 A2Z SOC Docker Deployment Guide

Complete guide for deploying both the full A2Z SOC platform and standalone A2Z IDS/IPS using Docker.

## 📦 Available Docker Images

### 1. A2Z SOC Complete Platform
**Image**: `ghcr.io/a2z-soc/a2z-soc-platform:1.0.0`

Complete cybersecurity platform with:
- React frontend with comprehensive SOC dashboard
- Node.js API with full feature set
- Background workers for AI processing
- Nginx reverse proxy
- All-in-one deployment

**Ports**:
- `80` - Web Interface (Main Dashboard)
- `3001` - API Backend

**System Requirements**:
- **CPU**: 4+ cores
- **RAM**: 8+ GB
- **Storage**: 50+ GB
- **Docker**: 20.10+

### 2. A2Z IDS/IPS Standalone
**Image**: `ghcr.io/a2z-soc/a2z-ids-ips:1.0.0`

High-performance network intrusion detection with:
- Rust core engine for packet processing
- Go management API
- React web dashboard
- ML-powered anomaly detection
- Snort/Suricata rule compatibility

**Ports**:
- `3000` - Web Dashboard
- `8080` - Management API
- `9100` - Metrics Endpoint

**System Requirements**:
- **CPU**: 2+ cores
- **RAM**: 4+ GB
- **Storage**: 20+ GB
- **Network**: Requires privileged mode for packet capture
- **Docker**: 20.10+

## 🚀 Quick Deployment

### Option 1: Single Container Deployment

#### A2Z SOC Complete Platform
```bash
# Load the image (if using offline package)
docker load < a2z-soc-platform-1.0.0.tar.gz

# Run the complete platform
docker run -d \
  --name a2z-soc-platform \
  --restart unless-stopped \
  -p 80:80 \
  -p 3001:3001 \
  -e JWT_SECRET="your-secure-jwt-secret-here" \
  -e VIRUSTOTAL_API_KEY="your-virustotal-api-key" \
  -v a2z-soc-data:/var/lib/a2z-soc \
  ghcr.io/a2z-soc/a2z-soc-platform:1.0.0

# Access the platform
open http://localhost
```

#### A2Z IDS/IPS Standalone
```bash
# Load the image (if using offline package)
docker load < a2z-ids-ips-1.0.0.tar.gz

# Run the IDS/IPS system
docker run -d \
  --name a2z-ids-ips \
  --restart unless-stopped \
  --privileged \
  --net=host \
  -e A2Z_INTERFACE=eth0 \
  -e A2Z_MODE=passive \
  -v a2z-ids-data:/var/lib/a2z-ids \
  ghcr.io/a2z-soc/a2z-ids-ips:1.0.0

# Access the dashboard
open http://localhost:3000
```

### Option 2: Docker Compose Deployment (Recommended)

#### A2Z SOC Complete Platform with Database Stack
```bash
# Download the docker-compose file
curl -O https://raw.githubusercontent.com/a2z-soc/a2z-soc-platform/main/docker-compose.a2z-soc-full.yml

# Configure environment variables
cat > .env << 'EOF'
# Security
JWT_SECRET=your-secure-jwt-secret-change-this-in-production
API_KEY_SECRET=your-api-key-secret
ENCRYPTION_KEY=your-32-character-encryption-key

# External APIs
VIRUSTOTAL_API_KEY=your-virustotal-api-key
DEEPSEEK_API_KEY=your-deepseek-api-key
OPENAI_API_KEY=your-openai-api-key

# Cloud Credentials (optional)
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
EOF

# Deploy the platform
docker-compose -f docker-compose.a2z-soc-full.yml up -d

# Check status
docker-compose -f docker-compose.a2z-soc-full.yml ps

# Access the platform
open http://localhost
```

#### A2Z IDS/IPS with Full Monitoring Stack
```bash
# Download the docker-compose file
curl -O https://raw.githubusercontent.com/a2z-soc/a2z-soc-platform/main/docker-compose.a2z-ids-ips.yml

# Configure environment variables
cat > .env << 'EOF'
# Network Configuration
NETWORK_INTERFACE=eth0
DEPLOYMENT_MODE=passive

# Security
JWT_SECRET=your-secure-jwt-secret-change-this

# Database passwords
POSTGRES_PASSWORD=a2z_ids_password
REDIS_PASSWORD=redis_password
CLICKHOUSE_PASSWORD=clickhouse_password
EOF

# Deploy the IDS/IPS system
docker-compose -f docker-compose.a2z-ids-ips.yml up -d

# Check status
docker-compose -f docker-compose.a2z-ids-ips.yml ps

# Access the dashboards
open http://localhost:3000    # IDS/IPS Dashboard
open http://localhost:3001    # Grafana (admin/admin123)
open http://localhost:9090    # Prometheus
```

## 🔧 Configuration

### Environment Variables

#### A2Z SOC Complete Platform
```bash
# Core Configuration
NODE_ENV=production
PORT=3001
JWT_SECRET=your-jwt-secret

# Database URLs
DATABASE_URL=postgresql://user:pass@host:port/db
REDIS_URL=redis://host:port/db
CLICKHOUSE_URL=tcp://host:port/db
ELASTICSEARCH_URL=http://host:port

# External APIs
VIRUSTOTAL_API_KEY=your-api-key
DEEPSEEK_API_KEY=your-api-key
OPENAI_API_KEY=your-api-key
ANTHROPIC_API_KEY=your-api-key

# Cloud Provider Credentials
AWS_ACCESS_KEY_ID=your-key-id
AWS_SECRET_ACCESS_KEY=your-secret
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-secret
GCP_PROJECT_ID=your-project-id

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email
SMTP_PASS=your-password
```

#### A2Z IDS/IPS Standalone
```bash
# Core IDS/IPS Configuration
A2Z_CONFIG_PATH=/etc/a2z-ids/config.yaml
A2Z_RULES_PATH=/var/lib/a2z-ids/rules
A2Z_MODELS_PATH=/var/lib/a2z-ids/models
A2Z_INTERFACE=eth0
A2Z_MODE=passive

# Logging
RUST_LOG=info
GIN_MODE=release
LOG_LEVEL=info

# Database Configuration
DATABASE_URL=postgresql://a2z_ids:password@postgres:5432/a2z_ids
REDIS_URL=redis://redis:6379/0
CLICKHOUSE_URL=tcp://clickhouse:9000/a2z_ids

# API Configuration
API_PORT=8080
JWT_SECRET=your-jwt-secret

# Web Dashboard
VITE_API_URL=http://localhost:8080
VITE_WS_URL=ws://localhost:8080/ws
```

### Volume Mounts

#### A2Z SOC Complete Platform
```bash
# Essential volumes
-v a2z-soc-data:/var/lib/a2z-soc        # Application data
-v a2z-soc-logs:/var/log/a2z-soc        # Log files
-v a2z-soc-uploads:/app/uploads          # File uploads
-v a2z-soc-config:/etc/a2z-soc          # Configuration files
```

#### A2Z IDS/IPS Standalone
```bash
# Essential volumes
-v a2z-ids-data:/var/lib/a2z-ids/data     # Application data
-v a2z-ids-logs:/var/log/a2z-ids          # Log files
-v a2z-ids-pcap:/var/lib/a2z-ids/pcap     # Packet captures
-v a2z-ids-config:/etc/a2z-ids            # Configuration
-v a2z-ids-rules:/var/lib/a2z-ids/rules   # Detection rules
-v a2z-ids-models:/var/lib/a2z-ids/models # ML models
```

## 🔐 Security Configuration

### Network Security

#### A2Z SOC Complete Platform
```bash
# Secure deployment with TLS
docker run -d \
  --name a2z-soc-platform \
  -p 443:443 \
  -p 80:80 \
  -v /path/to/ssl:/etc/nginx/ssl:ro \
  -e TLS_ENABLED=true \
  -e TLS_CERT_PATH=/etc/nginx/ssl/cert.pem \
  -e TLS_KEY_PATH=/etc/nginx/ssl/key.pem \
  ghcr.io/a2z-soc/a2z-soc-platform:1.0.0
```

#### A2Z IDS/IPS Network Interface Selection
```bash
# List available network interfaces
ip addr show

# Deploy with specific interface
docker run -d \
  --name a2z-ids-ips \
  --privileged \
  --net=host \
  -e A2Z_INTERFACE=enp0s3 \
  -e A2Z_MODE=inline \
  ghcr.io/a2z-soc/a2z-ids-ips:1.0.0
```

### Access Control

#### Default Credentials
```bash
# A2Z SOC Platform (change on first login)
Username: admin@a2zsoc.com
Password: admin123

# Grafana (IDS/IPS monitoring)
Username: admin
Password: admin123

# Database passwords (configure in .env)
PostgreSQL: a2z_ids_password
Redis: (no password by default)
ClickHouse: clickhouse_password
```

## 📊 Monitoring and Health Checks

### Health Check Endpoints

#### A2Z SOC Complete Platform
```bash
# Platform health
curl http://localhost/health

# API health
curl http://localhost:3001/health

# Service status
curl http://localhost:3001/api/status
```

#### A2Z IDS/IPS Standalone
```bash
# Dashboard health
curl http://localhost:3000

# API health
curl http://localhost:8080/health

# Core engine health
curl http://localhost:9100/metrics

# System status
curl http://localhost:8080/api/v1/status
```

### Log Monitoring
```bash
# View application logs
docker logs -f a2z-soc-platform
docker logs -f a2z-ids-ips

# View all container logs (docker-compose)
docker-compose logs -f

# View specific service logs
docker-compose logs -f a2z-soc-platform
docker-compose logs -f a2z-ids-ips
```

### Resource Monitoring
```bash
# Monitor resource usage
docker stats

# Monitor specific containers
docker stats a2z-soc-platform a2z-ids-ips

# Check disk usage
docker system df
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Container Won't Start
```bash
# Check container logs
docker logs a2z-soc-platform
docker logs a2z-ids-ips

# Check system resources
docker system df
free -h
df -h

# Restart container
docker restart a2z-soc-platform
```

#### 2. Network Issues (IDS/IPS)
```bash
# Check network interfaces
ip addr show

# Verify privileged mode
docker inspect a2z-ids-ips | grep Privileged

# Test packet capture
docker exec a2z-ids-ips tcpdump -i eth0 -c 10
```

#### 3. Database Connection Issues
```bash
# Check database containers
docker-compose ps postgres redis clickhouse

# Test database connectivity
docker exec a2z-soc-postgres pg_isready
docker exec a2z-soc-redis redis-cli ping
```

#### 4. High Resource Usage
```bash
# Monitor resources
docker stats --no-stream

# Adjust resource limits
docker run --memory=4g --cpus=2 ...

# Optimize configuration
vim config/config.yaml  # Reduce worker count, buffer sizes
```

### Performance Tuning

#### A2Z SOC Complete Platform
```bash
# Increase worker processes
-e WORKER_PROCESSES=4

# Adjust memory limits
-e NODE_OPTIONS="--max-old-space-size=4096"

# Enable caching
-e REDIS_CACHE_ENABLED=true
```

#### A2Z IDS/IPS Standalone
```bash
# Optimize for high traffic
-e A2Z_WORKERS=8
-e A2Z_BUFFER_SIZE=512MB

# Enable fast pattern matching
-e A2Z_PATTERN_ENGINE=hyperscan

# Reduce logging verbosity
-e RUST_LOG=warn
```

## 🔄 Updates and Maintenance

### Updating Images
```bash
# Pull latest images
docker pull ghcr.io/a2z-soc/a2z-soc-platform:latest
docker pull ghcr.io/a2z-soc/a2z-ids-ips:latest

# Update using docker-compose
docker-compose pull
docker-compose up -d
```

### Backup and Restore
```bash
# Backup volumes
docker run --rm -v a2z-soc-data:/data -v $(pwd):/backup alpine tar czf /backup/a2z-soc-backup.tar.gz /data

# Restore volumes
docker run --rm -v a2z-soc-data:/data -v $(pwd):/backup alpine tar xzf /backup/a2z-soc-backup.tar.gz -C /
```

### Cleanup
```bash
# Remove unused containers and images
docker system prune -f

# Remove specific deployment
docker-compose down -v
docker rmi ghcr.io/a2z-soc/a2z-soc-platform:1.0.0
```

## 📚 Additional Resources

### Documentation
- [A2Z SOC User Guide](https://docs.a2zsoc.com)
- [IDS/IPS Configuration Guide](./A2Z_IDS_INSTALLATION_GUIDE.md)
- [Snort Rules Guide](./A2Z_SNORT_RULES_GUIDE.md)

### Support
- **Email**: support@a2zsoc.com
- **Issues**: [GitHub Issues](https://github.com/a2z-soc/a2z-soc-platform/issues)
- **Documentation**: [docs.a2zsoc.com](https://docs.a2zsoc.com)

### Community
- **Discord**: [A2Z SOC Community](https://discord.gg/a2zsoc)
- **Forum**: [community.a2zsoc.com](https://community.a2zsoc.com)

---

**🎉 Congratulations!** You now have a complete understanding of how to deploy and manage both A2Z SOC platforms using Docker. For additional support, consult our documentation or reach out to our support team. 