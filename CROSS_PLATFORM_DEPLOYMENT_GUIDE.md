# A2Z SOC Platform - Cross-Platform Deployment Guide

## Overview

The A2Z SOC platform is now fully compatible with **macOS**, **Windows**, and **Linux** systems, supporting both **x86_64** and **ARM64** architectures. This guide provides step-by-step instructions for deploying the platform on any supported system.

## Supported Platforms

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| **macOS** | Intel (x86_64) | ✅ Supported | Native Docker Desktop |
| **macOS** | Apple Silicon (ARM64) | ✅ Supported | Native ARM64 containers |
| **Linux** | x86_64 | ✅ Supported | Ubuntu, CentOS, RHEL, Debian |
| **Linux** | ARM64 | ✅ Supported | ARM servers, Raspberry Pi 4+ |
| **Windows** | x86_64 | ✅ Supported | Docker Desktop, WSL2 |

## Prerequisites

### All Platforms
- **Docker**: Version 20.10.0 or higher
- **Docker Compose**: Version 2.0.0 or higher
- **Memory**: Minimum 4GB RAM, Recommended 8GB+
- **Storage**: Minimum 10GB free space
- **Network**: Internet connection for initial build

### Platform-Specific Requirements

#### macOS
```bash
# Install Docker Desktop for Mac
# Download from: https://docs.docker.com/desktop/mac/install/

# Verify installation
docker --version
docker compose version
```

#### Windows
```powershell
# Install Docker Desktop for Windows
# Download from: https://docs.docker.com/desktop/windows/install/

# Enable WSL2 (recommended)
wsl --install

# Verify installation
docker --version
docker compose version
```

#### Linux (Ubuntu/Debian)
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

## Quick Start (All Platforms)

### 1. Clone the Repository
```bash
git clone <repository-url>
cd a2z-soc-main
```

### 2. Run the Cross-Platform Builder
```bash
# Make the script executable (Linux/macOS)
chmod +x build-cross-platform.sh

# Run the builder
./build-cross-platform.sh
```

### 3. Start the Platform
```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f
```

### 4. Access the Platform
- **Web Interface**: http://localhost
- **API Server**: http://localhost:3001
- **Frontend**: http://localhost:5173
- **Network Agent**: http://localhost:5200

## Detailed Deployment Instructions

### Manual Build Process

If you prefer to build manually:

```bash
# 1. Create necessary directories
mkdir -p data/{postgres,redis,clickhouse,elasticsearch,pcap,rules}
mkdir -p logs/{supervisor,app}

# 2. Build the Docker image
export DOCKER_BUILDKIT=1
docker build --platform linux/amd64 -t a2z-soc:cross-platform .

# For Apple Silicon Macs
docker build --platform linux/arm64 -t a2z-soc:cross-platform .

# 3. Start the services
docker compose up -d
```

### Platform-Specific Configurations

#### macOS Specific Settings

```yaml
# docker-compose.override.yml for macOS
version: '3.8'
services:
  a2z-soc:
    # Use ARM64 for Apple Silicon
    platform: linux/arm64  # or linux/amd64 for Intel Macs
    volumes:
      # macOS specific volume optimizations
      - type: bind
        source: ./data
        target: /app/data
        consistency: cached
```

#### Windows Specific Settings

```yaml
# docker-compose.override.yml for Windows
version: '3.8'
services:
  a2z-soc:
    platform: linux/amd64
    volumes:
      # Windows path handling
      - ./data:/app/data:rw
    environment:
      - COMPOSE_CONVERT_WINDOWS_PATHS=1
```

#### Linux Specific Settings

```yaml
# docker-compose.override.yml for Linux
version: '3.8'
services:
  a2z-soc:
    # Auto-detect platform
    volumes:
      - ./data:/app/data:Z  # SELinux compatibility
    sysctls:
      - net.core.somaxconn=1024
```

## Architecture Detection

The build script automatically detects your platform and architecture:

```bash
# Platform detection output example
====================================
   A2Z SOC Cross-Platform Builder
====================================
Host OS: Darwin
Host Architecture: arm64
Docker Platform: linux/arm64
Architecture Type: Apple Silicon (ARM64)
====================================
```

## Performance Optimizations

### Memory Settings by Platform

#### Small Systems (4GB RAM)
```yaml
deploy:
  resources:
    limits:
      memory: 2G
      cpus: '1.0'
```

#### Medium Systems (8GB RAM)
```yaml
deploy:
  resources:
    limits:
      memory: 4G
      cpus: '2.0'
```

#### Large Systems (16GB+ RAM)
```yaml
deploy:
  resources:
    limits:
      memory: 8G
      cpus: '4.0'
```

## Database Configurations

### Cross-Platform Database Settings

#### PostgreSQL
```bash
# Access the database
docker exec -it a2z-soc-unified psql -U postgres -d a2z_soc

# Connection string
postgresql://postgres@localhost:5432/a2z_soc
```

#### Redis
```bash
# Access Redis CLI
docker exec -it a2z-soc-unified redis-cli -a redis_password

# Connection string
redis://:redis_password@localhost:6379/0
```

#### ClickHouse
```bash
# Access ClickHouse client
docker exec -it a2z-soc-unified clickhouse-client

# Connection string
http://localhost:8123
```

#### Elasticsearch
```bash
# Check cluster health
curl http://localhost:9200/_cluster/health

# Connection string
http://localhost:9200
```

## Network Monitoring Capabilities

### Platform-Specific Network Features

| Feature | macOS | Windows | Linux |
|---------|-------|---------|-------|
| Packet Capture | ✅ Limited | ✅ WSL2 | ✅ Full |
| Network Interface Detection | ✅ Yes | ✅ Yes | ✅ Yes |
| Raw Socket Access | ⚠️ Requires privileges | ⚠️ Requires privileges | ✅ With capabilities |
| Traffic Analysis | ✅ Yes | ✅ Yes | ✅ Yes |

### Enabling Full Network Monitoring

#### macOS
```bash
# Grant network capabilities
sudo docker run --privileged --cap-add=NET_ADMIN --cap-add=NET_RAW a2z-soc:cross-platform
```

#### Windows (WSL2)
```powershell
# Run with administrator privileges
# Network monitoring works through WSL2 interface
```

#### Linux
```bash
# Set capabilities on the container
docker run --cap-add=NET_ADMIN --cap-add=NET_RAW a2z-soc:cross-platform
```

## Troubleshooting

### Common Issues

#### Docker Not Starting
```bash
# Check Docker status
docker info

# Restart Docker service (Linux)
sudo systemctl restart docker

# Restart Docker Desktop (macOS/Windows)
# Use Docker Desktop app
```

#### Port Conflicts
```bash
# Check for port conflicts
netstat -tulpn | grep :80
netstat -tulpn | grep :3001

# Modify docker-compose.yml ports if needed
ports:
  - "8080:80"  # Use different host port
```

#### Permission Issues (Linux)
```bash
# Fix Docker permissions
sudo usermod -aG docker $USER
sudo chown -R $USER:$USER ./data ./logs

# Fix SELinux issues
sudo setsebool -P container_manage_cgroup true
```

#### Memory Issues
```bash
# Increase Docker memory limit
# Docker Desktop > Settings > Resources > Memory

# Or modify docker-compose.yml
deploy:
  resources:
    limits:
      memory: 2G  # Reduce for smaller systems
```

### Platform-Specific Issues

#### macOS - Apple Silicon
```bash
# If x86_64 images don't work, force ARM64
docker build --platform linux/arm64 -t a2z-soc:cross-platform .
```

#### Windows - WSL2
```powershell
# Enable WSL2 features
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

#### Linux - Firewall
```bash
# Open required ports
sudo ufw allow 80
sudo ufw allow 3001
sudo ufw allow 5173
sudo ufw allow 5200
```

## Monitoring and Maintenance

### Health Checks
```bash
# Check container health
docker compose ps

# View health check logs
docker inspect a2z-soc-unified | grep Health -A 10
```

### Log Management
```bash
# View all logs
docker compose logs -f

# View specific service logs
docker compose logs -f a2z-soc

# View supervisor logs
docker exec a2z-soc-unified tail -f /var/log/supervisor/supervisord.log
```

### Updates and Maintenance
```bash
# Pull latest changes
git pull origin main

# Rebuild with latest changes
./build-cross-platform.sh

# Restart with new image
docker compose down
docker compose up -d
```

## Security Considerations

### Network Security
- Container runs with necessary network capabilities
- All services are behind Nginx reverse proxy
- Database access is restricted to container network

### Data Security
- Data is persisted in named volumes
- Logs are rotated and managed by supervisor
- Sensitive data is handled through environment variables

### Access Control
- Default credentials should be changed in production
- API endpoints require authentication
- Database access is password-protected

## Production Deployment

### Environment Variables
```bash
# Create production environment file
cp .env.example .env

# Configure production settings
NODE_ENV=production
DATABASE_URL=postgresql://user:pass@host:5432/db
REDIS_URL=redis://:pass@host:6379/0
```

### SSL/TLS Configuration
```nginx
# Add to nginx configuration for HTTPS
server {
    listen 443 ssl;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    # ... rest of configuration
}
```

### Backup Strategy
```bash
# Database backup
docker exec a2z-soc-unified pg_dump -U postgres a2z_soc > backup.sql

# Volume backup
docker run --rm -v a2z_data:/data -v $(pwd):/backup alpine tar czf /backup/backup.tar.gz /data
```

## Support and Contributing

### Getting Help
- Check the troubleshooting section above
- Review Docker logs for error messages
- Open an issue on the repository

### Contributing
- Fork the repository
- Test on your platform
- Submit platform-specific improvements
- Update documentation for new platforms

---

**Note**: This deployment guide is regularly updated to support new platforms and Docker versions. Always check for the latest version before deploying. 