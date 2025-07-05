# A2Z IDS/IPS Standalone

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)](https://github.com/a2z-soc/a2z-ids-ips)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED)](https://hub.docker.com/r/a2z-soc/ids-ips)

A high-performance, AI-enhanced Network Intrusion Detection and Prevention System (IDS/IPS) designed for modern cybersecurity operations. Built with Rust for performance, Go for APIs, and React for the web interface.

## 🚀 Quick Start

### Docker Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/a2z-soc/a2z-ids-ips.git
cd a2z-ids-ips

# Deploy with Docker
sudo ./scripts/deploy.sh

# Access the dashboard
open http://localhost:3000
```

### One-Line Installation

```bash
curl -sSL https://raw.githubusercontent.com/a2z-soc/a2z-ids-ips/main/scripts/deploy.sh | sudo bash
```

## 📋 Features

### 🔍 **Core IDS/IPS Capabilities**
- **Real-time Packet Inspection**: High-speed packet capture and analysis
- **Pattern Matching**: Advanced signature-based detection using Hyperscan
- **Machine Learning**: AI-powered anomaly detection and behavioral analysis
- **Protocol Analysis**: Deep packet inspection for multiple protocols
- **Flow Tracking**: Stateful connection monitoring and analysis

### 🛡️ **Security Features**
- **Multi-Mode Operation**: Passive monitoring, inline blocking, hybrid mode
- **Rule-Based Detection**: Snort/Suricata compatible rule engine
- **Threat Intelligence**: Integration with VirusTotal, MISP, and other sources
- **ML Anomaly Detection**: Behavioral analysis and zero-day threat detection
- **Geo-location**: IP-based geographic threat mapping

### 📊 **Management & Monitoring**
- **Modern Web Dashboard**: React-based real-time monitoring interface
- **REST API**: Comprehensive management API with OpenAPI documentation
- **Grafana Integration**: Advanced metrics visualization and alerting
- **Prometheus Metrics**: Performance and security metrics collection
- **Real-time Alerts**: Multi-channel alerting (Email, Webhook, Syslog)

### 🔧 **Operations**
- **High Performance**: 10Gbps+ throughput capability
- **Low Latency**: Sub-millisecond processing times
- **Scalable Architecture**: Horizontal scaling support
- **Cross-Platform**: Linux, macOS, Windows support
- **Container Ready**: Docker and Kubernetes deployment options

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │  Management API │    │   Core Engine   │
│    (React)      │◄──►│     (Go)        │◄──►│    (Rust)       │
│   Port: 3000    │    │   Port: 8080    │    │ Packet Capture  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Grafana     │    │   PostgreSQL    │    │  Network Tap    │
│   Port: 3001    │    │   Port: 5432    │    │     (eth0)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│   Prometheus    │    │   ClickHouse    │
│   Port: 9090    │    │   Port: 8123    │
└─────────────────┘    └─────────────────┘
```

## 💻 Installation

### System Requirements

#### Minimum Requirements
- **CPU**: 2 cores, 2.0 GHz
- **RAM**: 4 GB
- **Storage**: 20 GB
- **Network**: 1 Gbps interface

#### Recommended Requirements
- **CPU**: 8+ cores, 3.0+ GHz
- **RAM**: 16+ GB
- **Storage**: 100+ GB SSD
- **Network**: 10+ Gbps interface

### Platform-Specific Installation

#### Linux (Ubuntu/Debian)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y build-essential pkg-config libssl-dev libpcap-dev

# Deploy A2Z IDS/IPS
git clone https://github.com/a2z-soc/a2z-ids-ips.git
cd a2z-ids-ips
sudo ./scripts/deploy.sh -i eth0 -m passive
```

#### Linux (CentOS/RHEL)

```bash
# Update system
sudo yum update -y

# Install dependencies
sudo yum install -y gcc gcc-c++ openssl-devel libpcap-devel

# Deploy A2Z IDS/IPS
git clone https://github.com/a2z-soc/a2z-ids-ips.git
cd a2z-ids-ips
sudo ./scripts/deploy.sh -i eth0 -m passive
```

#### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Deploy A2Z IDS/IPS
git clone https://github.com/a2z-soc/a2z-ids-ips.git
cd a2z-ids-ips
sudo ./scripts/deploy.sh -i en0 -m passive
```

#### Windows

```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force

# Deploy A2Z IDS/IPS
git clone https://github.com/a2z-soc/a2z-ids-ips.git
cd a2z-ids-ips
.\scripts\deploy.ps1 -Interface "Ethernet" -Mode "passive"
```

### Configuration Options

#### Network Interface Selection

```bash
# List available interfaces
ip addr show                    # Linux
ifconfig                        # macOS
ipconfig                        # Windows

# Deploy with specific interface
./scripts/deploy.sh -i enp0s3   # Linux example
./scripts/deploy.sh -i en0      # macOS example
```

#### Deployment Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `passive` | Monitor-only mode | Network monitoring, compliance |
| `inline` | Active blocking | Network protection, IPS |
| `hybrid` | Selective blocking | Balanced monitoring and protection |

```bash
# Passive monitoring
./scripts/deploy.sh -m passive

# Inline protection
./scripts/deploy.sh -m inline

# Hybrid mode
./scripts/deploy.sh -m hybrid
```

### Docker Deployment

#### Using Docker Compose (Recommended)

```bash
# Clone and deploy
git clone https://github.com/a2z-soc/a2z-ids-ips.git
cd a2z-ids-ips

# Set environment variables
export NETWORK_INTERFACE=eth0
export DEPLOYMENT_MODE=passive
export GRAFANA_PASSWORD=secure_password_123

# Deploy
docker-compose -f docker-compose.standalone.yml up -d

# Check status
docker-compose -f docker-compose.standalone.yml ps
```

#### Using Makefile

```bash
# Build and run
make docker-run

# Check status
make status

# View logs
make logs

# Stop services
make docker-stop
```

## 🎯 Usage

### Web Dashboard

Access the main dashboard at `http://localhost:3000`

#### Features Available:
- **Real-time Overview**: System performance, threat distribution, resource usage
- **Packet Flows**: Live packet stream with detailed analysis
- **Rule Management**: CRUD operations for detection rules
- **Threat Analytics**: Security event analysis and reporting

### Management API

The REST API is available at `http://localhost:8080`

#### Common API Endpoints:

```bash
# Get system status
curl http://localhost:8080/api/v1/status

# Get alerts
curl http://localhost:8080/api/v1/alerts

# Get rules
curl http://localhost:8080/api/v1/rules

# Create new rule
curl -X POST http://localhost:8080/api/v1/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom Rule",
    "content": "alert tcp any any -> any 80 (msg:\"HTTP Traffic\"; sid:10001;)",
    "enabled": true
  }'
```

### Command Line Interface

#### Core Engine Commands

```bash
# Check status
/usr/local/bin/a2z-ids health

# Run with specific config
/usr/local/bin/a2z-ids run --config /etc/a2z-ids/config.yaml

# Test rules
/usr/local/bin/a2z-ids test-rules --rules-dir /var/lib/a2z-ids/rules
```

#### Using Makefile

```bash
# Show all available commands
make help

# Build from source
make build

# Run tests
make test

# Package for distribution
make package

# Install/uninstall
make install
make uninstall
```

## 📊 Monitoring

### Grafana Dashboard

Access Grafana at `http://localhost:3001`
- **Username**: admin
- **Password**: admin123 (configurable)

#### Pre-configured Dashboards:
- **A2Z IDS/IPS Overview**: System metrics and performance
- **Security Events**: Threat detection and analysis
- **Network Traffic**: Bandwidth and protocol analysis
- **System Health**: Resource utilization and alerts

### Prometheus Metrics

Access Prometheus at `http://localhost:9090`

#### Key Metrics:
- `a2z_packets_processed_total`: Total packets processed
- `a2z_alerts_generated_total`: Security alerts generated
- `a2z_processing_latency_seconds`: Packet processing time
- `a2z_memory_usage_bytes`: Memory consumption
- `a2z_cpu_usage_percent`: CPU utilization

### Log Files

#### Location by Platform:

| Platform | Log Directory |
|----------|---------------|
| Linux | `/var/log/a2z-ids/` |
| macOS | `/var/log/a2z-ids/` |
| Windows | `C:\ProgramData\A2Z-IDS\logs\` |

#### Log Types:
- `core.log`: Core engine events
- `api.log`: Management API logs
- `alerts.json`: Security alerts (JSON format)
- `pcap/`: Packet capture files (if enabled)

## 🔧 Configuration

### Main Configuration File

Located at `/etc/a2z-ids/config.yaml` (Linux/macOS) or `C:\Program Files\A2Z-IDS\config\config.yaml` (Windows)

#### Key Sections:

```yaml
# Network capture configuration
capture:
  interface: "eth0"
  mode: "passive"
  buffer_size: "256MB"
  workers: 8

# Detection engine settings
detection:
  rule_files:
    - "/var/lib/a2z-ids/rules/community.rules"
    - "/var/lib/a2z-ids/rules/custom.rules"
  
# Machine learning configuration
machine_learning:
  enabled: true
  models:
    anomaly_detection:
      threshold: 0.95
    malware_classification:
      threshold: 0.90

# Alerting configuration
alerting:
  outputs:
    - type: "json"
      file: "/var/log/a2z-ids/alerts.json"
    - type: "webhook"
      url: "https://your-soc.com/api/alerts"
```

### Environment Variables

```bash
# Core settings
export A2Z_CONFIG_PATH="/etc/a2z-ids/config.yaml"
export A2Z_INTERFACE="eth0"
export A2Z_MODE="passive"

# API settings
export DATABASE_URL="postgres://user:pass@localhost/a2z_ids"
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET="your-secret-key"

# Logging
export RUST_LOG="info"
export LOG_LEVEL="info"
```

### Rule Management

#### Built-in Rule Categories:
- **Malware Detection**: Known malware signatures
- **Web Application**: SQL injection, XSS, etc.
- **Network Scanning**: Port scans, reconnaissance
- **Brute Force**: Authentication attacks
- **DoS/DDoS**: Denial of service attacks

#### Adding Custom Rules:

```bash
# Edit custom rules file
sudo nano /var/lib/a2z-ids/rules/custom.rules

# Example rule
alert tcp any any -> $HOME_NET 22 (
    msg:"SSH Brute Force Attempt"; 
    flow:to_server,established; 
    content:"Failed password"; 
    detection_filter:track by_src, count 5, seconds 60; 
    sid:10001;
)

# Reload rules
curl -X POST http://localhost:8080/api/v1/rules/reload
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. Permission Denied (Packet Capture)

```bash
# Linux: Add user to pcap group
sudo usermod -a -G pcap $USER

# Or run with capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/a2z-ids
```

#### 2. High CPU Usage

```bash
# Check worker configuration
grep "workers:" /etc/a2z-ids/config.yaml

# Reduce workers if needed
sed -i 's/workers: 8/workers: 4/' /etc/a2z-ids/config.yaml

# Restart service
make docker-stop && make docker-run
```

#### 3. Memory Issues

```bash
# Check memory usage
make status

# Adjust buffer sizes in config
sed -i 's/buffer_size: "256MB"/buffer_size: "128MB"/' /etc/a2z-ids/config.yaml
```

#### 4. Network Interface Not Found

```bash
# List available interfaces
make network-info

# Update configuration
./scripts/deploy.sh -i correct_interface_name
```

### Logging and Debugging

```bash
# Enable debug logging
export RUST_LOG=debug

# View real-time logs
make logs

# Check specific component
make logs-core    # Core engine
make logs-api     # Management API
make logs-web     # Web dashboard

# System health check
make status
```

### Performance Tuning

#### For High-Traffic Networks:

```yaml
# config.yaml adjustments
capture:
  workers: 16              # Increase workers
  buffer_size: "512MB"     # Larger buffer
  batch_size: 128          # Larger batches

detection:
  pattern_matching:
    engine: "hyperscan"    # Use fastest engine
    
machine_learning:
  training:
    min_samples: 50000     # More training data
```

#### System-Level Optimizations:

```bash
# Increase network buffer sizes
echo 'net.core.rmem_max = 268435456' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf
sysctl -p

# CPU affinity for better performance
taskset -c 0-3 /usr/local/bin/a2z-ids

# Use dedicated network interface
ethtool -K eth0 gro off gso off tso off
```

## 📚 Documentation

### API Documentation

- **OpenAPI Spec**: `http://localhost:8080/swagger/`
- **Postman Collection**: Available in `docs/api/`

### Configuration Reference

- **Full Config Schema**: `docs/configuration.md`
- **Rule Writing Guide**: `docs/rules.md`
- **Deployment Guide**: `docs/deployment.md`

### Development

```bash
# Development environment
make dev

# Run individual components
make dev-core    # Core engine
make dev-api     # Management API
make dev-web     # Web dashboard

# Run tests
make test

# Security scanning
make security-scan

# Code formatting
make format
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs.a2zsoc.com](https://docs.a2zsoc.com)
- **Issues**: [GitHub Issues](https://github.com/a2z-soc/a2z-ids-ips/issues)
- **Discussions**: [GitHub Discussions](https://github.com/a2z-soc/a2z-ids-ips/discussions)
- **Email**: support@a2zsoc.com

## 🏆 Acknowledgments

- **Suricata Project**: Rule format compatibility
- **Snort Project**: Detection engine inspiration
- **Hyperscan**: High-performance pattern matching
- **Rust Community**: Performance and safety
- **Open Source Security Tools**: Foundation and inspiration

---

**Made with ❤️ by the A2Z SOC Team** 