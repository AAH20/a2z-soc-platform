# 🛡️ A2Z IDS/IPS Installation & Setup Guide

Complete guide to install, configure, and monitor your network with A2Z IDS/IPS using Snort community rules.

## 📋 Table of Contents
1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
3. [Network Configuration](#network-configuration)
4. [Rule Management](#rule-management)
5. [Monitoring Setup](#monitoring-setup)
6. [Troubleshooting](#troubleshooting)

## 🖥️ System Requirements

### Minimum Requirements
- **OS**: Ubuntu 20.04+, CentOS 8+, or RHEL 8+
- **CPU**: 4 cores (8+ recommended for production)
- **RAM**: 8GB (16GB+ recommended for production)
- **Storage**: 100GB SSD (500GB+ for production)
- **Network**: Dedicated monitoring interface

### Software Dependencies
- **Docker 24.0+** and **Docker Compose 2.0+**
- **Go 1.21+** (for building from source)
- **Rust 1.70+** (for core engine)
- **Node.js 18+** (for web interface)

## 🚀 Installation Methods

### Method 1: Docker Deployment (Recommended)

#### Step 1: Clone Repository
```bash
# Clone the A2Z IDS/IPS repository
git clone https://github.com/a2z-soc/a2z-ids-ips.git
cd a2z-ids-ips

# Make setup script executable
chmod +x scripts/setup-*.sh
```

#### Step 2: Quick Setup
```bash
# Run automated setup
sudo ./scripts/setup-dev-env.sh

# Or start with Docker Compose
docker-compose up -d
```

#### Step 3: Verify Installation
```bash
# Check services status
docker-compose ps

# Test API health
curl http://localhost:8080/api/v1/health

# Access web interface
curl http://localhost:3000
```

### Method 2: Native Installation

#### Step 1: Install Dependencies
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    build-essential \
    libpcap-dev \
    libssl-dev \
    pkg-config \
    curl \
    git

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install -y libpcap-devel openssl-devel curl git
```

#### Step 2: Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

#### Step 3: Install Go
```bash
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

#### Step 4: Build Components
```bash
# Use Makefile for automated build
make install
make build-all

# Or build manually
cd core-engine && cargo build --release
cd ../management-api && go build -o bin/a2z-ids-api
cd ../web-interface && npm install && npm run build
```

## 🌐 Network Configuration

### Step 1: Interface Setup

#### Identify Network Interface
```bash
# List available interfaces
ip link show

# Or use legacy command
ifconfig -a

# Example interfaces:
# eth0 - Management interface
# eth1 - Monitor interface (for packet capture)
```

#### Configure Monitor Interface
```bash
# Set interface in promiscuous mode
sudo ip link set eth1 promisc on

# Bring interface up without IP
sudo ip link set eth1 up

# Verify promiscuous mode
ip link show eth1
```

### Step 2: Configure A2Z IDS/IPS

#### Edit Configuration File
```bash
# Copy sample configuration
cp config/config.yaml /etc/a2z-ids/config.yaml

# Edit configuration
sudo nano /etc/a2z-ids/config.yaml
```

#### Key Configuration Settings
```yaml
# Network Capture Configuration
capture:
  interface: "eth1"  # Your monitoring interface
  mode: "passive"    # passive, inline, or hybrid
  buffer_size: "256MB"
  workers: 8         # Match your CPU cores
  promisc_mode: true
  snaplen: 65535
  
  # Packet filtering (optional)
  filter: "not host 192.168.1.100"  # Exclude management IP

# Detection Engine
detection:
  rule_files:
    - "/var/lib/a2z-ids/rules/snort-community.rules"
    - "/var/lib/a2z-ids/rules/emerging-threats.rules"
    - "/var/lib/a2z-ids/rules/custom.rules"
  
  enabled_categories:
    - "malware"
    - "exploit"
    - "trojan"
    - "web-application"
    - "network-scan"
    - "dos"
    - "sql-injection"
    - "xss"

# Alerting
alerting:
  outputs:
    - type: "json"
      file: "/var/log/a2z-ids/alerts.json"
    - type: "syslog"
      facility: "local0"
    - type: "webhook"
      url: "https://your-soc.example.com/api/alerts"
```

## 📋 Rule Management

### Step 1: Download Snort Community Rules

#### Option A: Direct Download
```bash
# Create rules directory
sudo mkdir -p /var/lib/a2z-ids/rules

# Download Snort Community Rules
cd /tmp
wget https://www.snort.org/rules/community -O snort-community-rules.tar.gz

# Extract rules
tar -xzf snort-community-rules.tar.gz
sudo cp community-rules/*.rules /var/lib/a2z-ids/rules/

# Rename for A2Z IDS
sudo mv /var/lib/a2z-ids/rules/community.rules \
       /var/lib/a2z-ids/rules/snort-community.rules
```

#### Option B: Use A2Z IDS Rule Manager
```bash
# Download and convert Snort rules
./a2z-ids rules update --source snort-community
./a2z-ids rules import --file /tmp/snort-community.rules
```

### Step 2: Download Additional Rule Sets

#### Emerging Threats Rules
```bash
# Download ET Open rules
wget https://rules.emergingthreats.net/open/suricata-6.0.9/emerging.rules.tar.gz
tar -xzf emerging.rules.tar.gz
sudo cp rules/*.rules /var/lib/a2z-ids/rules/

# Combine into single file
sudo cat /var/lib/a2z-ids/rules/emerging-*.rules > \
     /var/lib/a2z-ids/rules/emerging-threats.rules
```

#### OWASP ModSecurity Rules
```bash
# Download OWASP CRS
git clone https://github.com/coreruleset/coreruleset.git
cd coreruleset

# Convert ModSecurity rules to A2Z IDS format
./scripts/convert-modsec-rules.sh rules/ > /var/lib/a2z-ids/rules/owasp-crs.rules
```

### Step 3: Rule Configuration

#### Validate Rules
```bash
# Validate rule syntax
./a2z-ids rules validate --file /var/lib/a2z-ids/rules/snort-community.rules

# Test rule performance
./a2z-ids rules test --file /var/lib/a2z-ids/rules/snort-community.rules
```

#### Enable/Disable Rule Categories
```bash
# List available categories
./a2z-ids rules list --categories

# Enable specific categories
./a2z-ids rules enable --category malware
./a2z-ids rules enable --category web-application

# Disable noisy categories
./a2z-ids rules disable --category info
```

### Step 4: Custom Rules

#### Create Custom Rules Directory
```bash
sudo mkdir -p /var/lib/a2z-ids/rules/custom
```

#### Example Custom Rules
```bash
# Create custom.rules file
sudo nano /var/lib/a2z-ids/rules/custom.rules
```

```snort
# Custom A2Z IDS Rules
alert tcp any any -> $HOME_NET 22 (
    msg:"SSH Brute Force Attempt";
    flow:to_server,established;
    content:"SSH-";
    detection_filter:track by_src, count 5, seconds 60;
    classtype:attempted-recon;
    sid:1000001;
    rev:1;
)

alert tcp any any -> $HOME_NET 80 (
    msg:"Potential SQL Injection - Union Select";
    flow:to_server,established;
    content:"union"; nocase;
    content:"select"; nocase; distance:0; within:20;
    http_uri;
    classtype:web-application-attack;
    sid:1000002;
    rev:1;
)

alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"Potential Data Exfiltration - Large HTTPS Upload";
    flow:to_server,established;
    dsize:>1000000;
    threshold:type limit, track by_src, count 1, seconds 300;
    classtype:policy-violation;
    sid:1000003;
    rev:1;
)
```

## 📊 Monitoring Setup

### Step 1: Start A2Z IDS/IPS

#### Using Docker
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f a2z-ids-core
```

#### Using Native Installation
```bash
# Start core engine
sudo ./a2z-ids start --config /etc/a2z-ids/config.yaml --interface eth1

# Start in background
sudo ./a2z-ids start --config /etc/a2z-ids/config.yaml --interface eth1 --daemon
```

### Step 2: Monitor Performance

#### Real-time Monitoring
```bash
# Check packet processing stats
./a2z-ids stats --live

# Monitor memory usage
./a2z-ids stats --memory

# Check rule performance
./a2z-ids stats --rules
```

#### Web Dashboard
```bash
# Access web interface
http://localhost:3000

# Default credentials:
# Username: admin
# Password: a2z-admin-2024
```

### Step 3: Alert Management

#### View Alerts
```bash
# View recent alerts
tail -f /var/log/a2z-ids/alerts.json

# Query alerts by severity
./a2z-ids alerts --severity critical --last 24h

# Export alerts
./a2z-ids alerts export --format csv --output alerts.csv
```

#### Alert Integration
```bash
# Forward alerts to SIEM
curl -X POST http://your-siem.com/api/alerts \
  -H "Content-Type: application/json" \
  -d @/var/log/a2z-ids/alerts.json

# Send to Splunk
./scripts/splunk-forwarder.sh /var/log/a2z-ids/alerts.json
```

## 🔧 Advanced Configuration

### High-Performance Setup

#### Optimize for High Traffic
```yaml
# /etc/a2z-ids/config.yaml
capture:
  workers: 16                # Match CPU cores
  buffer_size: "1GB"         # Increase buffer
  batch_size: 128            # Larger batches
  
performance:
  cpu:
    max_threads: 16
    affinity: [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    priority: "high"
  
  memory:
    limit: "16GB"
    packet_pool_size: "2GB"
    rule_cache_size: "1GB"
    flow_cache_size: "4GB"
```

#### DPDK Acceleration (Optional)
```bash
# Install DPDK
sudo apt install dpdk dpdk-dev

# Configure hugepages
echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Bind interface to DPDK
sudo dpdk-devbind.py --bind=igb_uio eth1

# Update configuration
capture:
  engine: "dpdk"
  dpdk_port: 0
```

### Multi-Interface Setup

#### Configure Multiple Interfaces
```yaml
capture:
  interfaces:
    - name: "eth1"
      mode: "passive"
      filter: "vlan 100"
    - name: "eth2" 
      mode: "passive"
      filter: "vlan 200"
  
  load_balancing:
    enabled: true
    method: "round_robin"  # or "hash_ip"
```

## 🔍 Testing and Validation

### Step 1: Generate Test Traffic

#### Using Metasploit
```bash
# Test intrusion detection
msfconsole
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
set PORTS 1-1000
run
```

#### Using NMAP
```bash
# Port scan to trigger alerts
nmap -sS -O -A 192.168.1.100

# Aggressive scan
nmap -sV -sC -A -T4 192.168.1.0/24
```

### Step 2: Verify Detection
```bash
# Check if alerts were generated
grep "Port Scan" /var/log/a2z-ids/alerts.json

# View in web interface
http://localhost:3000/alerts

# Check specific rule triggers
./a2z-ids alerts --rule-id 1001 --last 1h
```

## 🔄 Maintenance and Updates

### Rule Updates
```bash
# Update Snort community rules
./a2z-ids rules update --source snort-community

# Update Emerging Threats rules
./a2z-ids rules update --source emerging-threats

# Reload rules without restart
./a2z-ids rules reload
```

### System Updates
```bash
# Update A2Z IDS components
make clean && make build-all

# Update Docker images
docker-compose pull
docker-compose up -d

# Backup configuration
sudo tar -czf a2z-ids-config-$(date +%Y%m%d).tar.gz /etc/a2z-ids/
```

## 🚨 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Fix permissions for capture interface
sudo setcap cap_net_raw,cap_net_admin=eip ./a2z-ids

# Or run with sudo
sudo ./a2z-ids start --config /etc/a2z-ids/config.yaml
```

#### High CPU Usage
```bash
# Reduce workers
workers: 4

# Lower rule sensitivity
detection_threshold: 0.8

# Disable non-critical rule categories
./a2z-ids rules disable --category info
```

#### Memory Issues
```bash
# Reduce memory limits
memory:
  limit: "4GB"
  packet_pool_size: "256MB"
  flow_cache_size: "512MB"
```

### Debugging Commands
```bash
# Enable debug logging
./a2z-ids start --log-level debug

# Test specific rule
./a2z-ids test rule --id 1001 --pcap test.pcap

# Validate configuration
./a2z-ids config validate
```

## 📞 Support and Resources

### Documentation
- **Installation Guide**: [docs/installation.md](docs/installation.md)
- **Rule Writing**: [docs/rule-writing.md](docs/rule-writing.md)
- **API Reference**: [docs/api.md](docs/api.md)

### Community Resources
- **Snort Community Rules**: https://www.snort.org/downloads
- **Emerging Threats**: https://rules.emergingthreats.net/
- **OWASP ModSecurity**: https://github.com/coreruleset/coreruleset

### Commercial Support
- **Email**: support@a2zsoc.com
- **Documentation**: https://docs.a2zsoc.com/ids-ips
- **Community Forum**: https://community.a2zsoc.com

---

**🎉 Congratulations!** Your A2Z IDS/IPS system is now configured and monitoring your network. Check the web dashboard at `http://localhost:3000` to view real-time alerts and network activity. 