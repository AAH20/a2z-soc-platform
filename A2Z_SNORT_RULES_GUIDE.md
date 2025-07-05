# 📋 A2Z IDS/IPS Snort Rules Integration Guide

Complete guide for integrating and managing Snort community rules with A2Z IDS/IPS.

## 📖 Table of Contents
1. [Snort Rules Overview](#snort-rules-overview)
2. [Rule Sources](#rule-sources)
3. [Installation & Setup](#installation--setup)
4. [Rule Management](#rule-management)
5. [Performance Optimization](#performance-optimization)
6. [Custom Rules](#custom-rules)
7. [Troubleshooting](#troubleshooting)

## 🎯 Snort Rules Overview

### What are Snort Rules?
Snort rules are detection signatures that identify malicious or suspicious network traffic patterns. A2Z IDS/IPS is fully compatible with Snort rule syntax and can use community rules directly.

### Rule Format
```snort
alert tcp any any -> $HOME_NET 80 (
    msg:"HTTP malicious request";
    content:"payload"; 
    sid:1000001; 
    rev:1;
)
```

### Key Components
- **Action**: alert, log, pass, drop, reject
- **Protocol**: tcp, udp, icmp, ip
- **Source/Dest**: IP addresses and ports
- **Rule Options**: detection criteria and metadata

## 📦 Rule Sources

### 1. Snort Community Rules (Free)
- **URL**: https://www.snort.org/downloads
- **Coverage**: Basic network threats
- **Update Frequency**: Quarterly
- **License**: Free for personal/commercial use

### 2. Emerging Threats Open (Free)
- **URL**: https://rules.emergingthreats.net/
- **Coverage**: Current threats and indicators
- **Update Frequency**: Daily
- **License**: BSD-style license

### 3. Registered User Rules (Free Registration)
- **URL**: https://www.snort.org/users/sign_up
- **Coverage**: Extended rule set
- **Update Frequency**: Monthly
- **License**: Requires registration

### 4. Subscriber Rules (Commercial)
- **URL**: https://www.snort.org/products
- **Coverage**: Complete threat coverage
- **Update Frequency**: Real-time
- **License**: Commercial license required

## 🚀 Installation & Setup

### Automated Installation
```bash
# Download and run the installation script
curl -sSL https://raw.githubusercontent.com/a2z-soc/a2z-ids-ips/main/scripts/quick-install.sh | sudo bash

# Or use the manual approach below
```

### Manual Installation

#### Step 1: Download Snort Community Rules
```bash
# Create rules directory
sudo mkdir -p /var/lib/a2z-ids/rules

# Download community rules
wget -O /tmp/snort-community-rules.tar.gz \
  "https://www.snort.org/rules/community"

# Extract rules
cd /tmp
tar -xzf snort-community-rules.tar.gz

# Copy rules to A2Z IDS directory
sudo cp community-rules/*.rules /var/lib/a2z-ids/rules/
sudo mv /var/lib/a2z-ids/rules/community.rules \
     /var/lib/a2z-ids/rules/snort-community.rules
```

#### Step 2: Download Emerging Threats Rules
```bash
# Download ET Open rules
wget -O /tmp/emerging-rules.tar.gz \
  "https://rules.emergingthreats.net/open/suricata-6.0.9/emerging.rules.tar.gz"

# Extract and organize
cd /tmp
tar -xzf emerging-rules.tar.gz

# Combine emerging threat rules
sudo cat rules/emerging-*.rules > \
     /var/lib/a2z-ids/rules/emerging-threats.rules
```

#### Step 3: Download Registered User Rules (Optional)
```bash
# Register at snort.org and get your oinkcode
OINKCODE="your_oinkcode_here"

# Download registered rules
wget -O /tmp/snortrules-snapshot.tar.gz \
  "https://www.snort.org/reg-rules/snortrules-snapshot.tar.gz/${OINKCODE}"

# Extract and copy
tar -xzf /tmp/snortrules-snapshot.tar.gz
sudo cp snortrules-snapshot-*/rules/*.rules /var/lib/a2z-ids/rules/
```

### Rule Directory Structure
```
/var/lib/a2z-ids/rules/
├── snort-community.rules      # Community rules
├── emerging-threats.rules     # ET Open rules
├── registered-rules.rules     # Registered user rules
├── custom.rules              # Your custom rules
├── disabled/                 # Disabled rules
└── local/                   # Local modifications
```

## 🔧 Rule Management

### Using A2Z IDS CLI

#### List Available Rules
```bash
# List all rules
./a2z-ids rules list

# List by category
./a2z-ids rules list --category malware

# Show rule details
./a2z-ids rules show --sid 1000001
```

#### Import Rules
```bash
# Import Snort community rules
./a2z-ids rules import --file /var/lib/a2z-ids/rules/snort-community.rules

# Import with category filtering
./a2z-ids rules import --file rules.rules --categories "malware,exploit"

# Import and enable immediately
./a2z-ids rules import --file rules.rules --enable
```

#### Enable/Disable Rules
```bash
# Enable specific rule
./a2z-ids rules enable --sid 1000001

# Disable rule
./a2z-ids rules disable --sid 1000001

# Enable by category
./a2z-ids rules enable --category web-application

# Disable noisy categories
./a2z-ids rules disable --category info
```

#### Update Rules
```bash
# Update all rule sources
./a2z-ids rules update --all

# Update specific source
./a2z-ids rules update --source snort-community
./a2z-ids rules update --source emerging-threats

# Update and reload (no restart required)
./a2z-ids rules update --reload
```

### Configuration File Management

#### Rule Configuration in config.yaml
```yaml
detection:
  rule_files:
    - "/var/lib/a2z-ids/rules/snort-community.rules"
    - "/var/lib/a2z-ids/rules/emerging-threats.rules"
    - "/var/lib/a2z-ids/rules/registered-rules.rules"
    - "/var/lib/a2z-ids/rules/custom.rules"
  
  # Rule categories to enable
  enabled_categories:
    - "malware"
    - "exploit"
    - "trojan"
    - "web-application"
    - "network-scan"
    - "dos"
    - "sql-injection"
    - "xss"
    - "policy-violation"
  
  # Rule categories to disable
  disabled_categories:
    - "info"
    - "misc"
  
  # Rule performance settings
  rule_processing:
    max_rules: 50000
    rule_cache_size: "256MB"
    pattern_matching: "hyperscan"  # hyperscan, pcre
    
  # Rule threshold settings
  thresholds:
    global_threshold: 100  # Max alerts per minute
    rule_specific:
      - sid: 1000001
        threshold: 10
        window: 60
```

### Web Interface Management

#### Accessing Rule Management
```bash
# Open web interface
http://localhost:3000/rules

# Default credentials
Username: admin
Password: a2z-admin-2024
```

#### Web Interface Features
- **Rule Browser**: Browse and search rules by category
- **Rule Editor**: Modify rules with syntax highlighting
- **Performance Monitor**: View rule performance metrics
- **Bulk Operations**: Enable/disable multiple rules
- **Import/Export**: Manage rule sets

## ⚡ Performance Optimization

### Rule Performance Analysis
```bash
# Analyze rule performance
./a2z-ids rules analyze --performance

# Show slowest rules
./a2z-ids rules analyze --slowest 10

# Show rule statistics
./a2z-ids rules stats --detailed
```

### Optimization Strategies

#### 1. Rule Prioritization
```yaml
# Prioritize critical rules
rule_priority:
  high:
    - "malware"
    - "exploit"
    - "trojan"
  medium:
    - "web-application"
    - "network-scan"
  low:
    - "policy-violation"
    - "info"
```

#### 2. Pattern Matching Optimization
```yaml
detection:
  pattern_matching:
    engine: "hyperscan"        # Fastest for multi-pattern
    compile_mode: "hs_mode_block"
    cpu_features: "auto"       # Use CPU-specific optimizations
    case_sensitive: false      # Disable if not needed
```

#### 3. Rule Thresholds
```snort
# Add thresholds to high-volume rules
alert tcp any any -> any 80 (
    msg:"HTTP request";
    content:"GET";
    threshold:type limit, track by_src, count 100, seconds 60;
    sid:1000001;
)
```

#### 4. Network Segmentation
```yaml
# Define network variables for better performance
network_variables:
  HOME_NET: "192.168.0.0/16,10.0.0.0/8"
  EXTERNAL_NET: "!$HOME_NET"
  DMZ_NET: "192.168.100.0/24"
  WEB_SERVERS: "192.168.100.10-20"
```

### Memory and CPU Optimization
```yaml
performance:
  rule_engine:
    workers: 8                 # Match CPU cores
    memory_limit: "2GB"        # Rule engine memory
    cache_size: "512MB"        # Pattern cache
    
  packet_processing:
    batch_size: 64            # Process packets in batches
    queue_size: 10000         # Packet queue size
```

## ✏️ Custom Rules

### Creating Custom Rules

#### Basic Custom Rule
```snort
# SSH brute force detection
alert tcp any any -> $HOME_NET 22 (
    msg:"SSH Brute Force Attack";
    flow:to_server,established;
    content:"SSH-";
    detection_filter:track by_src, count 5, seconds 60;
    classtype:attempted-recon;
    reference:url,attack.mitre.org/techniques/T1110;
    sid:1000001;
    rev:1;
)
```

#### Advanced Custom Rule with Multiple Conditions
```snort
# Detect potential data exfiltration
alert tcp $HOME_NET any -> $EXTERNAL_NET [443,993,995] (
    msg:"Potential Data Exfiltration - Large SSL Upload";
    flow:to_server,established;
    dsize:>1000000;
    flowbits:set,large_upload;
    threshold:type limit, track by_src, count 3, seconds 300;
    classtype:policy-violation;
    reference:url,attack.mitre.org/techniques/T1041;
    sid:1000002;
    rev:1;
)
```

#### Rule with HTTP Inspection
```snort
# SQL injection detection
alert tcp any any -> $HOME_NET [80,443] (
    msg:"SQL Injection Attempt - Union Select";
    flow:to_server,established;
    content:"union"; nocase; http_uri;
    content:"select"; nocase; http_uri; distance:0; within:50;
    pcre:"/union\s+select/Ui";
    classtype:web-application-attack;
    reference:url,owasp.org/www-community/attacks/SQL_Injection;
    sid:1000003;
    rev:1;
)
```

### Custom Rule Templates

#### Network Reconnaissance
```snort
# Port scan detection
alert tcp any any -> $HOME_NET any (
    msg:"Port Scan Detected";
    flags:S;
    detection_filter:track by_src, count 10, seconds 60;
    classtype:attempted-recon;
    sid:1000010;
    rev:1;
)
```

#### Malware Communication
```snort
# C2 beacon detection
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Possible C2 Beacon";
    flow:to_server,established;
    dsize:100<>200;
    detection_filter:track by_src, count 10, seconds 600;
    classtype:trojan-activity;
    sid:1000020;
    rev:1;
)
```

### Rule Testing
```bash
# Test rule syntax
./a2z-ids rules validate --file custom.rules

# Test rule against PCAP
./a2z-ids rules test --rule-id 1000001 --pcap test.pcap

# Performance test
./a2z-ids rules benchmark --file custom.rules
```

## 🔍 Rule Categories and Organization

### Standard Categories
- **malware**: Malware detection rules
- **exploit**: Exploit attempt detection
- **trojan**: Trojan horse activity
- **web-application**: Web application attacks
- **network-scan**: Network reconnaissance
- **dos**: Denial of service attacks
- **sql-injection**: SQL injection attempts
- **xss**: Cross-site scripting attacks
- **policy-violation**: Policy violations
- **info**: Informational rules

### Organizing Rules by Threat Intelligence
```bash
# Create threat-specific rule files
/var/lib/a2z-ids/rules/
├── apt/
│   ├── apt28.rules
│   ├── apt29.rules
│   └── lazarus.rules
├── malware-families/
│   ├── emotet.rules
│   ├── trickbot.rules
│   └── ransomware.rules
└── industry-specific/
    ├── financial.rules
    ├── healthcare.rules
    └── manufacturing.rules
```

## 🚨 Troubleshooting

### Common Issues

#### Rules Not Loading
```bash
# Check rule syntax
./a2z-ids rules validate --file /var/lib/a2z-ids/rules/snort-community.rules

# Check file permissions
ls -la /var/lib/a2z-ids/rules/

# Fix permissions
sudo chown a2z-ids:a2z-ids /var/lib/a2z-ids/rules/*.rules
sudo chmod 644 /var/lib/a2z-ids/rules/*.rules
```

#### High False Positives
```bash
# Analyze alert patterns
./a2z-ids alerts analyze --false-positives

# Tune specific rules
./a2z-ids rules tune --sid 1000001 --threshold 50

# Disable problematic rules
./a2z-ids rules disable --category info
```

#### Performance Issues
```bash
# Check rule performance
./a2z-ids rules stats --performance

# Disable slow rules
./a2z-ids rules disable --slow-rules

# Optimize pattern matching
./a2z-ids config set detection.pattern_matching.engine hyperscan
```

#### Rule Update Failures
```bash
# Check network connectivity
curl -I https://www.snort.org/rules/community

# Manual download
wget -O /tmp/rules.tar.gz "https://www.snort.org/rules/community"

# Clear rule cache
./a2z-ids rules clear-cache
```

### Debug Commands
```bash
# Enable rule debugging
./a2z-ids start --debug-rules

# Test specific rule
./a2z-ids debug rule --sid 1000001 --packet-file test.pcap

# Rule engine status
./a2z-ids status --rule-engine

# Memory usage by rules
./a2z-ids stats --memory --rules
```

## 📚 Additional Resources

### Rule Writing References
- **Snort Manual**: https://snort.org/documents
- **Rule Writing Guide**: https://snort.org/faq/readme-rule-writing
- **PCRE Reference**: https://www.pcre.org/original/doc/html/

### Threat Intelligence Sources
- **MITRE ATT&CK**: https://attack.mitre.org/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cybersecurity
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/

### Community Resources
- **Snort Community**: https://snort.org/community
- **Emerging Threats**: https://community.emergingthreats.net/
- **A2Z SOC Forum**: https://community.a2zsoc.com

## 🔄 Automated Rule Management

### Rule Update Automation
```bash
# Create cron job for daily updates
echo "0 2 * * * /usr/local/bin/a2z-ids rules update --all --reload" | sudo crontab -

# Weekly rule cleanup
echo "0 3 * * 0 /usr/local/bin/a2z-ids rules cleanup --old" | sudo crontab -
```

### Monitoring Rule Performance
```bash
# Daily performance report
./a2z-ids rules report --performance --email admin@company.com

# Alert on rule failures
./a2z-ids rules monitor --failures --webhook https://alerts.company.com
```

---

**🎉 Success!** You now have a comprehensive understanding of how to manage Snort community rules with A2Z IDS/IPS. For additional support, visit our [documentation portal](https://docs.a2zsoc.com/ids-ips) or join our [community forum](https://community.a2zsoc.com). 