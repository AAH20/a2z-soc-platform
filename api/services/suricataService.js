const fs = require('fs').promises;
const path = require('path');
const { spawn, exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

class SuricataService {
  constructor() {
    this.suricataPath = process.env.SURICATA_PATH || '/usr/bin/suricata';
    this.configPath = process.env.SURICATA_CONFIG_PATH || '/etc/suricata/suricata.yaml';
    this.rulesPath = process.env.SURICATA_RULES_PATH || '/var/lib/suricata/rules';
    this.logPath = process.env.SURICATA_LOG_PATH || '/var/log/suricata';
    this.eveLogFile = path.join(this.logPath, 'eve.json');
    this.pidFile = path.join(this.logPath, 'suricata.pid');
    this.socketPath = process.env.SURICATA_SOCKET_PATH || '/var/run/suricata/suricata-command.socket';
    this.isRunning = false;
    this.suricataProcess = null;
    
    this.initializeService();
  }

  async initializeService() {
    try {
      await this.checkSuricataInstallation();
      await this.createDirectories();
      await this.updateRulesFromSources();
      console.log('Suricata service initialized successfully');
    } catch (error) {
      console.error('Failed to initialize Suricata service:', error.message);
    }
  }

  async checkSuricataInstallation() {
    try {
      const { stdout } = await execAsync(`${this.suricataPath} --build-info`);
      const versionMatch = stdout.match(/This is Suricata version ([\d\.]+)/);
      const version = versionMatch ? versionMatch[1] : 'Unknown';
      
      return {
        installed: true,
        version,
        path: this.suricataPath,
        buildInfo: stdout
      };
    } catch (error) {
      throw new Error(`Suricata not found at ${this.suricataPath}: ${error.message}`);
    }
  }

  async createDirectories() {
    const directories = [this.logPath, this.rulesPath, path.dirname(this.socketPath)];
    
    for (const dir of directories) {
      try {
        await fs.mkdir(dir, { recursive: true });
      } catch (error) {
        console.warn(`Could not create directory ${dir}:`, error.message);
      }
    }
  }

  // Service Management
  async getServiceStatus() {
    try {
      const isRunning = await this.isSuricataRunning();
      const stats = isRunning ? await this.getPerformanceStats() : null;
      const version = await this.checkSuricataInstallation();
      
      return {
        status: isRunning ? 'running' : 'stopped',
        pid: isRunning ? await this.getSuricataPid() : null,
        version: version.version,
        uptime: isRunning ? await this.getUptime() : null,
        mode: isRunning ? await this.getRunMode() : null,
        stats,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'error',
        message: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  async isSuricataRunning() {
    try {
      const pidExists = await fs.access(this.pidFile).then(() => true).catch(() => false);
      if (!pidExists) return false;
      
      const pid = await fs.readFile(this.pidFile, 'utf8');
      const { stdout } = await execAsync(`ps -p ${pid.trim()} -o pid=`);
      return stdout.trim() !== '';
    } catch (error) {
      return false;
    }
  }

  async getSuricataPid() {
    try {
      const pid = await fs.readFile(this.pidFile, 'utf8');
      return parseInt(pid.trim());
    } catch (error) {
      return null;
    }
  }

  async startSuricata(networkInterface = 'eth0', options = {}) {
    try {
      if (await this.isSuricataRunning()) {
        throw new Error('Suricata is already running');
      }

      const args = [
        '-c', this.configPath,
        '-i', networkInterface,
        '-D', // Daemon mode
        '--pidfile', this.pidFile,
        '-l', this.logPath
      ];

      if (options.promiscuous !== false) {
        args.push('--set', 'af-packet.0.promisc=yes');
      }

      if (options.verbose) {
        args.push('-v');
      }

      if (options.statsInterval) {
        args.push('--set', `stats.interval=${options.statsInterval}`);
      }

      const suricataProcess = spawn(this.suricataPath, args, {
        detached: true,
        stdio: ['ignore', 'ignore', 'ignore']
      });

      suricataProcess.unref();

      // Wait a moment to check if process started successfully
      await new Promise(resolve => setTimeout(resolve, 3000));

      if (await this.isSuricataRunning()) {
        this.isRunning = true;
        return {
          status: 'started',
          pid: await this.getSuricataPid(),
          interface: networkInterface,
          timestamp: new Date().toISOString()
        };
      } else {
        throw new Error('Failed to start Suricata process');
      }
    } catch (error) {
      throw new Error(`Failed to start Suricata: ${error.message}`);
    }
  }

  async stopSuricata() {
    try {
      const pid = await this.getSuricataPid();
      if (!pid) {
        throw new Error('Suricata is not running');
      }

      await execAsync(`kill -TERM ${pid}`);
      
      // Wait for graceful shutdown
      let attempts = 0;
      while (await this.isSuricataRunning() && attempts < 15) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        attempts++;
      }

      if (await this.isSuricataRunning()) {
        // Force kill if graceful shutdown failed
        await execAsync(`kill -KILL ${pid}`);
      }

      this.isRunning = false;
      
      return {
        status: 'stopped',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to stop Suricata: ${error.message}`);
    }
  }

  async restartSuricata(networkInterface = 'eth0', options = {}) {
    try {
      if (await this.isSuricataRunning()) {
        await this.stopSuricata();
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
      return await this.startSuricata(networkInterface, options);
    } catch (error) {
      throw new Error(`Failed to restart Suricata: ${error.message}`);
    }
  }

  async reloadRules() {
    try {
      if (!await this.isSuricataRunning()) {
        throw new Error('Suricata is not running');
      }

      const pid = await this.getSuricataPid();
      await execAsync(`kill -USR2 ${pid}`);
      
      return {
        status: 'reloaded',
        timestamp: new Date().toISOString(),
        message: 'Rules reloaded successfully'
      };
    } catch (error) {
      throw new Error(`Failed to reload rules: ${error.message}`);
    }
  }

  // Rules Management
  async getRules(source = null) {
    try {
      const rulesDir = this.rulesPath;
      const files = await fs.readdir(rulesDir);
      const ruleFiles = files.filter(file => file.endsWith('.rules'));
      
      if (source) {
        const sourceFile = `${source}.rules`;
        if (ruleFiles.includes(sourceFile)) {
          return await this.parseRuleFile(path.join(rulesDir, sourceFile));
        } else {
          return [];
        }
      }

      const allRules = [];
      for (const file of ruleFiles) {
        const rules = await this.parseRuleFile(path.join(rulesDir, file));
        allRules.push(...rules.map(rule => ({ ...rule, source: file.replace('.rules', '') })));
      }

      return allRules;
    } catch (error) {
      throw new Error(`Failed to get rules: ${error.message}`);
    }
  }

  async parseRuleFile(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      const lines = content.split('\n');
      const rules = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;

        const rule = this.parseRule(line, i + 1);
        if (rule) {
          rules.push(rule);
        }
      }

      return rules;
    } catch (error) {
      throw new Error(`Failed to parse rule file ${filePath}: ${error.message}`);
    }
  }

  parseRule(ruleText, lineNumber) {
    try {
      // Suricata rule parsing (similar to Snort but with some differences)
      const rulePattern = /^(alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s+\((.*)\)$/;
      const match = ruleText.match(rulePattern);

      if (!match) return null;

      const [, action, protocol, srcIp, srcPort, direction, destIp, destPort, options] = match;
      
      // Parse options
      const parsedOptions = this.parseRuleOptions(options);

      return {
        id: parsedOptions.sid || `line_${lineNumber}`,
        action,
        protocol,
        source: {
          ip: srcIp,
          port: srcPort
        },
        destination: {
          ip: destIp,
          port: destPort
        },
        direction,
        message: parsedOptions.msg || 'No message',
        classification: parsedOptions.classtype || 'unknown',
        priority: parsedOptions.priority || 3,
        revision: parsedOptions.rev || 1,
        reference: parsedOptions.reference || [],
        metadata: parsedOptions.metadata || [],
        enabled: !ruleText.startsWith('#'),
        raw: ruleText,
        lineNumber
      };
    } catch (error) {
      console.warn(`Failed to parse rule at line ${lineNumber}:`, error.message);
      return null;
    }
  }

  parseRuleOptions(optionsString) {
    const options = {};
    const pairs = optionsString.split(';');

    for (const pair of pairs) {
      const trimmed = pair.trim();
      if (!trimmed) continue;

      const colonIndex = trimmed.indexOf(':');
      if (colonIndex === -1) {
        options[trimmed] = true;
      } else {
        const key = trimmed.substring(0, colonIndex).trim();
        const value = trimmed.substring(colonIndex + 1).trim().replace(/^"(.+)"$/, '$1');
        
        if (key === 'reference' || key === 'metadata') {
          if (!options[key]) options[key] = [];
          options[key].push(value);
        } else {
          options[key] = value;
        }
      }
    }

    return options;
  }

  async getRuleSources() {
    try {
      const files = await fs.readdir(this.rulesPath);
      const sources = files
        .filter(file => file.endsWith('.rules'))
        .map(file => file.replace('.rules', ''))
        .sort();

      const sourcesWithStats = [];
      for (const source of sources) {
        const rules = await this.getRules(source);
        sourcesWithStats.push({
          name: source,
          rulesCount: rules.length,
          enabledCount: rules.filter(rule => rule.enabled).length,
          file: `${source}.rules`
        });
      }

      return sourcesWithStats;
    } catch (error) {
      throw new Error(`Failed to get rule sources: ${error.message}`);
    }
  }

  async updateRulesFromSources() {
    // Mock implementation with various rule sources
    const mockRules = {
      'suricata.rules': `# Core Suricata rules
alert http any any -> any any (msg:"HTTP traffic detected"; flow:established,to_server; http.method; content:"GET"; sid:3000001; rev:1;)
alert tls any any -> any 443 (msg:"TLS traffic detected"; flow:established; tls.subject; content:"CN="; sid:3000002; rev:1;)`,
      
      'emerging-threats.rules': `# Emerging Threats rules
alert tcp any any -> any any (msg:"ET MALWARE Suspicious User-Agent"; content:"User-Agent: "; http_header; content:"suspicious"; sid:3000003; rev:1;)
alert dns any any -> any 53 (msg:"ET DNS Malicious domain lookup"; content:"|01 00 00 01|"; dns.query; content:"malicious.com"; sid:3000004; rev:1;)`,
      
      'local.rules': `# Local custom rules
alert tcp any any -> any 22 (msg:"SSH connection attempt"; flow:to_server,established; content:"SSH"; sid:3000005; rev:1;)
alert icmp any any -> any any (msg:"ICMP ping detected"; itype:8; sid:3000006; rev:1;)`
    };

    try {
      for (const [filename, content] of Object.entries(mockRules)) {
        const filePath = path.join(this.rulesPath, filename);
        await fs.writeFile(filePath, content);
      }
      
      return {
        status: 'success',
        updated: Object.keys(mockRules).length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to update rules: ${error.message}`);
    }
  }

  // Alert Management (Eve JSON format)
  async getAlerts(params = {}) {
    try {
      const alerts = await this.parseEveLogFile(params);
      
      // Apply filters
      let filteredAlerts = alerts.filter(entry => entry.event_type === 'alert');
      
      if (params.severity) {
        filteredAlerts = filteredAlerts.filter(alert => 
          alert.alert && alert.alert.severity <= parseInt(params.severity)
        );
      }

      if (params.timeRange) {
        const from = new Date(params.timeRange.from);
        const to = new Date(params.timeRange.to);
        filteredAlerts = filteredAlerts.filter(alert => {
          const alertTime = new Date(alert.timestamp);
          return alertTime >= from && alertTime <= to;
        });
      }

      if (params.category) {
        filteredAlerts = filteredAlerts.filter(alert => 
          alert.alert && alert.alert.category === params.category
        );
      }

      // Sort by timestamp (newest first)
      filteredAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      // Pagination
      const limit = params.limit || 100;
      const offset = params.offset || 0;
      const paginatedAlerts = filteredAlerts.slice(offset, offset + limit);

      return {
        total: filteredAlerts.length,
        alerts: paginatedAlerts,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get alerts: ${error.message}`);
    }
  }

  async parseEveLogFile(params = {}) {
    try {
      const eveLogExists = await fs.access(this.eveLogFile).then(() => true).catch(() => false);
      if (!eveLogExists) {
        return [];
      }

      const content = await fs.readFile(this.eveLogFile, 'utf8');
      const lines = content.trim().split('\n').filter(line => line.trim());
      const events = [];

      for (const line of lines) {
        try {
          const event = JSON.parse(line);
          events.push(event);
        } catch (parseError) {
          console.warn('Failed to parse eve log line:', parseError.message);
        }
      }

      return events;
    } catch (error) {
      console.warn('Failed to parse eve log file:', error.message);
      return [];
    }
  }

  async getFlowData(params = {}) {
    try {
      const events = await this.parseEveLogFile(params);
      const flows = events.filter(entry => entry.event_type === 'flow');
      
      return {
        total: flows.length,
        flows: flows.slice(0, params.limit || 100),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get flow data: ${error.message}`);
    }
  }

  async getHttpLogs(params = {}) {
    try {
      const events = await this.parseEveLogFile(params);
      const httpLogs = events.filter(entry => entry.event_type === 'http');
      
      return {
        total: httpLogs.length,
        logs: httpLogs.slice(0, params.limit || 100),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get HTTP logs: ${error.message}`);
    }
  }

  async getDnsLogs(params = {}) {
    try {
      const events = await this.parseEveLogFile(params);
      const dnsLogs = events.filter(entry => entry.event_type === 'dns');
      
      return {
        total: dnsLogs.length,
        logs: dnsLogs.slice(0, params.limit || 100),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get DNS logs: ${error.message}`);
    }
  }

  // Statistics and Performance
  async getPerformanceStats() {
    try {
      // Mock implementation - in reality this would parse Suricata stats or use Unix socket
      return {
        packets_processed: Math.floor(Math.random() * 5000000),
        packets_dropped: Math.floor(Math.random() * 1000),
        alerts_generated: Math.floor(Math.random() * 2000),
        flows_tracked: Math.floor(Math.random() * 100000),
        memory_usage_mb: Math.floor(Math.random() * 1024),
        cpu_usage_percent: Math.floor(Math.random() * 100),
        uptime_seconds: Math.floor(Math.random() * 86400),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get performance stats: ${error.message}`);
    }
  }

  async getUptime() {
    try {
      const pid = await this.getSuricataPid();
      if (!pid) return null;

      const { stdout } = await execAsync(`ps -o etime= -p ${pid}`);
      return stdout.trim();
    } catch (error) {
      return null;
    }
  }

  async getRunMode() {
    try {
      // Mock implementation - could be determined from config or process arguments
      return 'IDS';
    } catch (error) {
      return 'Unknown';
    }
  }

  async getAlertStatistics(timeRange = '24h') {
    try {
      const alerts = await this.getAlerts({ 
        timeRange: {
          from: new Date(Date.now() - (timeRange === '24h' ? 86400000 : 3600000)).toISOString(),
          to: new Date().toISOString()
        }
      });

      const stats = {
        total: alerts.total,
        by_severity: {
          1: 0, // Critical
          2: 0, // High
          3: 0, // Medium
          4: 0  // Low
        },
        by_category: {},
        by_hour: new Array(24).fill(0),
        top_source_ips: {},
        top_destination_ips: {},
        top_signatures: {},
        timestamp: new Date().toISOString()
      };

      alerts.alerts.forEach(alert => {
        if (!alert.alert) return;

        // Count by severity
        const severity = alert.alert.severity || 4;
        stats.by_severity[severity]++;

        // Count by category
        const category = alert.alert.category || 'Unknown';
        stats.by_category[category] = (stats.by_category[category] || 0) + 1;

        // Count by hour
        const hour = new Date(alert.timestamp).getHours();
        stats.by_hour[hour]++;

        // Count source IPs
        if (alert.src_ip) {
          stats.top_source_ips[alert.src_ip] = (stats.top_source_ips[alert.src_ip] || 0) + 1;
        }

        // Count destination IPs
        if (alert.dest_ip) {
          stats.top_destination_ips[alert.dest_ip] = (stats.top_destination_ips[alert.dest_ip] || 0) + 1;
        }

        // Count signatures
        if (alert.alert.signature) {
          stats.top_signatures[alert.alert.signature] = (stats.top_signatures[alert.alert.signature] || 0) + 1;
        }
      });

      // Convert objects to sorted arrays
      stats.top_source_ips = Object.entries(stats.top_source_ips)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }));

      stats.top_destination_ips = Object.entries(stats.top_destination_ips)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }));

      stats.top_signatures = Object.entries(stats.top_signatures)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([signature, count]) => ({ signature, count }));

      return stats;
    } catch (error) {
      throw new Error(`Failed to get alert statistics: ${error.message}`);
    }
  }

  // Configuration Management
  async getConfiguration() {
    try {
      const config = await fs.readFile(this.configPath, 'utf8');
      return {
        config_file: this.configPath,
        content: config,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to read configuration: ${error.message}`);
    }
  }

  async validateConfiguration() {
    try {
      const { stdout, stderr } = await execAsync(`${this.suricataPath} -T -c ${this.configPath}`);
      
      return {
        valid: true,
        output: stdout,
        errors: stderr,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        valid: false,
        output: error.stdout || '',
        errors: error.stderr || error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  // Health Check
  async testConnection() {
    try {
      const status = await this.getServiceStatus();
      const version = await this.checkSuricataInstallation();
      
      return {
        status: 'connected',
        service_status: status.status,
        version: version.version,
        timestamp: new Date().toISOString(),
        message: 'Suricata service is accessible'
      };
    } catch (error) {
      return {
        status: 'error',
        timestamp: new Date().toISOString(),
        message: error.message
      };
    }
  }

  // File Extraction and Analysis
  async getFileExtractions(params = {}) {
    try {
      const events = await this.parseEveLogFile(params);
      const fileEvents = events.filter(entry => entry.event_type === 'fileinfo');
      
      return {
        total: fileEvents.length,
        files: fileEvents.slice(0, params.limit || 100),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get file extractions: ${error.message}`);
    }
  }

  // TLS/SSL Analysis
  async getTlsEvents(params = {}) {
    try {
      const events = await this.parseEveLogFile(params);
      const tlsEvents = events.filter(entry => entry.event_type === 'tls');
      
      return {
        total: tlsEvents.length,
        events: tlsEvents.slice(0, params.limit || 100),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to get TLS events: ${error.message}`);
    }
  }
}

module.exports = SuricataService; 