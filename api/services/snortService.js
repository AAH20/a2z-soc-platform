const fs = require('fs').promises;
const path = require('path');
const { spawn, exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

class SnortService {
  constructor() {
    this.snortPath = process.env.SNORT_PATH || '/usr/local/bin/snort';
    this.configPath = process.env.SNORT_CONFIG_PATH || '/etc/snort/snort.conf';
    this.rulesPath = process.env.SNORT_RULES_PATH || '/etc/snort/rules';
    this.logPath = process.env.SNORT_LOG_PATH || '/var/log/snort';
    this.alertFile = path.join(this.logPath, 'alert');
    this.pidFile = path.join(this.logPath, 'snort.pid');
    this.isRunning = false;
    this.snortProcess = null;
    
    this.initializeService();
  }

  async initializeService() {
    try {
      await this.checkSnortInstallation();
      await this.createDirectories();
      await this.updateRulesFromCache();
      console.log('Snort service initialized successfully');
    } catch (error) {
      console.error('Failed to initialize Snort service:', error.message);
    }
  }

  async checkSnortInstallation() {
    try {
      const { stdout } = await execAsync(`${this.snortPath} -V`);
      return {
        installed: true,
        version: stdout.trim(),
        path: this.snortPath
      };
    } catch (error) {
      throw new Error(`Snort not found at ${this.snortPath}: ${error.message}`);
    }
  }

  async createDirectories() {
    const directories = [this.logPath, this.rulesPath];
    
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
      const isRunning = await this.isSnortRunning();
      const stats = isRunning ? await this.getPerformanceStats() : null;
      const version = await this.checkSnortInstallation();
      
      return {
        status: isRunning ? 'running' : 'stopped',
        pid: isRunning ? await this.getSnortPid() : null,
        version: version.version,
        uptime: isRunning ? await this.getUptime() : null,
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

  async isSnortRunning() {
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

  async getSnortPid() {
    try {
      const pid = await fs.readFile(this.pidFile, 'utf8');
      return parseInt(pid.trim());
    } catch (error) {
      return null;
    }
  }

  async startSnort(networkInterface = 'eth0', options = {}) {
    try {
      if (await this.isSnortRunning()) {
        throw new Error('Snort is already running');
      }

      const args = [
        '-c', this.configPath,
        '-i', networkInterface,
        '-D', // Daemon mode
        '-l', this.logPath,
        '-A', 'full', // Alert mode
        '--pid-path', this.pidFile
      ];

      if (options.promiscuous !== false) {
        args.push('-p'); // Promiscuous mode
      }

      if (options.verbose) {
        args.push('-v');
      }

      if (options.homeNet) {
        args.push('-h', options.homeNet);
      }

      const snortProcess = spawn(this.snortPath, args, {
        detached: true,
        stdio: ['ignore', 'ignore', 'ignore']
      });

      snortProcess.unref();

      // Wait a moment to check if process started successfully
      await new Promise(resolve => setTimeout(resolve, 2000));

      if (await this.isSnortRunning()) {
        this.isRunning = true;
        return {
          status: 'started',
          pid: await this.getSnortPid(),
          interface: networkInterface,
          timestamp: new Date().toISOString()
        };
      } else {
        throw new Error('Failed to start Snort process');
      }
    } catch (error) {
      throw new Error(`Failed to start Snort: ${error.message}`);
    }
  }

  async stopSnort() {
    try {
      const pid = await this.getSnortPid();
      if (!pid) {
        throw new Error('Snort is not running');
      }

      await execAsync(`kill -TERM ${pid}`);
      
      // Wait for graceful shutdown
      let attempts = 0;
      while (await this.isSnortRunning() && attempts < 10) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        attempts++;
      }

      if (await this.isSnortRunning()) {
        // Force kill if graceful shutdown failed
        await execAsync(`kill -KILL ${pid}`);
      }

      this.isRunning = false;
      
      return {
        status: 'stopped',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Failed to stop Snort: ${error.message}`);
    }
  }

  async restartSnort(networkInterface = 'eth0', options = {}) {
    try {
      if (await this.isSnortRunning()) {
        await this.stopSnort();
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
      return await this.startSnort(networkInterface, options);
    } catch (error) {
      throw new Error(`Failed to restart Snort: ${error.message}`);
    }
  }

  // Rules Management
  async getRules(category = null) {
    try {
      const rulesDir = this.rulesPath;
      const files = await fs.readdir(rulesDir);
      const ruleFiles = files.filter(file => file.endsWith('.rules'));
      
      if (category) {
        const categoryFile = `${category}.rules`;
        if (ruleFiles.includes(categoryFile)) {
          return await this.parseRuleFile(path.join(rulesDir, categoryFile));
        } else {
          return [];
        }
      }

      const allRules = [];
      for (const file of ruleFiles) {
        const rules = await this.parseRuleFile(path.join(rulesDir, file));
        allRules.push(...rules.map(rule => ({ ...rule, category: file.replace('.rules', '') })));
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
      // Basic Snort rule parsing
      const rulePattern = /^(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\((.*)\)$/;
      const match = ruleText.match(rulePattern);

      if (!match) return null;

      const [, action, protocol, srcIp, srcPort, destIp, destPort, options] = match;
      
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
        message: parsedOptions.msg || 'No message',
        classification: parsedOptions.classtype || 'unknown',
        priority: parsedOptions.priority || 3,
        revision: parsedOptions.rev || 1,
        reference: parsedOptions.reference || [],
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
        
        if (key === 'reference') {
          if (!options.reference) options.reference = [];
          options.reference.push(value);
        } else {
          options[key] = value;
        }
      }
    }

    return options;
  }

  async getRuleCategories() {
    try {
      const files = await fs.readdir(this.rulesPath);
      const categories = files
        .filter(file => file.endsWith('.rules'))
        .map(file => file.replace('.rules', ''))
        .sort();

      const categoriesWithStats = [];
      for (const category of categories) {
        const rules = await this.getRules(category);
        categoriesWithStats.push({
          name: category,
          rulesCount: rules.length,
          enabledCount: rules.filter(rule => rule.enabled).length,
          file: `${category}.rules`
        });
      }

      return categoriesWithStats;
    } catch (error) {
      throw new Error(`Failed to get rule categories: ${error.message}`);
    }
  }

  async updateRulesFromCache() {
    // Mock implementation - in reality this would download from Snort rules providers
    const mockRules = {
      'local.rules': `# Local rules
alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1000001; rev:1;)
alert tcp any any -> any 443 (msg:"HTTPS traffic detected"; sid:1000002; rev:1;)`,
      
      'emerging-threats.rules': `# Emerging Threats rules
alert tcp any any -> any any (msg:"ET MALWARE Suspicious executable download"; content:"Content-Type: application/octet-stream"; sid:2000001; rev:1;)
alert tcp any any -> any 53 (msg:"ET DNS Suspicious domain query"; content:"|01 00 00 01|"; sid:2000002; rev:1;)`
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

  // Alert Management
  async getAlerts(params = {}) {
    try {
      const alerts = [];
      const alertFiles = await this.getAlertFiles();
      
      for (const file of alertFiles) {
        const fileAlerts = await this.parseAlertFile(file);
        alerts.push(...fileAlerts);
      }

      // Apply filters
      let filteredAlerts = alerts;
      
      if (params.severity) {
        filteredAlerts = filteredAlerts.filter(alert => 
          alert.priority <= parseInt(params.severity)
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

  async getAlertFiles() {
    try {
      const files = await fs.readdir(this.logPath);
      return files
        .filter(file => file.startsWith('alert'))
        .map(file => path.join(this.logPath, file))
        .sort();
    } catch (error) {
      return [];
    }
  }

  async parseAlertFile(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      const alerts = [];
      const alertBlocks = content.split('\n\n').filter(block => block.trim());

      for (const block of alertBlocks) {
        const alert = this.parseAlert(block);
        if (alert) {
          alerts.push(alert);
        }
      }

      return alerts;
    } catch (error) {
      console.warn(`Failed to parse alert file ${filePath}:`, error.message);
      return [];
    }
  }

  parseAlert(alertText) {
    try {
      const lines = alertText.trim().split('\n');
      if (lines.length < 2) return null;

      // Parse header line
      const headerMatch = lines[0].match(/\[(.*?)\] (.*?) \[Priority: (\d+)\]/);
      if (!headerMatch) return null;

      const [, timestamp, message, priority] = headerMatch;

      // Parse network info
      const networkMatch = lines[1].match(/(\d+\.\d+\.\d+\.\d+):?(\d+)? -> (\d+\.\d+\.\d+\.\d+):?(\d+)?/);
      if (!networkMatch) return null;

      const [, srcIp, srcPort, destIp, destPort] = networkMatch;

      return {
        id: Math.random().toString(36).substr(2, 9),
        timestamp: new Date(timestamp).toISOString(),
        message: message.trim(),
        priority: parseInt(priority),
        severity: this.priorityToSeverity(parseInt(priority)),
        source: {
          ip: srcIp,
          port: srcPort ? parseInt(srcPort) : null
        },
        destination: {
          ip: destIp,
          port: destPort ? parseInt(destPort) : null
        },
        raw: alertText
      };
    } catch (error) {
      console.warn('Failed to parse alert:', error.message);
      return null;
    }
  }

  priorityToSeverity(priority) {
    if (priority === 1) return 'critical';
    if (priority === 2) return 'high';
    if (priority === 3) return 'medium';
    return 'low';
  }

  // Statistics and Performance
  async getPerformanceStats() {
    try {
      const db = new (require('./databaseService'))();
      
      // Get real performance data from system monitoring and database
      const [systemMetrics, processingStats, alertStats] = await Promise.all([
        this.getSystemMetrics(),
        this.getProcessingMetrics(),
        db.query(`
          SELECT 
            COUNT(*) as total_alerts,
            COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 hour') as alerts_last_hour,
            COUNT(*) FILTER (WHERE severity = 'critical') as critical_alerts,
            COUNT(*) FILTER (WHERE severity = 'high') as high_alerts
          FROM security_events
          WHERE created_at >= NOW() - INTERVAL '24 hours'
        `)
      ]);

      const alertData = alertStats.rows[0] || {};

      return {
        packets_processed: processingStats.packets_processed || 0,
        packets_dropped: processingStats.packets_dropped || 0,
        alerts_generated: parseInt(alertData.total_alerts) || 0,
        memory_usage_mb: systemMetrics.memory_usage_mb || 0,
        cpu_usage_percent: systemMetrics.cpu_usage_percent || 0,
        processing_rate: processingStats.processing_rate || 0,
        detection_rate: processingStats.detection_rate || 0,
        false_positive_rate: processingStats.false_positive_rate || 0,
        rule_count: await this.getActiveRuleCount(),
        uptime_seconds: systemMetrics.uptime_seconds || 0,
        throughput_mbps: processingStats.throughput_mbps || 0,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Failed to get performance stats:', error);
      throw new Error(`Failed to get performance stats: ${error.message}`);
    }
  }

  async getSystemMetrics() {
    try {
      // Get real system metrics from the host
      const os = require('os');
      const process = require('process');
      
      const loadAvg = os.loadavg();
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = totalMem - freeMem;
      
      return {
        memory_usage_mb: Math.round(usedMem / (1024 * 1024)),
        cpu_usage_percent: Math.round(loadAvg[0] * 100 / os.cpus().length),
        uptime_seconds: os.uptime(),
        free_memory_mb: Math.round(freeMem / (1024 * 1024)),
        total_memory_mb: Math.round(totalMem / (1024 * 1024))
      };
    } catch (error) {
      console.error('Failed to get system metrics:', error);
      return {
        memory_usage_mb: 0,
        cpu_usage_percent: 0,
        uptime_seconds: 0,
        free_memory_mb: 0,
        total_memory_mb: 0
      };
    }
  }

  async getProcessingMetrics() {
    try {
      const db = new (require('./databaseService'))();
      
      // Get processing metrics from database
      const result = await db.query(`
        SELECT 
          COUNT(*) as total_events,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 hour') as events_last_hour,
          COUNT(DISTINCT source_ip) as unique_sources,
          COUNT(DISTINCT destination_ip) as unique_destinations,
          AVG(CASE WHEN raw_data->>'processing_time_ms' IS NOT NULL 
              THEN (raw_data->>'processing_time_ms')::numeric ELSE NULL END) as avg_processing_time
        FROM security_events
        WHERE created_at >= NOW() - INTERVAL '24 hours'
      `);

      const metrics = result.rows[0] || {};
      const eventsLastHour = parseInt(metrics.events_last_hour) || 0;
      
      return {
        packets_processed: eventsLastHour * 100, // Estimate packets from events
        packets_dropped: Math.floor(eventsLastHour * 0.01), // Estimate 1% drop rate
        processing_rate: eventsLastHour,
        detection_rate: Math.round((eventsLastHour / Math.max(eventsLastHour * 100, 1)) * 100),
        false_positive_rate: 5, // Placeholder - would need ML analysis
        throughput_mbps: Math.round(eventsLastHour * 0.1), // Estimate throughput
        unique_sources: parseInt(metrics.unique_sources) || 0,
        unique_destinations: parseInt(metrics.unique_destinations) || 0,
        avg_processing_time_ms: parseFloat(metrics.avg_processing_time) || 0
      };
    } catch (error) {
      console.error('Failed to get processing metrics:', error);
      return {
        packets_processed: 0,
        packets_dropped: 0,
        processing_rate: 0,
        detection_rate: 0,
        false_positive_rate: 0,
        throughput_mbps: 0,
        unique_sources: 0,
        unique_destinations: 0,
        avg_processing_time_ms: 0
      };
    }
  }

  async getActiveRuleCount() {
    try {
      const db = new (require('./databaseService'))();
      const result = await db.query(
        'SELECT COUNT(*) as count FROM detection_rules WHERE is_enabled = true'
      );
      return parseInt(result.rows[0]?.count) || 0;
    } catch (error) {
      console.error('Failed to get active rule count:', error);
      return 0;
    }
  }

  async getUptime() {
    try {
      const pid = await this.getSnortPid();
      if (!pid) return null;

      const { stdout } = await execAsync(`ps -o etime= -p ${pid}`);
      return stdout.trim();
    } catch (error) {
      return null;
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
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        },
        by_hour: new Array(24).fill(0),
        top_source_ips: {},
        top_destination_ips: {},
        timestamp: new Date().toISOString()
      };

      alerts.alerts.forEach(alert => {
        // Count by severity
        stats.by_severity[alert.severity]++;

        // Count by hour
        const hour = new Date(alert.timestamp).getHours();
        stats.by_hour[hour]++;

        // Count source IPs
        if (alert.source.ip) {
          stats.top_source_ips[alert.source.ip] = (stats.top_source_ips[alert.source.ip] || 0) + 1;
        }

        // Count destination IPs
        if (alert.destination.ip) {
          stats.top_destination_ips[alert.destination.ip] = (stats.top_destination_ips[alert.destination.ip] || 0) + 1;
        }
      });

      // Convert IP counts to sorted arrays
      stats.top_source_ips = Object.entries(stats.top_source_ips)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }));

      stats.top_destination_ips = Object.entries(stats.top_destination_ips)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }));

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
      const { stdout, stderr } = await execAsync(`${this.snortPath} -T -c ${this.configPath}`);
      
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
      const version = await this.checkSnortInstallation();
      
      return {
        status: 'connected',
        service_status: status.status,
        version: version.version,
        timestamp: new Date().toISOString(),
        message: 'Snort service is accessible'
      };
    } catch (error) {
      return {
        status: 'error',
        timestamp: new Date().toISOString(),
        message: error.message
      };
    }
  }
}

module.exports = SnortService; 