const { exec, spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');
const os = require('os');

class MacOSLogCollector extends EventEmitter {
    constructor(config) {
        super();
        this.config = config;
        this.isRunning = false;
        this.logProcess = null;
        this.securityProcess = null;
        this.logPaths = [
            '/var/log/system.log',
            '/var/log/install.log',
            '/var/log/wifi.log',
            '/var/log/kernel.log',
            '/Library/Logs/DiagnosticReports/',
            '~/Library/Logs/'
        ];
        this.statistics = {
            logsProcessed: 0,
            systemEventsDetected: 0,
            securityEventsDetected: 0,
            errorsEncountered: 0,
            lastCollectionTime: null
        };
        
        // File watchers for traditional log files
        this.fileWatchers = new Map();
        
        // Security monitoring intervals
        this.securityIntervals = new Map();
        this.startTime = null;
    }

    async start() {
        if (this.isRunning) {
            console.log('🍎 macOS log collector is already running');
            return;
        }

        this.isRunning = true;
        this.startTime = Date.now();
        console.log('🍎 Starting macOS log collection...');
        
        try {
            // Start unified log streaming
            await this.startUnifiedLogStream();
            
            // Monitor traditional log files
            await this.monitorLogFiles();
            
            // Start security monitoring
            await this.startSecurityMonitoring();
            
            // Collect system information periodically
            this.collectSystemInfo();
            
            // Monitor network security events
            await this.monitorNetworkSecurity();
            
            // Monitor file system changes
            await this.monitorSystemChanges();
            
            console.log('✅ macOS log collector started successfully');
            
        } catch (error) {
            console.error('❌ Failed to start macOS log collector:', error);
            this.isRunning = false;
            throw error;
        }
    }

    async stop() {
        if (!this.isRunning) {
            return;
        }

        this.isRunning = false;
        
        console.log('🛑 Stopping macOS log collector...');
        
        // Stop unified log stream
        if (this.logProcess) {
            this.logProcess.kill('SIGTERM');
            this.logProcess = null;
        }
        
        // Stop security monitoring
        if (this.securityProcess) {
            this.securityProcess.kill('SIGTERM');
            this.securityProcess = null;
        }
        
        // Clear file watchers
        for (const [path, watcher] of this.fileWatchers) {
            try {
                if (watcher && watcher.close) {
                    watcher.close();
                }
            } catch (error) {
                console.debug(`Error closing watcher for ${path}:`, error.message);
            }
        }
        this.fileWatchers.clear();
        
        // Clear intervals
        for (const [name, interval] of this.securityIntervals) {
            clearInterval(interval);
        }
        this.securityIntervals.clear();
        
        console.log('✅ macOS log collector stopped');
    }

    async startUnifiedLogStream() {
        try {
            console.log('📊 Starting unified log stream...');
            
            // Use 'log stream' command to capture real-time logs
            this.logProcess = spawn('log', [
                'stream',
                '--style', 'syslog',
                '--level', 'info',
                '--type', 'activity,log,trace',
                '--predicate', 'eventType == logEvent'
            ]);

            this.logProcess.stdout.on('data', (data) => {
                this.parseLogEntry(data.toString());
            });

            this.logProcess.stderr.on('data', (data) => {
                console.debug('Log stream stderr:', data.toString());
                this.statistics.errorsEncountered++;
            });

            this.logProcess.on('close', (code) => {
                if (this.isRunning && code !== 0) {
                    console.warn(`Log stream closed with code ${code}, restarting in 5 seconds...`);
                    setTimeout(() => {
                        if (this.isRunning) {
                            this.startUnifiedLogStream();
                        }
                    }, 5000);
                }
            });

            this.logProcess.on('error', (error) => {
                console.error('Log stream error:', error);
                this.statistics.errorsEncountered++;
                if (this.isRunning) {
                    setTimeout(() => this.startUnifiedLogStream(), 5000);
                }
            });
            
            console.log('✅ Unified log stream started');
            
        } catch (error) {
            console.error('❌ Failed to start unified log stream:', error);
            throw error;
        }
    }

    parseLogEntry(logData) {
        const lines = logData.trim().split('\n');
        
        for (const line of lines) {
            if (line.trim()) {
                try {
                    const entry = this.parseSingleLogLine(line);
                    if (entry) {
                        this.statistics.logsProcessed++;
                        this.statistics.lastCollectionTime = new Date();
                        
                        // Emit the log entry
                        this.emit('log', entry);
                        
                        // Check for security events
                        if (this.isSecurityEvent(entry)) {
                            this.statistics.securityEventsDetected++;
                            this.emit('securityEvent', entry);
                        }
                        
                        // Check for system events
                        if (this.isSystemEvent(entry)) {
                            this.statistics.systemEventsDetected++;
                            this.emit('systemEvent', entry);
                        }
                    }
                } catch (error) {
                    console.debug('Error parsing log line:', error);
                }
            }
        }
    }

    parseSingleLogLine(line) {
        try {
            // Parse macOS unified log format
            // Example: "2024-01-20 10:30:45.123456-0800  localhost kernel[0]: (AppleACPIPlatform) Message here"
            
            const logPattern = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[-+]\d{4})\s+(\S+)\s+([^:]+):\s*(.*)$/;
            const match = line.match(logPattern);
            
            if (match) {
                const [, timestamp, hostname, process, message] = match;
                
                // Extract process name and PID
                const processMatch = process.match(/([^[]+)(?:\[(\d+)\])?/);
                const processName = processMatch ? processMatch[1] : process;
                const pid = processMatch && processMatch[2] ? parseInt(processMatch[2]) : null;
                
                return this.createLogEntry(timestamp, hostname, processName, pid, message, line);
            } else {
                // Fallback for lines that don't match the expected format
                return this.createLogEntry(
                    new Date().toISOString(),
                    os.hostname(),
                    'unknown',
                    null,
                    line,
                    line
                );
            }
        } catch (error) {
            console.debug('Error parsing log line:', error);
            return null;
        }
    }

    createLogEntry(timestamp, hostname, processName, pid, message, rawLine) {
        return {
            timestamp: timestamp,
            hostname: hostname,
            process: processName,
            pid: pid,
            message: message.trim(),
            level: this.determineLogLevel(message),
            source: 'macos_unified_log',
            category: this.categorizeLog(processName, message),
            raw: rawLine,
            platform: 'darwin'
        };
    }

    determineLogLevel(message) {
        const lowerMessage = message.toLowerCase();
        
        if (lowerMessage.includes('error') || lowerMessage.includes('failed') || lowerMessage.includes('critical')) {
            return 'error';
        } else if (lowerMessage.includes('warning') || lowerMessage.includes('warn')) {
            return 'warn';
        } else if (lowerMessage.includes('debug')) {
            return 'debug';
        } else {
            return 'info';
        }
    }

    categorizeLog(processName, message) {
        const lowerProcess = processName.toLowerCase();
        const lowerMessage = message.toLowerCase();
        
        if (lowerProcess.includes('kernel') || lowerMessage.includes('kernel')) {
            return 'system_kernel';
        } else if (lowerProcess.includes('network') || lowerMessage.includes('network')) {
            return 'network';
        } else if (lowerProcess.includes('security') || lowerMessage.includes('authentication')) {
            return 'security';
        } else if (lowerProcess.includes('disk') || lowerMessage.includes('filesystem')) {
            return 'storage';
        } else {
            return 'application';
        }
    }

    isSecurityEvent(logEntry) {
        const securityKeywords = [
            'authentication', 'login', 'logout', 'failed', 'denied',
            'unauthorized', 'permission', 'security', 'firewall',
            'blocked', 'virus', 'malware', 'intrusion', 'breach',
            'sudo', 'su ', 'privilege', 'encryption', 'certificate'
        ];
        
        const message = logEntry.message.toLowerCase();
        const process = logEntry.process.toLowerCase();
        
        return securityKeywords.some(keyword => 
            message.includes(keyword) || process.includes(keyword)
        );
    }

    isSystemEvent(logEntry) {
        const systemKeywords = [
            'startup', 'shutdown', 'reboot', 'crash', 'panic',
            'memory', 'cpu', 'disk', 'mount', 'unmount',
            'service', 'daemon', 'process', 'thread', 'driver'
        ];
        
        const message = logEntry.message.toLowerCase();
        const process = logEntry.process.toLowerCase();
        
        return systemKeywords.some(keyword => 
            message.includes(keyword) || process.includes(keyword)
        );
    }

    async monitorLogFiles() {
        console.log('📁 Setting up log file monitoring...');
        
        for (const logPath of this.logPaths) {
            const expandedPath = logPath.replace('~', os.homedir());
            
            try {
                const stats = await fs.stat(expandedPath);
                if (stats.isFile()) {
                    await this.watchLogFile(expandedPath);
                } else if (stats.isDirectory()) {
                    await this.watchLogDirectory(expandedPath);
                }
            } catch (error) {
                // File/directory doesn't exist or no permission, skip
                console.debug(`Cannot monitor ${logPath}:`, error.message);
            }
        }
    }

    async watchLogFile(filePath) {
        try {
            const watcher = require('fs').watch(filePath, (eventType, filename) => {
                if (eventType === 'change') {
                    this.readLogFileChanges(filePath);
                }
            });
            
            this.fileWatchers.set(filePath, watcher);
            console.debug(`Watching log file: ${filePath}`);
            
        } catch (error) {
            console.debug(`Cannot watch ${filePath}:`, error.message);
        }
    }

    async watchLogDirectory(dirPath) {
        try {
            const files = await fs.readdir(dirPath);
            
            for (const file of files) {
                if (file.endsWith('.log') || file.endsWith('.crash')) {
                    const fullPath = path.join(dirPath, file);
                    await this.watchLogFile(fullPath);
                }
            }
        } catch (error) {
            console.debug(`Cannot watch directory ${dirPath}:`, error.message);
        }
    }

    async readLogFileChanges(filePath) {
        try {
            // For simplicity, we'll just emit a file change event
            // In production, you'd want to tail the file properly
            this.emit('log', {
                timestamp: new Date().toISOString(),
                hostname: os.hostname(),
                process: 'file_monitor',
                pid: process.pid,
                message: `Log file changed: ${filePath}`,
                level: 'info',
                source: 'file_watcher',
                category: 'system_monitoring',
                file_path: filePath
            });
            
        } catch (error) {
            console.debug(`Error reading ${filePath}:`, error.message);
        }
    }

    async collectSystemInfo() {
        console.log('📊 Collecting macOS system information...');
        
        // Collect system info periodically
        const collectInfo = async () => {
            if (!this.isRunning) return;
            
            try {
                const systemInfo = await this.gatherSystemInformation();
                this.emit('systemInfo', systemInfo);
                this.statistics.systemEventsDetected++;
            } catch (error) {
                console.error('Error collecting system info:', error);
                this.statistics.errorsEncountered++;
            }
            
            // Schedule next collection
            setTimeout(collectInfo, 60000); // Every minute
        };
        
        collectInfo();
    }

    async gatherSystemInformation() {
        const commands = {
            uptime: 'uptime',
            memory: 'vm_stat',
            disk: 'df -h',
            network: 'netstat -rn',
            processes: 'ps aux | head -20',
            system_version: 'sw_vers'
        };
        
        const systemInfo = {
            timestamp: new Date().toISOString(),
            hostname: os.hostname(),
            type: 'system_snapshot'
        };
        
        for (const [key, command] of Object.entries(commands)) {
            try {
                const output = await this.execCommand(command);
                systemInfo[key] = output.trim();
            } catch (error) {
                systemInfo[key] = `Error: ${error.message}`;
            }
        }
        
        return systemInfo;
    }

    async execCommand(command) {
        return new Promise((resolve, reject) => {
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(stdout);
                }
            });
        });
    }

    getStatistics() {
        return {
            ...this.statistics,
            isRunning: this.isRunning,
            uptime: this.isRunning ? Date.now() - this.startTime : 0
        };
    }

    // Security-focused log monitoring
    async startSecurityMonitoring() {
        console.log('🔒 Starting security-focused log monitoring...');
        
        // Monitor authentication events
        this.monitorSecurityLogs();
        
        // Monitor system changes
        this.monitorSystemChanges();
        
        // Monitor network security events
        this.monitorNetworkSecurity();
    }

    async monitorSecurityLogs() {
        try {
            // Monitor authentication logs
            const authLogProcess = spawn('log', [
                'stream',
                '--predicate', 'category == "authentication" OR process == "loginwindow" OR process == "authd"',
                '--style', 'syslog'
            ]);

            authLogProcess.stdout.on('data', (data) => {
                const securityEntries = this.parseSecurityLogs(data.toString());
                securityEntries.forEach(entry => {
                    this.emit('log', {
                        ...entry,
                        category: 'security_authentication',
                        security_event: true
                    });
                });
            });
        } catch (error) {
            console.warn('Failed to start security log monitoring:', error.message);
        }
    }

    async monitorSystemChanges() {
        try {
            // Monitor system file changes
            const fsEventsProcess = spawn('fs_usage', ['-w', '-f', 'filesys'], {
                stdio: ['ignore', 'pipe', 'pipe']
            });

            fsEventsProcess.stdout.on('data', (data) => {
                const systemChanges = this.parseFileSystemEvents(data.toString());
                systemChanges.forEach(change => {
                    this.emit('log', {
                        ...change,
                        category: 'system_changes',
                        security_event: true
                    });
                });
            });
        } catch (error) {
            console.warn('Failed to start system changes monitoring:', error.message);
        }
    }

    async monitorNetworkSecurity() {
        try {
            // Monitor network security events through system logs
            const networkLogProcess = spawn('log', [
                'stream',
                '--predicate', 'category CONTAINS "network" OR process == "firewall" OR process == "pfctl"',
                '--style', 'syslog'
            ]);

            networkLogProcess.stdout.on('data', (data) => {
                const networkEntries = this.parseNetworkSecurityLogs(data.toString());
                networkEntries.forEach(entry => {
                    this.emit('log', {
                        ...entry,
                        category: 'network_security',
                        security_event: true
                    });
                });
            });
        } catch (error) {
            console.warn('Failed to start network security monitoring:', error.message);
        }
    }

    parseSecurityLogs(logData) {
        // Parse authentication and security-related logs
        const entries = [];
        const lines = logData.split('\n');
        
        for (const line of lines) {
            if (line.includes('authentication') || 
                line.includes('login') || 
                line.includes('sudo') ||
                line.includes('su ')) {
                
                const entry = this.parseSingleLogLine(line);
                if (entry) {
                    entry.security_type = 'authentication';
                    entries.push(entry);
                }
            }
        }
        
        return entries;
    }

    parseFileSystemEvents(fsData) {
        // Parse file system events from fs_usage
        const events = [];
        const lines = fsData.split('\n');
        
        for (const line of lines) {
            if (line.includes('/System/') || 
                line.includes('/usr/bin/') || 
                line.includes('/etc/')) {
                
                const event = {
                    timestamp: new Date().toISOString(),
                    hostname: os.hostname(),
                    process: 'fs_usage',
                    message: line.trim(),
                    level: 'info',
                    source: 'filesystem_monitor',
                    security_type: 'file_access'
                };
                
                events.push(event);
            }
        }
        
        return events;
    }

    parseNetworkSecurityLogs(logData) {
        // Parse network security logs
        const entries = [];
        const lines = logData.split('\n');
        
        for (const line of lines) {
            if (line.includes('firewall') || 
                line.includes('blocked') || 
                line.includes('denied') ||
                line.includes('pfctl')) {
                
                const entry = this.parseSingleLogLine(line);
                if (entry) {
                    entry.security_type = 'network_firewall';
                    entries.push(entry);
                }
            }
        }
        
        return entries;
    }
}

module.exports = MacOSLogCollector; 