const { exec, spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');

class MacOSLogCollector extends EventEmitter {
    constructor(config) {
        super();
        this.config = config;
        this.isRunning = false;
        this.logProcess = null;
        this.logPaths = [
            '/var/log/system.log',
            '/var/log/install.log',
            '/var/log/wifi.log',
            '/var/log/kernel.log',
            '/Library/Logs/DiagnosticReports/',
            '~/Library/Logs/'
        ];
    }

    async start() {
        this.isRunning = true;
        console.log('🍎 Starting MacOS log collection...');
        
        // Start unified log streaming
        this.startUnifiedLogStream();
        
        // Monitor traditional log files
        this.monitorLogFiles();
        
        // Collect system information
        this.collectSystemInfo();
        
        console.log('✅ MacOS log collector started');
    }

    startUnifiedLogStream() {
        // Use 'log stream' command to capture real-time logs
        this.logProcess = spawn('log', [
            'stream',
            '--style', 'syslog',
            '--level', 'info',
            '--type', 'activity,log,trace'
        ]);

        this.logProcess.stdout.on('data', (data) => {
            const logEntry = this.parseLogEntry(data.toString());
            if (logEntry) {
                this.emit('log', logEntry);
            }
        });

        this.logProcess.stderr.on('data', (data) => {
            console.error('Log stream error:', data.toString());
        });

        this.logProcess.on('close', (code) => {
            if (this.isRunning) {
                console.warn(`Log stream closed with code ${code}, restarting...`);
                setTimeout(() => this.startUnifiedLogStream(), 5000);
            }
        });
    }

    parseLogEntry(logData) {
        const lines = logData.trim().split('\n');
        const entries = [];
        
        for (const line of lines) {
            if (line.trim()) {
                const entry = {
                    timestamp: new Date().toISOString(),
                    source: 'macos-unified-log',
                    level: this.extractLogLevel(line),
                    message: line,
                    hostname: require('os').hostname(),
                    platform: 'darwin'
                };
                entries.push(entry);
            }
        }
        
        return entries.length > 0 ? entries : null;
    }

    extractLogLevel(logLine) {
        if (logLine.includes('Error') || logLine.includes('ERROR')) return 'error';
        if (logLine.includes('Warning') || logLine.includes('WARN')) return 'warning';
        if (logLine.includes('Info') || logLine.includes('INFO')) return 'info';
        if (logLine.includes('Debug') || logLine.includes('DEBUG')) return 'debug';
        return 'info';
    }

    async monitorLogFiles() {
        for (const logPath of this.logPaths) {
            try {
                const resolvedPath = logPath.startsWith('~') 
                    ? logPath.replace('~', require('os').homedir())
                    : logPath;
                
                const stats = await fs.stat(resolvedPath);
                if (stats.isFile()) {
                    this.watchLogFile(resolvedPath);
                } else if (stats.isDirectory()) {
                    this.watchLogDirectory(resolvedPath);
                }
            } catch (error) {
                // File doesn't exist or no permission, skip
                console.warn(`Cannot access ${logPath}: ${error.message}`);
            }
        }
    }

    watchLogFile(filePath) {
        const fs = require('fs');
        let lastSize = 0;
        
        const checkForNewContent = async () => {
            try {
                const stats = await fs.promises.stat(filePath);
                if (stats.size > lastSize) {
                    const stream = fs.createReadStream(filePath, {
                        start: lastSize,
                        end: stats.size
                    });
                    
                    let buffer = '';
                    stream.on('data', (chunk) => {
                        buffer += chunk.toString();
                        const lines = buffer.split('\n');
                        buffer = lines.pop(); // Keep incomplete line
                        
                        for (const line of lines) {
                            if (line.trim()) {
                                this.emit('log', {
                                    timestamp: new Date().toISOString(),
                                    source: path.basename(filePath),
                                    level: 'info',
                                    message: line,
                                    hostname: require('os').hostname(),
                                    platform: 'darwin'
                                });
                            }
                        }
                    });
                    
                    lastSize = stats.size;
                }
            } catch (error) {
                console.warn(`Error reading ${filePath}: ${error.message}`);
            }
        };
        
        // Check every 5 seconds
        setInterval(checkForNewContent, 5000);
    }

    watchLogDirectory(dirPath) {
        const fs = require('fs');
        
        fs.watch(dirPath, { recursive: true }, (eventType, filename) => {
            if (filename && filename.endsWith('.log')) {
                const fullPath = path.join(dirPath, filename);
                this.watchLogFile(fullPath);
            }
        });
    }

    async collectSystemInfo() {
        const systemInfo = {
            platform: require('os').platform(),
            arch: require('os').arch(),
            hostname: require('os').hostname(),
            version: require('os').release(),
            uptime: require('os').uptime(),
            memory: {
                total: require('os').totalmem(),
                free: require('os').freemem()
            },
            cpus: require('os').cpus(),
            networkInterfaces: require('os').networkInterfaces(),
            timestamp: new Date().toISOString()
        };

        // Get macOS specific information
        try {
            const macOSVersion = await this.execCommand('sw_vers -productVersion');
            const macOSBuild = await this.execCommand('sw_vers -buildVersion');
            
            systemInfo.macOS = {
                version: macOSVersion.trim(),
                build: macOSBuild.trim()
            };
        } catch (error) {
            console.warn('Could not get macOS version info:', error.message);
        }

        this.emit('systemInfo', systemInfo);
    }

    execCommand(command) {
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

    async stop() {
        this.isRunning = false;
        
        if (this.logProcess) {
            this.logProcess.kill();
            this.logProcess = null;
        }
        
        console.log('🛑 MacOS log collector stopped');
    }
}

module.exports = MacOSLogCollector;
