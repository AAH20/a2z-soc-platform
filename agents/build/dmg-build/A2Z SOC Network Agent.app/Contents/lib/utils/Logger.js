const fs = require('fs').promises;
const path = require('path');
const os = require('os');

class Logger {
    constructor(name = 'A2ZAgent', options = {}) {
        this.name = name;
        this.options = {
            level: options.level || 'info',
            logPath: options.logPath || null, // null = console only
            maxLogSize: options.maxLogSize || 10 * 1024 * 1024, // 10MB
            maxLogFiles: options.maxLogFiles || 5,
            enableColors: options.enableColors !== false,
            timestampFormat: options.timestampFormat || 'ISO',
            ...options
        };

        this.levels = {
            error: 0,
            warn: 1,
            info: 2,
            debug: 3,
            trace: 4
        };

        this.colors = {
            error: '\x1b[31m',   // Red
            warn: '\x1b[33m',    // Yellow
            info: '\x1b[36m',    // Cyan
            debug: '\x1b[32m',   // Green
            trace: '\x1b[35m',   // Magenta
            reset: '\x1b[0m'     // Reset
        };

        this.currentLogLevel = this.levels[this.options.level] || this.levels.info;
        this.logQueue = [];
        this.isWriting = false;
        this.setupLogDirectory();
    }

    async setupLogDirectory() {
        if (this.options.logPath) {
            try {
                const logDir = path.dirname(this.options.logPath);
                await fs.mkdir(logDir, { recursive: true });
            } catch (error) {
                console.error('Failed to create log directory:', error.message);
                this.options.logPath = null; // Fall back to console only
            }
        }
    }

    error(message, ...args) {
        this.log('error', message, ...args);
    }

    warn(message, ...args) {
        this.log('warn', message, ...args);
    }

    info(message, ...args) {
        this.log('info', message, ...args);
    }

    debug(message, ...args) {
        this.log('debug', message, ...args);
    }

    trace(message, ...args) {
        this.log('trace', message, ...args);
    }

    log(level, message, ...args) {
        const levelNum = this.levels[level];
        if (levelNum === undefined || levelNum > this.currentLogLevel) {
            return;
        }

        const logEntry = this.createLogEntry(level, message, ...args);
        
        // Output to console
        this.outputToConsole(logEntry);
        
        // Queue for file output if enabled
        if (this.options.logPath) {
            this.queueForFile(logEntry);
        }
    }

    createLogEntry(level, message, ...args) {
        const timestamp = this.formatTimestamp();
        const processedMessage = this.processMessage(message, ...args);
        
        return {
            timestamp: timestamp,
            level: level.toUpperCase(),
            name: this.name,
            message: processedMessage,
            pid: process.pid,
            platform: process.platform
        };
    }

    processMessage(message, ...args) {
        if (typeof message === 'string') {
            // Handle string interpolation
            if (args.length > 0) {
                try {
                    return message.replace(/%[sdj%]/g, (match) => {
                        if (args.length === 0) return match;
                        const arg = args.shift();
                        switch (match) {
                            case '%s': return String(arg);
                            case '%d': return Number(arg);
                            case '%j': return JSON.stringify(arg);
                            case '%%': return '%';
                            default: return match;
                        }
                    }) + (args.length > 0 ? ' ' + args.map(this.formatArg).join(' ') : '');
                } catch (error) {
                    return message + ' ' + args.map(this.formatArg).join(' ');
                }
            }
            return message;
        }
        
        // Handle object/array logging
        return [message, ...args].map(this.formatArg).join(' ');
    }

    formatArg(arg) {
        if (arg === null) return 'null';
        if (arg === undefined) return 'undefined';
        if (typeof arg === 'string') return arg;
        if (typeof arg === 'number' || typeof arg === 'boolean') return String(arg);
        if (arg instanceof Error) {
            return `${arg.name}: ${arg.message}\n${arg.stack}`;
        }
        
        try {
            return JSON.stringify(arg, null, 2);
        } catch (error) {
            return `[Object: ${Object.prototype.toString.call(arg)}]`;
        }
    }

    formatTimestamp() {
        const now = new Date();
        
        switch (this.options.timestampFormat) {
            case 'ISO':
                return now.toISOString();
            case 'locale':
                return now.toLocaleString();
            case 'unix':
                return Math.floor(now.getTime() / 1000).toString();
            case 'custom':
                return this.options.customTimestampFormatter ? 
                    this.options.customTimestampFormatter(now) : 
                    now.toISOString();
            default:
                return now.toISOString();
        }
    }

    outputToConsole(logEntry) {
        const levelColor = this.options.enableColors ? this.colors[logEntry.level.toLowerCase()] : '';
        const resetColor = this.options.enableColors ? this.colors.reset : '';
        
        const formattedMessage = `${levelColor}[${logEntry.timestamp}] ${logEntry.level} [${logEntry.name}]: ${logEntry.message}${resetColor}`;
        
        // Output to appropriate stream
        if (logEntry.level === 'ERROR') {
            console.error(formattedMessage);
        } else {
            console.log(formattedMessage);
        }
    }

    queueForFile(logEntry) {
        const fileMessage = `[${logEntry.timestamp}] ${logEntry.level} [${logEntry.name}] PID:${logEntry.pid}: ${logEntry.message}\n`;
        
        this.logQueue.push(fileMessage);
        
        if (!this.isWriting) {
            this.processLogQueue();
        }
    }

    async processLogQueue() {
        if (this.logQueue.length === 0 || this.isWriting) {
            return;
        }

        this.isWriting = true;
        
        try {
            const messages = [...this.logQueue];
            this.logQueue = [];
            
            await this.writeToFile(messages.join(''));
            
        } catch (error) {
            console.error('Failed to write to log file:', error.message);
            // Put messages back in queue
            this.logQueue.unshift(...messages);
        } finally {
            this.isWriting = false;
            
            // Process any new messages that arrived
            if (this.logQueue.length > 0) {
                setImmediate(() => this.processLogQueue());
            }
        }
    }

    async writeToFile(content) {
        if (!this.options.logPath) return;
        
        try {
            // Check if log rotation is needed
            await this.rotateLogIfNeeded();
            
            // Append to current log file
            await fs.appendFile(this.options.logPath, content);
            
        } catch (error) {
            throw new Error(`Log file write failed: ${error.message}`);
        }
    }

    async rotateLogIfNeeded() {
        try {
            const stats = await fs.stat(this.options.logPath);
            
            if (stats.size >= this.options.maxLogSize) {
                await this.rotateLogs();
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                throw error;
            }
            // File doesn't exist yet, no rotation needed
        }
    }

    async rotateLogs() {
        const logDir = path.dirname(this.options.logPath);
        const logName = path.basename(this.options.logPath, path.extname(this.options.logPath));
        const logExt = path.extname(this.options.logPath);
        
        try {
            // Rotate existing log files
            for (let i = this.options.maxLogFiles - 1; i >= 1; i--) {
                const oldPath = path.join(logDir, `${logName}.${i}${logExt}`);
                const newPath = path.join(logDir, `${logName}.${i + 1}${logExt}`);
                
                try {
                    await fs.access(oldPath);
                    if (i === this.options.maxLogFiles - 1) {
                        // Remove the oldest log file
                        await fs.unlink(newPath).catch(() => {}); // Ignore if doesn't exist
                    }
                    await fs.rename(oldPath, newPath);
                } catch (error) {
                    // File doesn't exist, continue
                }
            }
            
            // Move current log to .1
            const firstRotatedPath = path.join(logDir, `${logName}.1${logExt}`);
            try {
                await fs.rename(this.options.logPath, firstRotatedPath);
            } catch (error) {
                // Original file might not exist
            }
            
        } catch (error) {
            console.error('Log rotation failed:', error.message);
        }
    }

    // Advanced logging methods
    child(options = {}) {
        return new Logger(options.name || this.name, {
            ...this.options,
            ...options
        });
    }

    setLevel(level) {
        if (this.levels[level] !== undefined) {
            this.currentLogLevel = this.levels[level];
            this.options.level = level;
        } else {
            this.warn(`Invalid log level: ${level}`);
        }
    }

    isLevelEnabled(level) {
        return this.levels[level] !== undefined && this.levels[level] <= this.currentLogLevel;
    }

    // Structured logging
    logWithFields(level, message, fields = {}) {
        if (!this.isLevelEnabled(level)) return;
        
        const logEntry = this.createLogEntry(level, message);
        logEntry.fields = fields;
        
        // Add fields to the message for console output
        const fieldsStr = Object.entries(fields)
            .map(([key, value]) => `${key}=${this.formatArg(value)}`)
            .join(' ');
        
        if (fieldsStr) {
            logEntry.message += ` | ${fieldsStr}`;
        }
        
        this.outputToConsole(logEntry);
        
        if (this.options.logPath) {
            this.queueForFile(logEntry);
        }
    }

    // Performance logging
    time(label) {
        const startTime = process.hrtime.bigint();
        return () => {
            const endTime = process.hrtime.bigint();
            const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
            this.info(`Timer ${label}: ${duration.toFixed(2)}ms`);
            return duration;
        };
    }

    // Memory usage logging
    logMemoryUsage(label = 'Memory Usage') {
        const usage = process.memoryUsage();
        this.info(`${label}:`, {
            rss: `${Math.round(usage.rss / 1024 / 1024)}MB`,
            heapUsed: `${Math.round(usage.heapUsed / 1024 / 1024)}MB`,
            heapTotal: `${Math.round(usage.heapTotal / 1024 / 1024)}MB`,
            external: `${Math.round(usage.external / 1024 / 1024)}MB`
        });
    }

    // System information logging
    logSystemInfo() {
        this.info('System Information:', {
            platform: process.platform,
            arch: process.arch,
            nodeVersion: process.version,
            pid: process.pid,
            uptime: `${Math.round(process.uptime())}s`,
            cpus: os.cpus().length,
            totalMemory: `${Math.round(os.totalmem() / 1024 / 1024 / 1024)}GB`,
            freeMemory: `${Math.round(os.freemem() / 1024 / 1024 / 1024)}GB`
        });
    }

    // Error logging with stack traces
    logError(error, context = {}) {
        const errorInfo = {
            name: error.name,
            message: error.message,
            stack: error.stack,
            code: error.code,
            ...context
        };
        
        this.error('Error occurred:', errorInfo);
    }

    // Flush pending logs
    async flush() {
        while (this.logQueue.length > 0 || this.isWriting) {
            await new Promise(resolve => setTimeout(resolve, 10));
        }
    }

    // Cleanup and shutdown
    async close() {
        await this.flush();
        // Any additional cleanup can go here
    }

    // Statistics
    getLogStats() {
        return {
            currentLevel: this.options.level,
            queueSize: this.logQueue.length,
            isWriting: this.isWriting,
            logPath: this.options.logPath,
            maxLogSize: this.options.maxLogSize,
            maxLogFiles: this.options.maxLogFiles
        };
    }
}

module.exports = Logger; 