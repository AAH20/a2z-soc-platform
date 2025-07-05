const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

class ConfigManager {
    constructor() {
        this.config = null;
        this.configPath = null;
        this.defaultConfig = this.getDefaultConfig();
        this.watchers = [];
    }

    static async load(configPath = null) {
        const manager = new ConfigManager();
        await manager.initialize(configPath);
        return manager.config;
    }

    async initialize(configPath = null) {
        this.configPath = configPath || this.getDefaultConfigPath();
        
        try {
            // Ensure config directory exists
            await this.ensureConfigDirectory();
            
            // Load or create configuration
            await this.loadConfiguration();
            
            // Validate configuration
            this.validateConfiguration();
            
            console.log(`📋 Configuration loaded from: ${this.configPath}`);
            
        } catch (error) {
            console.warn(`⚠️  Failed to load config from ${this.configPath}, using defaults:`, error.message);
            this.config = { ...this.defaultConfig };
            await this.saveConfiguration();
        }
    }

    getDefaultConfigPath() {
        const platform = os.platform();
        const homeDir = os.homedir();
        
        switch (platform) {
            case 'win32':
                return path.join(process.env.APPDATA || homeDir, 'A2Z-SOC', 'agent-config.json');
            case 'darwin':
                return path.join(homeDir, 'Library', 'Application Support', 'A2Z-SOC', 'agent-config.json');
            default: // Linux and others
                return path.join(homeDir, '.a2z-soc', 'agent-config.json');
        }
    }

    getDefaultConfig() {
        return {
            // Agent identification
            agentId: crypto.randomUUID(),
            tenantId: null,
            apiKey: null,
            
            // Network configuration
            networkInterface: 'any',
            pcapFilter: 'ip',
            bufferSize: 10 * 1024 * 1024, // 10MB
            bufferTimeout: 1000, // 1 second
            
            // API server configuration
            apiPort: 5200,
            apiHost: '0.0.0.0',
            
            // Cloud connectivity
            cloudEndpoint: 'wss://api.a2zsoc.com',
            cloudReconnectInterval: 5000,
            cloudMaxReconnectAttempts: 10,
            
            // Logging
            logLevel: 'info',
            logRotation: {
                enabled: true,
                maxFiles: 10,
                maxSize: '10MB'
            },
            
            // Performance tuning
            maxBufferSize: 1000,
            heartbeatInterval: 30000,
            dataTransmissionInterval: 60000,
            
            // Compression
            compression: {
                enabled: true,
                algorithm: 'gzip',
                level: 6
            },
            
            // Security
            encryptData: true,
            validateCertificates: true,
            
            // Feature flags
            features: {
                packetCapture: true,
                threatDetection: true,
                logCollection: true,
                cloudSync: true
            },
            
            // Platform-specific settings
            platform: {
                windows: {
                    serviceMode: false,
                    autostart: false
                },
                linux: {
                    daemonMode: false,
                    systemdService: false
                },
                darwin: {
                    launchdService: false,
                    autostart: false
                }
            },
            
            // Metadata
            version: '1.0.0',
            createdAt: new Date().toISOString(),
            lastUpdated: new Date().toISOString()
        };
    }

    detectDefaultInterface() {
        const platform = os.platform();
        
        switch (platform) {
            case 'win32':
                return 'Ethernet'; // Common Windows interface name
            case 'darwin':
                return 'en0'; // Common macOS interface
            default: // Linux
                return 'eth0'; // Common Linux interface
        }
    }

    async ensureConfigDirectory() {
        const configDir = path.dirname(this.configPath);
        
        try {
            await fs.access(configDir);
        } catch (error) {
            await fs.mkdir(configDir, { recursive: true });
            console.log(`📁 Created config directory: ${configDir}`);
        }
    }

    async loadConfiguration() {
        try {
            const configData = await fs.readFile(this.configPath, 'utf8');
            const loadedConfig = JSON.parse(configData);
            
            // Merge with defaults to ensure all required fields exist
            this.config = this.mergeConfigs(this.defaultConfig, loadedConfig);
            
            // Update last loaded timestamp
            this.config.lastLoaded = new Date().toISOString();
            
        } catch (error) {
            if (error.code === 'ENOENT') {
                // Config file doesn't exist, create it
                this.config = { ...this.defaultConfig };
                await this.saveConfiguration();
            } else {
                throw error;
            }
        }
    }

    async saveConfiguration() {
        try {
            this.config.lastUpdated = new Date().toISOString();
            
            const configData = JSON.stringify(this.config, null, 2);
            await fs.writeFile(this.configPath, configData, 'utf8');
            
            console.log(`💾 Configuration saved to: ${this.configPath}`);
            
        } catch (error) {
            throw new Error(`Failed to save configuration: ${error.message}`);
        }
    }

    validateConfiguration() {
        const errors = [];
        
        // Check required fields
        if (!this.config.agentId) {
            errors.push('Missing agentId');
        }
        
        if (!this.config.cloudEndpoint) {
            errors.push('Missing cloudEndpoint');
        }
        
        // Validate URLs
        try {
            new URL(this.config.cloudEndpoint);
        } catch (error) {
            errors.push('Invalid cloudEndpoint URL');
        }
        
        if (this.config.apiEndpoint) {
            try {
                new URL(this.config.apiEndpoint);
            } catch (error) {
                errors.push('Invalid apiEndpoint URL');
            }
        }
        
        // Validate numeric values
        if (this.config.bufferSize <= 0) {
            errors.push('bufferSize must be positive');
        }
        
        if (this.config.maxBufferSize <= 0) {
            errors.push('maxBufferSize must be positive');
        }
        
        // Validate intervals
        if (this.config.heartbeatInterval < 5000) {
            errors.push('heartbeatInterval must be at least 5 seconds');
        }
        
        if (errors.length > 0) {
            throw new Error(`Configuration validation failed: ${errors.join(', ')}`);
        }
    }

    mergeConfigs(defaultConfig, userConfig) {
        const merged = { ...defaultConfig };
        
        for (const [key, value] of Object.entries(userConfig)) {
            if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                merged[key] = this.mergeConfigs(defaultConfig[key] || {}, value);
            } else {
                merged[key] = value;
            }
        }
        
        return merged;
    }

    async updateConfig(updates) {
        // Apply updates
        this.config = this.mergeConfigs(this.config, updates);
        
        // Validate after update
        this.validateConfiguration();
        
        // Save to disk
        await this.saveConfiguration();
        
        // Notify watchers
        this.notifyWatchers('config_updated', this.config);
    }

    async updateField(fieldPath, value) {
        const fields = fieldPath.split('.');
        let current = this.config;
        
        // Navigate to the parent object
        for (let i = 0; i < fields.length - 1; i++) {
            if (!current[fields[i]]) {
                current[fields[i]] = {};
            }
            current = current[fields[i]];
        }
        
        // Set the value
        current[fields[fields.length - 1]] = value;
        
        // Validate and save
        this.validateConfiguration();
        await this.saveConfiguration();
        
        // Notify watchers
        this.notifyWatchers('field_updated', { fieldPath, value });
    }

    getConfig() {
        return { ...this.config };
    }

    getField(fieldPath) {
        const fields = fieldPath.split('.');
        let current = this.config;
        
        for (const field of fields) {
            if (current && typeof current === 'object') {
                current = current[field];
            } else {
                return undefined;
            }
        }
        
        return current;
    }

    // Environment-specific configuration
    getPlatformConfig() {
        const platform = os.platform();
        const platformMap = {
            'win32': 'windows',
            'darwin': 'darwin',
            'linux': 'linux'
        };
        
        const platformKey = platformMap[platform] || 'linux';
        return this.config.platform[platformKey] || {};
    }

    // Network interface detection
    async detectAvailableInterfaces() {
        const interfaces = os.networkInterfaces();
        const available = [];
        
        for (const [name, details] of Object.entries(interfaces)) {
            // Skip loopback interfaces
            if (name.includes('lo') || name.includes('Loopback')) {
                continue;
            }
            
            // Check if interface has IP addresses
            const hasIp = details.some(detail => !detail.internal);
            
            if (hasIp) {
                available.push({
                    name: name,
                    addresses: details.filter(d => !d.internal).map(d => d.address),
                    type: details[0].family
                });
            }
        }
        
        return available;
    }

    // Configuration backup and restore
    async createBackup(backupPath = null) {
        if (!backupPath) {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const configDir = path.dirname(this.configPath);
            backupPath = path.join(configDir, `agent-config-backup-${timestamp}.json`);
        }
        
        await fs.copyFile(this.configPath, backupPath);
        console.log(`📋 Configuration backup created: ${backupPath}`);
        
        return backupPath;
    }

    async restoreBackup(backupPath) {
        try {
            // Validate backup file
            const backupData = await fs.readFile(backupPath, 'utf8');
            const backupConfig = JSON.parse(backupData);
            
            // Create backup of current config
            await this.createBackup();
            
            // Restore from backup
            this.config = this.mergeConfigs(this.defaultConfig, backupConfig);
            this.validateConfiguration();
            await this.saveConfiguration();
            
            console.log(`🔄 Configuration restored from: ${backupPath}`);
            
        } catch (error) {
            throw new Error(`Failed to restore backup: ${error.message}`);
        }
    }

    // Configuration watchers
    addWatcher(callback) {
        this.watchers.push(callback);
    }

    removeWatcher(callback) {
        const index = this.watchers.indexOf(callback);
        if (index > -1) {
            this.watchers.splice(index, 1);
        }
    }

    notifyWatchers(event, data) {
        this.watchers.forEach(callback => {
            try {
                callback(event, data);
            } catch (error) {
                console.error('Error in config watcher:', error);
            }
        });
    }

    // Factory reset
    async factoryReset() {
        console.log('⚠️  Performing factory reset...');
        
        // Create backup first
        await this.createBackup();
        
        // Reset to defaults
        this.config = { ...this.defaultConfig };
        this.config.agentId = uuidv4(); // Generate new agent ID
        
        await this.saveConfiguration();
        
        console.log('🔄 Factory reset completed');
    }

    // Configuration export/import
    async exportConfig(exportPath) {
        const exportData = {
            version: this.config.version,
            exportedAt: new Date().toISOString(),
            config: this.config
        };
        
        await fs.writeFile(exportPath, JSON.stringify(exportData, null, 2));
        console.log(`📤 Configuration exported to: ${exportPath}`);
    }

    async importConfig(importPath, merge = true) {
        try {
            const importData = JSON.parse(await fs.readFile(importPath, 'utf8'));
            
            if (merge) {
                this.config = this.mergeConfigs(this.config, importData.config);
            } else {
                this.config = this.mergeConfigs(this.defaultConfig, importData.config);
            }
            
            this.validateConfiguration();
            await this.saveConfiguration();
            
            console.log(`📥 Configuration imported from: ${importPath}`);
            
        } catch (error) {
            throw new Error(`Failed to import configuration: ${error.message}`);
        }
    }

    // Configuration information
    getConfigInfo() {
        return {
            configPath: this.configPath,
            version: this.config.version,
            agentId: this.config.agentId,
            createdAt: this.config.createdAt,
            lastUpdated: this.config.lastUpdated,
            lastLoaded: this.config.lastLoaded,
            platform: os.platform(),
            nodeVersion: process.version
        };
    }
}

module.exports = ConfigManager; 