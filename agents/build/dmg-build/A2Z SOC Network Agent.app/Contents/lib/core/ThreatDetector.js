const { EventEmitter } = require('events');
const crypto = require('crypto');

class ThreatDetector extends EventEmitter {
    constructor(config) {
        super();
        this.config = config;
        this.rules = new Map();
        this.threatSignatures = new Map();
        this.suspiciousIps = new Set();
        this.whitelist = new Set();
        this.rateLimits = new Map();
        this.anomalyBaselines = new Map();
        this.initialized = false;
    }

    async initialize() {
        try {
            // Load default rules
            await this.loadDefaultRules();
            
            // Initialize threat signatures
            await this.loadThreatSignatures();
            
            // Load IP reputation data
            await this.loadIpReputation();
            
            // Initialize ML baselines
            this.initializeBaselines();
            
            this.initialized = true;
            console.log('✅ ThreatDetector initialized successfully');
            
        } catch (error) {
            throw new Error(`Failed to initialize ThreatDetector: ${error.message}`);
        }
    }

    async loadRules() {
        try {
            // Load custom rules from config or remote source
            if (this.config.rulesUrl) {
                await this.loadRemoteRules(this.config.rulesUrl);
            }
            
            if (this.config.customRules) {
                this.loadCustomRules(this.config.customRules);
            }
            
            console.log(`📋 Loaded ${this.rules.size} threat detection rules`);
            
        } catch (error) {
            console.error('Error loading rules:', error);
        }
    }

    loadCustomRules(customRules) {
        if (!Array.isArray(customRules)) {
            console.warn('Custom rules should be an array');
            return;
        }

        customRules.forEach((rule, index) => {
            try {
                // Validate rule structure
                if (!rule.id || !rule.name || !rule.type || !rule.condition) {
                    console.warn(`Invalid rule at index ${index}: missing required fields`);
                    return;
                }

                // Set defaults
                const normalizedRule = {
                    id: rule.id,
                    name: rule.name,
                    type: rule.type || 'signature',
                    severity: rule.severity || 'medium',
                    description: rule.description || 'Custom rule',
                    technique: rule.technique || 'T0000',
                    tactics: rule.tactics || ['Unknown'],
                    enabled: rule.enabled !== false,
                    condition: rule.condition,
                    metadata: rule.metadata || {}
                };

                this.rules.set(rule.id, normalizedRule);
                console.log(`✅ Loaded custom rule: ${rule.name}`);
                
            } catch (error) {
                console.error(`Error loading custom rule at index ${index}:`, error);
            }
        });
    }

    async loadRemoteRules(rulesUrl) {
        try {
            console.log(`📥 Loading rules from remote URL: ${rulesUrl}`);
            // In a real implementation, this would fetch rules from a remote endpoint
            // For now, we'll just log that it would happen
            console.log('🔄 Remote rule loading not implemented in this version');
        } catch (error) {
            console.error('Error loading remote rules:', error);
        }
    }

    async loadDefaultRules() {
        const defaultRules = [
            // Port scanning detection
            {
                id: 'port_scan_1',
                name: 'Port Scan Detection',
                type: 'anomaly',
                severity: 'medium',
                description: 'Detects potential port scanning activity',
                technique: 'T1046',
                tactics: ['Discovery'],
                condition: this.detectPortScan.bind(this),
                enabled: true
            },
            
            // Suspicious DNS queries
            {
                id: 'dns_suspicious_1',
                name: 'Suspicious DNS Query',
                type: 'signature',
                severity: 'high',
                description: 'Detects DNS queries to suspicious domains',
                technique: 'T1071.004',
                tactics: ['Command and Control'],
                condition: this.detectSuspiciousDns.bind(this),
                enabled: true
            },
            
            // Large data transfers
            {
                id: 'data_exfil_1',
                name: 'Large Data Transfer',
                type: 'anomaly',
                severity: 'high',
                description: 'Detects unusually large data transfers',
                technique: 'T1041',
                tactics: ['Exfiltration'],
                condition: this.detectLargeTransfer.bind(this),
                enabled: true
            },
            
            // Brute force attempts
            {
                id: 'brute_force_1',
                name: 'Brute Force Attack',
                type: 'behavioral',
                severity: 'high',
                description: 'Detects brute force login attempts',
                technique: 'T1110',
                tactics: ['Credential Access'],
                condition: this.detectBruteForce.bind(this),
                enabled: true
            },
            
            // DDoS detection
            {
                id: 'ddos_1',
                name: 'DDoS Attack',
                type: 'volumetric',
                severity: 'critical',
                description: 'Detects distributed denial of service attacks',
                technique: 'T1498',
                tactics: ['Impact'],
                condition: this.detectDdos.bind(this),
                enabled: true
            },
            
            // Malware communication
            {
                id: 'malware_comm_1',
                name: 'Malware Communication',
                type: 'signature',
                severity: 'critical',
                description: 'Detects communication with known malware C&C servers',
                technique: 'T1071.001',
                tactics: ['Command and Control'],
                condition: this.detectMalwareComm.bind(this),
                enabled: true
            }
        ];

        defaultRules.forEach(rule => {
            this.rules.set(rule.id, rule);
        });
    }

    async loadThreatSignatures() {
        // Known malicious patterns
        const signatures = [
            // Known malicious domains
            'evil.com',
            'malware-c2.net',
            'phishing-site.org',
            
            // Known malicious IP ranges (examples)
            '192.0.2.0/24',    // RFC5737 test range (used as example)
            '198.51.100.0/24', // RFC5737 test range (used as example)
            
            // Suspicious user agents
            'Metasploit',
            'sqlmap',
            'Nikto',
            
            // Suspicious payloads
            'union select',
            'script>alert(',
            '../../../etc/passwd'
        ];

        signatures.forEach(sig => {
            const hash = crypto.createHash('md5').update(sig).digest('hex');
            this.threatSignatures.set(hash, {
                signature: sig,
                type: this.categorizeSignature(sig),
                severity: 'high'
            });
        });
    }

    async loadIpReputation() {
        // In production, this would load from threat intelligence feeds
        const suspiciousIps = [
            '192.0.2.1',    // Example malicious IP
            '198.51.100.1', // Example malicious IP
            '203.0.113.1'   // Example malicious IP
        ];

        suspiciousIps.forEach(ip => {
            this.suspiciousIps.add(ip);
        });

        // Load whitelist
        const whitelistIps = [
            '127.0.0.1',
            '::1',
            ...this.getPrivateIpRanges()
        ];

        whitelistIps.forEach(ip => {
            this.whitelist.add(ip);
        });
    }

    initializeBaselines() {
        // Initialize anomaly detection baselines
        this.anomalyBaselines.set('packet_rate', {
            normal_range: [10, 1000], // packets per second
            threshold_multiplier: 3
        });
        
        this.anomalyBaselines.set('connection_rate', {
            normal_range: [5, 100], // connections per minute
            threshold_multiplier: 4
        });
        
        this.anomalyBaselines.set('data_transfer', {
            normal_range: [1024, 10485760], // bytes (1KB - 10MB)
            threshold_multiplier: 5
        });
    }

    async analyzePacket(packet) {
        if (!this.initialized) {
            throw new Error('ThreatDetector not initialized');
        }

        const threats = [];

        try {
            // Run all enabled rules against the packet
            for (const [ruleId, rule] of this.rules) {
                if (!rule.enabled) continue;

                try {
                    const result = await rule.condition(packet);
                    if (result.detected) {
                        threats.push({
                            ruleId: ruleId,
                            type: rule.type,
                            name: rule.name,
                            severity: rule.severity,
                            description: rule.description,
                            technique: rule.technique,
                            tactics: rule.tactics,
                            confidence: result.confidence || 0.8,
                            indicators: result.indicators || [],
                            metadata: result.metadata || {},
                            timestamp: new Date().toISOString()
                        });
                    }
                } catch (ruleError) {
                    console.error(`Error in rule ${ruleId}:`, ruleError);
                }
            }

            // Additional signature-based detection
            const signatureThreats = await this.runSignatureDetection(packet);
            threats.push(...signatureThreats);

        } catch (error) {
            console.error('Error analyzing packet for threats:', error);
        }

        return threats;
    }

    async runSignatureDetection(packet) {
        const threats = [];

        // Check IP reputation
        if (packet.ip) {
            if (this.suspiciousIps.has(packet.ip.sourceIp)) {
                threats.push({
                    type: 'signature',
                    name: 'Suspicious Source IP',
                    severity: 'high',
                    description: `Communication from known malicious IP: ${packet.ip.sourceIp}`,
                    technique: 'T1071',
                    tactics: ['Command and Control'],
                    confidence: 0.9,
                    indicators: [packet.ip.sourceIp]
                });
            }

            if (this.suspiciousIps.has(packet.ip.destinationIp)) {
                threats.push({
                    type: 'signature',
                    name: 'Suspicious Destination IP',
                    severity: 'high',
                    description: `Communication to known malicious IP: ${packet.ip.destinationIp}`,
                    technique: 'T1071',
                    tactics: ['Command and Control'],
                    confidence: 0.9,
                    indicators: [packet.ip.destinationIp]
                });
            }
        }

        return threats;
    }

    // Rule implementations
    async detectPortScan(packet) {
        if (!packet.ip || !packet.ip.tcp) {
            return { detected: false };
        }

        const sourceIp = packet.ip.sourceIp;
        const destPort = packet.ip.tcp.destinationPort;
        
        // Track port access patterns
        const key = `port_scan_${sourceIp}`;
        const now = Date.now();
        
        if (!this.rateLimits.has(key)) {
            this.rateLimits.set(key, {
                ports: new Set(),
                firstSeen: now,
                lastSeen: now
            });
        }

        const tracker = this.rateLimits.get(key);
        tracker.ports.add(destPort);
        tracker.lastSeen = now;

        // Clean old entries
        if (now - tracker.firstSeen > 60000) { // 1 minute window
            tracker.ports.clear();
            tracker.firstSeen = now;
        }

        // Detect if too many different ports accessed
        if (tracker.ports.size > 10) {
            return {
                detected: true,
                confidence: Math.min(0.9, tracker.ports.size / 20),
                indicators: [sourceIp, Array.from(tracker.ports)],
                metadata: {
                    ports_scanned: tracker.ports.size,
                    time_window: '60s'
                }
            };
        }

        return { detected: false };
    }

    async detectSuspiciousDns(packet) {
        if (!packet.applicationProtocol || packet.applicationProtocol !== 'dns') {
            return { detected: false };
        }

        // In a real implementation, would parse DNS query
        // For now, check against known malicious domains
        const suspiciousDomains = [
            'evil.com',
            'malware-c2.net',
            'phishing-site.org'
        ];

        // Simplified detection (would need actual DNS parsing)
        const detected = suspiciousDomains.some(domain => {
            // This is a placeholder - would check actual DNS query
            return Math.random() < 0.1; // 10% chance for demo
        });

        if (detected) {
            return {
                detected: true,
                confidence: 0.85,
                indicators: ['suspicious_domain'],
                metadata: {
                    query_type: 'A',
                    response_code: 'NXDOMAIN'
                }
            };
        }

        return { detected: false };
    }

    async detectLargeTransfer(packet) {
        if (!packet.length) {
            return { detected: false };
        }

        const baseline = this.anomalyBaselines.get('data_transfer');
        const threshold = baseline.normal_range[1] * baseline.threshold_multiplier;

        if (packet.length > threshold) {
            return {
                detected: true,
                confidence: Math.min(0.9, packet.length / (threshold * 2)),
                indicators: [packet.length, threshold],
                metadata: {
                    packet_size: packet.length,
                    threshold: threshold,
                    protocol: packet.ip?.protocolName
                }
            };
        }

        return { detected: false };
    }

    async detectBruteForce(packet) {
        if (!packet.ip || !packet.ip.tcp) {
            return { detected: false };
        }

        // Check for common login ports
        const loginPorts = [22, 23, 21, 25, 110, 143, 993, 995, 3389];
        const destPort = packet.ip.tcp.destinationPort;
        
        if (!loginPorts.includes(destPort)) {
            return { detected: false };
        }

        const sourceIp = packet.ip.sourceIp;
        const key = `brute_force_${sourceIp}_${destPort}`;
        const now = Date.now();
        
        if (!this.rateLimits.has(key)) {
            this.rateLimits.set(key, {
                attempts: 0,
                firstAttempt: now,
                lastAttempt: now
            });
        }

        const tracker = this.rateLimits.get(key);
        tracker.attempts++;
        tracker.lastAttempt = now;

        // Reset counter after 5 minutes
        if (now - tracker.firstAttempt > 300000) {
            tracker.attempts = 1;
            tracker.firstAttempt = now;
        }

        // Detect brute force (more than 10 attempts in 5 minutes)
        if (tracker.attempts > 10) {
            return {
                detected: true,
                confidence: Math.min(0.95, tracker.attempts / 50),
                indicators: [sourceIp, destPort],
                metadata: {
                    attempts: tracker.attempts,
                    target_port: destPort,
                    time_window: '5m'
                }
            };
        }

        return { detected: false };
    }

    async detectDdos(packet) {
        const sourceIp = packet.ip?.sourceIp;
        if (!sourceIp) {
            return { detected: false };
        }

        const key = `ddos_${sourceIp}`;
        const now = Date.now();
        
        if (!this.rateLimits.has(key)) {
            this.rateLimits.set(key, {
                packets: 0,
                firstPacket: now,
                lastPacket: now
            });
        }

        const tracker = this.rateLimits.get(key);
        tracker.packets++;
        tracker.lastPacket = now;

        // Reset counter every minute
        if (now - tracker.firstPacket > 60000) {
            tracker.packets = 1;
            tracker.firstPacket = now;
        }

        // Detect DDoS (more than 1000 packets per minute from single source)
        if (tracker.packets > 1000) {
            return {
                detected: true,
                confidence: Math.min(0.99, tracker.packets / 2000),
                indicators: [sourceIp],
                metadata: {
                    packets_per_minute: tracker.packets,
                    attack_type: 'volumetric'
                }
            };
        }

        return { detected: false };
    }

    async detectMalwareComm(packet) {
        if (!packet.ip) {
            return { detected: false };
        }

        // Check against known C&C servers
        const maliciousIps = Array.from(this.suspiciousIps);
        const destIp = packet.ip.destinationIp;
        
        if (maliciousIps.includes(destIp)) {
            return {
                detected: true,
                confidence: 0.95,
                indicators: [destIp],
                metadata: {
                    c2_server: destIp,
                    protocol: packet.ip.protocolName
                }
            };
        }

        return { detected: false };
    }

    categorizeSignature(signature) {
        if (signature.includes('.') && signature.includes('/')) {
            return 'ip_range';
        } else if (signature.includes('.com') || signature.includes('.net')) {
            return 'domain';
        } else if (signature.includes('select') || signature.includes('union')) {
            return 'sql_injection';
        } else if (signature.includes('<script')) {
            return 'xss';
        } else {
            return 'generic';
        }
    }

    getPrivateIpRanges() {
        return [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16'
        ];
    }

    updateRule(ruleId, updates) {
        if (this.rules.has(ruleId)) {
            const rule = this.rules.get(ruleId);
            Object.assign(rule, updates);
            this.rules.set(ruleId, rule);
            return true;
        }
        return false;
    }

    addCustomRule(rule) {
        this.rules.set(rule.id, rule);
    }

    removeRule(ruleId) {
        return this.rules.delete(ruleId);
    }

    getStats() {
        return {
            total_rules: this.rules.size,
            enabled_rules: Array.from(this.rules.values()).filter(r => r.enabled).length,
            threat_signatures: this.threatSignatures.size,
            suspicious_ips: this.suspiciousIps.size,
            whitelist_entries: this.whitelist.size
        };
    }
}

module.exports = ThreatDetector; 