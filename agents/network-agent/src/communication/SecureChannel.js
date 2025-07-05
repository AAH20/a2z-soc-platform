const WebSocket = require('ws');
const https = require('https');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const EventEmitter = require('events');

class SecureChannel extends EventEmitter {
    constructor(config) {
        super();
        this.config = config;
        this.ws = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 5000;
        this.messageQueue = [];
        this.pendingMessages = new Map();
        this.sessionId = uuidv4();
        
        // Security
        this.agentKey = config.agentKey;
        this.tenantCert = config.tenantCert;
        this.encryptionKey = this.deriveEncryptionKey();
        
        // Heartbeat
        this.lastHeartbeat = null;
        this.heartbeatTimeout = null;
    }

    async connect() {
        try {
            const endpoint = this.buildWebSocketUrl();
            const headers = await this.generateAuthHeaders();
            
            this.ws = new WebSocket(endpoint, {
                headers: headers,
                timeout: 30000,
                perMessageDeflate: true,
                clientCertEngine: this.config.clientCertEngine
            });

            this.setupWebSocketHandlers();
            
            // Wait for connection
            await new Promise((resolve, reject) => {
                const timeout = setTimeout(() => {
                    reject(new Error('Connection timeout'));
                }, 30000);

                this.ws.once('open', () => {
                    clearTimeout(timeout);
                    resolve();
                });

                this.ws.once('error', (error) => {
                    clearTimeout(timeout);
                    reject(error);
                });
            });

            await this.authenticate();
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.startHeartbeat();
            this.processQueuedMessages();
            
            console.log('🔐 Secure channel established');
            this.emit('connected');

        } catch (error) {
            console.error('❌ Failed to establish secure channel:', error);
            this.scheduleReconnect();
            throw error;
        }
    }

    buildWebSocketUrl() {
        const baseUrl = this.config.cloudEndpoint.replace('https://', 'wss://');
        return `${baseUrl}/agents/v1/stream?tenant=${this.config.tenantId}&session=${this.sessionId}`;
    }

    async generateAuthHeaders() {
        const timestamp = Date.now();
        const nonce = crypto.randomBytes(16).toString('hex');
        
        // Create signature
        const payload = `${this.config.agentId}:${timestamp}:${nonce}`;
        const signature = crypto
            .createHmac('sha256', this.agentKey)
            .update(payload)
            .digest('hex');

        return {
            'X-Agent-ID': this.config.agentId,
            'X-Tenant-ID': this.config.tenantId,
            'X-Timestamp': timestamp.toString(),
            'X-Nonce': nonce,
            'X-Signature': signature,
            'User-Agent': `A2Z-Agent/1.0.0 (${process.platform})`
        };
    }

    setupWebSocketHandlers() {
        this.ws.on('open', () => {
            console.log('📡 WebSocket connection opened');
        });

        this.ws.on('message', async (data) => {
            try {
                await this.handleIncomingMessage(data);
            } catch (error) {
                console.error('❌ Error handling incoming message:', error);
            }
        });

        this.ws.on('close', (code, reason) => {
            console.log(`📡 WebSocket closed: ${code} - ${reason}`);
            this.handleDisconnection();
        });

        this.ws.on('error', (error) => {
            console.error('❌ WebSocket error:', error);
            this.handleDisconnection();
        });

        this.ws.on('ping', () => {
            this.ws.pong();
        });

        this.ws.on('pong', () => {
            this.lastHeartbeat = Date.now();
        });
    }

    async authenticate() {
        const authMessage = {
            type: 'auth',
            payload: {
                agent_id: this.config.agentId,
                tenant_id: this.config.tenantId,
                version: '1.0.0',
                capabilities: [
                    'network_monitoring',
                    'threat_detection',
                    'real_time_alerts',
                    'compression',
                    'encryption'
                ],
                system_info: {
                    platform: process.platform,
                    arch: process.arch,
                    node_version: process.version,
                    memory: process.memoryUsage().rss
                }
            }
        };

        await this.sendMessage(authMessage);
        
        // Wait for auth response
        const authResponse = await this.waitForMessage('auth_response', 10000);
        
        if (authResponse.payload.status !== 'success') {
            throw new Error(`Authentication failed: ${authResponse.payload.message}`);
        }

        console.log('✅ Agent authenticated successfully');
    }

    async handleIncomingMessage(data) {
        try {
            // Decrypt if needed
            const decryptedData = this.config.encryption ? 
                this.decrypt(data) : data;
            
            const message = JSON.parse(decryptedData);
            
            switch (message.type) {
                case 'auth_response':
                    this.emit('auth_response', message);
                    break;
                    
                case 'ack':
                    this.handleAcknowledgment(message);
                    break;
                    
                case 'command':
                    await this.handleCommand(message);
                    break;
                    
                case 'config_update':
                    await this.handleConfigUpdate(message);
                    break;
                    
                case 'heartbeat_response':
                    this.lastHeartbeat = Date.now();
                    break;
                    
                default:
                    console.warn('⚠️  Unknown message type:', message.type);
            }
            
        } catch (error) {
            console.error('❌ Error processing incoming message:', error);
        }
    }

    handleAcknowledgment(message) {
        const messageId = message.payload.message_id;
        if (this.pendingMessages.has(messageId)) {
            const { resolve } = this.pendingMessages.get(messageId);
            this.pendingMessages.delete(messageId);
            resolve(message);
        }
    }

    async handleCommand(message) {
        const { command, parameters } = message.payload;
        
        try {
            let response;
            
            switch (command) {
                case 'get_status':
                    response = await this.getAgentStatus();
                    break;
                    
                case 'get_metrics':
                    response = await this.getAgentMetrics();
                    break;
                    
                case 'update_config':
                    response = await this.updateAgentConfig(parameters);
                    break;
                    
                case 'restart_monitoring':
                    response = await this.restartMonitoring();
                    break;
                    
                default:
                    response = { error: `Unknown command: ${command}` };
            }
            
            await this.sendCommandResponse(message.id, response);
            
        } catch (error) {
            await this.sendCommandResponse(message.id, { 
                error: error.message 
            });
        }
    }

    async handleConfigUpdate(message) {
        try {
            const newConfig = message.payload.config;
            await this.updateLocalConfig(newConfig);
            
            await this.sendMessage({
                type: 'config_update_ack',
                payload: {
                    message_id: message.id,
                    status: 'success'
                }
            });
            
            this.emit('config_updated', newConfig);
            
        } catch (error) {
            await this.sendMessage({
                type: 'config_update_ack',
                payload: {
                    message_id: message.id,
                    status: 'error',
                    error: error.message
                }
            });
        }
    }

    async sendMessage(message, waitForAck = false) {
        if (!this.isConnected || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
            if (message.type !== 'heartbeat') {
                this.messageQueue.push({ message, waitForAck });
            }
            return null;
        }

        try {
            // Add message ID and timestamp
            message.id = message.id || uuidv4();
            message.timestamp = new Date().toISOString();
            
            // Encrypt if needed
            const payload = this.config.encryption ? 
                this.encrypt(JSON.stringify(message)) : 
                JSON.stringify(message);
            
            this.ws.send(payload);
            
            if (waitForAck) {
                return this.waitForAcknowledgment(message.id);
            }
            
            return message.id;
            
        } catch (error) {
            console.error('❌ Error sending message:', error);
            throw error;
        }
    }

    waitForAcknowledgment(messageId, timeout = 30000) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.pendingMessages.delete(messageId);
                reject(new Error('Message acknowledgment timeout'));
            }, timeout);
            
            this.pendingMessages.set(messageId, { 
                resolve: (ack) => {
                    clearTimeout(timer);
                    resolve(ack);
                },
                reject: (error) => {
                    clearTimeout(timer);
                    reject(error);
                }
            });
        });
    }

    waitForMessage(messageType, timeout = 10000) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.removeListener(messageType, handler);
                reject(new Error(`Timeout waiting for message: ${messageType}`));
            }, timeout);
            
            const handler = (message) => {
                clearTimeout(timer);
                resolve(message);
            };
            
            this.once(messageType, handler);
        });
    }

    async sendEvents(eventsPayload) {
        const message = {
            type: 'events',
            payload: eventsPayload
        };
        
        return await this.sendMessage(message, true);
    }

    async sendAlerts(alertsPayload) {
        const message = {
            type: 'alerts',
            payload: alertsPayload,
            priority: 'high'
        };
        
        return await this.sendMessage(message, true);
    }

    async sendHeartbeat(status) {
        const message = {
            type: 'heartbeat',
            payload: {
                ...status,
                last_heartbeat: this.lastHeartbeat
            }
        };
        
        return await this.sendMessage(message);
    }

    async sendCommandResponse(commandId, response) {
        const message = {
            type: 'command_response',
            payload: {
                command_id: commandId,
                response: response
            }
        };
        
        return await this.sendMessage(message);
    }

    startHeartbeat() {
        this.heartbeatTimeout = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.ping();
            }
        }, 30000); // 30 seconds
    }

    stopHeartbeat() {
        if (this.heartbeatTimeout) {
            clearInterval(this.heartbeatTimeout);
            this.heartbeatTimeout = null;
        }
    }

    processQueuedMessages() {
        while (this.messageQueue.length > 0 && this.isConnected) {
            const { message, waitForAck } = this.messageQueue.shift();
            this.sendMessage(message, waitForAck).catch(console.error);
        }
    }

    handleDisconnection() {
        this.isConnected = false;
        this.stopHeartbeat();
        
        // Reject pending messages
        for (const [messageId, { reject }] of this.pendingMessages) {
            reject(new Error('Connection lost'));
        }
        this.pendingMessages.clear();
        
        this.emit('disconnected');
        this.scheduleReconnect();
    }

    scheduleReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('❌ Max reconnection attempts reached');
            this.emit('max_reconnects_reached');
            return;
        }

        this.reconnectAttempts++;
        const delay = this.reconnectDelay * this.reconnectAttempts;
        
        console.log(`🔄 Scheduling reconnection attempt ${this.reconnectAttempts} in ${delay}ms`);
        
        setTimeout(() => {
            this.connect().catch(console.error);
        }, delay);
    }

    deriveEncryptionKey() {
        if (!this.config.encryption || !this.agentKey) {
            return null;
        }
        
        return crypto.scrypt(this.agentKey, 'a2z-salt', 32, (err, key) => {
            if (err) throw err;
            return key;
        });
    }

    encrypt(data) {
        if (!this.encryptionKey) return data;
        
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher('aes-256-cbc', this.encryptionKey);
        cipher.setAAD(iv);
        
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return iv.toString('hex') + ':' + encrypted;
    }

    decrypt(encryptedData) {
        if (!this.encryptionKey) return encryptedData;
        
        const [ivHex, encrypted] = encryptedData.split(':');
        const iv = Buffer.from(ivHex, 'hex');
        
        const decipher = crypto.createDecipher('aes-256-cbc', this.encryptionKey);
        decipher.setAAD(iv);
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    }

    async close() {
        this.isConnected = false;
        this.stopHeartbeat();
        
        if (this.ws) {
            this.ws.close(1000, 'Agent shutdown');
            this.ws = null;
        }
        
        console.log('🔐 Secure channel closed');
    }
}

// Factory function
async function createSecureConnection(config) {
    const channel = new SecureChannel(config);
    await channel.connect();
    return channel;
}

module.exports = SecureChannel;
module.exports.SecureChannel = SecureChannel;
module.exports.createSecureConnection = createSecureConnection; 