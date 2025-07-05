const http = require('http');
const url = require('url');
const querystring = require('querystring');

class ApiServer {
    constructor(networkAgent, options = {}) {
        this.networkAgent = networkAgent;
        this.options = {
            port: options.port || 3001,
            host: options.host || '0.0.0.0',
            cors: options.cors !== false,
            ...options
        };
        
        this.server = null;
        this.routes = new Map();
        this.middlewares = [];
        
        this.setupRoutes();
    }

    setupRoutes() {
        // Health check
        this.addRoute('GET', '/health', this.handleHealth.bind(this));
        
        // Agent status and control
        this.addRoute('GET', '/api/v1/status', this.handleGetStatus.bind(this));
        this.addRoute('POST', '/api/v1/agent/start', this.handleStartAgent.bind(this));
        this.addRoute('POST', '/api/v1/agent/stop', this.handleStopAgent.bind(this));
        this.addRoute('POST', '/api/v1/agent/restart', this.handleRestartAgent.bind(this));
        
        // System metrics
        this.addRoute('GET', '/api/v1/metrics/system', this.handleGetSystemMetrics.bind(this));
        this.addRoute('GET', '/api/v1/metrics/system/latest', this.handleGetLatestSystemMetrics.bind(this));
        
        // Network metrics
        this.addRoute('GET', '/api/v1/metrics/network', this.handleGetNetworkMetrics.bind(this));
        this.addRoute('GET', '/api/v1/metrics/network/latest', this.handleGetLatestNetworkMetrics.bind(this));
        this.addRoute('GET', '/api/v1/metrics/protocols', this.handleGetProtocolDistribution.bind(this));
        
        // Threat detection
        this.addRoute('GET', '/api/v1/threats/alerts', this.handleGetThreatAlerts.bind(this));
        this.addRoute('GET', '/api/v1/threats/alerts/:id', this.handleGetThreatAlert.bind(this));
        this.addRoute('PATCH', '/api/v1/threats/alerts/:id', this.handleUpdateThreatAlert.bind(this));
        this.addRoute('GET', '/api/v1/threats/rules', this.handleGetThreatRules.bind(this));
        this.addRoute('PATCH', '/api/v1/threats/rules/:id', this.handleUpdateThreatRule.bind(this));
        this.addRoute('POST', '/api/v1/threats/rules', this.handleCreateThreatRule.bind(this));
        this.addRoute('DELETE', '/api/v1/threats/rules/:id', this.handleDeleteThreatRule.bind(this));
        
        // Configuration
        this.addRoute('GET', '/api/v1/config', this.handleGetConfiguration.bind(this));
        this.addRoute('PATCH', '/api/v1/config', this.handleUpdateConfiguration.bind(this));
        this.addRoute('POST', '/api/v1/config/reset', this.handleResetConfiguration.bind(this));
        this.addRoute('GET', '/api/v1/config/export', this.handleExportConfiguration.bind(this));
        this.addRoute('POST', '/api/v1/config/import', this.handleImportConfiguration.bind(this));
        
        // Logs
        this.addRoute('GET', '/api/v1/logs', this.handleGetLogs.bind(this));
        this.addRoute('GET', '/api/v1/logs/download', this.handleDownloadLogs.bind(this));
    }

    addRoute(method, path, handler) {
        const key = `${method}:${path}`;
        this.routes.set(key, { method, path, handler });
    }

    async start() {
        return new Promise((resolve, reject) => {
            this.server = http.createServer(this.handleRequest.bind(this));
            
            this.server.listen(this.options.port, this.options.host, (error) => {
                if (error) {
                    reject(error);
                } else {
                    console.log(`🌐 API Server listening on http://${this.options.host}:${this.options.port}`);
                    resolve();
                }
            });
        });
    }

    async stop() {
        if (this.server) {
            return new Promise((resolve) => {
                this.server.close(() => {
                    console.log('🌐 API Server stopped');
                    resolve();
                });
            });
        }
    }

    async handleRequest(req, res) {
        try {
            // CORS headers
            if (this.options.cors) {
                res.setHeader('Access-Control-Allow-Origin', '*');
                res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
                res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
                
                if (req.method === 'OPTIONS') {
                    res.writeHead(204);
                    res.end();
                    return;
                }
            }

            // Parse URL and method
            const { pathname, query } = url.parse(req.url, true);
            const method = req.method;
            
            // Find matching route
            const route = this.findRoute(method, pathname);
            
            if (!route) {
                this.sendError(res, 404, 'Route not found');
                return;
            }

            // Parse body for POST/PUT/PATCH requests
            let body = null;
            if (['POST', 'PUT', 'PATCH'].includes(method)) {
                body = await this.parseBody(req);
            }

            // Create request context
            const context = {
                method,
                pathname,
                query,
                body,
                params: this.extractParams(route.path, pathname)
            };

            // Execute route handler
            await route.handler(context, res);

        } catch (error) {
            console.error('API Server Error:', error);
            this.sendError(res, 500, 'Internal Server Error');
        }
    }

    findRoute(method, pathname) {
        // First try exact match
        const exactKey = `${method}:${pathname}`;
        if (this.routes.has(exactKey)) {
            return this.routes.get(exactKey);
        }

        // Try pattern matching for routes with parameters
        for (const [key, route] of this.routes) {
            const [routeMethod, routePath] = key.split(':');
            if (routeMethod === method && this.pathMatches(routePath, pathname)) {
                return route;
            }
        }

        return null;
    }

    pathMatches(routePath, pathname) {
        const routeParts = routePath.split('/');
        const pathParts = pathname.split('/');
        
        if (routeParts.length !== pathParts.length) {
            return false;
        }

        for (let i = 0; i < routeParts.length; i++) {
            const routePart = routeParts[i];
            const pathPart = pathParts[i];
            
            if (routePart.startsWith(':')) {
                continue; // Parameter match
            }
            
            if (routePart !== pathPart) {
                return false;
            }
        }

        return true;
    }

    extractParams(routePath, pathname) {
        const routeParts = routePath.split('/');
        const pathParts = pathname.split('/');
        const params = {};

        for (let i = 0; i < routeParts.length; i++) {
            const routePart = routeParts[i];
            if (routePart.startsWith(':')) {
                const paramName = routePart.slice(1);
                params[paramName] = pathParts[i];
            }
        }

        return params;
    }

    async parseBody(req) {
        return new Promise((resolve, reject) => {
            let body = '';
            req.on('data', chunk => {
                body += chunk.toString();
            });
            req.on('end', () => {
                try {
                    if (req.headers['content-type']?.includes('application/json')) {
                        resolve(JSON.parse(body));
                    } else {
                        resolve(body);
                    }
                } catch (error) {
                    reject(error);
                }
            });
        });
    }

    sendResponse(res, statusCode, data) {
        res.setHeader('Content-Type', 'application/json');
        res.writeHead(statusCode);
        res.end(JSON.stringify({
            success: statusCode < 400,
            data: statusCode < 400 ? data : undefined,
            error: statusCode >= 400 ? data : undefined,
            timestamp: new Date().toISOString()
        }));
    }

    sendError(res, statusCode, message) {
        this.sendResponse(res, statusCode, message);
    }

    // Route Handlers
    async handleHealth(context, res) {
        this.sendResponse(res, 200, {
            status: 'ok',
            timestamp: new Date().toISOString()
        });
    }

    async handleGetStatus(context, res) {
        const status = await this.networkAgent.getStatus();
        this.sendResponse(res, 200, status);
    }

    async handleStartAgent(context, res) {
        await this.networkAgent.start();
        this.sendResponse(res, 200, { message: 'Agent started' });
    }

    async handleStopAgent(context, res) {
        await this.networkAgent.stop();
        this.sendResponse(res, 200, { message: 'Agent stopped' });
    }

    async handleRestartAgent(context, res) {
        await this.networkAgent.restart();
        this.sendResponse(res, 200, { message: 'Agent restarted' });
    }

    async handleGetSystemMetrics(context, res) {
        const metrics = this.networkAgent.metricsCollector?.getAllMetrics() || {};
        this.sendResponse(res, 200, this.formatSystemMetrics(metrics));
    }

    async handleGetLatestSystemMetrics(context, res) {
        const metrics = this.networkAgent.metricsCollector?.getAllMetrics() || {};
        this.sendResponse(res, 200, this.formatLatestSystemMetrics(metrics));
    }

    async handleGetNetworkMetrics(context, res) {
        const stats = this.networkAgent.packetAnalyzer?.getStatistics() || {};
        this.sendResponse(res, 200, this.formatNetworkMetrics(stats));
    }

    async handleGetLatestNetworkMetrics(context, res) {
        const stats = this.networkAgent.packetAnalyzer?.getStatistics() || {};
        this.sendResponse(res, 200, this.formatLatestNetworkMetrics(stats));
    }

    async handleGetProtocolDistribution(context, res) {
        const stats = this.networkAgent.packetAnalyzer?.getStatistics() || {};
        this.sendResponse(res, 200, stats.protocolStats || {});
    }

    async handleGetThreatAlerts(context, res) {
        // This would integrate with a threat alert storage system
        // For now, return mock data
        this.sendResponse(res, 200, {
            data: [],
            total: 0,
            page: 1,
            limit: 50,
            hasMore: false
        });
    }

    async handleGetThreatAlert(context, res) {
        const { id } = context.params;
        // Mock implementation
        this.sendError(res, 404, 'Alert not found');
    }

    async handleUpdateThreatAlert(context, res) {
        const { id } = context.params;
        const updates = context.body;
        // Mock implementation
        this.sendError(res, 404, 'Alert not found');
    }

    async handleGetThreatRules(context, res) {
        const rules = Array.from(this.networkAgent.threatDetector?.rules.values() || []);
        this.sendResponse(res, 200, rules);
    }

    async handleUpdateThreatRule(context, res) {
        const { id } = context.params;
        const updates = context.body;
        
        if (this.networkAgent.threatDetector?.updateRule(id, updates)) {
            this.sendResponse(res, 200, { message: 'Rule updated' });
        } else {
            this.sendError(res, 404, 'Rule not found');
        }
    }

    async handleCreateThreatRule(context, res) {
        const rule = { ...context.body, id: this.generateId() };
        this.networkAgent.threatDetector?.addCustomRule(rule);
        this.sendResponse(res, 201, rule);
    }

    async handleDeleteThreatRule(context, res) {
        const { id } = context.params;
        
        if (this.networkAgent.threatDetector?.removeRule(id)) {
            this.sendResponse(res, 200, { message: 'Rule deleted' });
        } else {
            this.sendError(res, 404, 'Rule not found');
        }
    }

    async handleGetConfiguration(context, res) {
        const config = this.networkAgent.configManager?.getConfig() || {};
        this.sendResponse(res, 200, config);
    }

    async handleUpdateConfiguration(context, res) {
        const updates = context.body;
        await this.networkAgent.configManager?.updateConfig(updates);
        const config = this.networkAgent.configManager?.getConfig() || {};
        this.sendResponse(res, 200, config);
    }

    async handleResetConfiguration(context, res) {
        await this.networkAgent.configManager?.factoryReset();
        const config = this.networkAgent.configManager?.getConfig() || {};
        this.sendResponse(res, 200, config);
    }

    async handleExportConfiguration(context, res) {
        const config = this.networkAgent.configManager?.getConfig() || {};
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', 'attachment; filename=agent-config.json');
        res.writeHead(200);
        res.end(JSON.stringify(config, null, 2));
    }

    async handleImportConfiguration(context, res) {
        // Mock implementation for file upload
        this.sendError(res, 501, 'Not implemented');
    }

    async handleGetLogs(context, res) {
        // Mock implementation
        this.sendResponse(res, 200, [
            'Agent started successfully',
            'Network monitoring initiated',
            'Packet analysis running'
        ]);
    }

    async handleDownloadLogs(context, res) {
        const logs = 'Mock log data\nTimestamp: ' + new Date().toISOString();
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', 'attachment; filename=agent-logs.txt');
        res.writeHead(200);
        res.end(logs);
    }

    // Helper methods
    formatSystemMetrics(metrics) {
        const timestamp = new Date().toISOString();
        return {
            timestamp,
            cpu: {
                usage: metrics.gauges?.system_cpu_user_seconds || 0,
                user: metrics.gauges?.system_cpu_user_seconds || 0,
                system: metrics.gauges?.system_cpu_system_seconds || 0
            },
            memory: {
                used: metrics.gauges?.system_memory_rss_bytes || 0,
                total: metrics.gauges?.system_memory_heap_total_bytes || 0,
                percentage: 0
            },
            network: {
                packetsReceived: 0,
                packetsSent: 0,
                bytesReceived: 0,
                bytesSent: 0,
                errorsReceived: 0,
                errorsSent: 0
            },
            disk: {
                used: 0,
                total: 0,
                percentage: 0
            }
        };
    }

    formatLatestSystemMetrics(metrics) {
        return this.formatSystemMetrics(metrics);
    }

    formatNetworkMetrics(stats) {
        const timestamp = new Date().toISOString();
        return {
            timestamp,
            totalPackets: stats.packetCounts?.total || 0,
            packetsPerSecond: 0,
            bytesPerSecond: 0,
            protocolDistribution: stats.protocolStats || {},
            topSources: [],
            topDestinations: []
        };
    }

    formatLatestNetworkMetrics(stats) {
        return this.formatNetworkMetrics(stats);
    }

    generateId() {
        return 'rule_' + Math.random().toString(36).substr(2, 9);
    }
}

module.exports = ApiServer; 