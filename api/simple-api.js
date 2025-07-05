#!/usr/bin/env node

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

/**
 * Simple A2Z SOC API Server
 * Lightweight API without complex dependencies
 */

const app = express();
const port = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Simple in-memory storage for demo
const customers = new Map();
const agents = new Map();
const subscriptions = new Map();

// Initialize demo data
const demoCustomer = {
    id: 'demo-customer-1',
    email: 'demo@a2zsoc.com',
    company: 'Demo Company',
    apiKey: 'a2z-demo-key-123',
    subscription: 'professional',
    status: 'active',
    createdAt: new Date().toISOString()
};
customers.set(demoCustomer.id, demoCustomer);

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'A2Z SOC API',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
});

// Authentication endpoints
app.post('/api/onboarding/register', (req, res) => {
    const { email, password, company } = req.body;
    
    if (!email || !password || !company) {
        return res.status(400).json({
            success: false,
            message: 'Email, password, and company are required'
        });
    }

    const customerId = `customer-${Date.now()}`;
    const apiKey = `a2z-${crypto.randomBytes(16).toString('hex')}`;
    
    const customer = {
        id: customerId,
        email,
        company,
        apiKey,
        subscription: 'starter',
        status: 'trial',
        trialDays: 14,
        createdAt: new Date().toISOString()
    };
    
    customers.set(customerId, customer);
    
    res.json({
        success: true,
        customer: {
            id: customer.id,
            email: customer.email,
            company: customer.company,
            apiKey: customer.apiKey,
            subscription: customer.subscription,
            status: customer.status
        },
        message: 'Registration successful! Your 14-day trial has started.'
    });
});

app.post('/api/onboarding/login', (req, res) => {
    const { email, password } = req.body;
    
    // Simple demo login - find customer by email
    const customer = Array.from(customers.values()).find(c => c.email === email);
    
    if (!customer) {
        return res.status(401).json({
            success: false,
            message: 'Invalid credentials'
        });
    }
    
    const token = `token-${crypto.randomBytes(16).toString('hex')}`;
    
    res.json({
        success: true,
        token,
        customer: {
            id: customer.id,
            email: customer.email,
            company: customer.company,
            subscription: customer.subscription,
            status: customer.status
        }
    });
});

// Subscription tiers
app.get('/api/onboarding/tiers', (req, res) => {
    res.json({
        tiers: [
            {
                id: 'starter',
                name: 'Starter',
                price: 500,
                currency: 'USD',
                interval: 'month',
                endpoints: 500,
                features: [
                    'Basic network monitoring',
                    'Email alerts',
                    'Standard reports',
                    'Community support'
                ]
            },
            {
                id: 'professional',
                name: 'Professional',
                price: 2500,
                currency: 'USD',
                interval: 'month',
                endpoints: 5000,
                features: [
                    'Advanced threat detection',
                    'Real-time alerts',
                    'Custom reports',
                    'API access',
                    'Priority support'
                ]
            },
            {
                id: 'enterprise',
                name: 'Enterprise',
                price: 10000,
                currency: 'USD',
                interval: 'month',
                endpoints: 50000,
                features: [
                    'Full platform access',
                    'Custom integrations',
                    'Dedicated support',
                    'SLA guarantee',
                    'On-premise option'
                ]
            }
        ]
    });
});

// Agent downloads
app.get('/api/agents/download/:platform', (req, res) => {
    const { platform } = req.params;
    
    const downloads = {
        windows: {
            url: '/downloads/a2z-agent-windows.exe',
            version: '1.0.0',
            size: '15.2 MB',
            checksum: 'sha256:a1b2c3d4...'
        },
        linux: {
            url: '/downloads/a2z-agent-linux',
            version: '1.0.0',
            size: '12.8 MB',
            checksum: 'sha256:e5f6g7h8...'
        },
        macos: {
            url: '/downloads/a2z-agent-macos',
            version: '1.0.0',
            size: '14.5 MB',
            checksum: 'sha256:i9j0k1l2...'
        },
        docker: {
            command: 'docker pull a2zsoc/network-agent:latest',
            version: '1.0.0',
            size: '85 MB'
        }
    };
    
    if (!downloads[platform]) {
        return res.status(404).json({
            success: false,
            message: 'Platform not supported'
        });
    }
    
    res.json({
        success: true,
        platform,
        download: downloads[platform],
        installation: {
            requirements: ['Root/Administrator privileges', 'Network access'],
            steps: [
                'Download the agent',
                'Run as administrator/root',
                'Configure with your API key',
                'Start monitoring'
            ]
        }
    });
});

// IDS/IPS downloads
app.get('/api/ids/download/:component', (req, res) => {
    const { component } = req.params;
    
    const components = {
        core: {
            url: '/downloads/a2z-ids-core',
            version: '1.0.0',
            size: '45 MB',
            description: 'Core IDS/IPS engine with ML capabilities'
        },
        rules: {
            url: '/downloads/a2z-rules-pack.tar.gz',
            version: '2025.06.08',
            size: '25 MB',
            description: 'Latest threat detection rules'
        },
        signatures: {
            url: '/downloads/a2z-signatures.db',
            version: '2025.06.08',
            size: '15 MB',
            description: 'Threat signature database'
        }
    };
    
    if (!components[component]) {
        return res.status(404).json({
            success: false,
            message: 'Component not found'
        });
    }
    
    res.json({
        success: true,
        component,
        download: components[component],
        installation: {
            requirements: ['Linux/Unix system', 'Root privileges', 'libpcap'],
            configuration: [
                'Extract to /opt/a2z-ids/',
                'Configure network interface',
                'Set up logging directory',
                'Start IDS service'
            ]
        }
    });
});

// Customer usage stats
app.get('/api/onboarding/usage', (req, res) => {
    const customerId = req.headers['x-customer-id'] || 'demo-customer-1';
    const customer = customers.get(customerId);
    
    if (!customer) {
        return res.status(404).json({
            success: false,
            message: 'Customer not found'
        });
    }
    
    res.json({
        success: true,
        usage: {
            endpoints: {
                current: Math.floor(Math.random() * 100) + 50,
                limit: customer.subscription === 'starter' ? 500 : 
                       customer.subscription === 'professional' ? 5000 : 50000
            },
            alerts: {
                thisMonth: Math.floor(Math.random() * 500) + 100,
                lastMonth: Math.floor(Math.random() * 400) + 80
            },
            threats: {
                blocked: Math.floor(Math.random() * 50) + 10,
                detected: Math.floor(Math.random() * 100) + 25
            },
            dataProcessed: {
                thisMonth: `${(Math.random() * 10 + 5).toFixed(1)} GB`,
                lastMonth: `${(Math.random() * 8 + 4).toFixed(1)} GB`
            }
        }
    });
});

// Platform status
app.get('/api/status', (req, res) => {
    res.json({
        platform: 'A2Z SOC',
        version: '1.0.0',
        status: 'operational',
        services: {
            api: 'healthy',
            database: 'healthy',
            monitoring: 'healthy',
            alerts: 'healthy'
        },
        stats: {
            totalCustomers: customers.size,
            activeMonitoring: Math.floor(Math.random() * 500) + 200,
            threatsBlocked: Math.floor(Math.random() * 10000) + 5000
        },
        uptime: '99.9%',
        lastUpdate: new Date().toISOString()
    });
});

// Documentation
app.get('/docs', (req, res) => {
    res.json({
        title: 'A2Z SOC API Documentation',
        version: '1.0.0',
        endpoints: {
            authentication: [
                'POST /api/onboarding/register - Customer registration',
                'POST /api/onboarding/login - Customer login'
            ],
            subscriptions: [
                'GET /api/onboarding/tiers - Available subscription tiers'
            ],
            downloads: [
                'GET /api/agents/download/:platform - Download network agents',
                'GET /api/ids/download/:component - Download IDS/IPS components'
            ],
            monitoring: [
                'GET /api/onboarding/usage - Customer usage statistics',
                'GET /api/status - Platform status'
            ]
        },
        examples: {
            register: {
                method: 'POST',
                url: '/api/onboarding/register',
                body: {
                    email: 'user@company.com',
                    password: 'securepassword',
                    company: 'Company Name'
                }
            },
            download: {
                method: 'GET',
                url: '/api/agents/download/linux',
                headers: {
                    'X-API-Key': 'your-api-key'
                }
            }
        }
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        service: 'A2Z SOC API',
        version: '1.0.0',
        status: 'operational',
        documentation: '/docs',
        health: '/health'
    });
});

// Start server
app.listen(port, () => {
    console.log(`🚀 A2Z SOC API listening on port ${port}`);
    console.log(`📖 Documentation: http://localhost:${port}/docs`);
    console.log(`💊 Health Check: http://localhost:${port}/health`);
    console.log(`🎯 Ready for customer onboarding!`);
});

module.exports = app; 