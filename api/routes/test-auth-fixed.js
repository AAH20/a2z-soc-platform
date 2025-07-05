const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const router = express.Router();

// Simple database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://a2z_ids:secure_password@localhost:5432/a2z_ids'
});

// Test endpoint
router.get('/test', (req, res) => {
    res.json({ message: 'Test auth endpoint working', timestamp: new Date().toISOString() });
});

// Simple registration
router.post('/simple-register', async (req, res) => {
    try {
        const { email, password, firstName, lastName } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        // Hash password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        // Create tenant first
        const tenantResult = await pool.query(
            'INSERT INTO tenants (name, subdomain, contact_email, status, plan) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            ['Test Company', 'test-' + Date.now(), email, 'active', 'trial']
        );
        
        const tenantId = tenantResult.rows[0].id;
        
        // Create user
        const userResult = await pool.query(
            'INSERT INTO users (tenant_id, email, password_hash, first_name, last_name, role, email_verified) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, email, first_name, last_name, role',
            [tenantId, email, passwordHash, firstName || 'Test', lastName || 'User', 'admin', true]
        );
        
        const user = userResult.rows[0];
        
        // Generate JWT
        const token = jwt.sign(
            { userId: user.id, tenantId: tenantId, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '24h' }
        );
        
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                role: user.role,
                tenantId: tenantId
            },
            tenant: {
                id: tenantId,
                name: 'Test Company'
            }
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed: ' + error.message });
    }
});

// Simple login
router.post('/simple-login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        // Find user
        const userResult = await pool.query(
            'SELECT u.*, t.name as tenant_name FROM users u JOIN tenants t ON u.tenant_id = t.id WHERE u.email = $1',
            [email]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = userResult.rows[0];
        
        // Check password
        const passwordValid = await bcrypt.compare(password, user.password_hash);
        if (!passwordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT
        const token = jwt.sign(
            { userId: user.id, tenantId: user.tenant_id, email: user.email, role: user.role },
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                role: user.role,
                tenantId: user.tenant_id
            },
            tenant: {
                id: user.tenant_id,
                name: user.tenant_name
            }
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed: ' + error.message });
    }
});

module.exports = router; 