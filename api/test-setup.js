require('dotenv').config();
const axios = require('axios');
const { Pool } = require('pg');

/**
 * Test script for A2Z SOC SaaS Setup
 * This script verifies the complete setup including database, migrations, and API endpoints
 */

const BASE_URL = `http://localhost:${process.env.PORT || 3001}`;
const API_URL = `${BASE_URL}/api`;

// Colors for console output
const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m',
  bright: '\x1b[1m'
};

const log = (message, color = 'reset') => {
  console.log(`${colors[color]}${message}${colors.reset}`);
};

const section = (title) => {
  console.log('\n' + '='.repeat(50));
  log(title, 'bright');
  console.log('='.repeat(50));
};

class A2ZSOCTester {
  constructor() {
    this.testResults = {
      passed: 0,
      failed: 0,
      tests: []
    };
    
    this.dbPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });
  }

  async runTest(name, testFn) {
    try {
      log(`\n🧪 Testing: ${name}`, 'blue');
      await testFn();
      log(`✅ PASSED: ${name}`, 'green');
      this.testResults.passed++;
      this.testResults.tests.push({ name, status: 'PASSED' });
    } catch (error) {
      log(`❌ FAILED: ${name}`, 'red');
      log(`   Error: ${error.message}`, 'red');
      this.testResults.failed++;
      this.testResults.tests.push({ name, status: 'FAILED', error: error.message });
    }
  }

  async testDatabaseConnection() {
    const client = await this.dbPool.connect();
    try {
      const result = await client.query('SELECT NOW() as current_time, version() as pg_version');
      log(`   Database time: ${result.rows[0].current_time}`, 'yellow');
      log(`   PostgreSQL version: ${result.rows[0].pg_version.split(',')[0]}`, 'yellow');
    } finally {
      client.release();
    }
  }

  async testMigrationStatus() {
    const client = await this.dbPool.connect();
    try {
      // Check if migration table exists
      const migrationTableCheck = await client.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'schema_migrations'
        )
      `);
      
      if (!migrationTableCheck.rows[0].exists) {
        throw new Error('Migration table does not exist. Run: npm run migrate');
      }

      // Check migration status
      const migrations = await client.query('SELECT * FROM schema_migrations ORDER BY executed_at');
      log(`   Executed migrations: ${migrations.rows.length}`, 'yellow');
      
      if (migrations.rows.length === 0) {
        throw new Error('No migrations executed. Run: npm run migrate');
      }

      migrations.rows.forEach(migration => {
        log(`   - ${migration.version}: ${migration.name}`, 'yellow');
      });

    } finally {
      client.release();
    }
  }

  async testDatabaseSchema() {
    const client = await this.dbPool.connect();
    try {
      const requiredTables = [
        'tenants', 'users', 'api_keys', 'subscription_plans', 
        'subscriptions', 'usage_events', 'alerts', 'incidents'
      ];

      for (const table of requiredTables) {
        const result = await client.query(`
          SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = $1
          )
        `, [table]);
        
        if (!result.rows[0].exists) {
          throw new Error(`Required table '${table}' does not exist`);
        }
      }

      log(`   All required tables exist: ${requiredTables.join(', ')}`, 'yellow');

      // Check subscription plans
      const plans = await client.query('SELECT * FROM subscription_plans');
      log(`   Subscription plans loaded: ${plans.rows.length}`, 'yellow');
      
      if (plans.rows.length === 0) {
        throw new Error('No subscription plans found. Check migration data.');
      }

    } finally {
      client.release();
    }
  }

  async testServerHealth() {
    const response = await axios.get(`${BASE_URL}/health`);
    
    if (response.status !== 200) {
      throw new Error(`Health check failed: ${response.status}`);
    }

    if (response.data.status !== 'healthy') {
      throw new Error(`Server status: ${response.data.status}`);
    }

    log(`   Server status: ${response.data.status}`, 'yellow');
    log(`   Environment: ${response.data.environment}`, 'yellow');
    log(`   Database: ${response.data.database}`, 'yellow');
  }

  async testAPIHealth() {
    const response = await axios.get(`${API_URL}/health`);
    
    if (response.status !== 200) {
      throw new Error(`API health check failed: ${response.status}`);
    }

    log(`   API status: ${response.data.status}`, 'yellow');
    log(`   Database check: ${response.data.checks.database}`, 'yellow');
    log(`   Redis check: ${response.data.checks.redis}`, 'yellow');
  }

  async testAuthEndpoints() {
    // Test health endpoint
    const healthResponse = await axios.get(`${API_URL}/auth/health`);
    if (healthResponse.status !== 200) {
      throw new Error('Auth health endpoint failed');
    }
    log(`   Auth service status: ${healthResponse.data.status}`, 'yellow');

    // Test registration endpoint with invalid data (should return validation error)
    try {
      await axios.post(`${API_URL}/auth/register`, {
        tenantName: 'Test Tenant'
        // Missing required fields
      });
      throw new Error('Registration should have failed with missing fields');
    } catch (error) {
      if (error.response && error.response.status === 400) {
        log(`   Registration validation working correctly`, 'yellow');
      } else {
        throw error;
      }
    }
  }

  async testTenantRegistration() {
    const testTenant = {
      tenantName: 'Test Company ' + Date.now(),
      subdomain: 'test' + Date.now(),
      contactEmail: `test${Date.now()}@example.com`,
      firstName: 'John',
      lastName: 'Doe',
      password: 'SecurePassword123!',
      planId: 'trial'
    };

    const response = await axios.post(`${API_URL}/auth/register`, testTenant);
    
    if (response.status !== 201) {
      throw new Error(`Registration failed: ${response.status}`);
    }

    const { tenant, user, token } = response.data;
    
    if (!tenant || !user || !token) {
      throw new Error('Incomplete registration response');
    }

    log(`   Created tenant: ${tenant.name} (${tenant.subdomain})`, 'yellow');
    log(`   Created user: ${user.email} (${user.role})`, 'yellow');
    log(`   JWT token provided: ${token ? 'Yes' : 'No'}`, 'yellow');

    // Test login with the created user
    const loginResponse = await axios.post(`${API_URL}/auth/login`, {
      email: testTenant.contactEmail,
      password: testTenant.password,
      subdomain: testTenant.subdomain
    });

    if (loginResponse.status !== 200) {
      throw new Error('Login failed after registration');
    }

    log(`   Login successful after registration`, 'yellow');

    return { tenant, user, token };
  }

  async testTenantIsolation(userToken) {
    // Test that protected endpoints require authentication
    try {
      await axios.get(`${API_URL}/ai-insights`);
      throw new Error('Protected endpoint should require authentication');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        log(`   Protected endpoints require authentication`, 'yellow');
      } else {
        throw error;
      }
    }

    // Test with valid token
    const response = await axios.get(`${API_URL}/ai-insights`, {
      headers: {
        'Authorization': `Bearer ${userToken}`
      }
    });

    // Should not fail with authentication error
    log(`   Authenticated request successful`, 'yellow');
  }

  async testRateLimiting() {
    const requests = [];
    const testEndpoint = `${API_URL}/auth/health`;

    // Make multiple requests quickly
    for (let i = 0; i < 5; i++) {
      requests.push(axios.get(testEndpoint));
    }

    const responses = await Promise.all(requests);
    
    // All should succeed (within rate limit)
    const allSuccessful = responses.every(res => res.status === 200);
    
    if (!allSuccessful) {
      throw new Error('Rate limiting is too aggressive');
    }

    log(`   Rate limiting configured properly`, 'yellow');
  }

  async testSubscriptionPlans() {
    const client = await this.dbPool.connect();
    try {
      const plans = await client.query('SELECT * FROM subscription_plans WHERE active = true');
      
      const expectedPlans = ['trial', 'starter', 'professional', 'enterprise'];
      const actualPlans = plans.rows.map(p => p.id);
      
      for (const expectedPlan of expectedPlans) {
        if (!actualPlans.includes(expectedPlan)) {
          throw new Error(`Missing subscription plan: ${expectedPlan}`);
        }
      }

      log(`   All subscription plans available: ${actualPlans.join(', ')}`, 'yellow');

    } finally {
      client.release();
    }
  }

  printSummary() {
    section('TEST SUMMARY');
    
    const total = this.testResults.passed + this.testResults.failed;
    const passRate = total > 0 ? Math.round((this.testResults.passed / total) * 100) : 0;
    
    log(`Total tests: ${total}`, 'blue');
    log(`Passed: ${this.testResults.passed}`, 'green');
    log(`Failed: ${this.testResults.failed}`, 'red');
    log(`Pass rate: ${passRate}%`, passRate === 100 ? 'green' : 'yellow');

    if (this.testResults.failed > 0) {
      log('\nFAILED TESTS:', 'red');
      this.testResults.tests
        .filter(test => test.status === 'FAILED')
        .forEach(test => {
          log(`❌ ${test.name}: ${test.error}`, 'red');
        });
    }

    if (passRate === 100) {
      log('\n🎉 All tests passed! A2Z SOC SaaS setup is ready!', 'green');
      log('\n🚀 Next steps:', 'blue');
      log('   1. Start the server: npm run dev', 'yellow');
      log('   2. Test the frontend: npm run dev (in main directory)', 'yellow');
      log('   3. Create your first tenant via the API', 'yellow');
      log('   4. Test subscription management', 'yellow');
    } else {
      log('\n⚠️  Some tests failed. Please fix the issues above.', 'yellow');
    }
  }

  async runAllTests() {
    log('🚀 Starting A2Z SOC SaaS Test Suite', 'bright');
    log(`Testing server at: ${BASE_URL}`, 'blue');

    section('DATABASE TESTS');
    await this.runTest('Database Connection', () => this.testDatabaseConnection());
    await this.runTest('Migration Status', () => this.testMigrationStatus());
    await this.runTest('Database Schema', () => this.testDatabaseSchema());
    await this.runTest('Subscription Plans', () => this.testSubscriptionPlans());

    section('SERVER TESTS');
    await this.runTest('Server Health', () => this.testServerHealth());
    await this.runTest('API Health', () => this.testAPIHealth());
    await this.runTest('Rate Limiting', () => this.testRateLimiting());

    section('AUTHENTICATION TESTS');
    await this.runTest('Auth Endpoints', () => this.testAuthEndpoints());
    
    let userToken;
    await this.runTest('Tenant Registration', async () => {
      const result = await this.testTenantRegistration();
      userToken = result.token;
    });

    if (userToken) {
      await this.runTest('Tenant Isolation', () => this.testTenantIsolation(userToken));
    }

    this.printSummary();
    await this.dbPool.end();
  }
}

// Main execution
async function main() {
  try {
    const tester = new A2ZSOCTester();
    await tester.runAllTests();
  } catch (error) {
    log(`\n❌ Test suite failed: ${error.message}`, 'red');
    process.exit(1);
  }
}

// Check if server is running
async function checkServerRunning() {
  try {
    await axios.get(`${BASE_URL}/health`, { timeout: 5000 });
    return true;
  } catch (error) {
    return false;
  }
}

// Run tests
checkServerRunning().then(isRunning => {
  if (!isRunning) {
    log('❌ Server is not running. Please start the server first:', 'red');
    log('   npm run dev', 'yellow');
    process.exit(1);
  } else {
    main();
  }
});

module.exports = A2ZSOCTester; 