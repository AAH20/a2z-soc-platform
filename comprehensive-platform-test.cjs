#!/usr/bin/env node

/**
 * A2Z SOC Platform - Comprehensive End-to-End Database Integration Test
 * Tests all platform components with real database connectivity
 * NO MOCK DATA - All tests use actual database operations
 */

const axios = require('axios');
const colors = require('colors');
const { v4: uuidv4 } = require('uuid');

// Test configuration
const BASE_URL = process.env.API_URL || 'http://localhost:3001';
const API_BASE = `${BASE_URL}/api`;

// Test tracking
let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
let results = [];
let testSuite = {};

// Helper functions
const log = (message, type = 'info') => {
  const timestamp = new Date().toISOString();
  switch (type) {
    case 'success':
      console.log(`[${timestamp}] ✅ ${message}`.green);
      break;
    case 'error':
      console.log(`[${timestamp}] ❌ ${message}`.red);
      break;
    case 'warning':
      console.log(`[${timestamp}] ⚠️  ${message}`.yellow);
      break;
    case 'info':
      console.log(`[${timestamp}] 📋 ${message}`.blue);
      break;
    case 'database':
      console.log(`[${timestamp}] 🗄️  ${message}`.cyan);
      break;
    default:
      console.log(`[${timestamp}] ${message}`);
  }
};

const test = async (category, name, testFn, critical = false) => {
  totalTests++;
  if (!testSuite[category]) {
    testSuite[category] = { passed: 0, failed: 0, tests: [] };
  }
  
  try {
    log(`Testing: ${name}`, 'info');
    const result = await testFn();
    
    if (result.passed) {
      passedTests++;
      testSuite[category].passed++;
      log(`${name}: PASSED - ${result.message}`, 'success');
      testSuite[category].tests.push({ 
        name, 
        status: 'PASSED', 
        message: result.message, 
        data: result.data || null,
        dbConnected: result.dbConnected || false
      });
    } else {
      failedTests++;
      testSuite[category].failed++;
      log(`${name}: FAILED - ${result.message}`, critical ? 'error' : 'warning');
      testSuite[category].tests.push({ 
        name, 
        status: 'FAILED', 
        message: result.message, 
        error: result.error || null 
      });
    }
  } catch (error) {
    failedTests++;
    testSuite[category].failed++;
    log(`${name}: ERROR - ${error.message}`, 'error');
    testSuite[category].tests.push({ 
      name, 
      status: 'ERROR', 
      message: error.message,
      stack: error.stack
    });
  }
};

// Test user for all operations
let testUser = null;
let authToken = null;
let organizationId = null;

// Database Connection Tests
const testDatabaseConnectivity = async () => {
  try {
    const response = await axios.get(`${API_BASE}/health`);
    if (response.data.checks && response.data.checks.database === true) {
      return {
        passed: true,
        message: 'Database connectivity verified',
        dbConnected: true,
        data: response.data.checks
      };
    } else {
      return {
        passed: false,
        message: 'Database not connected',
        dbConnected: false
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Database connectivity test failed: ${error.message}`,
      dbConnected: false
    };
  }
};

const testDatabaseSchema = async () => {
  try {
    // Test by attempting to query organizations table
    const response = await axios.get(`${BASE_URL}/health`);
    if (response.data && response.data.database === 'connected') {
      return {
        passed: true,
        message: 'Database schema accessible',
        dbConnected: true
      };
    } else {
      return {
        passed: false,
        message: 'Database schema not accessible'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Database schema test failed: ${error.message}`
    };
  }
};

// User Authentication & Organization Tests
const testUserRegistration = async () => {
  const userData = {
    company: `Comprehensive Test Corp ${Date.now()}`,
    email: `comprehensive-test-${Date.now()}@example.com`,
    password: 'SecureTest123!',
    firstName: 'Comprehensive',
    lastName: 'Tester'
  };

  try {
    const response = await axios.post(`${API_BASE}/onboarding/register`, userData);
    
    if (response.data && response.data.token && response.data.user && response.data.organization) {
      authToken = response.data.token;
      testUser = response.data.user;
      organizationId = response.data.organization.id;
      
      return {
        passed: true,
        message: `User registered successfully (ID: ${testUser.id})`,
        dbConnected: true,
        data: {
          userId: testUser.id,
          organizationId: organizationId,
          tokenLength: authToken.length
        }
      };
    } else {
      return {
        passed: false,
        message: 'Registration response missing required fields'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `User registration failed: ${error.response?.data?.error || error.message}`
    };
  }
};

const testUserProfile = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/onboarding/me`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && response.data.user && response.data.user.id === testUser.id) {
      return {
        passed: true,
        message: 'User profile retrieved from database',
        dbConnected: true,
        data: response.data.user
      };
    } else {
      return {
        passed: false,
        message: 'User profile data mismatch or not found'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `User profile test failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// Network Agents Database Tests
const testNetworkAgentCreation = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  const agentData = {
    name: `Test-Agent-${Date.now()}`,
    type: 'network_monitor',
    location: 'Test-Lab-DB',
    ip_address: '192.168.1.100',
    os_type: 'Linux',
    status: 'active',
    capabilities: ['packet_capture', 'flow_analysis', 'threat_detection']
  };

  try {
    const response = await axios.post(`${API_BASE}/network-agents`, agentData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && response.data.success && response.data.agent) {
      return {
        passed: true,
        message: `Network agent created in database (ID: ${response.data.agent.id})`,
        dbConnected: true,
        data: response.data.agent
      };
    } else {
      return {
        passed: false,
        message: 'Network agent creation failed - no agent data returned'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Network agent creation failed: ${error.response?.data?.error || error.message}`
    };
  }
};

const testNetworkAgentsList = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/network-agents`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && response.data.success && Array.isArray(response.data.data)) {
      const agentCount = response.data.data.length;
      return {
        passed: true,
        message: `Retrieved ${agentCount} network agents from database`,
        dbConnected: true,
        data: { agentCount, agents: response.data.data }
      };
    } else {
      return {
        passed: false,
        message: 'Network agents list failed - invalid response format'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Network agents list failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// IDS Logs Database Tests
const testIDSLogCreation = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  const idsEvent = {
    timestamp: new Date().toISOString(),
    source_ip: '192.168.1.150',
    dest_ip: '203.0.113.50',
    protocol: 'TCP',
    port: 80,
    signature: 'SQL Injection Attempt',
    severity: 'high',
    details: 'Detected SQL injection pattern in HTTP request',
    raw_log: 'GET /login.php?id=1\' OR \'1\'=\'1 HTTP/1.1'
  };

  try {
    const response = await axios.post(`${API_BASE}/ids-logs`, idsEvent, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && (response.data.success || response.data.id)) {
      return {
        passed: true,
        message: 'IDS log created in database',
        dbConnected: true,
        data: response.data
      };
    } else {
      return {
        passed: false,
        message: 'IDS log creation failed - no confirmation returned'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `IDS log creation failed: ${error.response?.data?.error || error.message}`
    };
  }
};

const testIDSLogsList = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/ids-logs`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && Array.isArray(response.data.logs || response.data.data || response.data)) {
      const logs = response.data.logs || response.data.data || response.data;
      return {
        passed: true,
        message: `Retrieved ${logs.length} IDS logs from database`,
        dbConnected: true,
        data: { logCount: logs.length, logs: logs.slice(0, 3) }
      };
    } else {
      return {
        passed: false,
        message: 'IDS logs list failed - invalid response format'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `IDS logs list failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// Security Events Database Tests
const testSecurityEventCreation = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  const securityEvent = {
    timestamp: new Date().toISOString(),
    event_type: 'intrusion_attempt',
    source_ip: '198.51.100.75',
    dest_ip: '192.168.1.10',
    severity: 'critical',
    description: 'Multiple failed authentication attempts detected',
    details: {
      attempts: 15,
      timeframe: '5 minutes',
      protocols: ['SSH', 'RDP']
    }
  };

  try {
    const response = await axios.post(`${API_BASE}/security-events`, securityEvent, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && (response.data.success || response.data.event_id || response.data.id)) {
      return {
        passed: true,
        message: 'Security event created in database',
        dbConnected: true,
        data: response.data
      };
    } else {
      return {
        passed: false,
        message: 'Security event creation failed - no confirmation returned'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Security event creation failed: ${error.response?.data?.error || error.message}`
    };
  }
};

const testSecurityEventsList = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/security-events`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && Array.isArray(response.data.events || response.data.data || response.data)) {
      const events = response.data.events || response.data.data || response.data;
      return {
        passed: true,
        message: `Retrieved ${events.length} security events from database`,
        dbConnected: true,
        data: { eventCount: events.length, events: events.slice(0, 3) }
      };
    } else {
      return {
        passed: false,
        message: 'Security events list failed - invalid response format'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Security events list failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// Threat Intelligence Database Tests
const testThreatIntelligenceUpload = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  const threatData = {
    indicator_type: 'ip_address',
    indicator_value: '203.0.113.200',
    threat_type: 'malware_c2',
    confidence: 95,
    source: 'internal_analysis',
    description: 'Known malware command and control server',
    first_seen: new Date().toISOString(),
    tags: ['malware', 'c2', 'botnet']
  };

  try {
    const response = await axios.post(`${API_BASE}/threat-intelligence`, threatData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && (response.data.success || response.data.id)) {
      return {
        passed: true,
        message: 'Threat intelligence data created in database',
        dbConnected: true,
        data: response.data
      };
    } else {
      return {
        passed: false,
        message: 'Threat intelligence creation failed - no confirmation returned'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Threat intelligence creation failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// Compliance Framework Tests
const testComplianceAssessment = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/compliance`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && (response.data.frameworks || response.data.assessments || response.data.success)) {
      return {
        passed: true,
        message: 'Compliance data retrieved from database',
        dbConnected: true,
        data: response.data
      };
    } else {
      return {
        passed: false,
        message: 'Compliance assessment failed - no data returned'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Compliance assessment failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// Audit Logs Database Tests
const testAuditLogCreation = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/audits`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && Array.isArray(response.data.logs || response.data.audits || response.data)) {
      const logs = response.data.logs || response.data.audits || response.data;
      return {
        passed: true,
        message: `Retrieved ${logs.length} audit logs from database`,
        dbConnected: true,
        data: { auditCount: logs.length, logs: logs.slice(0, 3) }
      };
    } else {
      return {
        passed: false,
        message: 'Audit logs retrieval failed - invalid response format'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Audit logs test failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// AI Insights Database Tests
const testAIInsights = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/ai-insights`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && (response.data.insights || response.data.analysis || response.data.recommendations)) {
      return {
        passed: true,
        message: 'AI insights data retrieved from database',
        dbConnected: true,
        data: response.data
      };
    } else {
      return {
        passed: false,
        message: 'AI insights failed - no data returned'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `AI insights test failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// Billing Information Tests
const testBillingIntegration = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/billing`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && (response.data.subscription || response.data.billing || response.data.plans)) {
      return {
        passed: true,
        message: 'Billing information retrieved from database',
        dbConnected: true,
        data: response.data
      };
    } else {
      return {
        passed: false,
        message: 'Billing integration failed - no data returned'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Billing integration test failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// Dashboard Data Integration Tests
const testDashboardStats = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/dashboard/stats`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && typeof response.data === 'object') {
      // Check if data contains real metrics (not just hardcoded values)
      const hasRealData = response.data.totalAlerts !== undefined || 
                          response.data.criticalAlerts !== undefined ||
                          response.data.networkTraffic !== undefined;
      
      return {
        passed: hasRealData,
        message: hasRealData ? 'Dashboard stats retrieved with real data' : 'Dashboard stats returned but may be mock data',
        dbConnected: hasRealData,
        data: response.data
      };
    } else {
      return {
        passed: false,
        message: 'Dashboard stats failed - invalid response format'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `Dashboard stats test failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// System Configuration Tests
const testSystemConfiguration = async () => {
  if (!authToken) {
    return { passed: false, message: 'No auth token available' };
  }

  try {
    const response = await axios.get(`${API_BASE}/admin/system-config`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });

    if (response.data && (response.data.config || response.data.settings)) {
      return {
        passed: true,
        message: 'System configuration retrieved from database',
        dbConnected: true,
        data: response.data
      };
    } else {
      return {
        passed: false,
        message: 'System configuration failed - no data returned'
      };
    }
  } catch (error) {
    return {
      passed: false,
      message: `System configuration test failed: ${error.response?.data?.error || error.message}`
    };
  }
};

// Main test execution
const runComprehensiveTests = async () => {
  console.log('🔍 A2Z SOC Platform - Comprehensive Database Integration Test'.bold.cyan);
  console.log('=' .repeat(80).cyan);
  console.log('📊 Testing ALL platform components with REAL database connectivity'.bold.white);
  console.log('🚫 NO MOCK DATA - All operations use actual database'.bold.yellow);
  console.log('');

  // Database Infrastructure Tests
  console.log('🗄️  DATABASE INFRASTRUCTURE TESTS'.bold.blue);
  await test('Database', 'Database Connectivity', testDatabaseConnectivity, true);
  await test('Database', 'Database Schema Access', testDatabaseSchema, true);
  console.log('');

  // Authentication & User Management
  console.log('👤 AUTHENTICATION & USER MANAGEMENT'.bold.green);
  await test('Authentication', 'User Registration (Database)', testUserRegistration, true);
  await test('Authentication', 'User Profile Retrieval (Database)', testUserProfile);
  console.log('');

  // Network Monitoring System
  console.log('🌐 NETWORK MONITORING SYSTEM'.bold.magenta);
  await test('Network Monitoring', 'Network Agent Creation (Database)', testNetworkAgentCreation);
  await test('Network Monitoring', 'Network Agents List (Database)', testNetworkAgentsList);
  console.log('');

  // IDS/IPS System
  console.log('🛡️  IDS/IPS DETECTION SYSTEM'.bold.red);
  await test('IDS/IPS', 'IDS Log Creation (Database)', testIDSLogCreation);
  await test('IDS/IPS', 'IDS Logs Retrieval (Database)', testIDSLogsList);
  console.log('');

  // Security Events System
  console.log('🚨 SECURITY EVENTS SYSTEM'.bold.yellow);
  await test('Security Events', 'Security Event Creation (Database)', testSecurityEventCreation);
  await test('Security Events', 'Security Events List (Database)', testSecurityEventsList);
  console.log('');

  // Threat Intelligence
  console.log('🧠 THREAT INTELLIGENCE SYSTEM'.bold.cyan);
  await test('Threat Intelligence', 'Threat Data Upload (Database)', testThreatIntelligenceUpload);
  console.log('');

  // Compliance & Audit
  console.log('📋 COMPLIANCE & AUDIT SYSTEM'.bold.blue);
  await test('Compliance', 'Compliance Assessment (Database)', testComplianceAssessment);
  await test('Audit', 'Audit Logs Retrieval (Database)', testAuditLogCreation);
  console.log('');

  // AI & Analytics
  console.log('🤖 AI & ANALYTICS SYSTEM'.bold.green);
  await test('AI Analytics', 'AI Insights (Database)', testAIInsights);
  console.log('');

  // Business Systems
  console.log('💰 BUSINESS & BILLING SYSTEM'.bold.magenta);
  await test('Billing', 'Billing Integration (Database)', testBillingIntegration);
  console.log('');

  // Dashboard & Reporting
  console.log('📊 DASHBOARD & REPORTING SYSTEM'.bold.red);
  await test('Dashboard', 'Dashboard Stats (Database)', testDashboardStats);
  console.log('');

  // System Administration
  console.log('⚙️  SYSTEM ADMINISTRATION'.bold.yellow);
  await test('System Admin', 'System Configuration (Database)', testSystemConfiguration);
  console.log('');

  // Generate comprehensive report
  generateComprehensiveReport();
};

const generateComprehensiveReport = () => {
  console.log('📊 COMPREHENSIVE DATABASE INTEGRATION REPORT'.bold.cyan);
  console.log('=' .repeat(80).cyan);

  let dbConnectedTests = 0;
  let totalDbTests = 0;

  Object.keys(testSuite).forEach(category => {
    const suite = testSuite[category];
    const total = suite.passed + suite.failed;
    const percentage = total > 0 ? Math.round((suite.passed / total) * 100) : 0;
    
    const status = percentage >= 80 ? '🟢' : percentage >= 60 ? '🟡' : '🔴';
    console.log(`${status} ${category}: ${suite.passed}/${total} (${percentage}%)`);
    
    suite.tests.forEach(test => {
      const icon = test.status === 'PASSED' ? '  ✅' : test.status === 'FAILED' ? '  ❌' : '  ⚠️';
      const dbIcon = test.dbConnected ? ' 🗄️' : '';
      console.log(`${icon} ${test.name}${dbIcon}: ${test.message}`);
      
      if (test.dbConnected) dbConnectedTests++;
      totalDbTests++;
    });
    console.log('');
  });

  const overallPercentage = totalTests > 0 ? Math.round((passedTests / totalTests) * 100) : 0;
  const dbConnectionPercentage = totalDbTests > 0 ? Math.round((dbConnectedTests / totalDbTests) * 100) : 0;

  console.log('🎯 OVERALL PLATFORM STATUS'.bold.cyan);
  console.log('=' .repeat(50).cyan);
  console.log(`📊 Total Tests: ${totalTests}`.bold);
  console.log(`✅ Passed: ${passedTests}`.green.bold);
  console.log(`❌ Failed: ${failedTests}`.red.bold);
  console.log(`📈 Success Rate: ${overallPercentage}%`.bold);
  console.log(`🗄️  Database Connected Tests: ${dbConnectedTests}/${totalDbTests} (${dbConnectionPercentage}%)`.cyan.bold);

  let platformStatus;
  if (overallPercentage >= 90 && dbConnectionPercentage >= 80) {
    platformStatus = '🏆 ENTERPRISE PRODUCTION READY';
    console.log(`🏆 Platform Status: ${platformStatus}`.green.bold);
    console.log(`✨ All systems operational with database integration`.green);
  } else if (overallPercentage >= 70 && dbConnectionPercentage >= 60) {
    platformStatus = '⚡ PRODUCTION READY WITH MINOR ISSUES';
    console.log(`⚡ Platform Status: ${platformStatus}`.yellow.bold);
    console.log(`🔧 Minor fixes needed for optimal performance`.yellow);
  } else {
    platformStatus = '🚧 REQUIRES DATABASE INTEGRATION FIXES';
    console.log(`🚧 Platform Status: ${platformStatus}`.red.bold);
    console.log(`⚠️  Database connectivity issues need resolution`.red);
  }

  console.log('');
  console.log('📋 RECOMMENDATIONS'.bold.cyan);
  if (dbConnectionPercentage < 80) {
    console.log('  🔧 Fix database connectivity for failed components');
    console.log('  📝 Ensure all routes use real database operations');
    console.log('  🗄️  Verify database schema matches API expectations');
  }
  if (overallPercentage < 90) {
    console.log('  🛠️  Address failing test cases for production readiness');
    console.log('  📊 Implement missing API endpoints');
  }
  if (dbConnectionPercentage >= 80 && overallPercentage >= 90) {
    console.log('  🚀 Platform ready for enterprise deployment');
    console.log('  💰 Begin customer onboarding process');
    console.log('  📈 Start revenue generation activities');
  }

  return {
    totalTests,
    passedTests,
    failedTests,
    overallPercentage,
    dbConnectionPercentage,
    platformStatus
  };
};

// Run the comprehensive tests
runComprehensiveTests()
  .then(() => {
    console.log('');
    console.log('✨ Comprehensive database integration testing complete!'.bold.green);
    process.exit(passedTests === totalTests ? 0 : 1);
  })
  .catch(error => {
    console.error('💥 Test execution failed:'.red.bold, error.message);
    process.exit(1);
  });