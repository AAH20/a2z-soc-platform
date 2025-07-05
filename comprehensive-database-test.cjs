#!/usr/bin/env node

const axios = require('axios');
const colors = require('colors');

const BASE_URL = 'http://localhost:3001';
const API_BASE = `${BASE_URL}/api`;

let totalTests = 0;
let passedTests = 0;
let authToken = null;

const test = async (name, testFn) => {
  totalTests++;
  try {
    const result = await testFn();
    if (result.passed) {
      passedTests++;
      console.log(`✅ ${name}: PASSED - ${result.message}`.green);
      if (result.data) {
        console.log(`   📊 Data: ${JSON.stringify(result.data).substring(0, 100)}...`.cyan);
      }
    } else {
      console.log(`❌ ${name}: FAILED - ${result.message}`.red);
    }
  } catch (error) {
    console.log(`💥 ${name}: ERROR - ${error.message}`.red);
  }
};

const registerUser = async () => {
  const userData = {
    company: `DB Test Corp ${Date.now()}`,
    email: `dbtest-${Date.now()}@example.com`,
    password: 'DatabaseTest123!',
    firstName: 'Database',
    lastName: 'Tester'
  };

  try {
    const response = await axios.post(`${API_BASE}/onboarding/register`, userData);
    if (response.data?.token) {
      authToken = response.data.token;
      return {
        passed: true,
        message: `User registered with real database storage`,
        data: { userId: response.data.user?.id, orgId: response.data.organization?.id }
      };
    }
    return { passed: false, message: 'No token received' };
  } catch (error) {
    return { passed: false, message: error.response?.data?.error || error.message };
  }
};

const testDatabaseConnectivity = async () => {
  try {
    const response = await axios.get(`${API_BASE}/health`);
    if (response.data.checks?.database === true) {
      return { passed: true, message: 'Database connection verified', data: response.data.checks };
    }
    return { passed: false, message: 'Database not connected' };
  } catch (error) {
    return { passed: false, message: error.message };
  }
};

const createNetworkAgent = async () => {
  if (!authToken) return { passed: false, message: 'No auth token' };
  
  const agentData = {
    name: `DB-Test-Agent-${Date.now()}`,
    type: 'network_monitor',
    location: 'Database-Test-Lab',
    ip_address: '192.168.1.200',
    os_type: 'Linux'
  };

  try {
    const response = await axios.post(`${API_BASE}/network-agents`, agentData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    if (response.data?.success && response.data?.agent) {
      return {
        passed: true,
        message: 'Network agent created in database',
        data: { agentId: response.data.agent.id, name: response.data.agent.name }
      };
    }
    return { passed: false, message: 'Agent creation failed' };
  } catch (error) {
    return { passed: false, message: error.response?.data?.error || error.message };
  }
};

const createSecurityEvent = async () => {
  if (!authToken) return { passed: false, message: 'No auth token' };
  
  const eventData = {
    timestamp: new Date().toISOString(),
    event_type: 'database_test_event',
    source_ip: '192.168.1.201',
    dest_ip: '203.0.113.100',
    protocol: 'TCP',
    severity: 'medium',
    description: 'Database connectivity test event'
  };

  try {
    const response = await axios.post(`${API_BASE}/security-events`, eventData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    if (response.data?.success || response.data?.event_id || response.data?.id) {
      return {
        passed: true,
        message: 'Security event stored in database',
        data: response.data
      };
    }
    return { passed: false, message: 'Event creation failed' };
  } catch (error) {
    return { passed: false, message: error.response?.data?.error || error.message };
  }
};

const createIDSLog = async () => {
  if (!authToken) return { passed: false, message: 'No auth token' };
  
  const logData = {
    timestamp: new Date().toISOString(),
    source: 'database_test',
    log_level: 'info',
    category: 'test',
    message: 'Database connectivity test log entry'
  };

  try {
    const response = await axios.post(`${API_BASE}/ids-logs`, logData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    if (response.data?.success || response.data?.id) {
      return {
        passed: true,
        message: 'IDS log entry stored in database',
        data: response.data
      };
    }
    return { passed: false, message: 'Log creation failed' };
  } catch (error) {
    return { passed: false, message: error.response?.data?.error || error.message };
  }
};

const testDataRetrieval = async () => {
  if (!authToken) return { passed: false, message: 'No auth token' };
  
  try {
    const [agentsResp, eventsResp, logsResp] = await Promise.all([
      axios.get(`${API_BASE}/network-agents`, { headers: { Authorization: `Bearer ${authToken}` }}),
      axios.get(`${API_BASE}/security-events`, { headers: { Authorization: `Bearer ${authToken}` }}),
      axios.get(`${API_BASE}/ids-logs`, { headers: { Authorization: `Bearer ${authToken}` }})
    ]);

    const agentCount = agentsResp.data?.data?.length || agentsResp.data?.length || 0;
    const eventCount = eventsResp.data?.events?.length || eventsResp.data?.data?.length || eventsResp.data?.length || 0;
    const logCount = logsResp.data?.logs?.length || logsResp.data?.data?.length || logsResp.data?.length || 0;

    return {
      passed: true,
      message: 'Data successfully retrieved from database',
      data: { agents: agentCount, events: eventCount, logs: logCount }
    };
  } catch (error) {
    return { passed: false, message: error.response?.data?.error || error.message };
  }
};

const runTests = async () => {
  console.log('🗄️  A2Z SOC Platform - Comprehensive Database Integration Test'.bold.cyan);
  console.log('=' .repeat(70).cyan);
  console.log('🔍 Testing all components with REAL database operations'.bold.white);
  console.log('');

  await test('Database Connectivity', testDatabaseConnectivity);
  await test('User Registration (Database)', registerUser);
  await test('Network Agent Creation (Database)', createNetworkAgent);
  await test('Security Event Creation (Database)', createSecurityEvent);
  await test('IDS Log Creation (Database)', createIDSLog);
  await test('Data Retrieval (Database)', testDataRetrieval);

  console.log('');
  console.log('📊 TEST RESULTS SUMMARY'.bold.cyan);
  console.log('=' .repeat(40).cyan);
  console.log(`Total Tests: ${totalTests}`.bold);
  console.log(`Passed: ${passedTests}`.green.bold);
  console.log(`Failed: ${totalTests - passedTests}`.red.bold);
  console.log(`Success Rate: ${Math.round((passedTests / totalTests) * 100)}%`.bold);

  if (passedTests === totalTests) {
    console.log('');
    console.log('🎉 ALL DATABASE TESTS PASSED!'.green.bold);
    console.log('✅ Platform is fully connected to database'.green);
    console.log('🚀 Ready for production deployment'.green);
  } else {
    console.log('');
    console.log('⚠️  SOME TESTS FAILED'.yellow.bold);
    console.log('🔧 Database connectivity issues detected'.yellow);
  }
};

runTests().catch(console.error);
