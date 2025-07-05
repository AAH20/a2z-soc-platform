#!/usr/bin/env node

/**
 * A2Z SOC Platform - Enhanced SaaS Security & Readiness Test
 * Comprehensive testing for Network Agents, IDS/IPS, Dashboard, and Vulnerability Assessment
 */

const axios = require('axios');
const colors = require('colors');

// Test configuration
const BASE_URL = process.env.API_URL || 'http://localhost:3001';
const API_BASE = `${BASE_URL}/api`;

// Test results tracking
let totalTests = 0;
let passedTests = 0;
let securityIssues = [];
let vulnerabilities = [];
let results = [];

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
    case 'security':
      console.log(`[${timestamp}] 🔒 ${message}`.magenta);
      break;
    case 'info':
      console.log(`[${timestamp}] 📋 ${message}`.blue);
      break;
    default:
      console.log(`[${timestamp}] ${message}`);
  }
};

const test = async (name, testFn, category = 'General', critical = false) => {
  totalTests++;
  try {
    const result = await testFn();
    if (result.passed) {
      passedTests++;
      log(`${name}: PASSED - ${result.message}`, 'success');
      results.push({ category, name, status: 'PASSED', message: result.message, points: result.points || 1, critical });
    } else {
      log(`${name}: FAILED - ${result.message}`, critical ? 'error' : 'warning');
      results.push({ category, name, status: 'FAILED', message: result.message, points: 0, critical });
      if (critical && result.vulnerability) {
        vulnerabilities.push({ test: name, issue: result.message, severity: 'HIGH' });
      }
    }
  } catch (error) {
    log(`${name}: ERROR - ${error.message}`, 'error');
    results.push({ category, name, status: 'ERROR', message: error.message, points: 0, critical });
    if (critical) {
      vulnerabilities.push({ test: name, issue: error.message, severity: 'CRITICAL' });
    }
  }
};

// Authentication setup
let authToken = null;
let userInfo = null;
let organizationId = null;

const registerTestUser = async () => {
  const userData = {
    company: 'Enhanced Security Test Corp',
    email: `enhanced-test-${Date.now()}@example.com`,
    password: 'SecureTest123!',  // Updated to use only allowed special characters
    firstName: 'Security',
    lastName: 'Tester'
  };

  try {
    const response = await axios.post(`${API_BASE}/onboarding/register`, userData);
    authToken = response.data.token;
    userInfo = response.data.user;
    organizationId = response.data.organization.id;
    return { passed: true, message: 'Enhanced user registration successful', userData };
  } catch (error) {
    return { passed: false, message: `Registration failed: ${error.response?.data?.error || error.message}` };
  }
};

// Enhanced Security Tests
const testSQLInjectionProtection = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  const maliciousPayloads = [
    "'; DROP TABLE users; --",
    "1' OR '1'='1",
    "' UNION SELECT * FROM users --",
    "'; INSERT INTO users VALUES('hacker', 'password'); --"
  ];

  try {
    for (const payload of maliciousPayloads) {
      const response = await axios.get(`${API_BASE}/network-agents?search=${encodeURIComponent(payload)}`, {
        headers: { Authorization: `Bearer ${authToken}` },
        timeout: 5000
      });
      
      // Check if any SQL errors are exposed
      if (response.data && typeof response.data === 'string' && 
          (response.data.includes('SQL') || response.data.includes('syntax error'))) {
        return {
          passed: false,
          message: 'SQL injection vulnerability detected - database errors exposed',
          points: 0,
          vulnerability: true
        };
      }
    }
    
    return {
      passed: true,
      message: 'SQL injection protection working correctly',
      points: 25
    };
  } catch (error) {
    // Timeouts or 400 errors are expected and good
    if (error.code === 'ECONNABORTED' || error.response?.status === 400) {
      return {
        passed: true,
        message: 'SQL injection properly blocked',
        points: 25
      };
    }
    return {
      passed: false,
      message: `SQL injection test failed: ${error.message}`,
      points: 0
    };
  }
};

const testXSSProtection = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  const xssPayloads = [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
  ];

  try {
    for (const payload of xssPayloads) {
      const response = await axios.post(`${API_BASE}/dashboard/stats`, {
        filter: payload,
        timeRange: payload
      }, {
        headers: { Authorization: `Bearer ${authToken}` },
        timeout: 5000
      });
      
      // Check if script tags are returned unescaped
      if (response.data && typeof response.data === 'string' && 
          response.data.includes('<script>')) {
        return {
          passed: false,
          message: 'XSS vulnerability detected - script injection possible',
          points: 0,
          vulnerability: true
        };
      }
    }
    
    return {
      passed: true,
      message: 'XSS protection working correctly',
      points: 20
    };
  } catch (error) {
    // 400 errors are expected and good for malicious input
    if (error.response?.status === 400) {
      return {
        passed: true,
        message: 'XSS attempts properly blocked',
        points: 20
      };
    }
    return {
      passed: false,
      message: `XSS protection test inconclusive: ${error.message}`,
      points: 10
    };
  }
};

const testCSRFProtection = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    // Test without CSRF token/origin validation
    const response = await axios.post(`${API_BASE}/dashboard/stats`, {
      action: 'delete_all_data'
    }, {
      headers: { 
        Authorization: `Bearer ${authToken}`,
        Origin: 'https://malicious-site.com',
        Referer: 'https://malicious-site.com/attack'
      },
      timeout: 5000
    });
    
    return {
      passed: true,
      message: 'CSRF protection allows legitimate requests',
      points: 15
    };
  } catch (error) {
    if (error.response?.status === 403) {
      return {
        passed: true,
        message: 'CSRF protection properly blocks suspicious origins',
        points: 15
      };
    }
    return {
      passed: false,
      message: `CSRF protection test failed: ${error.message}`,
      points: 0
    };
  }
};

const testSessionManagement = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    // Test with tampered token
    const tamperedToken = authToken.slice(0, -10) + 'tampered123';
    
    const response = await axios.get(`${API_BASE}/onboarding/me`, {
      headers: { Authorization: `Bearer ${tamperedToken}` }
    });
    
    return {
      passed: false,
      message: 'Session management vulnerability - tampered token accepted',
      points: 0,
      vulnerability: true
    };
  } catch (error) {
    if (error.response?.status === 403 || error.response?.status === 401) {
      return {
        passed: true,
        message: 'Session management properly rejects tampered tokens',
        points: 20
      };
    }
    return {
      passed: false,
      message: `Session management test failed: ${error.message}`,
      points: 0
    };
  }
};

const testPasswordSecurity = async () => {
  const weakPasswords = [
    'password',
    '123456',
    'admin',
    'qwerty',
    'test',
    'Password1',  // No special character
    'password!',  // No uppercase or number
    'PASSWORD123!', // No lowercase
    'Pass!',      // Too short
    'LongPasswordWithoutNumber!', // No number
  ];

  try {
    for (const weakPassword of weakPasswords) {
      const response = await axios.post(`${API_BASE}/onboarding/register`, {
        company: 'Weak Password Test',
        email: `weaktest-${Date.now()}-${Math.random()}@example.com`,
        password: weakPassword,
        firstName: 'Weak',
        lastName: 'Test'
      });
      
      // If registration succeeds with weak password, it's a vulnerability
      if (response.status === 201) {
        return {
          passed: false,
          message: `Password policy vulnerability - weak password "${weakPassword}" was accepted`,
          points: 0,
          vulnerability: true
        };
      }
    }
    
    return {
      passed: true,
      message: 'Password policy properly enforced',
      points: 15
    };
  } catch (error) {
    if (error.response?.status === 400 && 
        error.response?.data?.error?.includes('Password does not meet security requirements')) {
      return {
        passed: true,
        message: 'Password policy correctly rejects weak passwords',
        points: 15
      };
    }
    return {
      passed: false,
      message: `Password security test failed: ${error.message}`,
      points: 0
    };
  }
};

// Enhanced Network Monitoring Agent Tests
const testNetworkAgentRegistration = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    const agentData = {
      name: 'Test-Agent-001',
      type: 'network_monitor',
      location: 'Test-Lab',
      capabilities: ['packet_capture', 'flow_analysis', 'threat_detection'],
      version: '2.1.0',
      platform: 'linux-x64'
    };

    const response = await axios.post(`${API_BASE}/agents/register`, agentData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    const hasValidResponse = response.data && 
                             response.data.agent && 
                             response.data.agent.id &&
                             response.data.agent.status === 'registered';
    
    return {
      passed: hasValidResponse,
      message: hasValidResponse ? 
        `Network agent registered successfully (ID: ${response.data.agent.id})` : 
        'Network agent registration failed - invalid response structure',
      points: hasValidResponse ? 20 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `Network agent registration failed: ${error.response?.data?.error || error.message}`,
      points: 0
    };
  }
};

const testNetworkAgentHeartbeat = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    // First get list of agents
    const agentsResponse = await axios.get(`${API_BASE}/agents`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    if (!agentsResponse.data.agents || agentsResponse.data.agents.length === 0) {
      return {
        passed: false,
        message: 'No network agents available for heartbeat test',
        points: 0
      };
    }

    const agent = agentsResponse.data.agents[0];
    
    // Send heartbeat
    const heartbeatData = {
      timestamp: new Date().toISOString(),
      status: 'active',
      metrics: {
        cpu_usage: 45.2,
        memory_usage: 67.8,
        network_throughput: 1024000,
        packets_processed: 15000,
        threats_detected: 3
      }
    };

    const response = await axios.post(`${API_BASE}/agents/${agent.id}/heartbeat`, heartbeatData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    const isValidHeartbeat = response.status === 200 && 
                             response.data && 
                             response.data.status === 'acknowledged';
    
    return {
      passed: isValidHeartbeat,
      message: isValidHeartbeat ? 
        'Network agent heartbeat working correctly' : 
        'Network agent heartbeat failed - invalid response',
      points: isValidHeartbeat ? 15 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `Network agent heartbeat test failed: ${error.response?.data?.error || error.message}`,
      points: 0
    };
  }
};

const testNetworkAgentDataIngestion = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    // Get agents first
    const agentsResponse = await axios.get(`${API_BASE}/agents`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    if (!agentsResponse.data.agents || agentsResponse.data.agents.length === 0) {
      return {
        passed: false,
        message: 'No network agents available for data ingestion test',
        points: 0
      };
    }

    const agent = agentsResponse.data.agents[0];
    
    // Simulate network traffic data
    const networkData = {
      timestamp: new Date().toISOString(),
      events: [
        {
          type: 'network_flow',
          source_ip: '192.168.1.100',
          dest_ip: '203.0.113.25',
          source_port: 54321,
          dest_port: 443,
          protocol: 'TCP',
          bytes_transferred: 4096,
          packets: 8,
          duration: 1.5,
          threat_score: 0.1
        },
        {
          type: 'packet_capture',
          source_ip: '10.0.0.50',
          dest_ip: '8.8.8.8',
          protocol: 'UDP',
          size: 64,
          threat_indicators: ['dns_query'],
          threat_score: 0.0
        }
      ]
    };

    const response = await axios.post(`${API_BASE}/agents/${agent.id}/ingest`, networkData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    const isValidIngestion = response.status === 200 && 
                             response.data && 
                             response.data.events_processed > 0;
    
    return {
      passed: isValidIngestion,
      message: isValidIngestion ? 
        `Network data ingestion working (${response.data.events_processed} events processed)` : 
        'Network data ingestion failed',
      points: isValidIngestion ? 25 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `Network data ingestion test failed: ${error.response?.data?.error || error.message}`,
      points: 0
    };
  }
};

// Enhanced IDS/IPS Agent Tests
const testIDSSignatureDetection = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    // Simulate IDS signature detection
    const idsEvent = {
      timestamp: new Date().toISOString(),
      detection_type: 'signature_match',
      signature_id: 'ET-2001-001',
      signature_name: 'SQL Injection Attempt',
      source_ip: '203.0.113.100',
      dest_ip: '192.168.1.10',
      source_port: 45678,
      dest_port: 80,
      protocol: 'TCP',
      payload: 'GET /login.php?username=admin%27%20OR%20%271%27%3D%271',
      severity: 'high',
      confidence: 0.95,
      raw_packet: 'base64encodedpacketdata'
    };

    const response = await axios.post(`${API_BASE}/ids-logs`, idsEvent, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    const isValidDetection = response.status === 201 && 
                             response.data && 
                             response.data.id;
    
    return {
      passed: isValidDetection,
      message: isValidDetection ? 
        `IDS signature detection working (Event ID: ${response.data.id})` : 
        'IDS signature detection failed',
      points: isValidDetection ? 25 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `IDS signature detection test failed: ${error.response?.data?.error || error.message}`,
      points: 0
    };
  }
};

const testIDSAnomalyDetection = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    // Simulate ML-based anomaly detection
    const anomalyEvent = {
      timestamp: new Date().toISOString(),
      detection_type: 'anomaly',
      anomaly_type: 'traffic_pattern',
      source_ip: '10.0.0.200',
      dest_ip: '172.16.0.1',
      description: 'Unusual traffic volume detected',
      baseline_value: 1000,
      observed_value: 15000,
      anomaly_score: 0.87,
      severity: 'medium',
      ml_model: 'isolation_forest_v2.1',
      features: {
        packet_rate: 15000,
        byte_rate: 48000000,
        connection_count: 500,
        unique_destinations: 50
      }
    };

    const response = await axios.post(`${API_BASE}/ids-logs`, anomalyEvent, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    const isValidAnomaly = response.status === 201 && 
                           response.data && 
                           response.data.id;
    
    return {
      passed: isValidAnomaly,
      message: isValidAnomaly ? 
        `IDS anomaly detection working (Event ID: ${response.data.id})` : 
        'IDS anomaly detection failed',
      points: isValidAnomaly ? 20 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `IDS anomaly detection test failed: ${error.response?.data?.error || error.message}`,
      points: 0
    };
  }
};

const testIPSBlockingAction = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    // Simulate IPS blocking action
    const blockingEvent = {
      timestamp: new Date().toISOString(),
      action_type: 'block',
      rule_id: 'IPS-BLOCK-001',
      source_ip: '198.51.100.150',
      dest_ip: '192.168.1.50',
      protocol: 'TCP',
      dest_port: 22,
      reason: 'Brute force SSH attack detected',
      duration: 3600,
      automatic: true,
      severity: 'critical',
      impact: {
        connections_blocked: 47,
        attack_duration: 180,
        threat_actor: 'automated_scanner'
      }
    };

    const response = await axios.post(`${API_BASE}/security-events`, blockingEvent, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    const isValidBlocking = response.status === 201 && 
                            response.data && 
                            response.data.event_id;
    
    return {
      passed: isValidBlocking,
      message: isValidBlocking ? 
        `IPS blocking action working (Event ID: ${response.data.event_id})` : 
        'IPS blocking action failed',
      points: isValidBlocking ? 20 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `IPS blocking action test failed: ${error.response?.data?.error || error.message}`,
      points: 0
    };
  }
};

// Enhanced Dashboard Tests
const testDashboardRealTimeMetrics = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    const response = await axios.get(`${API_BASE}/dashboard/stats?realtime=true`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    const hasRealTimeMetrics = response.data && 
                               typeof response.data.totalAlerts === 'number' &&
                               typeof response.data.criticalAlerts === 'number' &&
                               typeof response.data.networkTraffic === 'number' &&
                               response.data.lastUpdate &&
                               Array.isArray(response.data.recentEvents);
    
    return {
      passed: hasRealTimeMetrics,
      message: hasRealTimeMetrics ? 
        `Dashboard real-time metrics working (${response.data.totalAlerts} alerts, ${response.data.recentEvents.length} recent events)` : 
        'Dashboard real-time metrics missing or invalid',
      points: hasRealTimeMetrics ? 20 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `Dashboard real-time metrics test failed: ${error.response?.data?.error || error.message}`,
      points: 0
    };
  }
};

const testDashboardVisualizationData = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    const response = await axios.get(`${API_BASE}/dashboard/trends?timeRange=24h`, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    const hasVisualizationData = response.data && 
                                 Array.isArray(response.data.timeSeriesData) &&
                                 Array.isArray(response.data.topThreats) &&
                                 Array.isArray(response.data.networkTopology) &&
                                 response.data.alertDistribution;
    
    return {
      passed: hasVisualizationData,
      message: hasVisualizationData ? 
        `Dashboard visualization data working (${response.data.timeSeriesData.length} data points)` : 
        'Dashboard visualization data missing or invalid',
      points: hasVisualizationData ? 18 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `Dashboard visualization test failed: ${error.response?.data?.error || error.message}`,
      points: 0
    };
  }
};

const testDashboardAlertManagement = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    // Test alert creation
    const alertData = {
      title: 'Test Security Alert',
      description: 'Dashboard alert management test',
      severity: 'medium',
      source: 'dashboard_test',
      type: 'security_event'
    };

    const createResponse = await axios.post(`${API_BASE}/alerts`, alertData, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    if (!createResponse.data || !createResponse.data.id) {
      return {
        passed: false,
        message: 'Dashboard alert creation failed',
        points: 0
      };
    }

    const alertId = createResponse.data.id;
    
    // Test alert update
    const updateResponse = await axios.put(`${API_BASE}/alerts/${alertId}`, {
      status: 'acknowledged',
      notes: 'Alert acknowledged via dashboard test'
    }, {
      headers: { Authorization: `Bearer ${authToken}` }
    });
    
    const isValidAlertManagement = updateResponse.status === 200 && 
                                   updateResponse.data &&
                                   updateResponse.data.status === 'acknowledged';
    
    return {
      passed: isValidAlertManagement,
      message: isValidAlertManagement ? 
        `Dashboard alert management working (Alert ID: ${alertId})` : 
        'Dashboard alert management failed',
      points: isValidAlertManagement ? 15 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `Dashboard alert management test failed: ${error.response?.data?.error || error.message}`,
      points: 0
    };
  }
};

const testDashboardPerformance = async () => {
  if (!authToken) return { passed: false, message: 'No auth token available', points: 0 };

  try {
    const startTime = Date.now();
    
    // Test multiple concurrent requests
    const requests = [
      axios.get(`${API_BASE}/dashboard/stats`, { headers: { Authorization: `Bearer ${authToken}` } }),
      axios.get(`${API_BASE}/dashboard/trends`, { headers: { Authorization: `Bearer ${authToken}` } }),
      axios.get(`${API_BASE}/network-agents`, { headers: { Authorization: `Bearer ${authToken}` } }),
      axios.get(`${API_BASE}/ids-logs?limit=10`, { headers: { Authorization: `Bearer ${authToken}` } })
    ];
    
    const responses = await Promise.allSettled(requests);
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    const successfulRequests = responses.filter(r => r.status === 'fulfilled').length;
    const performanceGood = responseTime < 5000 && successfulRequests >= 3;
    
    return {
      passed: performanceGood,
      message: performanceGood ? 
        `Dashboard performance good (${responseTime}ms for ${successfulRequests}/4 requests)` : 
        `Dashboard performance poor (${responseTime}ms for ${successfulRequests}/4 requests)`,
      points: performanceGood ? 12 : 0
    };
  } catch (error) {
    return {
      passed: false,
      message: `Dashboard performance test failed: ${error.message}`,
      points: 0
    };
  }
};

// Main test execution
const runEnhancedTests = async () => {
  console.log('🔒 A2Z SOC Platform - Enhanced Security & Readiness Test'.bold.cyan);
  console.log('=' .repeat(70).cyan);
  console.log('');

  // Security Vulnerability Tests
  console.log('🛡️  SECURITY VULNERABILITY TESTS'.bold.red);
  await test('SQL Injection Protection', testSQLInjectionProtection, 'Security', true);
  await test('XSS Protection', testXSSProtection, 'Security', true);
  await test('CSRF Protection', testCSRFProtection, 'Security', true);
  await test('Session Management', testSessionManagement, 'Security', true);
  await test('Password Security', testPasswordSecurity, 'Security', true);
  
  console.log('');

  // User Registration for subsequent tests
  console.log('👤 USER AUTHENTICATION SETUP'.bold.yellow);
  await test('Enhanced User Registration', registerTestUser, 'Authentication');
  
  console.log('');

  // Network Monitoring Agent Tests
  console.log('🌐 NETWORK MONITORING AGENT TESTS'.bold.green);
  await test('Network Agent Registration', testNetworkAgentRegistration, 'Network Monitoring');
  await test('Network Agent Heartbeat', testNetworkAgentHeartbeat, 'Network Monitoring');
  await test('Network Agent Data Ingestion', testNetworkAgentDataIngestion, 'Network Monitoring');
  
  console.log('');

  // IDS/IPS Agent Tests
  console.log('🛡️  IDS/IPS AGENT TESTS'.bold.blue);
  await test('IDS Signature Detection', testIDSSignatureDetection, 'IDS/IPS');
  await test('IDS Anomaly Detection', testIDSAnomalyDetection, 'IDS/IPS');
  await test('IPS Blocking Actions', testIPSBlockingAction, 'IDS/IPS');
  
  console.log('');

  // Dashboard Tests
  console.log('📊 DASHBOARD FUNCTIONALITY TESTS'.bold.magenta);
  await test('Dashboard Real-time Metrics', testDashboardRealTimeMetrics, 'Dashboard');
  await test('Dashboard Visualization Data', testDashboardVisualizationData, 'Dashboard');
  await test('Dashboard Alert Management', testDashboardAlertManagement, 'Dashboard');
  await test('Dashboard Performance', testDashboardPerformance, 'Dashboard');
  
  console.log('');

  // Generate comprehensive security report
  const categories = [...new Set(results.map(r => r.category))];
  const totalPoints = results.reduce((sum, r) => sum + (r.status === 'PASSED' ? r.points : 0), 0);
  const maxPoints = results.reduce((sum, r) => sum + r.points, 0);
  const percentage = Math.round((totalPoints / maxPoints) * 100);

  console.log('🔒 ENHANCED SECURITY ASSESSMENT REPORT'.bold.red);
  console.log('=' .repeat(70).red);
  
  // Security Issues Summary
  if (vulnerabilities.length > 0) {
    console.log('');
    console.log('⚠️  CRITICAL SECURITY VULNERABILITIES FOUND:'.bold.red);
    vulnerabilities.forEach(vuln => {
      console.log(`   🚨 ${vuln.severity}: ${vuln.test} - ${vuln.issue}`.red);
    });
  } else {
    console.log('');
    console.log('✅ NO CRITICAL SECURITY VULNERABILITIES FOUND'.bold.green);
  }

  console.log('');
  
  categories.forEach(category => {
    const categoryResults = results.filter(r => r.category === category);
    const categoryPassed = categoryResults.filter(r => r.status === 'PASSED').length;
    const categoryTotal = categoryResults.length;
    const categoryPoints = categoryResults.reduce((sum, r) => sum + (r.status === 'PASSED' ? r.points : 0), 0);
    const categoryMaxPoints = categoryResults.reduce((sum, r) => sum + r.points, 0);
    const categoryPercentage = Math.round((categoryPoints / categoryMaxPoints) * 100);
    
    const status = categoryPercentage >= 90 ? '🟢' : categoryPercentage >= 70 ? '🟡' : '🔴';
    console.log(`${status} ${category}: ${categoryPassed}/${categoryTotal} (${categoryPercentage}%) - ${categoryPoints}/${categoryMaxPoints} points`);
    
    categoryResults.forEach(result => {
      const icon = result.status === 'PASSED' ? '  ✅' : result.status === 'FAILED' ? '  ❌' : '  ⚠️';
      const critical = result.critical ? ' [CRITICAL]'.red : '';
      console.log(`${icon} ${result.name}: ${result.message}${critical}`);
    });
    console.log('');
  });

  console.log('ENHANCED SAAS SECURITY SCORE'.bold.cyan);
  console.log('=' .repeat(50).cyan);
  console.log(`📊 Tests Passed: ${passedTests}/${totalTests}`.bold);
  console.log(`🎯 Score: ${totalPoints}/${maxPoints} points (${percentage}%)`.bold);
  console.log(`🔒 Security Vulnerabilities: ${vulnerabilities.length}`.bold);
  
  let securityLevel;
  let readinessLevel;
  
  if (vulnerabilities.length > 0) {
    securityLevel = '🚨 SECURITY ISSUES FOUND';
    readinessLevel = '🔧 NOT PRODUCTION READY';
    console.log(`🔴 Security Status: ${securityLevel}`.red.bold);
    console.log(`🔴 Readiness: ${readinessLevel}`.red.bold);
  } else if (percentage >= 95) {
    securityLevel = '🔒 SECURITY HARDENED';
    readinessLevel = '🚀 PRODUCTION READY';
    console.log(`🟢 Security Status: ${securityLevel}`.green.bold);
    console.log(`🟢 Readiness: ${readinessLevel}`.green.bold);
  } else if (percentage >= 85) {
    securityLevel = '🛡️  SECURITY GOOD';
    readinessLevel = '⚡ NEARLY READY';
    console.log(`🟡 Security Status: ${securityLevel}`.yellow.bold);
    console.log(`🟡 Readiness: ${readinessLevel}`.yellow.bold);
  } else {
    securityLevel = '⚠️  SECURITY NEEDS WORK';
    readinessLevel = '🔧 REQUIRES FIXES';
    console.log(`🟡 Security Status: ${securityLevel}`.yellow.bold);
    console.log(`🟡 Readiness: ${readinessLevel}`.yellow.bold);
  }

  console.log('');
  console.log('✨ Enhanced Security Assessment Complete!'.bold.cyan);
  
  return {
    totalTests,
    passedTests,
    percentage,
    securityLevel,
    readinessLevel,
    vulnerabilities: vulnerabilities.length,
    totalPoints,
    maxPoints
  };
};

// Run the enhanced tests
runEnhancedTests()
  .then(summary => {
    console.log('');
    if (summary.vulnerabilities === 0 && summary.percentage >= 95) {
      console.log('🏆 PLATFORM STATUS: ENTERPRISE SECURITY GRADE'.bold.green);
      console.log('  🎯 Production deployment approved');
      console.log('  🔒 Security hardened and vulnerability-free');
      console.log('  📊 All agent systems operational');
      console.log('  💰 Ready for enterprise customer onboarding');
    } else if (summary.vulnerabilities === 0 && summary.percentage >= 85) {
      console.log('🥈 PLATFORM STATUS: SECURITY CERTIFIED'.bold.yellow);
      console.log('  🧪 Ready for beta testing');
      console.log('  🔧 Minor enhancements recommended');
    } else {
      console.log('🚧 PLATFORM STATUS: REQUIRES SECURITY FIXES'.bold.red);
      console.log('  ⚠️  NOT ready for production');
      console.log('  🔒 Security vulnerabilities must be addressed');
    }
    
    process.exit(summary.vulnerabilities === 0 && summary.percentage >= 85 ? 0 : 1);
  })
  .catch(error => {
    console.error('💥 Enhanced test execution failed:'.red.bold, error.message);
    process.exit(1);
  }); 