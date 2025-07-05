-- A2Z SOC Test Data Seeding Script
-- This script creates realistic test data for comprehensive platform testing

-- Clean existing test data
DELETE FROM ai_analysis_results WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');
DELETE FROM security_recommendations WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');
DELETE FROM compliance_assessments WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');
DELETE FROM ids_logs WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');
DELETE FROM security_events WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');
DELETE FROM threat_intelligence WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');
DELETE FROM detection_rules WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');
DELETE FROM agent_configurations WHERE agent_id IN (SELECT id FROM network_agents WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp'));
DELETE FROM network_interfaces WHERE agent_id IN (SELECT id FROM network_agents WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp'));
DELETE FROM network_agents WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');
DELETE FROM audit_logs WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');
DELETE FROM user_sessions WHERE user_id IN (SELECT id FROM users WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp'));
DELETE FROM users WHERE organization_id = (SELECT id FROM organizations WHERE name = 'A2Z Security Corp');

-- Get or create test organization
INSERT INTO organizations (id, name, domain, subscription_tier, subscription_status) 
VALUES ('550e8400-e29b-41d4-a716-446655440000', 'A2Z Security Corp', 'a2zsec.com', 'professional', 'active')
ON CONFLICT (id) DO UPDATE SET 
    name = EXCLUDED.name,
    domain = EXCLUDED.domain,
    subscription_tier = EXCLUDED.subscription_tier,
    subscription_status = EXCLUDED.subscription_status;

-- Create test users
INSERT INTO users (id, organization_id, email, password_hash, first_name, last_name, role, is_active, email_verified) VALUES
('660e8400-e29b-41d4-a716-446655440001', '550e8400-e29b-41d4-a716-446655440000', 'admin@a2zsec.com', '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'John', 'Administrator', 'admin', true, true),
('660e8400-e29b-41d4-a716-446655440002', '550e8400-e29b-41d4-a716-446655440000', 'analyst@a2zsec.com', '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Sarah', 'Analyst', 'analyst', true, true),
('660e8400-e29b-41d4-a716-446655440003', '550e8400-e29b-41d4-a716-446655440000', 'user@a2zsec.com', '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Mike', 'User', 'user', true, true);

-- Create test network agents
INSERT INTO network_agents (id, organization_id, name, agent_type, ip_address, hostname, operating_system, version, status, last_heartbeat, configuration) VALUES
('770e8400-e29b-41d4-a716-446655440001', '550e8400-e29b-41d4-a716-446655440000', 'Main Gateway Agent', 'gateway', '192.168.1.1', 'gw-prod-01', 'Ubuntu 22.04', '1.2.3', 'online', NOW(), '{"capture_interfaces": ["eth0", "eth1"], "detection_mode": "active"}'),
('770e8400-e29b-41d4-a716-446655440002', '550e8400-e29b-41d4-a716-446655440000', 'DMZ Monitor', 'endpoint', '192.168.100.10', 'dmz-mon-01', 'CentOS 8', '1.2.3', 'online', NOW() - INTERVAL '5 minutes', '{"capture_interfaces": ["eth0"], "detection_mode": "passive"}'),
('770e8400-e29b-41d4-a716-446655440003', '550e8400-e29b-41d4-a716-446655440000', 'Cloud Connector', 'cloud', '10.0.1.50', 'cloud-agent-01', 'macOS 14.5', '1.2.3', 'online', NOW() - INTERVAL '2 minutes', '{"cloud_provider": "aws", "region": "us-east-1"}'),
('770e8400-e29b-41d4-a716-446655440004', '550e8400-e29b-41d4-a716-446655440000', 'Branch Office Agent', 'endpoint', '172.16.50.100', 'branch-agent-01', 'Windows Server 2022', '1.2.3', 'warning', NOW() - INTERVAL '30 minutes', '{"capture_interfaces": ["Ethernet"], "detection_mode": "active"}');

-- Create network interfaces
INSERT INTO network_interfaces (agent_id, interface_name, interface_type, ip_address, mac_address, is_active) VALUES
('770e8400-e29b-41d4-a716-446655440001', 'eth0', 'ethernet', '192.168.1.1', '00:1b:44:11:3a:b7', true),
('770e8400-e29b-41d4-a716-446655440001', 'eth1', 'ethernet', '10.0.0.1', '00:1b:44:11:3a:b8', true),
('770e8400-e29b-41d4-a716-446655440002', 'eth0', 'ethernet', '192.168.100.10', '00:1b:44:22:4c:d9', true),
('770e8400-e29b-41d4-a716-446655440003', 'en0', 'wifi', '10.0.1.50', '00:1b:44:33:5e:fa', true),
('770e8400-e29b-41d4-a716-446655440004', 'Ethernet', 'ethernet', '172.16.50.100', '00:1b:44:44:6f:1b', true);

-- Create realistic security events (last 7 days)
INSERT INTO security_events (organization_id, agent_id, event_type, severity, status, source_ip, destination_ip, source_port, destination_port, protocol, rule_id, rule_name, description, mitre_technique, confidence_score, raw_data, created_at) VALUES
-- Recent critical events
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440001', 'malware_detection', 'critical', 'investigating', '203.0.113.45', '192.168.1.100', 443, 8080, 'TCP', 'SID:2001001', 'Malware C2 Communication', 'Detected communication with known malware command and control server', 'T1071.001', 0.95, '{"packet_size": 1024, "payload_hash": "d41d8cd98f00b204e9800998ecf8427e"}', NOW() - INTERVAL '2 hours'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440002', 'intrusion_attempt', 'high', 'new', '198.51.100.25', '192.168.100.50', 22, 22, 'TCP', 'SID:2001002', 'SSH Brute Force Attack', 'Multiple failed SSH login attempts detected', 'T1110.001', 0.87, '{"failed_attempts": 45, "duration": "5 minutes"}', NOW() - INTERVAL '4 hours'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440001', 'data_exfiltration', 'critical', 'resolved', '192.168.1.200', '203.0.113.100', 80, 443, 'TCP', 'SID:2001003', 'Large Data Upload Detected', 'Unusual large data transfer to external server', 'T1041', 0.78, '{"bytes_transferred": 50000000, "duration": "2 minutes"}', NOW() - INTERVAL '6 hours'),

-- Medium severity events from yesterday
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440003', 'policy_violation', 'medium', 'acknowledged', '10.0.1.75', '8.8.8.8', 53, 53, 'UDP', 'SID:2001004', 'Unauthorized DNS Query', 'DNS query to non-approved server detected', 'T1071.004', 0.65, '{"query_type": "A", "domain": "suspicious-domain.com"}', NOW() - INTERVAL '1 day'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440004', 'network_scan', 'medium', 'new', '172.16.50.200', '172.16.50.1', 445, 445, 'TCP', 'SID:2001005', 'Internal Network Scan', 'Host scanning internal network ranges', 'T1046', 0.72, '{"ports_scanned": ["22", "23", "80", "443", "445"], "hosts_scanned": 254}', NOW() - INTERVAL '1 day'),

-- Lower severity events from past week
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440002', 'suspicious_traffic', 'low', 'false_positive', '192.168.100.25', '192.168.100.30', 1024, 8080, 'TCP', 'SID:2001006', 'Unusual Port Usage', 'Application using non-standard port', 'T1571', 0.45, '{"application": "custom_app", "expected_port": 80}', NOW() - INTERVAL '2 days'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440001', 'ddos_attempt', 'high', 'mitigated', '203.0.113.0', '192.168.1.1', 80, 80, 'TCP', 'SID:2001007', 'DDoS Attack Detected', 'High volume of requests from multiple sources', 'T1498.001', 0.89, '{"requests_per_second": 10000, "source_ips": 150}', NOW() - INTERVAL '3 days'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440003', 'file_integrity', 'medium', 'investigating', '10.0.1.50', '10.0.1.50', 0, 0, 'N/A', 'SID:2001008', 'File Integrity Violation', 'Critical system file modified unexpectedly', 'T1565.001', 0.67, '{"file_path": "/etc/passwd", "checksum_before": "abc123", "checksum_after": "def456"}', NOW() - INTERVAL '4 days'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440004', 'privilege_escalation', 'high', 'resolved', '172.16.50.100', '172.16.50.100', 0, 0, 'N/A', 'SID:2001009', 'Privilege Escalation Attempt', 'User attempted to gain elevated privileges', 'T1548.003', 0.83, '{"user": "standard_user", "attempted_privilege": "administrator"}', NOW() - INTERVAL '5 days'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440001', 'web_attack', 'medium', 'new', '198.51.100.50', '192.168.1.150', 80, 80, 'TCP', 'SID:2001010', 'SQL Injection Attempt', 'Malicious SQL injection detected in web traffic', 'T1190', 0.76, '{"url": "/login.php", "payload": "1'' OR ''1''=''1"}', NOW() - INTERVAL '6 days');

-- Create IDS logs
INSERT INTO ids_logs (organization_id, agent_id, log_level, source, category, message, metadata, created_at) VALUES
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440001', 'INFO', 'packet_capture', 'performance', 'Packet capture started on interface eth0', '{"interface": "eth0", "mode": "promiscuous"}', NOW() - INTERVAL '2 hours'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440001', 'WARN', 'detection_engine', 'rules', 'Detection rule SID:2001001 triggered', '{"rule_id": "SID:2001001", "trigger_count": 1}', NOW() - INTERVAL '2 hours'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440002', 'ERROR', 'network_monitor', 'connectivity', 'Failed to connect to central management server', '{"error": "connection_timeout", "retry_count": 3}', NOW() - INTERVAL '30 minutes'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440003', 'INFO', 'cloud_connector', 'sync', 'Successfully synchronized threat intelligence feeds', '{"feeds_updated": 5, "new_iocs": 127}', NOW() - INTERVAL '1 hour'),
('550e8400-e29b-41d4-a716-446655440000', '770e8400-e29b-41d4-a716-446655440004', 'WARN', 'system_monitor', 'resources', 'High CPU usage detected', '{"cpu_percent": 85, "memory_percent": 72}', NOW() - INTERVAL '45 minutes');

-- Create threat intelligence data
INSERT INTO threat_intelligence (organization_id, ioc_type, ioc_value, threat_type, confidence_score, source, description, first_seen, last_seen) VALUES
('550e8400-e29b-41d4-a716-446655440000', 'ip', '203.0.113.45', 'malware_c2', 0.95, 'threat_feed_alpha', 'Known malware command and control server', NOW() - INTERVAL '7 days', NOW() - INTERVAL '2 hours'),
('550e8400-e29b-41d4-a716-446655440000', 'domain', 'suspicious-domain.com', 'phishing', 0.78, 'internal_analysis', 'Domain hosting phishing content', NOW() - INTERVAL '3 days', NOW() - INTERVAL '1 day'),
('550e8400-e29b-41d4-a716-446655440000', 'hash', 'd41d8cd98f00b204e9800998ecf8427e', 'trojan', 0.89, 'threat_feed_beta', 'Banking trojan hash signature', NOW() - INTERVAL '10 days', NOW() - INTERVAL '2 hours'),
('550e8400-e29b-41d4-a716-446655440000', 'ip', '198.51.100.25', 'bruteforce', 0.67, 'honeypot_network', 'IP conducting SSH brute force attacks', NOW() - INTERVAL '5 days', NOW() - INTERVAL '4 hours'),
('550e8400-e29b-41d4-a716-446655440000', 'url', 'http://malicious-site.net/payload.exe', 'malware_download', 0.92, 'web_crawler', 'URL hosting malware payloads', NOW() - INTERVAL '2 days', NOW() - INTERVAL '6 hours');

-- Create detection rules
INSERT INTO detection_rules (organization_id, rule_id, name, description, rule_content, rule_type, severity, category, is_enabled) VALUES
('550e8400-e29b-41d4-a716-446655440000', 'SID:2001001', 'Malware C2 Communication', 'Detects communication with known malware C2 servers', 'alert tcp any any -> any any (msg:"Malware C2 Communication"; flow:established; content:"POST"; http_method; content:"/api/bot"; http_uri; sid:2001001; rev:1;)', 'snort', 'critical', 'malware', true),
('550e8400-e29b-41d4-a716-446655440000', 'SID:2001002', 'SSH Brute Force Attack', 'Detects SSH brute force attempts', 'alert tcp any any -> any 22 (msg:"SSH Brute Force Attack"; threshold:type both, track by_src, count 10, seconds 60; sid:2001002; rev:1;)', 'snort', 'high', 'intrusion', true),
('550e8400-e29b-41d4-a716-446655440000', 'SID:2001003', 'Large Data Upload', 'Detects large data transfers', 'alert tcp any any -> !$HOME_NET any (msg:"Large Data Upload Detected"; threshold:type both, track by_src, count 1, seconds 60; dsize:>10000000; sid:2001003; rev:1;)', 'snort', 'medium', 'data_loss', true),
('550e8400-e29b-41d4-a716-446655440000', 'SID:2001004', 'DNS Policy Violation', 'Detects DNS queries to unauthorized servers', 'alert udp any any -> !$DNS_SERVERS 53 (msg:"Unauthorized DNS Query"; sid:2001004; rev:1;)', 'snort', 'low', 'policy', true),
('550e8400-e29b-41d4-a716-446655440000', 'SID:2001005', 'Internal Network Scan', 'Detects internal network scanning', 'alert tcp any any -> $HOME_NET any (msg:"Internal Network Scan"; threshold:type both, track by_src, count 100, seconds 60; flags:S; sid:2001005; rev:1;)', 'snort', 'medium', 'reconnaissance', true);

-- Create security recommendations
INSERT INTO security_recommendations (organization_id, recommendation_type, title, description, severity, implementation_effort, risk_reduction_score) VALUES
('550e8400-e29b-41d4-a716-446655440000', 'network_security', 'Implement Network Segmentation', 'Deploy network segmentation to isolate critical systems and limit lateral movement in case of breach', 'high', 'high', 8.5),
('550e8400-e29b-41d4-a716-446655440000', 'endpoint_security', 'Enable Multi-Factor Authentication', 'Implement MFA for all administrative accounts to prevent unauthorized access', 'critical', 'medium', 9.2),
('550e8400-e29b-41d4-a716-446655440000', 'vulnerability_management', 'Patch Management Program', 'Establish regular patching schedule for all systems to address known vulnerabilities', 'high', 'medium', 7.8),
('550e8400-e29b-41d4-a716-446655440000', 'monitoring', 'Enhanced Logging Configuration', 'Configure comprehensive logging for all security events and network traffic', 'medium', 'low', 6.5),
('550e8400-e29b-41d4-a716-446655440000', 'training', 'Security Awareness Training', 'Conduct regular security awareness training for all employees', 'medium', 'low', 7.0);

-- Create compliance frameworks (if not exists)
INSERT INTO compliance_frameworks (id, name, version, description, requirements) VALUES
('880e8400-e29b-41d4-a716-446655440001', 'NIST Cybersecurity Framework', '1.1', 'Framework for improving critical infrastructure cybersecurity', '{"identify": ["asset_management", "business_environment"], "protect": ["access_control", "awareness_training"], "detect": ["anomalies_events", "continuous_monitoring"], "respond": ["response_planning", "communications"], "recover": ["recovery_planning", "improvements"]}'),
('880e8400-e29b-41d4-a716-446655440002', 'ISO 27001', '2013', 'Information security management systems requirements', '{"controls": ["access_control", "cryptography", "physical_security", "operations_security", "communications_security"]}'),
('880e8400-e29b-41d4-a716-446655440003', 'SOC 2 Type II', '2017', 'Security, availability, and confidentiality criteria', '{"security": ["access_controls", "logical_access"], "availability": ["system_operations", "change_management"], "confidentiality": ["data_classification", "encryption"]}')
ON CONFLICT (id) DO NOTHING;

-- Create compliance assessment
INSERT INTO compliance_assessments (organization_id, framework_id, assessment_name, status, score, results) VALUES
('550e8400-e29b-41d4-a716-446655440000', '880e8400-e29b-41d4-a716-446655440001', 'Q4 2024 NIST Assessment', 'completed', 75.5, '{"identify": {"score": 80, "status": "good"}, "protect": {"score": 70, "status": "needs_improvement"}, "detect": {"score": 85, "status": "excellent"}, "respond": {"score": 65, "status": "needs_improvement"}, "recover": {"score": 78, "status": "good"}}');

-- Create audit logs
INSERT INTO audit_logs (organization_id, user_id, action, resource_type, resource_id, details, created_at) VALUES
('550e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440001', 'LOGIN', 'user', '660e8400-e29b-41d4-a716-446655440001', '{"ip_address": "192.168.1.100", "user_agent": "Mozilla/5.0"}', NOW() - INTERVAL '1 hour'),
('550e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440001', 'UPDATE_RULE', 'detection_rule', 'SID:2001001', '{"field": "is_enabled", "old_value": false, "new_value": true}', NOW() - INTERVAL '2 hours'),
('550e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440002', 'INVESTIGATE_EVENT', 'security_event', '1', '{"action": "assigned_analyst", "notes": "Investigating potential C2 communication"}', NOW() - INTERVAL '3 hours'),
('550e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440001', 'CREATE_AGENT', 'network_agent', '770e8400-e29b-41d4-a716-446655440003', '{"agent_type": "cloud", "hostname": "cloud-agent-01"}', NOW() - INTERVAL '1 day'),
('550e8400-e29b-41d4-a716-446655440000', '660e8400-e29b-41d4-a716-446655440002', 'RESOLVE_EVENT', 'security_event', '3', '{"resolution": "false_positive", "notes": "Legitimate application behavior"}', NOW() - INTERVAL '6 hours');

-- Create AI analysis results
INSERT INTO ai_analysis_results (organization_id, analysis_type, input_data, results, confidence_score, model_version, processing_time_ms) VALUES
('550e8400-e29b-41d4-a716-446655440000', 'threat_classification', '{"packet_data": "HTTP POST request with suspicious payload"}', '{"classification": "malware_c2", "risk_score": 95, "indicators": ["suspicious_url", "encrypted_payload"]}', 0.95, 'v2.1.0', 150),
('550e8400-e29b-41d4-a716-446655440000', 'anomaly_detection', '{"network_traffic": "unusual_pattern_detected"}', '{"anomaly_type": "data_exfiltration", "severity": "high", "patterns": ["large_upload", "off_hours"]}', 0.87, 'v2.1.0', 300),
('550e8400-e29b-41d4-a716-446655440000', 'behavioral_analysis', '{"user_activity": "privilege_escalation_attempt"}', '{"behavior": "malicious", "techniques": ["T1548.003"], "recommendation": "immediate_investigation"}', 0.89, 'v2.1.0', 200);

-- Update agent last heartbeat times to show realistic status
UPDATE network_agents SET 
    last_heartbeat = CASE 
        WHEN name = 'Main Gateway Agent' THEN NOW()
        WHEN name = 'DMZ Monitor' THEN NOW() - INTERVAL '5 minutes'
        WHEN name = 'Cloud Connector' THEN NOW() - INTERVAL '2 minutes'
        WHEN name = 'Branch Office Agent' THEN NOW() - INTERVAL '30 minutes'
    END,
    status = CASE 
        WHEN name = 'Main Gateway Agent' THEN 'online'
        WHEN name = 'DMZ Monitor' THEN 'online'
        WHEN name = 'Cloud Connector' THEN 'online'
        WHEN name = 'Branch Office Agent' THEN 'warning'
    END
WHERE organization_id = '550e8400-e29b-41d4-a716-446655440000';

-- Show summary of created data
SELECT 
    'Data seeding completed successfully!' as status,
    (SELECT COUNT(*) FROM organizations WHERE id = '550e8400-e29b-41d4-a716-446655440000') as organizations,
    (SELECT COUNT(*) FROM users WHERE organization_id = '550e8400-e29b-41d4-a716-446655440000') as users,
    (SELECT COUNT(*) FROM network_agents WHERE organization_id = '550e8400-e29b-41d4-a716-446655440000') as agents,
    (SELECT COUNT(*) FROM security_events WHERE organization_id = '550e8400-e29b-41d4-a716-446655440000') as security_events,
    (SELECT COUNT(*) FROM ids_logs WHERE organization_id = '550e8400-e29b-41d4-a716-446655440000') as ids_logs,
    (SELECT COUNT(*) FROM threat_intelligence WHERE organization_id = '550e8400-e29b-41d4-a716-446655440000') as threat_intel,
    (SELECT COUNT(*) FROM detection_rules WHERE organization_id = '550e8400-e29b-41d4-a716-446655440000') as detection_rules; 