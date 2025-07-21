-- SIEM Tables
CREATE TABLE IF NOT EXISTS siem_events (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    event_id VARCHAR(255) UNIQUE NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_type VARCHAR(100) NOT NULL,
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    severity VARCHAR(20) DEFAULT 'LOW',
    message TEXT,
    raw_log TEXT,
    parsed_data JSONB,
    correlation_id VARCHAR(255),
    tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS siem_alerts (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    alert_id VARCHAR(255) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'LOW',
    status VARCHAR(50) NOT NULL DEFAULT 'OPEN',
    source_ip INET,
    destination_ip INET,
    affected_assets TEXT[],
    indicators JSONB,
    correlation_rule_id VARCHAR(255),
    event_count INTEGER DEFAULT 1,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    assigned_to VARCHAR(255),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS siem_correlation_rules (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    rule_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    query TEXT NOT NULL,
    conditions JSONB NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'LOW',
    enabled BOOLEAN DEFAULT true,
    time_window INTEGER DEFAULT 300, -- seconds
    threshold INTEGER DEFAULT 1,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- SOAR Tables
CREATE TABLE IF NOT EXISTS soar_playbooks (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    playbook_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trigger_conditions TEXT[],
    steps JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    execution_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    last_executed TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS soar_incidents (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    incident_id VARCHAR(255) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'LOW',
    status VARCHAR(50) NOT NULL DEFAULT 'NEW',
    priority VARCHAR(20) DEFAULT 'MEDIUM',
    category VARCHAR(100),
    affected_assets TEXT[],
    indicators JSONB,
    timeline JSONB DEFAULT '[]',
    evidence JSONB DEFAULT '[]',
    playbooks_executed TEXT[],
    auto_response_triggered BOOLEAN DEFAULT false,
    assigned_to VARCHAR(255),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS soar_executions (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    execution_id VARCHAR(255) UNIQUE NOT NULL,
    playbook_id VARCHAR(255) NOT NULL,
    incident_id VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    progress INTEGER DEFAULT 0,
    current_step VARCHAR(255),
    current_step_index INTEGER DEFAULT 0,
    total_steps INTEGER DEFAULT 0,
    input_data JSONB,
    output_data JSONB,
    error_message TEXT,
    execution_log JSONB DEFAULT '[]',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS soar_integrations (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    integration_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    config JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    last_health_check TIMESTAMP WITH TIME ZONE,
    health_status VARCHAR(50) DEFAULT 'UNKNOWN',
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_siem_events_tenant_timestamp ON siem_events(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_siem_events_source_type ON siem_events(source_type);
CREATE INDEX IF NOT EXISTS idx_siem_events_source_ip ON siem_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_siem_events_severity ON siem_events(severity);
CREATE INDEX IF NOT EXISTS idx_siem_events_correlation_id ON siem_events(correlation_id);

CREATE INDEX IF NOT EXISTS idx_siem_alerts_tenant_status ON siem_alerts(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_severity ON siem_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_first_seen ON siem_alerts(first_seen DESC);

CREATE INDEX IF NOT EXISTS idx_soar_playbooks_tenant_enabled ON soar_playbooks(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_soar_incidents_tenant_status ON soar_incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_soar_incidents_severity ON soar_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_soar_incidents_created_at ON soar_incidents(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_soar_executions_tenant_status ON soar_executions(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_soar_executions_playbook_id ON soar_executions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_soar_executions_incident_id ON soar_executions(incident_id);
CREATE INDEX IF NOT EXISTS idx_soar_executions_started_at ON soar_executions(started_at DESC);

-- Sample data for testing
INSERT INTO siem_correlation_rules (tenant_id, rule_id, name, description, query, conditions, severity) VALUES
('default', 'rule_brute_force', 'Brute Force Detection', 'Detect multiple failed login attempts', 'source_ip AND message:*failed*', '{"threshold": 5, "time_window": 300}', 'HIGH'),
('default', 'rule_malware', 'Malware Detection', 'Detect malware signatures', 'message:*malware* OR message:*virus*', '{"threshold": 1, "time_window": 60}', 'CRITICAL'),
('default', 'rule_suspicious_traffic', 'Suspicious Network Traffic', 'Detect unusual network patterns', 'protocol:tcp AND destination_port:443', '{"threshold": 100, "time_window": 600}', 'MEDIUM');

INSERT INTO soar_playbooks (tenant_id, playbook_id, name, description, trigger_conditions, steps) VALUES
('default', 'malware_response', 'Malware Response Playbook', 'Automated response to malware detection', ARRAY['malware_detected', 'virus_found'], '[
    {"action": "isolate_host", "parameters": {"host": "{{affected_host}}"}, "timeout": 30},
    {"action": "scan_system", "parameters": {"host": "{{affected_host}}", "scan_type": "full"}, "timeout": 300},
    {"action": "notify_team", "parameters": {"message": "Malware detected on {{affected_host}}", "channel": "#security"}, "timeout": 10},
    {"action": "create_ticket", "parameters": {"title": "Malware Incident", "priority": "high"}, "timeout": 30}
]'),
('default', 'brute_force_response', 'Brute Force Response Playbook', 'Automated response to brute force attacks', ARRAY['brute_force_detected', 'multiple_failed_logins'], '[
    {"action": "block_ip", "parameters": {"ip": "{{source_ip}}", "duration": 3600}, "timeout": 10},
    {"action": "analyze_ip", "parameters": {"ip": "{{source_ip}}"}, "timeout": 30},
    {"action": "notify_team", "parameters": {"message": "Brute force attack from {{source_ip}}", "channel": "#security"}, "timeout": 10},
    {"action": "update_firewall", "parameters": {"action": "deny", "source": "{{source_ip}}"}, "timeout": 30}
]'),
('default', 'phishing_response', 'Phishing Response Playbook', 'Automated response to phishing attempts', ARRAY['phishing_detected', 'suspicious_email'], '[
    {"action": "quarantine_email", "parameters": {"email_id": "{{email_id}}"}, "timeout": 10},
    {"action": "block_sender", "parameters": {"sender": "{{sender_email}}"}, "timeout": 10},
    {"action": "notify_users", "parameters": {"message": "Phishing attempt detected", "users": "{{affected_users}}"}, "timeout": 30},
    {"action": "analyze_urls", "parameters": {"urls": "{{suspicious_urls}}"}, "timeout": 60}
]');

INSERT INTO soar_integrations (tenant_id, integration_id, name, type, config, enabled) VALUES
('default', 'slack_integration', 'Slack Notifications', 'notification', '{"webhook_url": "https://hooks.slack.com/services/example", "default_channel": "#security"}', true),
('default', 'virustotal_integration', 'VirusTotal API', 'threat_intel', '{"api_key": "your_api_key_here", "base_url": "https://www.virustotal.com/vtapi/v2"}', true),
('default', 'shodan_integration', 'Shodan API', 'reconnaissance', '{"api_key": "your_api_key_here", "base_url": "https://api.shodan.io"}', true);

-- Sample events and alerts for testing
INSERT INTO siem_events (tenant_id, event_id, source_type, source_ip, message, severity, parsed_data) VALUES
('default', 'evt_001', 'syslog', '192.168.1.100', 'Failed login attempt for user admin', 'MEDIUM', '{"user": "admin", "action": "login_failed"}'),
('default', 'evt_002', 'syslog', '192.168.1.100', 'Failed login attempt for user admin', 'MEDIUM', '{"user": "admin", "action": "login_failed"}'),
('default', 'evt_003', 'syslog', '192.168.1.100', 'Failed login attempt for user admin', 'MEDIUM', '{"user": "admin", "action": "login_failed"}'),
('default', 'evt_004', 'firewall', '203.0.113.45', 'Blocked connection attempt', 'HIGH', '{"action": "blocked", "reason": "suspicious_ip"}'),
('default', 'evt_005', 'antivirus', '192.168.1.50', 'Malware detected: Trojan.Win32.Generic', 'CRITICAL', '{"malware_type": "trojan", "file_path": "/tmp/suspicious.exe"}');

INSERT INTO siem_alerts (tenant_id, alert_id, title, description, severity, source_ip, affected_assets) VALUES
('default', 'alert_001', 'Brute Force Attack Detected', 'Multiple failed login attempts from 192.168.1.100', 'HIGH', '192.168.1.100', ARRAY['login-server']),
('default', 'alert_002', 'Malware Detection', 'Trojan detected on workstation', 'CRITICAL', '192.168.1.50', ARRAY['workstation-01']),
('default', 'alert_003', 'Suspicious Network Activity', 'Unusual outbound traffic detected', 'MEDIUM', '192.168.1.75', ARRAY['server-02']);

INSERT INTO soar_incidents (tenant_id, incident_id, title, description, severity, affected_assets, auto_response_triggered) VALUES
('default', 'inc_001', 'Malware Outbreak', 'Multiple systems infected with malware', 'CRITICAL', ARRAY['workstation-01', 'server-03'], true),
('default', 'inc_002', 'Brute Force Campaign', 'Coordinated brute force attack', 'HIGH', ARRAY['login-server', 'web-server'], true),
('default', 'inc_003', 'Data Exfiltration Attempt', 'Suspicious data transfer detected', 'HIGH', ARRAY['database-server'], false); 