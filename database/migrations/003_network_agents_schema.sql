-- Network Agents Tables
CREATE TABLE IF NOT EXISTS network_agents (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL DEFAULT 'network-agent',
    version VARCHAR(50) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET,
    status VARCHAR(50) NOT NULL DEFAULT 'inactive',
    configuration JSONB,
    metrics JSONB,
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS network_events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    packet_size INTEGER,
    threat_level VARCHAR(20) DEFAULT 'low',
    event_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES network_agents(agent_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS network_interfaces (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    interface_name VARCHAR(100) NOT NULL,
    interface_type VARCHAR(50),
    ip_address INET,
    mac_address VARCHAR(17),
    status VARCHAR(20) DEFAULT 'unknown',
    rx_bytes BIGINT DEFAULT 0,
    tx_bytes BIGINT DEFAULT 0,
    rx_packets BIGINT DEFAULT 0,
    tx_packets BIGINT DEFAULT 0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES network_agents(agent_id) ON DELETE CASCADE
);

-- Enhanced IDS/IPS Tables
CREATE TABLE IF NOT EXISTS ids_logs (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'low',
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    signature_id VARCHAR(100),
    rule_name VARCHAR(255),
    message TEXT NOT NULL,
    packet_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    pattern TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    enabled BOOLEAN DEFAULT true,
    rule_type VARCHAR(50) DEFAULT 'signature',
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Enhanced Security Events Table
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS event_category VARCHAR(100);
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS false_positive BOOLEAN DEFAULT false;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS investigation_status VARCHAR(50) DEFAULT 'new';

-- Agent Configurations Table
CREATE TABLE IF NOT EXISTS agent_configurations (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(255) UNIQUE NOT NULL,
    agent_type VARCHAR(50) NOT NULL,
    configuration JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'inactive',
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_network_agents_agent_id ON network_agents(agent_id);
CREATE INDEX IF NOT EXISTS idx_network_agents_status ON network_agents(status);
CREATE INDEX IF NOT EXISTS idx_network_agents_last_heartbeat ON network_agents(last_heartbeat DESC);

CREATE INDEX IF NOT EXISTS idx_network_events_agent_id ON network_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_network_events_timestamp ON network_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_events_event_type ON network_events(event_type);
CREATE INDEX IF NOT EXISTS idx_network_events_source_ip ON network_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_network_events_threat_level ON network_events(threat_level);

CREATE INDEX IF NOT EXISTS idx_network_interfaces_agent_id ON network_interfaces(agent_id);
CREATE INDEX IF NOT EXISTS idx_network_interfaces_status ON network_interfaces(status);

CREATE INDEX IF NOT EXISTS idx_ids_logs_agent_id ON ids_logs(agent_id);
CREATE INDEX IF NOT EXISTS idx_ids_logs_created_at ON ids_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ids_logs_severity ON ids_logs(severity);
CREATE INDEX IF NOT EXISTS idx_ids_logs_source_ip ON ids_logs(source_ip);

CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON detection_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON detection_rules(severity);

CREATE INDEX IF NOT EXISTS idx_agent_configurations_agent_id ON agent_configurations(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_configurations_status ON agent_configurations(status);
CREATE INDEX IF NOT EXISTS idx_agent_configurations_agent_type ON agent_configurations(agent_type);

-- Sample detection rules
INSERT INTO detection_rules (name, pattern, severity, rule_type, description) VALUES
('HTTP SQL Injection', '(union|select|insert|update|delete|drop|create|alter).*from', 'high', 'signature', 'Detects potential SQL injection attempts in HTTP traffic'),
('Malware Communication', '(cmd\.exe|powershell\.exe|nc\.exe)', 'critical', 'signature', 'Detects potential malware command execution'),
('Port Scan Detection', 'SYN flood', 'medium', 'anomaly', 'Detects potential port scanning activity'),
('Brute Force Login', 'failed.*login.*attempt', 'high', 'signature', 'Detects brute force login attempts'),
('DDoS Attack', 'flood.*attack', 'critical', 'anomaly', 'Detects potential DDoS attacks')
ON CONFLICT (name) DO NOTHING;

-- Sample network agent configuration
INSERT INTO agent_configurations (agent_id, agent_type, configuration, status) VALUES
('network-agent-001', 'network-agent', '{
    "monitoring": {
        "interfaces": ["eth0", "wlan0"],
        "capture_filter": "tcp or udp",
        "packet_buffer_size": 1024
    },
    "detection": {
        "enabled": true,
        "threat_threshold": "medium",
        "real_time_analysis": true
    },
    "reporting": {
        "interval": 60,
        "metrics_enabled": true,
        "log_level": "info"
    }
}', 'active'),
('ids-ips-001', 'ids-ips', '{
    "detection": {
        "signature_rules": true,
        "anomaly_detection": true,
        "machine_learning": false
    },
    "prevention": {
        "enabled": true,
        "block_threats": true,
        "quarantine_hosts": false
    },
    "performance": {
        "max_packet_rate": 100000,
        "memory_limit": "1GB",
        "cpu_limit": 80
    }
}', 'active')
ON CONFLICT (agent_id) DO UPDATE SET
    configuration = EXCLUDED.configuration,
    status = EXCLUDED.status,
    updated_at = CURRENT_TIMESTAMP; 