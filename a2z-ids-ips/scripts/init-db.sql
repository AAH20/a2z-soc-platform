-- A2Z IDS/IPS Database Initialization Script
-- This script sets up the database schema for the standalone IDS/IPS system

-- Create the main database if it doesn't exist
CREATE DATABASE IF NOT EXISTS a2z_ids;
USE a2z_ids;

-- Create users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'operator',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create alerts table
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    rule_id INTEGER NOT NULL,
    severity VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10),
    packet_data TEXT,
    metadata JSON,
    acknowledged BOOLEAN DEFAULT false,
    acknowledged_by INTEGER,
    acknowledged_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_alerts_severity (severity),
    INDEX idx_alerts_created_at (created_at),
    INDEX idx_alerts_source_ip (source_ip),
    INDEX idx_alerts_rule_id (rule_id)
);

-- Create rules table
CREATE TABLE IF NOT EXISTS rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    content TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    sid INTEGER UNIQUE,
    revision INTEGER DEFAULT 1,
    priority INTEGER DEFAULT 3,
    false_positive_count INTEGER DEFAULT 0,
    last_triggered TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_rules_category (category),
    INDEX idx_rules_enabled (enabled),
    INDEX idx_rules_sid (sid)
);

-- Create packet_flows table for flow tracking
CREATE TABLE IF NOT EXISTS packet_flows (
    id SERIAL PRIMARY KEY,
    flow_id VARCHAR(255) UNIQUE NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10) NOT NULL,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP NULL,
    packet_count INTEGER DEFAULT 0,
    byte_count BIGINT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active',
    threat_score FLOAT DEFAULT 0.0,
    geolocation JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_flows_status (status),
    INDEX idx_flows_start_time (start_time),
    INDEX idx_flows_source_ip (source_ip),
    INDEX idx_flows_threat_score (threat_score)
);

-- Create performance_metrics table
CREATE TABLE IF NOT EXISTS performance_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value FLOAT NOT NULL,
    metric_unit VARCHAR(20),
    component VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_metrics_name_time (metric_name, timestamp),
    INDEX idx_metrics_component (component)
);

-- Create configuration table
CREATE TABLE IF NOT EXISTS configuration (
    id SERIAL PRIMARY KEY,
    key_name VARCHAR(255) UNIQUE NOT NULL,
    value TEXT,
    description TEXT,
    category VARCHAR(100),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create sessions table for authentication
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sessions_user_id (user_id),
    INDEX idx_sessions_expires_at (expires_at)
);

-- Create audit_log table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    resource_id VARCHAR(100),
    details JSON,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_user_id (user_id),
    INDEX idx_audit_action (action),
    INDEX idx_audit_created_at (created_at)
);

-- Insert default admin user (password: admin123)
INSERT IGNORE INTO users (username, email, password_hash, role) VALUES 
('admin', 'admin@a2z-ids.local', '$2b$10$8K1p/a3f8WOUwrXivQRpm.CzlY9lQxFl3p5tGBr4LL3sXu4Nq7/K6', 'admin');

-- Insert default configuration
INSERT IGNORE INTO configuration (key_name, value, description, category) VALUES 
('system.version', '1.0.0', 'System version', 'system'),
('capture.interface', 'eth0', 'Default network interface', 'capture'),
('capture.mode', 'passive', 'Capture mode (passive/inline/hybrid)', 'capture'),
('detection.enabled', 'true', 'Detection engine enabled', 'detection'),
('ml.anomaly_threshold', '0.95', 'ML anomaly detection threshold', 'machine_learning'),
('alerting.enabled', 'true', 'Alerting system enabled', 'alerting'),
('monitoring.metrics_retention_days', '30', 'Metrics retention period', 'monitoring');

-- Insert some sample rules
INSERT IGNORE INTO rules (name, category, content, sid) VALUES 
('SSH Brute Force Detection', 'brute-force', 'alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flow:to_server,established; content:"Failed password"; detection_filter:track by_src, count 5, seconds 60; sid:100001; rev:1;)', 100001),
('HTTP SQL Injection', 'web-application', 'alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; flow:to_server,established; content:"union select"; nocase; http_uri; sid:100002; rev:1;)', 100002),
('Port Scan Detection', 'network-scan', 'alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; detection_filter:track by_src, count 10, seconds 60; sid:100003; rev:1;)', 100003),
('DNS Tunneling', 'policy-violation', 'alert udp any any -> any 53 (msg:"Potential DNS Tunneling"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; dsize:>100; sid:100004; rev:1;)', 100004),
('Malware Download', 'malware', 'alert tcp any any -> any 80 (msg:"Malware Download Attempt"; flow:to_server,established; content:"GET"; http_method; content:".exe"; http_uri; sid:100005; rev:1;)', 100005);

-- Create views for common queries
CREATE OR REPLACE VIEW alerts_summary AS
SELECT 
    DATE(created_at) as alert_date,
    severity,
    COUNT(*) as alert_count
FROM alerts 
GROUP BY DATE(created_at), severity
ORDER BY alert_date DESC, severity;

CREATE OR REPLACE VIEW top_alerts AS
SELECT 
    rule_id,
    message,
    COUNT(*) as frequency,
    MAX(created_at) as last_seen
FROM alerts 
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY rule_id, message
ORDER BY frequency DESC
LIMIT 10;

CREATE OR REPLACE VIEW active_flows AS
SELECT 
    source_ip,
    destination_ip,
    protocol,
    COUNT(*) as connection_count,
    SUM(packet_count) as total_packets,
    SUM(byte_count) as total_bytes,
    AVG(threat_score) as avg_threat_score
FROM packet_flows 
WHERE status = 'active'
GROUP BY source_ip, destination_ip, protocol
ORDER BY total_packets DESC;

-- Create stored procedures for common operations
DELIMITER //

CREATE PROCEDURE GetAlertStatistics(IN time_range_hours INT)
BEGIN
    SELECT 
        severity,
        COUNT(*) as count,
        COUNT(*) * 100.0 / (SELECT COUNT(*) FROM alerts WHERE created_at >= DATE_SUB(NOW(), INTERVAL time_range_hours HOUR)) as percentage
    FROM alerts 
    WHERE created_at >= DATE_SUB(NOW(), INTERVAL time_range_hours HOUR)
    GROUP BY severity
    ORDER BY count DESC;
END //

CREATE PROCEDURE GetTopSourceIPs(IN time_range_hours INT, IN limit_count INT)
BEGIN
    SELECT 
        source_ip,
        COUNT(*) as alert_count,
        COUNT(DISTINCT rule_id) as unique_rules_triggered,
        MAX(severity) as max_severity
    FROM alerts 
    WHERE created_at >= DATE_SUB(NOW(), INTERVAL time_range_hours HOUR)
        AND source_ip IS NOT NULL
    GROUP BY source_ip
    ORDER BY alert_count DESC
    LIMIT limit_count;
END //

CREATE PROCEDURE GetPerformanceMetrics(IN component_name VARCHAR(50), IN time_range_hours INT)
BEGIN
    SELECT 
        metric_name,
        AVG(metric_value) as avg_value,
        MIN(metric_value) as min_value,
        MAX(metric_value) as max_value,
        metric_unit
    FROM performance_metrics 
    WHERE component = component_name
        AND timestamp >= DATE_SUB(NOW(), INTERVAL time_range_hours HOUR)
    GROUP BY metric_name, metric_unit
    ORDER BY metric_name;
END //

DELIMITER ;

-- Create triggers for audit logging
DELIMITER //

CREATE TRIGGER rules_audit_insert 
AFTER INSERT ON rules
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (action, resource, resource_id, details)
    VALUES ('CREATE', 'rule', NEW.id, JSON_OBJECT('name', NEW.name, 'category', NEW.category));
END //

CREATE TRIGGER rules_audit_update 
AFTER UPDATE ON rules
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (action, resource, resource_id, details)
    VALUES ('UPDATE', 'rule', NEW.id, JSON_OBJECT('name', NEW.name, 'old_enabled', OLD.enabled, 'new_enabled', NEW.enabled));
END //

CREATE TRIGGER rules_audit_delete 
AFTER DELETE ON rules
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (action, resource, resource_id, details)
    VALUES ('DELETE', 'rule', OLD.id, JSON_OBJECT('name', OLD.name, 'category', OLD.category));
END //

DELIMITER ;

-- Create indexes for performance
CREATE INDEX idx_alerts_created_severity ON alerts(created_at, severity);
CREATE INDEX idx_flows_source_dest ON packet_flows(source_ip, destination_ip);
CREATE INDEX idx_metrics_timestamp_component ON performance_metrics(timestamp, component);

-- Set proper permissions
GRANT ALL PRIVILEGES ON a2z_ids.* TO 'a2z_ids'@'%';
FLUSH PRIVILEGES;

-- Insert initial performance baseline
INSERT INTO performance_metrics (metric_name, metric_value, metric_unit, component) VALUES
('packets_per_second', 0, 'packets/sec', 'core'),
('memory_usage', 0, 'MB', 'core'),
('cpu_usage', 0, 'percent', 'core'),
('processing_latency', 0, 'milliseconds', 'core'),
('alerts_generated', 0, 'count/hour', 'detection'),
('rules_loaded', 5, 'count', 'detection'),
('active_flows', 0, 'count', 'flow_tracker');

-- Log the successful initialization
INSERT INTO audit_log (action, resource, details)
VALUES ('SYSTEM_INIT', 'database', JSON_OBJECT('message', 'Database initialized successfully', 'timestamp', NOW()));

-- Display initialization summary
SELECT 'A2Z IDS/IPS Database Initialized Successfully' as status,
       (SELECT COUNT(*) FROM users) as users_created,
       (SELECT COUNT(*) FROM rules) as default_rules,
       (SELECT COUNT(*) FROM configuration) as config_entries; 