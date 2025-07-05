-- Enhanced Security Testing Database Schema
-- Creates tables for alerts, security events, IDS logs, and network events

-- Security Alerts Table
CREATE TABLE IF NOT EXISTS security_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    alert_type VARCHAR(50) NOT NULL DEFAULT 'security_event',
    source VARCHAR(100),
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'investigating', 'resolved', 'false_positive')),
    assigned_to UUID REFERENCES users(id),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id)
);

-- Security Events Table (for IPS blocking actions, etc.)
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    source_ip INET,
    dest_ip INET,
    protocol VARCHAR(10),
    dest_port INTEGER,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    action_taken VARCHAR(50),
    rule_id VARCHAR(100),
    reason TEXT,
    duration INTEGER, -- in seconds
    automatic BOOLEAN DEFAULT FALSE,
    impact JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- IDS Logs Table (for signature and anomaly detection)
CREATE TABLE IF NOT EXISTS ids_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    detection_type VARCHAR(20) NOT NULL CHECK (detection_type IN ('signature_match', 'anomaly')),
    signature_id VARCHAR(100),
    signature_name VARCHAR(255),
    source_ip INET,
    dest_ip INET,
    source_port INTEGER,
    dest_port INTEGER,
    protocol VARCHAR(10),
    payload TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence DECIMAL(3,2), -- 0.00 to 1.00
    raw_packet TEXT,
    -- Anomaly detection fields
    anomaly_type VARCHAR(50),
    description TEXT,
    baseline_value DECIMAL,
    observed_value DECIMAL,
    anomaly_score DECIMAL(3,2), -- 0.00 to 1.00
    ml_model VARCHAR(100),
    features JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Network Events Table (for agent data ingestion)
CREATE TABLE IF NOT EXISTS network_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    source_ip INET,
    dest_ip INET,
    protocol VARCHAR(10),
    bytes_transferred BIGINT DEFAULT 0,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_security_alerts_org_id ON security_alerts(organization_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_security_alerts_created_at ON security_alerts(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_org_id ON security_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ids_logs_org_id ON ids_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_ids_logs_source_ip ON ids_logs(source_ip);
CREATE INDEX IF NOT EXISTS idx_ids_logs_detection_type ON ids_logs(detection_type);
CREATE INDEX IF NOT EXISTS idx_ids_logs_severity ON ids_logs(severity);
CREATE INDEX IF NOT EXISTS idx_ids_logs_created_at ON ids_logs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_network_events_org_id ON network_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_network_events_agent_id ON network_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_network_events_timestamp ON network_events(timestamp DESC);

-- Add additional columns to agents table if not exists
ALTER TABLE agents ADD COLUMN IF NOT EXISTS events_processed INTEGER DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS last_data_received TIMESTAMP WITH TIME ZONE;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS capabilities JSONB DEFAULT '[]';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS version VARCHAR(50);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS platform VARCHAR(50);

-- Update agents table to ensure proper structure
ALTER TABLE agents 
  ALTER COLUMN status SET DEFAULT 'offline',
  ADD COLUMN IF NOT EXISTS metrics JSONB DEFAULT '{}';

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to security_alerts
DROP TRIGGER IF EXISTS update_security_alerts_updated_at ON security_alerts;
CREATE TRIGGER update_security_alerts_updated_at 
    BEFORE UPDATE ON security_alerts 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grant necessary permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON security_alerts TO PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON security_events TO PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON ids_logs TO PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON network_events TO PUBLIC; 