-- A2Z SOC Production-Ready SaaS Database Schema
-- Comprehensive schema for multi-tenant SaaS platform

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "inet" CASCADE;

-- ================================
-- CORE AUTHENTICATION & TENANCY
-- ================================

-- Organizations/Tenants
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE,
    subscription_tier VARCHAR(50) DEFAULT 'free',
    subscription_status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Users and authentication
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ================================
-- NETWORK INFRASTRUCTURE
-- ================================

-- Network agents
CREATE TABLE IF NOT EXISTS network_agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    agent_type VARCHAR(100) NOT NULL,
    ip_address INET,
    hostname VARCHAR(255),
    operating_system VARCHAR(100),
    version VARCHAR(50),
    status VARCHAR(50) DEFAULT 'offline',
    last_heartbeat TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    configuration JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Network interfaces
CREATE TABLE IF NOT EXISTS network_interfaces (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES network_agents(id) ON DELETE CASCADE,
    interface_name VARCHAR(100) NOT NULL,
    interface_type VARCHAR(50),
    ip_address INET,
    mac_address MACADDR,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ================================
-- SECURITY EVENTS & LOGS
-- ================================

-- Security events and alerts
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES network_agents(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'new',
    source_ip INET,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20),
    rule_id VARCHAR(100),
    rule_name VARCHAR(255),
    description TEXT,
    mitre_technique VARCHAR(20),
    confidence_score DECIMAL(3,2),
    raw_data JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- IDS/IPS logs
CREATE TABLE IF NOT EXISTS ids_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES network_agents(id) ON DELETE SET NULL,
    log_level VARCHAR(20) NOT NULL,
    source VARCHAR(100) NOT NULL,
    category VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat intelligence data
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    ioc_type VARCHAR(50) NOT NULL, -- ip, domain, hash, etc.
    ioc_value VARCHAR(500) NOT NULL,
    threat_type VARCHAR(100),
    confidence_score DECIMAL(3,2),
    source VARCHAR(100),
    description TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

-- ================================
-- IDS/IPS CONFIGURATION
-- ================================

-- Detection rules
CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_content TEXT NOT NULL,
    rule_type VARCHAR(50) NOT NULL, -- snort, suricata, custom
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(100),
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Agent configurations
CREATE TABLE IF NOT EXISTS agent_configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES network_agents(id) ON DELETE CASCADE,
    configuration_type VARCHAR(100) NOT NULL,
    configuration_data JSONB NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ================================
-- COMPLIANCE & AUDITING
-- ================================

-- Compliance frameworks
CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(50),
    description TEXT,
    requirements JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Compliance assessments
CREATE TABLE IF NOT EXISTS compliance_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    framework_id UUID REFERENCES compliance_frameworks(id),
    assessment_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'in_progress',
    score DECIMAL(5,2),
    results JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ================================
-- AI & ANALYTICS
-- ================================

-- AI analysis results
CREATE TABLE IF NOT EXISTS ai_analysis_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    analysis_type VARCHAR(100) NOT NULL,
    input_data JSONB,
    results JSONB,
    confidence_score DECIMAL(3,2),
    model_version VARCHAR(50),
    processing_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security recommendations
CREATE TABLE IF NOT EXISTS security_recommendations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    recommendation_type VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) DEFAULT 'new',
    implementation_effort VARCHAR(20),
    risk_reduction_score INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    implemented_at TIMESTAMP
);

-- ================================
-- BILLING & SUBSCRIPTIONS
-- ================================

-- Subscription plans
CREATE TABLE IF NOT EXISTS subscription_plans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price_monthly DECIMAL(10,2),
    price_yearly DECIMAL(10,2),
    features JSONB,
    limits JSONB,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Billing information
CREATE TABLE IF NOT EXISTS billing_info (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    stripe_customer_id VARCHAR(255),
    subscription_id VARCHAR(255),
    plan_id UUID REFERENCES subscription_plans(id),
    billing_email VARCHAR(255),
    payment_method JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Usage metrics
CREATE TABLE IF NOT EXISTS usage_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    metric_type VARCHAR(100) NOT NULL,
    metric_value BIGINT NOT NULL,
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ================================
-- SYSTEM CONFIGURATION
-- ================================

-- System configuration
CREATE TABLE IF NOT EXISTS system_config (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    is_sensitive BOOLEAN DEFAULT false,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Notification settings
CREATE TABLE IF NOT EXISTS notification_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    notification_type VARCHAR(100) NOT NULL,
    channel VARCHAR(50) NOT NULL, -- email, slack, webhook
    configuration JSONB,
    is_enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ================================
-- INDEXES FOR PERFORMANCE
-- ================================

-- Core indexes
CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_network_agents_org ON network_agents(organization_id);
CREATE INDEX IF NOT EXISTS idx_network_agents_status ON network_agents(status);

-- Security events indexes
CREATE INDEX IF NOT EXISTS idx_security_events_org ON security_events(organization_id);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip);

-- IDS logs indexes
CREATE INDEX IF NOT EXISTS idx_ids_logs_org ON ids_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_ids_logs_level ON ids_logs(log_level);
CREATE INDEX IF NOT EXISTS idx_ids_logs_time ON ids_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_ids_logs_source ON ids_logs(source);

-- Threat intelligence indexes
CREATE INDEX IF NOT EXISTS idx_threat_intel_org ON threat_intelligence(organization_id);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intelligence(ioc_type);
CREATE INDEX IF NOT EXISTS idx_threat_intel_value ON threat_intelligence(ioc_value);

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_org ON audit_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(created_at);

-- ================================
-- DEFAULT DATA
-- ================================

-- Insert default organization for demo
INSERT INTO organizations (id, name, domain, subscription_tier) VALUES
('00000000-0000-0000-0000-000000000001', 'Demo Organization', 'demo.a2zsoc.com', 'enterprise')
ON CONFLICT (id) DO NOTHING;

-- Insert default subscription plans
INSERT INTO subscription_plans (id, name, description, price_monthly, price_yearly, features, limits) VALUES
('00000000-0000-0000-0000-000000000001', 'Free', 'Basic monitoring for small teams', 0.00, 0.00, 
 '{"agents": 1, "retention_days": 7, "support": "community"}', 
 '{"max_agents": 1, "max_events_per_month": 10000}'),
('00000000-0000-0000-0000-000000000002', 'Professional', 'Advanced features for growing businesses', 49.99, 499.99,
 '{"agents": 10, "retention_days": 30, "support": "email", "ai_analysis": true}',
 '{"max_agents": 10, "max_events_per_month": 100000}'),
('00000000-0000-0000-0000-000000000003', 'Enterprise', 'Full-featured solution for large organizations', 199.99, 1999.99,
 '{"agents": -1, "retention_days": 365, "support": "priority", "ai_analysis": true, "compliance": true}',
 '{"max_agents": -1, "max_events_per_month": -1}')
ON CONFLICT (id) DO NOTHING;

-- Insert default compliance frameworks
INSERT INTO compliance_frameworks (id, name, version, description, requirements) VALUES
('00000000-0000-0000-0000-000000000001', 'ISO 27001', '2013', 'Information Security Management Systems',
 '{"controls": 114, "domains": ["security_policy", "organization", "human_resources", "asset_management"]}'),
('00000000-0000-0000-0000-000000000002', 'SOC 2 Type II', '2017', 'Service Organization Control 2',
 '{"trust_principles": ["security", "availability", "processing_integrity", "confidentiality", "privacy"]}'),
('00000000-0000-0000-0000-000000000003', 'NIST Cybersecurity Framework', '1.1', 'National Institute of Standards and Technology',
 '{"functions": ["identify", "protect", "detect", "respond", "recover"]}}')
ON CONFLICT (id) DO NOTHING;

-- Insert default system configuration
INSERT INTO system_config (key, value, description) VALUES
('platform.version', '2.0.0', 'Platform version'),
('platform.name', 'A2Z SOC SaaS Platform', 'Platform name'),
('setup.completed', 'true', 'Initial setup completion status'),
('features.ai_analysis', 'true', 'AI analysis feature enabled'),
('features.threat_intel', 'true', 'Threat intelligence feature enabled'),
('features.compliance', 'true', 'Compliance management feature enabled'),
('retention.default_days', '30', 'Default data retention period'),
('security.session_timeout', '3600', 'Session timeout in seconds')
ON CONFLICT (key) DO NOTHING; 