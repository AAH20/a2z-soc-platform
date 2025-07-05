-- Migration 001: Initial Multi-Tenant Schema
-- A2Z SOC SaaS Platform Database Setup
-- Created: 2024-01-01

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create schemas for data organization
CREATE SCHEMA IF NOT EXISTS tenant_data;
CREATE SCHEMA IF NOT EXISTS system_data;
CREATE SCHEMA IF NOT EXISTS analytics;

-- =============================================
-- CORE TENANT MANAGEMENT TABLES
-- =============================================

-- Tenants (Organizations/Companies)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    subdomain VARCHAR(100) UNIQUE NOT NULL,
    contact_email VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    address TEXT,
    industry VARCHAR(100),
    company_size VARCHAR(50), -- 'startup', 'small', 'medium', 'large', 'enterprise'
    
    -- Subscription & Billing
    plan VARCHAR(50) NOT NULL DEFAULT 'trial', -- 'trial', 'starter', 'professional', 'enterprise'
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'suspended', 'trial', 'past_due', 'over_limit'
    stripe_customer_id VARCHAR(255),
    
    -- Security & Compliance
    encryption_key TEXT, -- Tenant-specific encryption key
    compliance_frameworks TEXT[], -- ['soc2', 'iso27001', 'hipaa', 'gdpr']
    data_retention_days INTEGER DEFAULT 365,
    
    -- Branding (White-label)
    logo_url TEXT,
    primary_color VARCHAR(7), -- Hex color
    secondary_color VARCHAR(7),
    custom_domain VARCHAR(255),
    custom_css TEXT,
    
    -- Metadata
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_plan CHECK (plan IN ('trial', 'starter', 'professional', 'enterprise')),
    CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'trial', 'past_due', 'over_limit', 'canceled'))
);

-- Users within tenants
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    
    -- Authorization
    role VARCHAR(50) NOT NULL DEFAULT 'viewer', -- 'admin', 'analyst', 'viewer'
    permissions TEXT[], -- Array of specific permissions
    
    -- Account Status
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- 'active', 'suspended', 'pending'
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    
    -- Security
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP WITH TIME ZONE,
    last_login TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- MFA
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    mfa_backup_codes TEXT[],
    
    -- Metadata
    preferences JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(tenant_id, email),
    CONSTRAINT valid_role CHECK (role IN ('admin', 'analyst', 'viewer')),
    CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'pending'))
);

-- API Keys for programmatic access
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    key_prefix VARCHAR(10) NOT NULL, -- First 8 chars for identification
    
    -- Authorization
    permissions TEXT[] NOT NULL DEFAULT ARRAY['read'],
    scopes TEXT[], -- API scopes like 'alerts:read', 'integrations:write'
    
    -- Usage & Limits
    rate_limit_per_minute INTEGER DEFAULT 100,
    monthly_usage_limit INTEGER,
    current_month_usage INTEGER DEFAULT 0,
    
    -- Status & Expiry
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    
    -- Metadata
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'expired'))
);

-- =============================================
-- SUBSCRIPTION & BILLING TABLES
-- =============================================

-- Subscription plans and pricing
CREATE TABLE subscription_plans (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price_cents INTEGER, -- Price in cents, NULL for custom pricing
    interval VARCHAR(20) NOT NULL, -- 'month', 'year'
    
    -- Feature limits
    limits JSONB NOT NULL DEFAULT '{}',
    features TEXT[] NOT NULL DEFAULT '{}',
    
    -- Status
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Active subscriptions
CREATE TABLE subscriptions (
    id VARCHAR(255) PRIMARY KEY, -- Stripe subscription ID
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    stripe_subscription_id VARCHAR(255) NOT NULL UNIQUE,
    plan_id VARCHAR(50) NOT NULL REFERENCES subscription_plans(id),
    
    -- Subscription status
    status VARCHAR(50) NOT NULL, -- 'active', 'trialing', 'past_due', 'canceled', 'unpaid'
    current_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    current_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    trial_end TIMESTAMP WITH TIME ZONE,
    canceled_at TIMESTAMP WITH TIME ZONE,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Usage tracking for billing
CREATE TABLE usage_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL, -- 'security_event', 'api_call', 'storage_gb', 'integration_sync'
    quantity INTEGER NOT NULL DEFAULT 1,
    unit VARCHAR(50) DEFAULT 'count', -- 'count', 'bytes', 'minutes'
    
    -- Context
    metadata JSONB DEFAULT '{}',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Billing period
    billing_month DATE NOT NULL DEFAULT DATE_TRUNC('month', NOW())
);

-- Invoice records
CREATE TABLE invoices (
    id VARCHAR(255) PRIMARY KEY, -- Stripe invoice ID
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subscription_id VARCHAR(255) REFERENCES subscriptions(id),
    
    -- Invoice details
    amount_paid INTEGER NOT NULL, -- Amount in cents
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    status VARCHAR(50) NOT NULL, -- 'paid', 'open', 'void', 'uncollectible'
    
    -- Dates
    invoice_date TIMESTAMP WITH TIME ZONE NOT NULL,
    due_date TIMESTAMP WITH TIME ZONE,
    paid_at TIMESTAMP WITH TIME ZONE,
    
    -- Metadata
    stripe_invoice_url TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================
-- SECURITY DATA TABLES (TENANT-SPECIFIC)
-- =============================================

-- Security alerts
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Alert details
    severity VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    title VARCHAR(500) NOT NULL,
    description TEXT,
    source VARCHAR(100) NOT NULL, -- 'wazuh', 'snort', 'suricata', 'custom'
    
    -- Classification
    category VARCHAR(100), -- 'malware', 'intrusion', 'policy_violation', etc.
    tags TEXT[],
    mitre_techniques TEXT[], -- MITRE ATT&CK technique IDs
    
    -- Status & Assignment
    status VARCHAR(50) NOT NULL DEFAULT 'open', -- 'open', 'investigating', 'resolved', 'false_positive'
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMP WITH TIME ZONE,
    
    -- Context
    affected_assets TEXT[],
    source_ip INET,
    destination_ip INET,
    raw_data JSONB,
    
    -- AI Analysis
    ai_confidence DECIMAL(5,2), -- 0.00 to 100.00
    ai_analysis TEXT,
    false_positive_probability DECIMAL(5,2),
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_severity CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT valid_status CHECK (status IN ('open', 'investigating', 'resolved', 'false_positive'))
);

-- Security incidents (collections of related alerts)
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Incident details
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(100),
    
    -- Status & Timeline
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Impact assessment
    affected_systems TEXT[],
    business_impact TEXT,
    estimated_cost DECIMAL(15,2),
    
    -- Response
    response_plan TEXT,
    lessons_learned TEXT,
    
    -- Timeline
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    containment_at TIMESTAMP WITH TIME ZONE,
    eradication_at TIMESTAMP WITH TIME ZONE,
    recovery_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Link alerts to incidents
CREATE TABLE incident_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    
    -- Relationship metadata
    relationship_type VARCHAR(50) DEFAULT 'related', -- 'root_cause', 'related', 'consequence'
    added_by UUID REFERENCES users(id) ON DELETE SET NULL,
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(incident_id, alert_id)
);

-- System integrations
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Integration details
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL, -- 'wazuh', 'elasticsearch', 'aws', 'azure', 'gcp', etc.
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    
    -- Configuration
    configuration JSONB NOT NULL DEFAULT '{}', -- Encrypted sensitive data
    endpoint_url TEXT,
    api_version VARCHAR(50),
    
    -- Health & Sync
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_health_check TIMESTAMP WITH TIME ZONE,
    health_status VARCHAR(50) DEFAULT 'unknown', -- 'healthy', 'warning', 'critical', 'unknown'
    error_count INTEGER DEFAULT 0,
    last_error TEXT,
    
    -- Rate limiting
    rate_limit_per_minute INTEGER DEFAULT 60,
    current_minute_requests INTEGER DEFAULT 0,
    rate_limit_reset_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Metadata
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(tenant_id, name)
);

-- =============================================
-- Create Indexes
-- =============================================

-- Core tenant indexes
CREATE INDEX idx_tenants_subdomain ON tenants(subdomain);
CREATE INDEX idx_tenants_status ON tenants(status);
CREATE INDEX idx_tenants_plan ON tenants(plan);

-- User indexes
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_tenant_email ON users(tenant_id, email);
CREATE INDEX idx_users_status ON users(status);

-- API key indexes
CREATE INDEX idx_api_keys_tenant_id ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX idx_api_keys_status ON api_keys(status);

-- Billing indexes
CREATE INDEX idx_subscriptions_tenant_id ON subscriptions(tenant_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);
CREATE INDEX idx_usage_events_tenant_id ON usage_events(tenant_id);
CREATE INDEX idx_usage_events_timestamp ON usage_events(timestamp);
CREATE INDEX idx_usage_events_billing_month ON usage_events(billing_month);

-- Security data indexes
CREATE INDEX idx_alerts_tenant_id ON alerts(tenant_id);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);
CREATE INDEX idx_alerts_tenant_severity_created ON alerts(tenant_id, severity, created_at DESC);

CREATE INDEX idx_incidents_tenant_id ON incidents(tenant_id);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);

CREATE INDEX idx_integrations_tenant_id ON integrations(tenant_id);
CREATE INDEX idx_integrations_type ON integrations(type);
CREATE INDEX idx_integrations_status ON integrations(status);

-- =============================================
-- Create Triggers
-- =============================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at triggers
CREATE TRIGGER update_tenants_updated_at 
    BEFORE UPDATE ON tenants 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_keys_updated_at 
    BEFORE UPDATE ON api_keys 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alerts_updated_at 
    BEFORE UPDATE ON alerts 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_incidents_updated_at 
    BEFORE UPDATE ON incidents 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_integrations_updated_at 
    BEFORE UPDATE ON integrations 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================
-- Insert Initial Data
-- =============================================

-- Insert default subscription plans
INSERT INTO subscription_plans (id, name, description, price_cents, interval, limits, features) VALUES
('trial', 'Trial', 'Free trial with limited features', 0, 'month', 
 '{"events_per_day": 100, "integrations": 2, "users": 2, "storage_gb": 1, "api_calls_per_month": 1000}',
 '{"basic_alerts", "basic_integrations", "email_support"}'),
 
('starter', 'Starter', 'Perfect for small teams getting started with security operations', 49900, 'month', 
 '{"events_per_day": 1000, "integrations": 5, "users": 5, "storage_gb": 10, "api_calls_per_month": 10000}',
 '{"basic_alerts", "basic_integrations", "basic_reports", "email_support"}'),
 
('professional', 'Professional', 'Comprehensive security operations for growing organizations', 199900, 'month',
 '{"events_per_day": 50000, "integrations": 20, "users": 25, "storage_gb": 100, "api_calls_per_month": 100000}',
 '{"basic_alerts", "advanced_alerts", "basic_integrations", "premium_integrations", "basic_reports", "custom_reports", "ai_insights", "email_support", "phone_support"}'),
 
('enterprise', 'Enterprise', 'Enterprise-grade security operations with unlimited scale', NULL, 'month',
 '{"events_per_day": -1, "integrations": -1, "users": -1, "storage_gb": -1, "api_calls_per_month": -1}',
 '{"basic_alerts", "advanced_alerts", "custom_alerts", "basic_integrations", "premium_integrations", "custom_integrations", "basic_reports", "custom_reports", "advanced_reports", "ai_insights", "custom_ai_models", "white_label", "email_support", "phone_support", "dedicated_support", "sla_guarantees"}'); 