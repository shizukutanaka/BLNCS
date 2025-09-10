-- MIGRATION_START
-- Version: 001
-- Name: Initial BLNCS Schema
-- Description: Create initial database schema for BLNCS Lightning Network management
-- Type: schema
-- Author: blncs
-- Dependencies: 
-- MIGRATION_END

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Nodes table
CREATE TABLE nodes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alias VARCHAR(255) NOT NULL,
    public_key VARCHAR(66) UNIQUE NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL DEFAULT 9735,
    is_active BOOLEAN DEFAULT true,
    configuration JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Channels table
CREATE TABLE channels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    channel_id VARCHAR(20) UNIQUE NOT NULL,
    short_channel_id VARCHAR(20),
    peer_public_key VARCHAR(66) NOT NULL,
    capacity_sat BIGINT NOT NULL,
    local_balance_sat BIGINT DEFAULT 0,
    remote_balance_sat BIGINT DEFAULT 0,
    fee_base_msat BIGINT DEFAULT 1000,
    fee_rate_ppm INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT true,
    is_private BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Channel events table for history tracking
CREATE TABLE channel_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    event_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Invoices table
CREATE TABLE invoices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    payment_hash VARCHAR(64) UNIQUE NOT NULL,
    payment_request TEXT NOT NULL,
    amount_sat BIGINT,
    description TEXT,
    expiry_timestamp TIMESTAMP WITH TIME ZONE,
    status VARCHAR(20) DEFAULT 'pending',
    settled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Payments table
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    payment_hash VARCHAR(64) NOT NULL,
    payment_preimage VARCHAR(64),
    destination VARCHAR(66) NOT NULL,
    amount_sat BIGINT NOT NULL,
    fee_sat BIGINT DEFAULT 0,
    status VARCHAR(20) DEFAULT 'pending',
    failure_reason TEXT,
    payment_request TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Fee policies table
CREATE TABLE fee_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    base_fee_msat BIGINT NOT NULL,
    fee_rate_ppm INTEGER NOT NULL,
    time_lock_delta INTEGER DEFAULT 40,
    min_htlc_msat BIGINT DEFAULT 1000,
    max_htlc_msat BIGINT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(node_id, channel_id)
);

-- Metrics snapshots table
CREATE TABLE metrics_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC,
    metric_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User sessions table for authentication
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE,
    user_role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    permissions JSONB DEFAULT '[]',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255),
    session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    metadata JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_nodes_public_key ON nodes(public_key);
CREATE INDEX idx_nodes_active ON nodes(is_active);
CREATE INDEX idx_channels_node_id ON channels(node_id);
CREATE INDEX idx_channels_channel_id ON channels(channel_id);
CREATE INDEX idx_channels_active ON channels(is_active);
CREATE INDEX idx_channel_events_channel_id ON channel_events(channel_id);
CREATE INDEX idx_channel_events_created_at ON channel_events(created_at);
CREATE INDEX idx_invoices_node_id ON invoices(node_id);
CREATE INDEX idx_invoices_payment_hash ON invoices(payment_hash);
CREATE INDEX idx_invoices_status ON invoices(status);
CREATE INDEX idx_payments_node_id ON payments(node_id);
CREATE INDEX idx_payments_payment_hash ON payments(payment_hash);
CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_fee_policies_node_channel ON fee_policies(node_id, channel_id);
CREATE INDEX idx_metrics_snapshots_node_id ON metrics_snapshots(node_id);
CREATE INDEX idx_metrics_snapshots_channel_id ON metrics_snapshots(channel_id);
CREATE INDEX idx_metrics_snapshots_created_at ON metrics_snapshots(created_at);
CREATE INDEX idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add updated_at triggers
CREATE TRIGGER update_nodes_updated_at BEFORE UPDATE ON nodes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_channels_updated_at BEFORE UPDATE ON channels
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_fee_policies_updated_at BEFORE UPDATE ON fee_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ROLLBACK
-- Drop all tables and objects created by this migration

DROP TRIGGER IF EXISTS update_fee_policies_updated_at ON fee_policies;
DROP TRIGGER IF EXISTS update_channels_updated_at ON channels;
DROP TRIGGER IF EXISTS update_nodes_updated_at ON nodes;

DROP FUNCTION IF EXISTS update_updated_at_column();

DROP INDEX IF EXISTS idx_audit_logs_action;
DROP INDEX IF EXISTS idx_audit_logs_created_at;
DROP INDEX IF EXISTS idx_audit_logs_user_id;
DROP INDEX IF EXISTS idx_user_sessions_expires_at;
DROP INDEX IF EXISTS idx_user_sessions_user_id;
DROP INDEX IF EXISTS idx_user_sessions_token;
DROP INDEX IF EXISTS idx_metrics_snapshots_created_at;
DROP INDEX IF EXISTS idx_metrics_snapshots_channel_id;
DROP INDEX IF EXISTS idx_metrics_snapshots_node_id;
DROP INDEX IF EXISTS idx_fee_policies_node_channel;
DROP INDEX IF EXISTS idx_payments_status;
DROP INDEX IF EXISTS idx_payments_payment_hash;
DROP INDEX IF EXISTS idx_payments_node_id;
DROP INDEX IF EXISTS idx_invoices_status;
DROP INDEX IF EXISTS idx_invoices_payment_hash;
DROP INDEX IF EXISTS idx_invoices_node_id;
DROP INDEX IF EXISTS idx_channel_events_created_at;
DROP INDEX IF EXISTS idx_channel_events_channel_id;
DROP INDEX IF EXISTS idx_channels_active;
DROP INDEX IF EXISTS idx_channels_channel_id;
DROP INDEX IF EXISTS idx_channels_node_id;
DROP INDEX IF EXISTS idx_nodes_active;
DROP INDEX IF EXISTS idx_nodes_public_key;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS metrics_snapshots;
DROP TABLE IF EXISTS fee_policies;
DROP TABLE IF EXISTS payments;
DROP TABLE IF EXISTS invoices;
DROP TABLE IF EXISTS channel_events;
DROP TABLE IF EXISTS channels;
DROP TABLE IF EXISTS nodes;

DROP EXTENSION IF EXISTS "btree_gin";
DROP EXTENSION IF EXISTS "uuid-ossp";