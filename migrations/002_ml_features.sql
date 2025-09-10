-- MIGRATION_START
-- Version: 002
-- Name: ML Features and Analytics
-- Description: Add tables and structures for machine learning fee optimization and analytics
-- Type: schema
-- Author: blncs
-- Dependencies: 001
-- MIGRATION_END

-- Channel metrics history for ML training
CREATE TABLE channel_metrics_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    local_balance_sat BIGINT NOT NULL,
    remote_balance_sat BIGINT NOT NULL,
    capacity_sat BIGINT NOT NULL,
    fee_base_msat BIGINT NOT NULL,
    fee_rate_ppm INTEGER NOT NULL,
    routing_revenue_msat BIGINT DEFAULT 0,
    routing_volume_msat BIGINT DEFAULT 0,
    routing_count INTEGER DEFAULT 0,
    failed_routing_count INTEGER DEFAULT 0,
    uptime_percentage NUMERIC(5,2) DEFAULT 100.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Fee optimization results
CREATE TABLE fee_optimization_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    optimization_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    current_fee_base_msat BIGINT NOT NULL,
    current_fee_rate_ppm INTEGER NOT NULL,
    recommended_fee_base_msat BIGINT NOT NULL,
    recommended_fee_rate_ppm INTEGER NOT NULL,
    predicted_revenue_increase NUMERIC(10,2),
    predicted_volume_increase NUMERIC(10,2),
    confidence_score NUMERIC(5,4),
    model_version VARCHAR(50),
    features_used JSONB DEFAULT '{}',
    applied_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ML model training history
CREATE TABLE ml_model_training (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_type VARCHAR(100) NOT NULL,
    model_version VARCHAR(50) NOT NULL,
    training_data_start TIMESTAMP WITH TIME ZONE NOT NULL,
    training_data_end TIMESTAMP WITH TIME ZONE NOT NULL,
    training_samples INTEGER NOT NULL,
    validation_score NUMERIC(10,6),
    feature_importance JSONB DEFAULT '{}',
    hyperparameters JSONB DEFAULT '{}',
    training_duration_seconds INTEGER,
    model_artifacts JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Channel rebalancing history
CREATE TABLE rebalancing_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    source_channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    target_channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    amount_sat BIGINT NOT NULL,
    fee_sat BIGINT NOT NULL,
    status VARCHAR(50) NOT NULL,
    strategy VARCHAR(100),
    duration_seconds INTEGER,
    error_message TEXT,
    metrics_before JSONB DEFAULT '{}',
    metrics_after JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Performance alerts
CREATE TABLE performance_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
    channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',
    title VARCHAR(255) NOT NULL,
    description TEXT,
    threshold_value NUMERIC,
    actual_value NUMERIC,
    metadata JSONB DEFAULT '{}',
    is_acknowledged BOOLEAN DEFAULT false,
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Network topology snapshots for analysis
CREATE TABLE network_topology_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapshot_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    total_nodes INTEGER NOT NULL,
    total_channels INTEGER NOT NULL,
    total_capacity_sat BIGINT NOT NULL,
    average_channel_capacity_sat BIGINT,
    network_diameter INTEGER,
    clustering_coefficient NUMERIC(10,8),
    betweenness_centrality JSONB DEFAULT '{}',
    degree_distribution JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Liquidity flow analysis
CREATE TABLE liquidity_flows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    flow_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    flow_direction VARCHAR(10) NOT NULL, -- 'inbound' or 'outbound'
    amount_msat BIGINT NOT NULL,
    fee_msat BIGINT DEFAULT 0,
    hop_count INTEGER,
    source_peer VARCHAR(66),
    destination_peer VARCHAR(66),
    payment_hash VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for ML and analytics performance
CREATE INDEX idx_channel_metrics_history_channel_id ON channel_metrics_history(channel_id);
CREATE INDEX idx_channel_metrics_history_timestamp ON channel_metrics_history(timestamp);
CREATE INDEX idx_channel_metrics_history_channel_timestamp ON channel_metrics_history(channel_id, timestamp);

CREATE INDEX idx_fee_optimization_results_channel_id ON fee_optimization_results(channel_id);
CREATE INDEX idx_fee_optimization_results_timestamp ON fee_optimization_results(optimization_timestamp);
CREATE INDEX idx_fee_optimization_results_applied ON fee_optimization_results(applied_at) WHERE applied_at IS NOT NULL;

CREATE INDEX idx_ml_model_training_type_version ON ml_model_training(model_type, model_version);
CREATE INDEX idx_ml_model_training_created_at ON ml_model_training(created_at);

CREATE INDEX idx_rebalancing_history_node_id ON rebalancing_history(node_id);
CREATE INDEX idx_rebalancing_history_created_at ON rebalancing_history(created_at);
CREATE INDEX idx_rebalancing_history_status ON rebalancing_history(status);

CREATE INDEX idx_performance_alerts_node_id ON performance_alerts(node_id);
CREATE INDEX idx_performance_alerts_channel_id ON performance_alerts(channel_id);
CREATE INDEX idx_performance_alerts_type ON performance_alerts(alert_type);
CREATE INDEX idx_performance_alerts_severity ON performance_alerts(severity);
CREATE INDEX idx_performance_alerts_unresolved ON performance_alerts(created_at) WHERE resolved_at IS NULL;

CREATE INDEX idx_network_topology_snapshots_timestamp ON network_topology_snapshots(snapshot_timestamp);

CREATE INDEX idx_liquidity_flows_channel_id ON liquidity_flows(channel_id);
CREATE INDEX idx_liquidity_flows_timestamp ON liquidity_flows(flow_timestamp);
CREATE INDEX idx_liquidity_flows_direction ON liquidity_flows(flow_direction);
CREATE INDEX idx_liquidity_flows_payment_hash ON liquidity_flows(payment_hash);

-- Create a function to calculate channel health score
CREATE OR REPLACE FUNCTION calculate_channel_health_score(
    p_channel_id UUID,
    p_days_back INTEGER DEFAULT 30
) RETURNS NUMERIC AS $$
DECLARE
    health_score NUMERIC := 0;
    routing_success_rate NUMERIC;
    uptime_avg NUMERIC;
    revenue_trend NUMERIC;
BEGIN
    -- Calculate routing success rate
    SELECT 
        CASE 
            WHEN (routing_count + failed_routing_count) = 0 THEN 1.0
            ELSE routing_count::NUMERIC / (routing_count + failed_routing_count)
        END INTO routing_success_rate
    FROM channel_metrics_history 
    WHERE channel_id = p_channel_id 
    AND timestamp > NOW() - INTERVAL '1 day' * p_days_back
    ORDER BY timestamp DESC 
    LIMIT 1;
    
    -- Calculate average uptime
    SELECT AVG(uptime_percentage) / 100.0 INTO uptime_avg
    FROM channel_metrics_history
    WHERE channel_id = p_channel_id 
    AND timestamp > NOW() - INTERVAL '1 day' * p_days_back;
    
    -- Calculate revenue trend (simplified)
    SELECT 
        CASE 
            WHEN LAG(routing_revenue_msat) OVER (ORDER BY timestamp) IS NULL THEN 0
            ELSE (routing_revenue_msat - LAG(routing_revenue_msat) OVER (ORDER BY timestamp))::NUMERIC / 
                 GREATEST(LAG(routing_revenue_msat) OVER (ORDER BY timestamp), 1)
        END INTO revenue_trend
    FROM channel_metrics_history
    WHERE channel_id = p_channel_id 
    AND timestamp > NOW() - INTERVAL '1 day' * p_days_back
    ORDER BY timestamp DESC
    LIMIT 1;
    
    -- Combine metrics into health score (0-1 scale)
    health_score := (
        COALESCE(routing_success_rate, 0) * 0.4 +
        COALESCE(uptime_avg, 0) * 0.3 +
        GREATEST(LEAST(COALESCE(revenue_trend, 0), 1), 0) * 0.3
    );
    
    RETURN health_score;
END;
$$ LANGUAGE plpgsql;

-- Create materialized view for channel statistics
CREATE MATERIALIZED VIEW channel_statistics_mv AS
SELECT 
    c.id as channel_id,
    c.channel_id,
    c.node_id,
    c.capacity_sat,
    c.local_balance_sat,
    c.remote_balance_sat,
    c.fee_base_msat,
    c.fee_rate_ppm,
    COALESCE(recent_metrics.avg_revenue_30d, 0) as avg_revenue_30d,
    COALESCE(recent_metrics.avg_volume_30d, 0) as avg_volume_30d,
    COALESCE(recent_metrics.routing_count_30d, 0) as routing_count_30d,
    COALESCE(recent_metrics.avg_uptime_30d, 100) as avg_uptime_30d,
    calculate_channel_health_score(c.id, 30) as health_score_30d,
    c.updated_at
FROM channels c
LEFT JOIN (
    SELECT 
        channel_id,
        AVG(routing_revenue_msat) as avg_revenue_30d,
        AVG(routing_volume_msat) as avg_volume_30d,
        AVG(routing_count) as routing_count_30d,
        AVG(uptime_percentage) as avg_uptime_30d
    FROM channel_metrics_history
    WHERE timestamp > NOW() - INTERVAL '30 days'
    GROUP BY channel_id
) recent_metrics ON c.id = recent_metrics.channel_id
WHERE c.is_active = true;

-- Create unique index on materialized view
CREATE UNIQUE INDEX idx_channel_statistics_mv_channel_id ON channel_statistics_mv(channel_id);

-- ROLLBACK
-- Drop all objects created by this migration

DROP MATERIALIZED VIEW IF EXISTS channel_statistics_mv;
DROP FUNCTION IF EXISTS calculate_channel_health_score(UUID, INTEGER);

DROP INDEX IF EXISTS idx_liquidity_flows_payment_hash;
DROP INDEX IF EXISTS idx_liquidity_flows_direction;
DROP INDEX IF EXISTS idx_liquidity_flows_timestamp;
DROP INDEX IF EXISTS idx_liquidity_flows_channel_id;
DROP INDEX IF EXISTS idx_network_topology_snapshots_timestamp;
DROP INDEX IF EXISTS idx_performance_alerts_unresolved;
DROP INDEX IF EXISTS idx_performance_alerts_severity;
DROP INDEX IF EXISTS idx_performance_alerts_type;
DROP INDEX IF EXISTS idx_performance_alerts_channel_id;
DROP INDEX IF EXISTS idx_performance_alerts_node_id;
DROP INDEX IF EXISTS idx_rebalancing_history_status;
DROP INDEX IF EXISTS idx_rebalancing_history_created_at;
DROP INDEX IF EXISTS idx_rebalancing_history_node_id;
DROP INDEX IF EXISTS idx_ml_model_training_created_at;
DROP INDEX IF EXISTS idx_ml_model_training_type_version;
DROP INDEX IF EXISTS idx_fee_optimization_results_applied;
DROP INDEX IF EXISTS idx_fee_optimization_results_timestamp;
DROP INDEX IF EXISTS idx_fee_optimization_results_channel_id;
DROP INDEX IF EXISTS idx_channel_metrics_history_channel_timestamp;
DROP INDEX IF EXISTS idx_channel_metrics_history_timestamp;
DROP INDEX IF EXISTS idx_channel_metrics_history_channel_id;

DROP TABLE IF EXISTS liquidity_flows;
DROP TABLE IF EXISTS network_topology_snapshots;
DROP TABLE IF EXISTS performance_alerts;
DROP TABLE IF EXISTS rebalancing_history;
DROP TABLE IF EXISTS ml_model_training;
DROP TABLE IF EXISTS fee_optimization_results;
DROP TABLE IF EXISTS channel_metrics_history;