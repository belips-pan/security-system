-- unified_schema.sql
\c security_db;

-- Users table (ενιαίο για όλο το σύστημα)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    api_key VARCHAR(64) NULL
);

-- Agents table (ενιαίο με συμβατότητα)
CREATE TABLE IF NOT EXISTS agents (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(50) UNIQUE,  -- Για συμβατότητα με app.py
    agent_type VARCHAR(50) NOT NULL,
    location VARCHAR(100),
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NULL,
    api_key VARCHAR(64) NULL
);

-- Telemetry table (ενιαίο)
CREATE TABLE IF NOT EXISTS telemetry (
    id SERIAL PRIMARY KEY,
    agent_id INTEGER REFERENCES agents(id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    security_score INTEGER,
    metrics TEXT,
    anomalies TEXT
);

-- Alerts table (από app.py)
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP NULL
);

-- Audit logs (από app.py)
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    details TEXT
);

-- User sessions (από app.py)
CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(500) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Δημιουργία indexes για βελτιστοποίηση
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id);
CREATE INDEX IF NOT EXISTS idx_agents_agent_type ON agents(agent_type);
CREATE INDEX IF NOT EXISTS idx_agents_api_key ON agents(api_key);
CREATE INDEX IF NOT EXISTS idx_telemetry_agent_id ON telemetry(agent_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_resolved ON alerts(resolved);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token);

-- Security scans table for containerized scanning
CREATE TABLE IF NOT EXISTS security_scans (
    id SERIAL PRIMARY KEY,
    tool VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL,
    results JSONB,
    success BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for security scans
CREATE INDEX IF NOT EXISTS idx_security_scans_tool ON security_scans(tool);
CREATE INDEX IF NOT EXISTS idx_security_scans_target ON security_scans(target);
CREATE INDEX IF NOT EXISTS idx_security_scans_created_at ON security_scans(created_at);
CREATE INDEX IF NOT EXISTS idx_security_scans_success ON security_scans(success);

-- Add container_scanner to agents table for alert tracking
INSERT INTO agents (agent_id, agent_type, location, status, created_at, api_key) 
VALUES ('container_scanner', 'security_scanner', 'Security VM', 'active', CURRENT_TIMESTAMP, 'container_scan_123')
ON CONFLICT (agent_id) DO NOTHING;