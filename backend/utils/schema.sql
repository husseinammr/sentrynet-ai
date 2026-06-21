-- SentryNet AI — PostgreSQL Schema
CREATE TABLE IF NOT EXISTS traffic_logs (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip      INET NOT NULL,
    dst_ip      INET NOT NULL,
    src_port    INTEGER,
    dst_port    INTEGER,
    proto       VARCHAR(10),
    service     VARCHAR(50),
    bytes       BIGINT DEFAULT 0,
    packets     INTEGER DEFAULT 0,
    duration    FLOAT,
    conn_state  VARCHAR(10),
    anomaly_score FLOAT,
    is_anomaly  BOOLEAN DEFAULT FALSE,
    attack_type VARCHAR(50),
    severity    VARCHAR(20),
    country     VARCHAR(5),
    city        VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS alerts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip      INET NOT NULL,
    dst_ip      INET,
    dst_port    INTEGER,
    attack_type VARCHAR(50),
    severity    VARCHAR(20),
    anomaly_score FLOAT,
    message     TEXT,
    acknowledged BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS ip_stats (
    ip          INET PRIMARY KEY,
    total_bytes BIGINT DEFAULT 0,
    total_packets BIGINT DEFAULT 0,
    total_conns INTEGER DEFAULT 0,
    last_seen   TIMESTAMPTZ,
    is_malicious BOOLEAN DEFAULT FALSE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_traffic_ts     ON traffic_logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_src    ON traffic_logs (src_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_anomaly ON traffic_logs (is_anomaly) WHERE is_anomaly = TRUE;
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
