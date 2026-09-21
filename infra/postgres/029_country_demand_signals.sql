CREATE TABLE IF NOT EXISTS country_demand_snapshot (
    snapshot_id UUID PRIMARY KEY,
    period TEXT NOT NULL CHECK (period IN ('7d','30d','90d')),
    min_sample_threshold INTEGER NOT NULL CHECK (min_sample_threshold > 0),
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','published','failed')),
    country_count INTEGER NOT NULL DEFAULT 0,
    completed_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS country_demand_signal (
    snapshot_id UUID NOT NULL REFERENCES country_demand_snapshot(snapshot_id) ON DELETE CASCADE,
    country_code TEXT NOT NULL,
    payload JSONB NOT NULL,
    qualified_sessions INTEGER NOT NULL CHECK (qualified_sessions >= 0),
    signal TEXT NOT NULL,
    confidence TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, country_code)
);

CREATE INDEX IF NOT EXISTS country_demand_snapshot_latest_idx
    ON country_demand_snapshot (period, status, completed_at DESC);
