-- Phase 022: internal sales ground truth.  PostgreSQL is the source of truth;
-- the summary table is intentionally not written by this migration.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS rfq_intake (
  rfq_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  geo_unit_id TEXT NOT NULL REFERENCES geo_unit(geo_unit_id),
  product_id TEXT NOT NULL REFERENCES product_track(product_id),
  customer_name TEXT NOT NULL,
  customer_company TEXT,
  stage TEXT NOT NULL CHECK (stage IN ('rfq','quoted','negotiating','won','lost')),
  quoted_at TIMESTAMPTZ,
  deal_value_original NUMERIC(14,2),
  deal_value_currency CHAR(3),
  fx_rate_used NUMERIC(18,8),
  fx_rate_date DATE,
  deal_value_usd NUMERIC(14,2) GENERATED ALWAYS AS (
    CASE WHEN deal_value_original IS NULL OR fx_rate_used IS NULL THEN NULL
         ELSE round(deal_value_original * fx_rate_used, 2) END
  ) STORED,
  won_at TIMESTAMPTZ,
  lost_reason TEXT,
  is_repeat_customer BOOLEAN NOT NULL DEFAULT FALSE,
  sales_rep TEXT,
  source_channel TEXT,
  source_system TEXT NOT NULL DEFAULT 'manual_csv',
  source_record_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  notes TEXT,
  CONSTRAINT rfq_deal_value_non_negative CHECK (deal_value_original IS NULL OR deal_value_original >= 0),
  CONSTRAINT rfq_currency_format CHECK (deal_value_currency IS NULL OR deal_value_currency ~ '^[A-Z]{3}$'),
  CONSTRAINT rfq_fx_positive CHECK (fx_rate_used IS NULL OR fx_rate_used > 0),
  CONSTRAINT rfq_fx_complete CHECK (
    deal_value_original IS NULL
    OR (deal_value_currency IS NOT NULL AND fx_rate_used IS NOT NULL AND fx_rate_date IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rfq_source_identity
  ON rfq_intake(source_system, source_record_id)
  WHERE source_record_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rfq_geo_product ON rfq_intake(geo_unit_id, product_id);
CREATE INDEX IF NOT EXISTS idx_rfq_stage ON rfq_intake(stage);
CREATE INDEX IF NOT EXISTS idx_rfq_created_at ON rfq_intake(created_at);

CREATE OR REPLACE VIEW rfq_summary_by_geo_product AS
SELECT geo_unit_id, product_id,
       COUNT(*) FILTER (WHERE created_at > now() - INTERVAL '12 months') AS rfq_count_12m,
       COUNT(*) FILTER (WHERE stage IN ('quoted','negotiating','won','lost')) AS quoted_count,
       COUNT(*) FILTER (WHERE stage = 'won') AS won_count,
       CASE WHEN COUNT(*) FILTER (WHERE stage IN ('won','lost')) > 0
            THEN COUNT(*) FILTER (WHERE stage = 'won')::NUMERIC /
                 COUNT(*) FILTER (WHERE stage IN ('won','lost'))
            ELSE NULL END AS win_rate,
       AVG(deal_value_usd) FILTER (WHERE stage = 'won') AS avg_deal_value_usd,
       BOOL_OR(is_repeat_customer) AS has_repeat_customer,
       MAX(created_at) AS last_activity_at
FROM rfq_intake
GROUP BY geo_unit_id, product_id;
