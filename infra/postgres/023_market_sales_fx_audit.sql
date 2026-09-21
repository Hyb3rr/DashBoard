-- Clarify historical FX provenance without mutating the applied 022 checksum.

ALTER TABLE rfq_intake ADD COLUMN IF NOT EXISTS fx_rate_provider TEXT;
ALTER TABLE rfq_intake ADD CONSTRAINT rfq_deal_value_usd_non_negative
  CHECK (deal_value_usd IS NULL OR deal_value_usd >= 0);
ALTER TABLE rfq_intake ADD CONSTRAINT rfq_fx_provider_complete CHECK (
  deal_value_original IS NULL OR
  (deal_value_currency = 'USD' AND fx_rate_used = 1 AND fx_rate_provider = 'identity_usd') OR
  (fx_rate_used IS NOT NULL AND fx_rate_date IS NOT NULL AND fx_rate_provider IS NOT NULL)
);
