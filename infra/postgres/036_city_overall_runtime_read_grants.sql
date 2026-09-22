-- The city-overall snapshot is published by the market refresh role and read
-- by the FastAPI runtime role. Keep the runtime permission read-only.
GRANT SELECT ON TABLE city_overall_opportunity_snapshot TO ipintel;
GRANT SELECT ON TABLE city_overall_opportunity TO ipintel;
