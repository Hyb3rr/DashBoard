-- Remove the behavior-events TTL introduced by 008 until its retention
-- contract is proven against all session/evidence consumers.
-- http_events retention remains governed by 008's separately audited
-- 90d-current + 90d-previous Country Demand horizon.
ALTER TABLE ipintel.behavior_events REMOVE TTL;
