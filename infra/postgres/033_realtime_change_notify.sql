-- LISTEN/NOTIFY is only a cross-process wake-up signal. ip_change_log remains
-- the durable source of truth for cursor replay and reset handling.
CREATE OR REPLACE FUNCTION notify_ip_change_log() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('sentinel_ip_changes', NEW.seq::text);
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS ip_change_log_realtime_notify ON ip_change_log;
CREATE TRIGGER ip_change_log_realtime_notify
AFTER INSERT ON ip_change_log
FOR EACH ROW EXECUTE FUNCTION notify_ip_change_log();
