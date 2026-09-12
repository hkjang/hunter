CREATE TABLE IF NOT EXISTS notification_channels(
 id text PRIMARY KEY,name text NOT NULL,type text NOT NULL CHECK(type IN('smtp','sms','kakao','webhook')),
 enabled boolean NOT NULL DEFAULT false,config_encrypted text NOT NULL,secret_encrypted text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS notification_rules(
 id text PRIMARY KEY,name text NOT NULL,channel_id text NOT NULL REFERENCES notification_channels(id),enabled boolean NOT NULL DEFAULT false,
 events jsonb NOT NULL,config_encrypted text NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS notification_events(
 id bigserial PRIMARY KEY,event_key text UNIQUE,event_type text NOT NULL,entity_id text NOT NULL,service_id text NOT NULL,
 source_revision timestamptz NOT NULL,metadata jsonb NOT NULL DEFAULT '{}',status text NOT NULL DEFAULT 'pending',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),processed_at timestamptz,rule_cursor text NOT NULL DEFAULT '');
ALTER TABLE notification_events ADD COLUMN IF NOT EXISTS rule_cursor text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS notification_events_pending ON notification_events(id) WHERE status='pending';
CREATE TABLE IF NOT EXISTS notification_deliveries(
 id text PRIMARY KEY,event_id bigint REFERENCES notification_events(id),event_type text NOT NULL,entity_id text NOT NULL DEFAULT '',service_id text NOT NULL DEFAULT '',
 rule_id text NOT NULL DEFAULT '',rule_name text NOT NULL DEFAULT '',rule_revision timestamptz,channel_id text NOT NULL,channel_name text NOT NULL,channel_type text NOT NULL,
 channel_revision timestamptz NOT NULL,payload_encrypted text NOT NULL,recipient_hash text NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN('queued','sending','sent','retry','failed','uncertain','cancelled')),
 attempts integer NOT NULL DEFAULT 0,max_attempts integer NOT NULL DEFAULT 3,available_at timestamptz NOT NULL DEFAULT now(),
 lease_token text NOT NULL DEFAULT '',lease_until timestamptz,cancel_requested boolean NOT NULL DEFAULT false,
 is_test boolean NOT NULL DEFAULT false,requested_by text NOT NULL DEFAULT '',credential_key_id text NOT NULL DEFAULT '',
 last_error text NOT NULL DEFAULT '',provider_id text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),sent_at timestamptz,
 UNIQUE(event_id,rule_id,recipient_hash));
CREATE INDEX IF NOT EXISTS notification_deliveries_ready ON notification_deliveries(available_at,created_at) WHERE status IN('queued','retry');
CREATE INDEX IF NOT EXISTS notification_deliveries_history ON notification_deliveries(created_at DESC,id);
CREATE TABLE IF NOT EXISTS notification_attempts(
 id bigserial PRIMARY KEY,delivery_id text NOT NULL REFERENCES notification_deliveries(id),attempt integer NOT NULL,status text NOT NULL,
 code text NOT NULL DEFAULT '',detail text NOT NULL DEFAULT '',provider_id text NOT NULL DEFAULT '',started_at timestamptz NOT NULL DEFAULT now(),finished_at timestamptz,
 UNIQUE(delivery_id,attempt));
CREATE OR REPLACE FUNCTION hunter_notification_capture() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE event_name text; meta jsonb;
BEGIN
 IF NEW.kind='findings' THEN
  IF TG_OP='INSERT' THEN event_name:='finding.created';
  ELSIF (NEW.data->'title',NEW.data->'severity',NEW.data->'status',NEW.data->'assignee',NEW.data->'due_date',NEW.data->'cve',NEW.data->'component') IS DISTINCT FROM
        (OLD.data->'title',OLD.data->'severity',OLD.data->'status',OLD.data->'assignee',OLD.data->'due_date',OLD.data->'cve',OLD.data->'component') THEN event_name:='finding.updated';
  END IF;
 ELSIF NEW.kind='scans' AND (TG_OP='INSERT' OR NEW.data->>'status' IS DISTINCT FROM OLD.data->>'status') THEN
  IF NEW.data->>'status'='completed' THEN event_name:='scan.completed';
  ELSIF NEW.data->>'status' IN('failed','inconclusive') THEN event_name:='scan.failed'; END IF;
 ELSIF NEW.kind='approvals' AND NEW.data->>'status'='pending' AND (TG_OP='INSERT' OR OLD.data->>'status' IS DISTINCT FROM 'pending') THEN event_name:='approval.pending';
 END IF;
 IF event_name IS NOT NULL AND EXISTS(SELECT 1 FROM notification_rules WHERE enabled AND events ? event_name) THEN
  -- No titles, evidence, recipient addresses, credentials or raw source payloads.
  meta:=jsonb_build_object('status',CASE WHEN NEW.data->>'status' IN('candidate','confirmed','in_progress','retest','inconclusive','resolved','accepted','false_positive','completed','failed','pending') THEN NEW.data->>'status' ELSE '' END,
                          'severity',CASE WHEN NEW.data->>'severity' IN('critical','high','medium','low','info') THEN NEW.data->>'severity' ELSE '' END);
  INSERT INTO notification_events(event_type,entity_id,service_id,source_revision,metadata)
  VALUES(event_name,NEW.id,coalesce(NEW.data->>'service_id',''),NEW.updated_at,meta);
 END IF;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS hunter_notification_capture ON resources;
CREATE TRIGGER hunter_notification_capture AFTER INSERT OR UPDATE ON resources FOR EACH ROW EXECUTE FUNCTION hunter_notification_capture();
