CREATE TABLE IF NOT EXISTS notification_operations_config (
 id boolean PRIMARY KEY DEFAULT true CHECK(id), config_encrypted text NOT NULL, updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS notification_channel_health (
 channel_id text PRIMARY KEY, config_revision timestamptz NOT NULL, state text NOT NULL DEFAULT 'closed', consecutive_failures integer NOT NULL DEFAULT 0,
 open_until timestamptz, next_allowed_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS notification_receipts (
 delivery_id text PRIMARY KEY REFERENCES notification_deliveries(id) ON DELETE CASCADE, channel_id text NOT NULL,
 config_revision timestamptz NOT NULL, channel_revision timestamptz NOT NULL, state text NOT NULL DEFAULT 'pending',
 provider_id text NOT NULL DEFAULT '', checks integer NOT NULL DEFAULT 0, next_check_at timestamptz,
 lease_token text, lease_until timestamptz, last_code text NOT NULL DEFAULT '', occurred_at timestamptz,
 fallback_checked boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notification_receipts_pending ON notification_receipts(next_check_at) WHERE state='pending';
CREATE TABLE IF NOT EXISTS notification_receipt_events (
 channel_id text NOT NULL, event_id text NOT NULL, delivery_id text NOT NULL, payload_hash text NOT NULL,
 state text NOT NULL, occurred_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(channel_id,event_id)
);
CREATE TABLE IF NOT EXISTS notification_fallbacks (
 parent_id text PRIMARY KEY, child_id text NOT NULL UNIQUE, config_revision timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
