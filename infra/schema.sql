BEGIN;

CREATE TABLE IF NOT EXISTS queues (
  id text PRIMARY KEY,
  send_token_hash text NOT NULL,
  receive_token_hash text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS queued_messages (
  id text PRIMARY KEY,
  queue_id text NOT NULL REFERENCES queues(id) ON DELETE CASCADE,
  client_message_id text,
  envelope_version integer NOT NULL DEFAULT 1,
  ciphertext text NOT NULL,
  nonce text,
  byte_size integer NOT NULL CHECK (byte_size > 0),
  delivery_state text NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS hourly_metrics (
  id text PRIMARY KEY,
  bucket_at timestamptz NOT NULL,
  metric_hash text NOT NULL,
  enqueued_count integer NOT NULL DEFAULT 0,
  delivered_count integer NOT NULL DEFAULT 0,
  expired_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (bucket_at, metric_hash)
);

CREATE TABLE IF NOT EXISTS reports (
  id text PRIMARY KEY,
  queue_id text,
  reason text NOT NULL CHECK (reason IN ('minor_safety', 'non_consensual', 'fraud', 'spam', 'harassment', 'illegal_content', 'other')),
  public_context_ref text,
  approximate_event_at timestamptz,
  evidence_ciphertext_hash text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS queued_messages_queue_idx ON queued_messages (queue_id, created_at);
CREATE INDEX IF NOT EXISTS queued_messages_expires_idx ON queued_messages (expires_at);
CREATE INDEX IF NOT EXISTS hourly_metrics_bucket_idx ON hourly_metrics (bucket_at);

COMMIT;

