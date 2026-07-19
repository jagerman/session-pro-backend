-- Baseline Session Pro backend schema. This is the launch schema; post-launch changes go in new,
-- ascii-later NNN_* migrations (never edit this file once it has shipped to a database with real
-- data). Tables are ordered so foreign-key targets exist before their referrers.

-- The user identity anchor. master_pkey (the account's Ed25519 public key) lives ONLY here; everything
-- else references a user by the surrogate `id`.
CREATE TABLE IF NOT EXISTS users (
    id                           BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    master_pkey                  BYTEA       NOT NULL UNIQUE CHECK (octet_length(master_pkey) = 32),
    gen_index                    INTEGER     NOT NULL,
    expires_at                   TIMESTAMPTZ NOT NULL,
    grace_period                 INTERVAL    NOT NULL,
    auto_renewing                BOOLEAN     NOT NULL DEFAULT FALSE,
    -- NULL = no refund requested (was a BIGINT DEFAULT 0 sentinel — 0 is a valid instant).
    refund_requested_at          TIMESTAMPTZ,
    google_obfuscated_account_id BYTEA       CHECK (octet_length(google_obfuscated_account_id) = 32),
    -- NULL = not an Apple account (was a TEXT DEFAULT '' sentinel).
    apple_app_account_token      TEXT
);

-- Enumerated value sets. The code string is the canonical value used in Python, on the wire, and in the
-- signed request hashes, so it is the PRIMARY KEY (no surrogate id): children FK the code directly, and
-- a new provider/plan is an additive INSERT (never an ALTER TYPE). Seeds are idempotent so re-applying
-- the baseline against a pre-ledger database is a no-op.
CREATE TABLE IF NOT EXISTS payment_providers (
    code TEXT PRIMARY KEY
);
INSERT INTO payment_providers (code) VALUES ('google_play'), ('app_store'), ('rangeproof')
    ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS pro_plans (
    code TEXT PRIMARY KEY
);
INSERT INTO pro_plans (code) VALUES ('1m'), ('3m'), ('1y')
    ON CONFLICT (code) DO NOTHING;

-- A payment is ingested UNREDEEMED (user_id NULL) before any identity is attached; at redemption the
-- master_pkey becomes known, its users row is upserted, and user_id is backfilled here.
CREATE TABLE IF NOT EXISTS payments (
    id                                BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                           BIGINT  REFERENCES users(id),   -- NULL until redeemed
    -- No `status` column: it is derived from the timestamps below (redeemed/revoked/expiry) — see
    -- backend.derive_payment_status. redeemed_unix_ts_ms IS NULL = unredeemed; revoked_unix_ts_ms
    -- IS NOT NULL = revoked; now >= expiry_unix_ts_ms = expired.
    plan                              TEXT        NOT     NULL REFERENCES pro_plans(code),
    payment_provider                  TEXT        NOT     NULL REFERENCES payment_providers(code),
    auto_renewing                     BOOLEAN     NOT     NULL DEFAULT FALSE,
    -- When this payment (billing cycle) was purchased at the provider (Apple purchaseDate / Google
    -- event ts). NOT when we witnessed it.
    purchased_at                      TIMESTAMPTZ NOT     NULL,

    redeemed_at                       TIMESTAMPTZ,                    -- NULL until redeemed
    expires_at                        TIMESTAMPTZ NOT     NULL,
    grace_period                      INTERVAL,
    platform_refund_expires_at        TIMESTAMPTZ NOT     NULL,
    revoked_at                        TIMESTAMPTZ,                    -- NOT NULL once revoked

    apple_original_tx_id              TEXT,
    apple_tx_id                       TEXT,
    apple_web_line_order_tx_id        TEXT,
    google_payment_token              TEXT,
    google_order_id                   TEXT,
    rangeproof_order_id               TEXT,

    -- NULL = no refund requested (was a BIGINT DEFAULT 0 sentinel — 0 is a valid instant).
    refund_requested_at               TIMESTAMPTZ,
    google_obfuscated_account_id      BYTEA       CHECK (octet_length(google_obfuscated_account_id) = 32),
    -- NULL = not an Apple payment (was a TEXT DEFAULT '' sentinel).
    apple_app_account_token           TEXT
);

-- Indexes (item 13): partial where the column is NULL for rows it doesn't apply to (one provider's ids
-- per payment; user_id NULL until redeemed) — the `= <value>` lookups never target NULL. google_order_id
-- and apple_web_line_order_tx_id are only ever secondary AND-filters, so they need no index of their own.
CREATE INDEX IF NOT EXISTS payments_user_id_idx              ON payments (user_id)              WHERE user_id              IS NOT NULL;  -- owner lookups + PAYMENTS_FROM join
CREATE INDEX IF NOT EXISTS payments_google_payment_token_idx ON payments (google_payment_token) WHERE google_payment_token IS NOT NULL;  -- provider tx-id lookup
CREATE INDEX IF NOT EXISTS payments_apple_original_tx_id_idx ON payments (apple_original_tx_id)  WHERE apple_original_tx_id  IS NOT NULL;  -- provider tx-id lookup
CREATE INDEX IF NOT EXISTS payments_apple_tx_id_idx          ON payments (apple_tx_id)           WHERE apple_tx_id          IS NOT NULL;  -- provider tx-id lookup
CREATE INDEX IF NOT EXISTS payments_rangeproof_order_id_idx  ON payments (rangeproof_order_id)   WHERE rangeproof_order_id  IS NOT NULL;  -- provider tx-id lookup
CREATE INDEX IF NOT EXISTS payments_expires_at_idx           ON payments (expires_at);                                                    -- daily expiry sweep

CREATE TABLE IF NOT EXISTS revocations (
    gen_index            INTEGER     PRIMARY KEY NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL,  -- When the revocation was created (used to calculate effective time)
    expires_at           TIMESTAMPTZ NOT NULL
);
-- The daily sweep prunes revocations by expiry (item 13).
CREATE INDEX IF NOT EXISTS revocations_expires_at_idx ON revocations (expires_at);

CREATE TABLE IF NOT EXISTS runtime (
    gen_index                                INTEGER NOT NULL DEFAULT 0,
    gen_index_salt                           BYTEA   NOT NULL CHECK   (octet_length(gen_index_salt) = 16),
    apple_notification_checkpoint_unix_ts_ms BIGINT  NOT NULL DEFAULT 0,
    revocation_ticket                        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS apple_notification_uuid_history (
    uuid              TEXT PRIMARY KEY,
    expires_at        TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS google_notification_history (
    message_id        BIGINT NOT NULL,
    handled           BOOLEAN NOT NULL DEFAULT FALSE,
    payload           TEXT,
    expires_at        TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS user_errors (
    payment_id         TEXT NOT NULL,
    payment_provider   TEXT NOT NULL REFERENCES payment_providers(code),
    at                 TIMESTAMPTZ NOT NULL,
    UNIQUE(payment_id, payment_provider)
);

-- Trigger: bump runtime.revocation_ticket whenever the revocations set changes (client cache-gen stamp).
CREATE OR REPLACE FUNCTION increment_revocation_ticket()
RETURNS TRIGGER AS '
BEGIN
    UPDATE runtime SET revocation_ticket = revocation_ticket + 1;
    RETURN NEW;
END;
' LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS increment_revocation_ticket_after_insert ON revocations;
CREATE TRIGGER increment_revocation_ticket_after_insert
    AFTER INSERT ON revocations
    FOR EACH ROW
    EXECUTE FUNCTION increment_revocation_ticket();

DROP TRIGGER IF EXISTS increment_revocation_ticket_after_delete ON revocations;
CREATE TRIGGER increment_revocation_ticket_after_delete
    AFTER DELETE ON revocations
    FOR EACH ROW
    EXECUTE FUNCTION increment_revocation_ticket();
