CREATE TABLE IF NOT EXISTS payments (
    id                                SERIAL  PRIMARY KEY,
    master_pkey                       BYTEA   CHECK   (octet_length(master_pkey) = 32),
    status                            INTEGER NOT     NULL,
    plan                              INTEGER NOT     NULL,
    payment_provider                  INTEGER NOT     NULL,
    auto_renewing                     BOOLEAN NOT     NULL DEFAULT FALSE,
    unredeemed_unix_ts_ms             BIGINT  NOT     NULL,

    redeemed_unix_ts_ms               BIGINT,
    expiry_unix_ts_ms                 BIGINT  NOT     NULL,
    grace_period_duration_ms          BIGINT,
    platform_refund_expiry_unix_ts_ms BIGINT  NOT     NULL,
    revoked_unix_ts_ms                BIGINT,

    apple_original_tx_id              TEXT,
    apple_tx_id                       TEXT,
    apple_web_line_order_tx_id        TEXT,
    google_payment_token              TEXT,
    google_order_id                   TEXT,
    rangeproof_order_id               TEXT,

    refund_requested_unix_ts_ms       BIGINT  NOT     NULL DEFAULT 0,
    google_obfuscated_account_id      BYTEA           NULL CHECK (octet_length(google_obfuscated_account_id) = 32),
    apple_app_account_token           TEXT    NOT     NULL DEFAULT ''
);
