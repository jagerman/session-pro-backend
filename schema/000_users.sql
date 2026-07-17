CREATE TABLE IF NOT EXISTS users (
    master_pkey                  BYTEA   PRIMARY KEY  CHECK (octet_length(master_pkey) = 32),
    gen_index                    INTEGER NOT     NULL,
    expiry_unix_ts_ms            BIGINT  NOT     NULL,
    grace_period_duration_ms     BIGINT  NOT     NULL,
    auto_renewing                BOOLEAN NOT     NULL DEFAULT FALSE,
    refund_requested_unix_ts_ms  BIGINT  NOT     NULL DEFAULT 0,
    google_obfuscated_account_id BYTEA           NULL CHECK (octet_length(google_obfuscated_account_id) = 32),
    apple_app_account_token      TEXT    NOT     NULL DEFAULT ''
);
