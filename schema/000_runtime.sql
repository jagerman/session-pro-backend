CREATE TABLE IF NOT EXISTS runtime (
    gen_index                                INTEGER NOT NULL DEFAULT 0,
    gen_index_salt                           BYTEA   NOT NULL CHECK   (octet_length(gen_index_salt) = 16),
    last_expire_unix_ts_ms                   BIGINT  NOT NULL DEFAULT 0,
    apple_notification_checkpoint_unix_ts_ms BIGINT  NOT NULL DEFAULT 0,
    revocation_ticket                        INTEGER NOT NULL DEFAULT 0
);
