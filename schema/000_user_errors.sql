CREATE TABLE IF NOT EXISTS user_errors (
    payment_id         TEXT NOT NULL,
    payment_provider   INTEGER NOT NULL,
    unix_ts_ms         BIGINT NOT NULL,
    UNIQUE(payment_id, payment_provider)
);
