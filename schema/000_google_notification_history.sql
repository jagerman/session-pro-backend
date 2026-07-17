CREATE TABLE IF NOT EXISTS google_notification_history (
    message_id        BIGINT NOT NULL,
    handled           BOOLEAN NOT NULL DEFAULT FALSE,
    payload           TEXT,
    expiry_unix_ts_ms BIGINT NOT NULL
);
