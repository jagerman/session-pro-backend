CREATE TABLE IF NOT EXISTS revocations (
    gen_index            INTEGER PRIMARY KEY NOT NULL,
    creation_unix_ts_ms  BIGINT NOT NULL,  -- When the revocation was created (used to calculate effective time)
    expiry_unix_ts_ms    BIGINT NOT NULL
);

-- Trigger function for revocation_ticket
CREATE OR REPLACE FUNCTION increment_revocation_ticket()
RETURNS TRIGGER AS '
BEGIN
    UPDATE runtime SET revocation_ticket = revocation_ticket + 1;
    RETURN NEW;
END;
' LANGUAGE plpgsql;

-- Triggers for revocation_ticket
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
