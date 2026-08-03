-- `user_errors` and the wire's `error_report` are deleted.
--
-- The table recorded that handling a provider notification failed, keyed by the provider's transaction id,
-- and its only consumer was `get_pro_status`, which emitted it as a single boolean. That bit was not
-- actionable: no reason, no detail, no remedy, and `docs/pro-wire-protocol.md` never defined what a client
-- should do with it -- so it exposed an internal handler failure to a user who could do nothing about it.
--
-- It had also stopped meaning the same thing on each provider. Once Google notification handling became
-- convergent, every remaining failure path set `tx.cancel`, which rolled back the row written in the same
-- transaction -- so no Google `user_error` could persist at all, while Apple still wrote one on a separate
-- connection. One field, live for one provider and permanently zero for the other.
--
-- Where a failing purchase is visible now: `google_reconcile_queue.attempts` and `.last_error`, which is
-- operator information and lives where an operator looks.
DROP VIEW IF EXISTS db_stats;
DROP TABLE IF EXISTS user_errors;

-- Recreated without the `user_errors` count, otherwise identical.
CREATE OR REPLACE VIEW db_stats AS
SELECT
    (SELECT COUNT(*) FROM users)                                                     AS users,
    (SELECT COUNT(*) FROM payments)                                                  AS payments,
    (SELECT COUNT(*) FROM payments WHERE redeemed_at IS NULL AND revoked_at IS NULL) AS unredeemed_payments,
    (SELECT COUNT(*) FROM generations)                                               AS generations,
    (SELECT COUNT(*) FROM generations WHERE revoked_at IS NOT NULL)                  AS revocations,
    (SELECT COUNT(*) FROM google_notification_history)                               AS google_notifications,
    (SELECT COUNT(*) FROM apple_notification_uuid_history)                           AS apple_notifications;
