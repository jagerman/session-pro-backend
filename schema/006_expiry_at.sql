-- `expires_at` -> `expiry_at` on the entitlement columns, and the credit drain's mark to `_checkpoint_at`.
--
-- The present tense was wrong for a value that is a future deadline for a subscription and a past fact once
-- a credit's length has run out (see schema/007). A noun does not have that problem, and it matches the
-- wire, which already calls this `expiry_ts`.
--
-- The notification-retention columns keep `expires_at`: those really are only ever future deadlines, read
-- by the prune and nothing else.
--
-- `credits_drained_through` becomes `credits_checkpoint_at`, matching `apple_notification_checkpoint_at`,
-- which is the same kind of value: a high-water mark, where the noun carries the meaning and `_at` says
-- where the mark sits. Not `credits_drained_at`, which would read as the instant a drain happened: when a
-- credit's length runs out partway through a window the mark is set to the instant it ran out, which is
-- EARLIER than the pass that wrote it, so an event name would make that assignment look like a bug.

-- Column renames have no IF EXISTS form, so each is guarded on the old name still being present. That keeps
-- re-applying the baseline against a database predating the ledger a no-op, per schema/README.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'payments' AND column_name = 'expires_at') THEN
        ALTER TABLE payments RENAME COLUMN expires_at TO expiry_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'payments' AND column_name = 'platform_refund_expires_at') THEN
        ALTER TABLE payments RENAME COLUMN platform_refund_expires_at TO platform_refund_expiry_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'users' AND column_name = 'expires_at') THEN
        ALTER TABLE users RENAME COLUMN expires_at TO expiry_at;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'users' AND column_name = 'credits_drained_through') THEN
        ALTER TABLE users RENAME COLUMN credits_drained_through TO credits_checkpoint_at;
    END IF;
END $$;

ALTER INDEX IF EXISTS users_credits_drained_through_idx RENAME TO users_credits_checkpoint_at_idx;
