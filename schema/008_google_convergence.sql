-- Schema for converging Google Play notifications on the subscription resource.
--
-- One migration for one atomic change, though it landed across several commits: the reconcile queue that
-- makes a notification durable, the grace column's change of meaning, and the removal of a wire field the
-- rework left with nothing to say. None of the three is deployable without the others.
--
-- Written idempotently per this directory's README, so re-applying it against a database that predates the
-- ledger is a no-op.

-- ---------------------------------------------------------------------------------------------------------
-- 1. The reconcile queue
-- ---------------------------------------------------------------------------------------------------------

-- A purchase token owing a reconcile against Google's current subscription resource.
--
-- The unit of work is the TOKEN, not the notification. An RTDN says only "something about this
-- subscription changed", and the resource is fetched at processing time, so ten notifications for one token
-- are one piece of work: whatever the tenth would have told us is already in the snapshot the first fetch
-- returns. That is why `payment_token` is the primary key rather than a message id — enqueueing collapses,
-- and a burst costs one fetch instead of ten.
--
-- It also decouples acking from handling. Recording that a token owes work is a single small write that has
-- to succeed; once it has, the notification can be acked immediately, because losing it costs nothing. The
-- first sighting of a token is the one fact in this system that cannot be recovered from anywhere else --
-- no Play endpoint enumerates subscribers, and no client route submits a token -- so it is the only thing
-- worth making durable, and everything downstream is re-derivable from the resource.
CREATE TABLE IF NOT EXISTS google_reconcile_queue (
    payment_token TEXT PRIMARY KEY,

    -- The instant from which this token may be claimed: a FLOOR, not a deadline. Nothing is owed by it and
    -- being late costs nothing — the token simply waits. A fresh notification pulls it EARLIER (see the
    -- enqueue's LEAST) so new information is acted on promptly; a failure pushes it later with a backoff.
    eligible_at   TIMESTAMPTZ NOT NULL,

    -- Held by a worker until this instant — a genuine DEADLINE, unlike the floor above: pass it and the
    -- lease is void. Kept separate rather than pushing `eligible_at` forward, because the two answer
    -- different questions: "when may this be looked at" versus "is somebody looking at it right now".
    -- Conflating them let a notification arriving mid-fetch pull the token back to eligible and hand it to
    -- a second runner while the first still held it — and the loser of that race is whichever snapshot
    -- commits last, which is not necessarily the newer one.
    leased_until  TIMESTAMPTZ,

    -- Bumped on every enqueue, so a worker can tell whether the obligation it claimed is still the
    -- obligation in front of it. A notification that arrives while a fetch is in flight describes a state
    -- the fetch cannot have seen, so finishing that fetch must not clear the queue entry: the worker
    -- compares revisions and leaves the newer obligation standing. Without it, `done` deletes
    -- unconditionally and the change that arrived during the fetch is silently lost until the next event.
    revision      BIGINT      NOT NULL DEFAULT 0,

    -- Consecutive failures, for the backoff and for telling a transient blip from a token that is genuinely
    -- stuck. Deliberately NOT reset when a new notification arrives for a failing token: the arrival says
    -- nothing about whether the reason for failing has gone away.
    attempts      INTEGER     NOT NULL DEFAULT 0,

    -- Why the last attempt failed, for an operator reading the table directly. Never parsed.
    last_error    TEXT,

    -- Set when the drain gives up retrying this token (`RECONCILE_MAX_ATTEMPTS`).
    --
    -- Without a cap a token that can never be reconciled retries forever: the backoff tops out at six hours,
    -- so one permanently-broken purchase costs four Play API fetches a day indefinitely. One row is nothing,
    -- but these failures are rarely isolated — an unrecognised base plan is an ordinary Play Console action
    -- and breaks EVERY new purchase — so what accumulates is a fetch bill and a queue in which broken work
    -- is claimed ahead of fresh work, because the claim orders by `eligible_at` and a stuck token's is
    -- always the oldest.
    --
    -- Parking stops the retries and nothing else. The row stays, `last_error` stays, and clearing this
    -- column puts the token straight back in the queue — which is what makes "deploy the fix and re-run it"
    -- possible. It is deliberately NOT a deletion: the token is the one fact about a subscription that
    -- cannot be recovered from anywhere else.
    parked_at     TIMESTAMPTZ
);

-- The claim reads `eligible_at <= now` among UNPARKED rows, ordered by it; without this the queue is a seq
-- scan on every pass, and without the WHERE a growing pile of permanently-broken tokens is scanned each time.
CREATE INDEX IF NOT EXISTS google_reconcile_queue_eligible_at_idx
    ON google_reconcile_queue (eligible_at) WHERE parked_at IS NULL;

-- ---------------------------------------------------------------------------------------------------------
-- 2. `grace_period` means store grace, and nothing else
-- ---------------------------------------------------------------------------------------------------------

-- The column used to hold whichever of two unrelated quantities wrote last. One is OUR renewal-latency
-- allowance -- an hour, invented here, never sent by any store, covering the gap between a term ending and
-- us learning whether it renewed. The other is store grace, which only Apple declares separately
-- (`gracePeriodExpiresDate - expiresDate`); Play applies grace by extending `expiryTime`, so a Google row's
-- grace is already inside `expiry_at`. The two differ by 24x and nothing marked which was present. From
-- here the allowance is a config setting applied on read, and this column is store data only.
--
-- NULL rather than zero, because "no grace declared here" is not the same fact as "a grace of zero length",
-- and it is not derivable from `payment_provider` either: a dev-minted voucher carries the Google provider
-- and a Google detail row, yet grace is inapplicable to it for one-shot reasons rather than provider ones.
-- No store can express a zero-length grace -- Apple's declaration carries a positive gap or does not
-- arrive, and Google never declares one at all -- so a zero here would be a state no input can produce and
-- no reader can interpret. Note the cost this accepts: an ad-hoc comparison like
-- `WHERE grace_period < '1 day'` silently drops NULL rows rather than counting them as zero.
--
-- Dropping the DEFAULT matters as much as dropping NOT NULL: `add_unredeemed_payment` never names this
-- column, so with the old `'0'` default every insert would keep writing the meaning-free zero this
-- migration exists to retire.
ALTER TABLE payments ALTER COLUMN grace_period DROP NOT NULL;
ALTER TABLE payments ALTER COLUMN grace_period SET DEFAULT NULL;

-- `users.grace_period` is a derived cache of whichever payment won the entitlement fold, denormalised onto
-- the account so the read paths need no join. It gets the same semantics as the column it caches: recomputed
-- on every entitlement refresh, so its own legacy values only matter until each account is next touched.
ALTER TABLE users ALTER COLUMN grace_period DROP NOT NULL;
ALTER TABLE users ALTER COLUMN grace_period SET DEFAULT NULL;

-- Two legacy values become NULL, and Apple's real declarations survive untouched.
--
-- `'1 hour'` is the fossilised allowance, and the predicate is exact rather than heuristic: both retired
-- constants were `1 * HOUR` for their entire history, so an hour is precisely and only that. No store value
-- can collide with it -- Apple's grace periods are 3, 16 or 28 days, Play's granularity is whole days, and
-- the testing overrides are seconds and never reach a production database. Read as store grace it would be
-- added a second time, silently handing every existing payment an extra hour of entitlement.
--
-- `'0'` is the old NOT NULL column default, carried by every row that never had a grace write at all.
-- Under the new meaning that is exactly "no declaration", so it should say so rather than surviving as a
-- zero nothing can interpret.
--
-- Clearing unconditionally would be worse than doing nothing: it would strip a live 16-day Apple grace from
-- a subscription in billing retry, with nothing left to re-set it, since the notification that wrote it has
-- already been consumed.
UPDATE payments SET grace_period = NULL
    WHERE grace_period = '1 hour'::interval OR grace_period = '0'::interval;
UPDATE users    SET grace_period = NULL
    WHERE grace_period = '1 hour'::interval OR grace_period = '0'::interval;

-- ---------------------------------------------------------------------------------------------------------
-- 3. `user_errors` and the wire's `error_report` are deleted
-- ---------------------------------------------------------------------------------------------------------

-- The table recorded that handling a provider notification failed, keyed by the provider's transaction id,
-- and its only consumer was `get_pro_status`, which emitted it as a single boolean. That bit was not
-- actionable: no reason, no detail, no remedy, and `docs/pro-wire-protocol.md` never defined what a client
-- should do with it -- so it exposed an internal handler failure to a user who could do nothing about it.
--
-- It had also stopped meaning the same thing on each provider. Once Google notification handling became
-- convergent, every remaining failure path set `tx.cancel`, which rolled back the row written in the same
-- transaction -- so no Google `user_error` could persist at all, while Apple still wrote one on a separate
-- connection. One field, live for one provider and permanently zero for the other. And on Apple it never
-- cleared: Google's row was removed by a later successful notification for the same token, and Apple had no
-- clearing path anywhere, so one transient parse failure latched the flag across the whole account for good.
--
-- Where a failing purchase is visible now: `google_reconcile_queue.attempts` and `.last_error`, which is
-- operator information and lives where an operator looks.
--
-- The view is dropped first because it depends on the table.
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
