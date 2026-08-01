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

    -- When this token is next eligible to be reconciled. A fresh notification pulls it EARLIER (see the
    -- enqueue's LEAST) so new information is acted on promptly; a failure pushes it later with a backoff.
    due_at        TIMESTAMPTZ NOT NULL,

    -- Consecutive failures, for the backoff and for telling a transient blip from a token that is genuinely
    -- stuck. Deliberately NOT reset when a new notification arrives for a failing token: the arrival says
    -- nothing about whether the reason for failing has gone away.
    attempts      INTEGER     NOT NULL DEFAULT 0,

    -- Why the last attempt failed, for an operator reading the table directly. Never parsed.
    last_error    TEXT
);

-- The claim reads `due_at <= now` ordered by `due_at`; without this it is a seq scan on every pass.
CREATE INDEX IF NOT EXISTS google_reconcile_queue_due_at_idx ON google_reconcile_queue (due_at);
