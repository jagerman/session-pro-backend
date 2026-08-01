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
    last_error    TEXT
);

-- The claim reads `eligible_at <= now` ordered by it; without this the queue is a seq scan on every pass.
CREATE INDEX IF NOT EXISTS google_reconcile_queue_eligible_at_idx ON google_reconcile_queue (eligible_at);
