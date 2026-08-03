-- A token the drain has given up on retrying automatically.
--
-- Without this a token that can never be reconciled retries forever: the backoff tops out at six hours, so
-- one permanently-broken purchase costs four Play API fetches a day indefinitely, and `attempts` has no
-- ceiling. One row is nothing, but the failures here are rarely isolated — an unrecognised base plan is an
-- ordinary Play Console action, and it breaks EVERY new purchase — so what accumulates is a fetch bill and a
-- queue in which broken work is claimed ahead of fresh work, because the claim orders by `eligible_at` and a
-- stuck token's is always the oldest.
--
-- Parking stops the retries and nothing else. The row stays, `last_error` stays, and clearing this column
-- puts the token straight back in the queue — which is what makes "deploy the fix and re-run it" possible.
-- It is deliberately NOT a deletion: the token is the one fact about a subscription that cannot be
-- recovered from anywhere else.
ALTER TABLE google_reconcile_queue ADD COLUMN IF NOT EXISTS parked_at TIMESTAMPTZ;

-- The claim reads `eligible_at <= now` among unparked rows, so the index has to exclude parked ones or a
-- growing pile of permanently-broken tokens makes every claim scan them.
DROP INDEX IF EXISTS google_reconcile_queue_eligible_at_idx;
CREATE INDEX IF NOT EXISTS google_reconcile_queue_eligible_at_idx
    ON google_reconcile_queue (eligible_at) WHERE parked_at IS NULL;
