-- One-shot "credit" payments (vouchers, and anything else minted rather than witnessed at a store).
--
-- A store subscription states an absolute paid-through instant, so `expiry_at` is the whole story and
-- these columns stay NULL/unused for it. A credit carries a *length* instead of an innate end, so it
-- stacks on top of whatever coverage the account already has: it is consumed only while nothing else
-- covers the account, and what remains extends the account's expiry.

-- NULL = this payment is a store subscription, not a credit.
--    0  = a credit whose length has been fully consumed.
--  > 0  = a live credit with this much length left to give.
-- A CHECK is satisfied by TRUE *or* NULL, so this constrains real values while leaving NULL free.
ALTER TABLE payments ADD COLUMN IF NOT EXISTS credit_remaining INTERVAL;
ALTER TABLE payments DROP CONSTRAINT IF EXISTS payments_credit_remaining_non_negative;
ALTER TABLE payments ADD CONSTRAINT payments_credit_remaining_non_negative
    CHECK (credit_remaining >= '0'::interval);

-- How far a user's credits have been drained. The drain charges the elapsed span since this instant
-- (never an assumed "one day"), so a pass that runs late charges exactly what it should and a pass that
-- runs twice charges nothing the second time. The account's expiry is anchored on it as well, so any
-- unrelated recompute between passes yields the same instant instead of walking forward.
--
-- NULL means "no credit with anything left to give", which is the overwhelmingly common case: it keeps
-- the drain's due-set to accounts that actually hold credit, and NULL drops out of the `<` comparison
-- for free. It must NEVER mean "currently covered by a subscription" — a covered account holding a live
-- credit stays non-NULL and is visited (charging nothing), or nothing would notice when its subscription
-- later lapsed and the credit would stop draining.
ALTER TABLE users ADD COLUMN IF NOT EXISTS credits_checkpoint_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS users_credits_checkpoint_at_idx
    ON users (credits_checkpoint_at) WHERE credits_checkpoint_at IS NOT NULL;
