-- A credit has no expiry until its length runs out.
--
-- `expiry_at` was written at grant time as a projection -- what the length would be worth if nothing else
-- covered the account -- which is wrong the moment a subscription protects the credit, and which the drain
-- then overwrote with a fact once the length ran out. One column meaning a guess for part of a row's life
-- and a fact for the rest.
--
-- NULL says what is true: not yet determined. The drain latches it at the instant the length is spent, the
-- same way `redeemed_at` and `revoked_at` latch, and the same way the absence of a stored `status` leaves
-- the timestamps to speak for themselves.
ALTER TABLE payments ALTER COLUMN expiry_at DROP NOT NULL;

-- Every payment must state where its coverage ends one way or the other: a fixed instant (a store
-- subscription, or a credit whose length has run out) or a remaining length (a live credit). Both are set on
-- a spent credit, which is its terminal state rather than a contradiction -- so this is "at least one",
-- not "exactly one".
ALTER TABLE payments DROP CONSTRAINT IF EXISTS payments_states_an_end;
ALTER TABLE payments ADD CONSTRAINT payments_states_an_end
    CHECK (expiry_at IS NOT NULL OR credit_remaining IS NOT NULL);
