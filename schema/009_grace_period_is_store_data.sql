-- `grace_period` means one thing: a store grace currently in effect that the store declared SEPARATELY
-- from its own expiry. NULL everywhere else.
--
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
-- Dropping the DEFAULT matters as much as dropping NOT NULL: `add_unredeemed_payment` never names this
-- column, so with the old `'0'` default every insert would keep writing the meaning-free zero this
-- migration exists to retire.
ALTER TABLE payments ALTER COLUMN grace_period DROP NOT NULL;
ALTER TABLE payments ALTER COLUMN grace_period SET DEFAULT NULL;

-- `users.grace_period` is a derived cache of whichever payment won the entitlement fold, not a store fact,
-- and it stays NOT NULL here: the fold that writes it still deals in a plain Duration, and giving it the
-- same NULL semantics means changing that arithmetic — which is the read-helper step's job, not this one.
-- Its fossilised hour is still cleared below, because that value is live until the account is recomputed.

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

-- Recomputed from the payments above on the account's next entitlement refresh, so this only closes the
-- window until then -- but that window is one in which the account reads as covered an hour past its term.
UPDATE users SET grace_period = '0'::interval WHERE grace_period = '1 hour'::interval;
