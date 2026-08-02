-- Rename the out-of-band payment provider from `rangeproof` to `stf`.
--
-- The provider axis names WHO the payment came from — Google Play, the App Store, the Session Foundation —
-- and the Foundation is who decides to issue a voucher and who runs the server that honours it. Rangeproof
-- was a development firm: never the issuer, and no longer involved. A second issuer, if one is ever
-- permitted, gets its own code rather than sharing a generic one.
--
-- (What KIND of payment it is lives on a different axis: `payments.credit_remaining`, see schema/004.)

-- Idempotent: a fresh database applies 000 (which creates the old names) and then this, while one that has
-- already been renamed skips each step.
ALTER TABLE IF EXISTS rangeproof_payment_details RENAME TO stf_payment_details;

-- `payments.payment_provider` is an FK to this lookup, so the new code has to exist before any row can be
-- pointed at it, and the old one can only go once nothing references it.
INSERT INTO payment_providers (code) VALUES ('stf') ON CONFLICT (code) DO NOTHING;
UPDATE payments SET payment_provider = 'stf' WHERE payment_provider = 'rangeproof';
DELETE FROM payment_providers WHERE code = 'rangeproof';
