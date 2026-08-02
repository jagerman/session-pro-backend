-- `users.grace_period` gets the same semantics as the payments column it caches: NULL means no store grace
-- applies, and zero is not used to mean absence.
--
-- Split from 009 only because that migration may already have been applied to a development database, and a
-- migration is applied once by filename. Semantically the two are one change.
--
-- This column is a cache of the winning payment's store grace, denormalised onto the account so the read
-- paths need no join. It is recomputed on every entitlement refresh, so the UPDATE below only closes the
-- window until each account is next touched.
ALTER TABLE users ALTER COLUMN grace_period DROP NOT NULL;
ALTER TABLE users ALTER COLUMN grace_period SET DEFAULT NULL;

-- 009 rewrote the fossilised allowance to zero here rather than NULL, because the fold still dealt in a
-- plain Duration at that point. Both that zero and the original NOT NULL default now mean "no store grace",
-- which is what NULL says.
UPDATE users SET grace_period = NULL WHERE grace_period = '0'::interval;
