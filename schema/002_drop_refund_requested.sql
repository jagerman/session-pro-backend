-- Drop the refund-requested tracking. The "a refund has been requested (but not yet granted)" timestamp
-- has been removed end-to-end: there is no client request to set it, no notification path to clear it, and
-- nothing reads it. Clients that want to surface a pending refund carry the timestamp in their own account
-- config instead. The terminal states we still track are the store-driven expiry/revocation, not this.
--
-- IF EXISTS so this is a no-op on a fresh database (the baseline no longer creates the columns) and a real
-- drop on any database that predates the baseline edit.
ALTER TABLE payments DROP COLUMN IF EXISTS refund_requested_at;
ALTER TABLE users    DROP COLUMN IF EXISTS refund_requested_at;
