-- Per-account proof-expiry offset: a uniform random number of seconds in [0, 86400) that is added to
-- every proof expiry the account is issued (see backend._build_proof_clamped_expiry_time).
--
-- Two jobs, one mechanism:
--   * Metadata reduction. Without it, a proof whose expiry has stopped sliding sits on the account's exact
--     true expiry — leaking the precise purchase/renewal instant (a stable time-of-day fingerprint) and,
--     via midnight-vs-not, the plan cadence. Any conversation partner reads that off the proof.
--   * Renewal spreading. Clients begin renewing a fixed lead before their proof expires, so an expiry that
--     is a deterministic function of the plan (a day boundary, or a fixed anniversary instant) herds every
--     client into the same minute. A per-account offset scatters them across the day.
--
-- It is a stored RANDOM value, not a hash of the master key: a derived offset would be a stable
-- cross-generation fingerprint, and determinism buys nothing here. It is stored rather than drawn per
-- request because a fresh draw per request would break multi-device convergence (two devices must be able
-- to agree on an expiry) and would let an observer recover the true expiry as the minimum of repeated
-- samples. It is re-drawn whenever the account's true expiry EXTENDS (a payment, a renewal), and whenever a
-- generation is minted — both because a fixed offset against a fixed purchase anniversary is itself a
-- stable fingerprint, and because the offset hands out up to ~1 day of over-provisioned Pro, which should
-- not perpetually favour the same accounts. A shrink deliberately keeps it, so that reducing an
-- entitlement cannot serve a later expiry than it did before; see backend's
-- `_offset_redrawn_if_expiry_extends`.
ALTER TABLE users ADD COLUMN IF NOT EXISTS proof_expiry_offset INTEGER;

-- Backfill one INDEPENDENT draw per pre-existing row (`random()` is volatile, so it is evaluated per row)
-- rather than leaving them clustered on a single value.
UPDATE users SET proof_expiry_offset = floor(random() * 86400)::int WHERE proof_expiry_offset IS NULL;

-- NOT NULL with NO default: every writer must supply a freshly drawn offset
-- (backend.new_proof_expiry_offset), so a write that forgets the column fails loudly instead of silently
-- meaning "offset 0" — which is both the worst case for the herd and a distinguishable fingerprint.
ALTER TABLE users ALTER COLUMN proof_expiry_offset SET NOT NULL;

-- The range mirrors base.PROOF_EXPIRY_OFFSET_RANGE (== base.SECONDS_IN_DAY). DROP-then-ADD because
-- PostgreSQL has no ADD CONSTRAINT IF NOT EXISTS, and re-applying a migration must be a no-op.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_proof_expiry_offset_range;
ALTER TABLE users ADD CONSTRAINT users_proof_expiry_offset_range
    CHECK (proof_expiry_offset >= 0 AND proof_expiry_offset < 86400);
