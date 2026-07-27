-- Track whether a Google purchase still owes an acknowledgement to Google (the "confirm within 3 days
-- or it's auto-refunded" step). The mule sets this TRUE when it registers a fresh, not-yet-acknowledged
-- purchase; a sweep in the mule's pull loop acknowledges such purchases and clears the flag. Keeping the
-- ack obligation as an explicit column on the payment row (rather than inferring it from notification
-- bookkeeping) lets it survive a mule crash between committing the payment and completing the ack.
--
-- Existing rows default FALSE: any payment already recorded was acknowledged by the old redeem-time ack
-- path, and re-acknowledging an already-acknowledged purchase is an error at Google.
ALTER TABLE google_play_payment_details ADD COLUMN IF NOT EXISTS needs_ack BOOLEAN NOT NULL DEFAULT FALSE;

-- The sweep reads `WHERE needs_ack`; a partial index keeps it off a seq-scan. Rows are TRUE only
-- briefly (between registration and a successful ack), so the index stays tiny.
CREATE INDEX IF NOT EXISTS google_play_payment_details_needs_ack
    ON google_play_payment_details (payment_id) WHERE needs_ack;
