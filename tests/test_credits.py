'''
One-shot credit payments: stacking on coverage, being consumed only while uncovered, and what a
refund does and does not do to them.
'''

import nacl.signing
import nacl.bindings
import nacl.public
import pendulum
import backend
import base
import minting
import db

from tests.helpers import _redeem_and_prove, _CreditFixture


def test_credit_stacks_on_nothing(pg_database):
    # A credit granted to an account with no coverage is worth exactly its length, from the grant -- the
    # behaviour that already existed, and the one case the old `now + duration` insert got right.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.mint(30 * base.DAY)
        assert f.expiry() == T + 30 * base.DAY
        assert f.checkpoint() == T
    pool.close()


def test_credit_stacks_on_a_live_subscription(pg_database):
    # The bug this whole mechanism exists for: a credit granted to a covered account used to lose the max
    # and be silently absorbed. It must sit on TOP of the subscription's coverage.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expires_at=T + 30 * base.DAY)
        assert f.expiry() == T + 30 * base.DAY
        f.mint(365 * base.DAY)
        assert f.expiry() == T + 30 * base.DAY + 365 * base.DAY
    pool.close()


def test_credit_is_not_drained_or_absorbed_while_a_subscription_covers(pg_database):
    # A short credit under a renewing subscription is the sharpest version: month after month of coverage
    # marches past it, and it must still be worth a full month whenever the subscription finally stops.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expires_at=T + 30 * base.DAY)
        credit = f.mint(30 * base.DAY)

        # Renewal cycles, each drained through while covered: nothing is charged, but the checkpoint keeps
        # advancing (otherwise the covered span would be charged later, once coverage ends).
        f.subscribe(expires_at=T + 60 * base.DAY, purchased_at=T + 30 * base.DAY)
        assert f.drain(at=T + 31 * base.DAY) == 1
        assert f.remaining(credit) == 30 * base.DAY
        assert f.checkpoint() == T + 31 * base.DAY

        f.subscribe(expires_at=T + 90 * base.DAY, purchased_at=T + 60 * base.DAY)
        assert f.drain(at=T + 61 * base.DAY) == 1
        assert f.remaining(credit) == 30 * base.DAY

        # Still a full month, now stacked on the latest coverage rather than on the term it was granted in.
        assert f.expiry() == T + 90 * base.DAY + 30 * base.DAY
    pool.close()


def test_three_credits_stack_with_and_without_a_subscription(pg_database):
    # Several live credits sum rather than run concurrently -- the case a plain max over expiries collapses
    # to one credit's worth.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expires_at=T + 30 * base.DAY)
        for _ in range(3):
            f.mint(30 * base.DAY)
        assert f.expiry() == T + 30 * base.DAY + 90 * base.DAY

        # And with no subscription at all, three credits are still worth their sum, consumed one at a time.
        g = _CreditFixture(conn, T)
        ids = [g.mint(30 * base.DAY) for _ in range(3)]
        assert g.expiry() == T + 90 * base.DAY
        # 45 days of uncovered time empties the first and takes half the second; the third is untouched.
        # Two accounts exist in this database and both are due, so a single pass visits both -- the drain is
        # not per-account-per-pass.
        assert g.drain(at=T + 45 * base.DAY) == 2
        assert g.remaining(ids[0]) == pendulum.duration()
        assert g.remaining(ids[1]) == 15 * base.DAY
        assert g.remaining(ids[2]) == 30 * base.DAY
        # The account's expiry has not moved: the credits were consumed by exactly the time that elapsed.
        assert g.expiry() == T + 90 * base.DAY
    pool.close()


def test_credit_only_account_actually_drains(pg_database):
    # The trap: computing "is this account covered?" from users.expires_at would see the credit's own
    # remaining length, report the account as covered, and protect the credit from ever being charged.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        credit = f.mint(30 * base.DAY)
        assert f.expiry() == T + 30 * base.DAY  # so users.expires_at IS in the future

        assert f.drain(at=T + 10 * base.DAY) == 1
        assert f.remaining(credit) == 20 * base.DAY
        assert f.expiry() == T + 30 * base.DAY  # unmoved: 10 days elapsed, 10 days charged
    pool.close()


def test_credit_exhaustion_does_not_slide(pg_database):
    # Once the length is gone the account's expiry is the instant it ran out -- not `now`, which would walk
    # forward on every pass and hand out free entitlement forever.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        credit = f.mint(30 * base.DAY)

        # A pass long after the credit ran out charges only what was there.
        assert f.drain(at=T + 100 * base.DAY) == 1
        assert f.remaining(credit) == pendulum.duration()
        assert f.expiry() == T + 30 * base.DAY
        # Nothing left to visit, so the account leaves the drain's due-set.
        assert f.checkpoint() is None

        # Further passes cannot move it, however late they run.
        assert f.drain(at=T + 400 * base.DAY) == 0
        assert f.expiry() == T + 30 * base.DAY
    pool.close()


def test_credit_multi_day_catchup_and_clock_skew(pg_database):
    # A pass that runs late charges the whole elapsed span in one go (the charge is the span since the
    # checkpoint, never an assumed interval), and one that runs with a checkpoint ahead of it charges
    # nothing rather than handing length back.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        a = f.mint(3 * base.DAY)
        b = f.mint(30 * base.DAY)

        # Down for five days: one pass charges five days, spilling from the first credit into the second.
        assert f.drain(at=T + 5 * base.DAY) == 1
        assert f.remaining(a) == pendulum.duration()
        assert f.remaining(b) == 28 * base.DAY
        assert f.total_remaining() == 28 * base.DAY

        # A pass dated BEFORE the checkpoint (clock stepped back) is inert.
        before = f.total_remaining()
        assert f.drain(at=T + 2 * base.DAY) == 0  # not even due: checkpoint is ahead of `now`
        assert f.total_remaining() == before
    pool.close()


def test_credit_stale_after_gates_which_accounts_are_visited(pg_database):
    # The per-account threshold only decides WHEN an account is visited, never what it is charged.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        credit = f.mint(30 * base.DAY)

        # Half a day in, with a one-day threshold: not yet due, nothing charged.
        assert f.drain(at=T + 12 * base.HOUR, stale_after=base.DAY) == 0
        assert f.remaining(credit) == 30 * base.DAY

        # Two days in: due, and charged for the full two days -- not for one.
        assert f.drain(at=T + 2 * base.DAY, stale_after=base.DAY) == 1
        assert f.remaining(credit) == 28 * base.DAY
    pool.close()


def test_credit_granted_while_covered_drains_only_after_the_lapse(pg_database):
    # The transition: a credit protected by a subscription starts being consumed when that coverage ends,
    # so its length is delivered rather than partly overlapping the term it was granted in.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expires_at=T + 30 * base.DAY, auto_renewing=False)  # cancelled: covers to term end
        credit = f.mint(10 * base.DAY)
        assert f.expiry() == T + 40 * base.DAY

        # Passes at the production cadence, straddling the lapse at T+30d.
        for day in range(1, 36):
            assert f.drain(at=T + day * base.DAY) == 1

        # 5 days of genuinely uncovered time elapsed (T+30d..T+35d), and 6 were charged. The extra day is
        # the sampled-coverage slop: the pass dated exactly T+30d finds the term already over and charges
        # the whole day it covers, including the covered part. Bounded by one interval, and only ever at a
        # real coverage transition -- a renewal is not one, since expiry moves before the old term lapses.
        assert f.remaining(credit) == 4 * base.DAY
        assert f.expiry() == T + 39 * base.DAY
    pool.close()


def test_credit_sampled_coverage_charges_a_whole_late_span(pg_database):
    # The other half of that trade, pinned deliberately: coverage is sampled once per pass, so if the drain
    # has not run for a while and the subscription lapsed somewhere inside that span, the WHOLE span is
    # charged. The error is bounded by however late the pass is, and it is against the account -- if this
    # ever needs to be exact, the fix is to clip the span at the coverage end, and this test should fail.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expires_at=T + 30 * base.DAY, auto_renewing=False)
        credit = f.mint(30 * base.DAY)

        # One pass inside the term, then nothing for fifteen days -- the lapse falls in the middle of it.
        assert f.drain(at=T + 20 * base.DAY) == 1
        assert f.remaining(credit) == 30 * base.DAY
        assert f.drain(at=T + 35 * base.DAY) == 1
        # Only 5 of those 15 days were uncovered, but all 15 are charged.
        assert f.remaining(credit) == 15 * base.DAY
    pool.close()


def test_credit_dark_gap_charges_nobody_and_a_regrant_restarts_the_clock(pg_database):
    # Time during which the account had nothing at all is charged to nobody: there is no credit to charge,
    # and the elapsed span must not be banked against a credit granted later.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        first = f.mint(10 * base.DAY)

        # Spend it, then go dark for 90 days.
        assert f.drain(at=T + 10 * base.DAY) == 1
        assert f.remaining(first) == pendulum.duration()
        assert f.checkpoint() is None
        assert f.drain(at=T + 100 * base.DAY) == 0  # nothing to visit while dark

        # A second credit granted after the dark stretch is worth its full length from the grant: the 90
        # unentitled days are not charged to it, and the checkpoint restarts rather than resuming.
        second = f.mint(30 * base.DAY, at=T + 100 * base.DAY)
        assert f.checkpoint() == T + 100 * base.DAY
        assert f.expiry() == T + 130 * base.DAY
        assert f.drain(at=T + 105 * base.DAY) == 1
        assert f.remaining(second) == 25 * base.DAY
        assert f.expiry() == T + 130 * base.DAY

        # And a subscription bought later simply takes over as the better coverage.
        f.subscribe(expires_at=T + 200 * base.DAY, purchased_at=T + 105 * base.DAY)
        assert f.expiry() == T + 200 * base.DAY + 25 * base.DAY
    pool.close()


def test_credit_expiry_is_unmoved_by_unrelated_recomputes(pg_database):
    # Why the credit total is anchored on the drain checkpoint rather than on `now`: the account's expiry has
    # to be a fixed instant. Anything that refreshes the user row between passes -- a payment registered, a
    # redeem, a revocation elsewhere -- must land on the same answer, not walk it forward by however much of
    # the interval has elapsed.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.mint(30 * base.DAY)
        before = f.expiry()
        assert before == T + 30 * base.DAY

        # Refresh the user row repeatedly at later and later instants, with no drain pass in between.
        for day in (1, 5, 12):
            with db.transaction(conn) as tx:
                backend._update_user_expiry_grace_and_renew_flag_from_payment_list(tx, f.pkey)
            assert f.expiry() == before, f'expiry moved on a refresh {day} days in'
            with db.transaction(conn) as tx:
                backend._ensure_active_generation(tx, f.pkey, issued_at=T + day * base.DAY)
            assert f.expiry() == before, f'expiry moved on a generation refresh {day} days in'
    pool.close()


def test_credit_expiry_obfuscation_is_not_perturbed_by_draining(pg_database):
    # A one-shot payment's true expiry is `grant + length`, so publishing it exactly would hand a DM
    # recipient the purchase instant. The proof carries an expiry rounded onto the account's random 24h
    # grid instead, which bounds an observer to ~a day -- but ONLY while the offset holds still. If the
    # grid were re-drawn as the credit drained, proofs collected over several days would average the
    # randomness out and recover the true instant far more precisely than the grid promises.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        # Short enough that the proof pins to the account's expiry rather than the ~30d sliding cap.
        f.mint(20 * base.DAY)

        def offset() -> int:
            return db.query_scalar(conn, 'SELECT proof_expiry_offset FROM users WHERE master_pkey = %s', bytes(f.pkey))

        expiry_before, offset_before = f.expiry(), offset()
        first = _redeem_and_prove(conn, backend_key, f.master_key, rotating_key, T + base.DAY)

        # Drain repeatedly, including past exhaustion, with proofs taken along the way.
        for day in (2, 5, 10, 19, 25):
            assert f.drain(at=T + day * base.DAY) in (0, 1)
            # The account's own expiry never moves, so the grid offset is never re-drawn...
            assert f.expiry() == expiry_before, f'account expiry moved at day {day}'
            assert offset() == offset_before, f'grid offset re-drawn at day {day}'

        # ...and therefore a proof taken later carries the SAME published expiry: repeated sampling tells
        # an observer nothing beyond the first sample.
        later = _redeem_and_prove(conn, backend_key, f.master_key, rotating_key, T + 3 * base.DAY)
        assert later.expires_at == first.expires_at

        # The published expiry is the grid point at or after the true one, never the true instant itself
        # unless the account's grid happens to land there.
        assert first.expires_at >= expiry_before
        assert first.expires_at - expiry_before < base.DAY
    pool.close()


def test_credit_survives_a_refund_and_grant_order_is_irrelevant(pg_database):
    # Refund-then-grant and grant-then-refund must land in the same place: a credit is not charged for the
    # period a subscription covered, and a refund does not retroactively charge it either (no clawback --
    # a refunded subscriber has already had that Pro, and that is accepted).
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        REFUND_AT = T + 60 * base.DAY
        err = base.ErrorSink()

        # Order A: refund lands, THEN the credit is granted.
        a = _CreditFixture(conn, T)
        sub_a = a.subscribe(expires_at=T + 365 * base.DAY)
        with db.transaction(conn) as tx:
            assert backend.add_google_revocation(
                tx, google_payment_token=sub_a.google_payment_token, revoke_at=REFUND_AT, err=err
            )
        a.mint(365 * base.DAY, at=REFUND_AT)

        # Order B: the credit is granted first, THEN the refund lands.
        b = _CreditFixture(conn, T)
        sub_b = b.subscribe(expires_at=T + 365 * base.DAY)
        b.mint(365 * base.DAY, at=REFUND_AT)
        with db.transaction(conn) as tx:
            assert backend.add_google_revocation(
                tx, google_payment_token=sub_b.google_payment_token, revoke_at=REFUND_AT, err=err
            )
        assert not err.msg_list, err.msg_list

        assert a.expiry() == b.expiry()
        # And that shared answer is the credit's full year from the refund: the two months already consumed
        # under the refunded subscription are not charged back to it.
        assert a.expiry() == REFUND_AT + 365 * base.DAY
    pool.close()


def test_revoking_a_credit_drops_exactly_its_remaining(pg_database):
    # Clawing a credit back removes its remaining length and nothing else -- the rest of the account's
    # entitlement is untouched.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expires_at=T + 30 * base.DAY)
        keep = f.mint(10 * base.DAY)
        claw = f.mint(90 * base.DAY)
        assert f.expiry() == T + 130 * base.DAY

        with db.transaction(conn) as tx:
            db.query(tx.conn, 'UPDATE payments SET revoked_at = %s, auto_renewing = FALSE WHERE id = %s', T, claw)
            backend._update_user_expiry_grace_and_renew_flag_from_payment_list(tx, f.pkey)

        assert f.expiry() == T + 40 * base.DAY
        assert f.remaining(keep) == 10 * base.DAY
        # A revoked credit is not charged either: the drain skips it entirely.
        assert f.drain(at=T + 5 * base.DAY) == 1
        assert f.remaining(claw) == 90 * base.DAY
    pool.close()


def test_credit_does_not_make_a_subscriber_look_non_renewing(pg_database):
    # A credit sets the account's expiry but says nothing about renewal: auto_renewing and the grace period
    # must still describe the live subscription, or a subscriber holding a voucher reads as cancelled.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expires_at=T + 30 * base.DAY, grace=2 * base.DAY)
        f.mint(365 * base.DAY)

        user = backend.get_user(conn, f.pkey)
        assert user.auto_renewing is True
        assert user.grace_period == 2 * base.DAY
        # Coverage runs to the paid term plus grace, and only then does the credit's year begin.
        assert user.expires_at == T + 32 * base.DAY + 365 * base.DAY
    pool.close()


def test_minted_credit_never_claims_to_renew(pg_database):
    # `auto_renewing` is a fact about the payment that only the caller registering it knows. It is not
    # derivable from the provider (a store sells renewing subscriptions AND one-time products) nor from
    # whether the payment is a credit (a one-time store product is neither renewing nor a credit), so
    # mint_payment states it. Otherwise a payment imitating a store shape inherits that shape's
    # renewing-by-default and reports an expired account as still auto-renewing, forever, with no
    # notification coming to correct it.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        for provider in (
            base.PaymentProvider.SessionFoundation,
            base.PaymentProvider.GooglePlayStore,
            base.PaymentProvider.iOSAppStore,
        ):
            master_key = nacl.signing.SigningKey.generate()
            with db.transaction(conn) as tx:
                minted = minting.mint_payment(
                    tx,
                    master_pkey=master_key.verify_key,
                    provider=provider,
                    plan=base.ProPlan.OneMonth,
                    now=T,
                    duration=10 * base.DAY,
                )
            assert minted.redeemed, provider
            renewing = db.query_scalar(
                conn,
                '''SELECT p.auto_renewing FROM payments p JOIN users u ON u.id = p.user_id
                   WHERE u.master_pkey = %s''',
                bytes(master_key.verify_key),
            )
            assert renewing is False, provider
            assert backend.get_user(conn, master_key.verify_key).auto_renewing is False, provider

        # A real store purchase is still renewing by default, which is what the credit check must not break.
        f = _CreditFixture(conn, T)
        f.subscribe(expires_at=T + 30 * base.DAY)
        assert backend.get_user(conn, f.pkey).auto_renewing is True
    pool.close()


def test_credit_sub_day_length(pg_database):
    # The --dev-duration-ms path: a credit shorter than the drain interval is the same arithmetic.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = base.round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        credit = f.mint(base.duration_from_seconds(30))
        assert f.expiry() == T + base.duration_from_seconds(30)

        assert f.drain(at=T + base.duration_from_seconds(10)) == 1
        assert f.remaining(credit) == base.duration_from_seconds(20)
        assert f.drain(at=T + base.duration_from_seconds(45)) == 1
        assert f.remaining(credit) == pendulum.duration()
        assert f.expiry() == T + base.duration_from_seconds(30)
    pool.close()


def test_grant_voucher(pg_database):
    # Admin/CLI voucher grant: create an already-redeemed payment linked to a master key and return a
    # proof -- no voucher, no client claim step.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = base.round_datetime_to_next_day(base.utc_now())

    with db.connection() as conn:
        assert not backend.get_user(conn, master_key.verify_key).found
        proof = backend.grant_voucher(
            conn,
            master_pkey=master_key.verify_key,
            rotating_pkey=rotating_key.verify_key,
            signing_key=backend_key,
            request_at=now,
            redeemed_at=now,
            plan=base.ProPlan.OneMonth,
            expires_at=now + 30 * base.DAY,
        )
        # The proof verifies against the backend key, and the key is now an entitled user.
        proof_hash = backend.build_proof_message(proof.revocation_tag, proof.rotating_pkey, proof.expires_at)
        backend_key.verify_key.verify(smessage=proof_hash, signature=proof.sig)
        assert backend.get_user(conn, master_key.verify_key).found
    pool.close()
