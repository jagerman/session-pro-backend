'''
The grace arcs end to end: what a subscription covers while a renewal is failing, what happens when it
recovers, and what happens when it does not.

The thing these exist to catch is DOUBLE COUNTING. A store's grace reaches us two different ways -- Apple
declares it beside an untouched expiry, Google folds it into an extended one -- and for a while the backend
added its own allowance to a column that sometimes already held the store's window. Every assertion below
pins the total, not the parts, because the parts were individually defensible each time this broke.
'''

import nacl.signing
import pendulum

import backend
import base
import db

from tests.helpers import _CreditFixture, _redeem_and_prove, round_datetime_to_next_day


def _converge(
    conn,
    sub: base.PaymentProviderTransaction,
    expiry_at: pendulum.DateTime,
    auto_renewing: bool,
    at,
    in_grace: bool = False,
):
    """What the reconcile does when Play's subscription resource is fetched: write what it now says."""
    err = base.ErrorSink()
    with db.transaction(conn) as tx:
        converged = backend.google_converge_payment(
            tx,
            payment_tx=sub,
            expiry_at=expiry_at,
            auto_renewing=auto_renewing,
            in_grace=in_grace,
            needs_ack=False,
            at=at,
            err=err,
        )
    assert not err.msg_list, err.msg_list
    assert converged, 'the fixture seeded this (token, order id), so there is a row to converge'


def test_google_grace_is_counted_once(pg_database):
    # Play applies grace by EXTENDING `expiryTime`, so the day arrives inside the term rather than beside
    # it. The bug this pins: converging that extended term while ALSO storing a grace value made the same
    # day count twice, once in the expiry and once next to it.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        sub = f.subscribe(expiry_at=T + 30 * base.DAY)

        # Healthy: the term is the paid-through date and we serve the allowance past it.
        assert f.expiry() == T + 30 * base.DAY
        assert backend.account_coverage_end(backend.get_user(conn, f.pkey)) == (
            T + 30 * base.DAY + base.RENEWAL_LATENCY_ALLOWANCE
        )

        # The renewal fails. Play extends its own expiry by the base plan's 1 day and reports the same
        # subscription, still auto-renewing because a retry is still coming.
        _converge(conn, sub, expiry_at=T + 31 * base.DAY, auto_renewing=True, at=T + 30 * base.DAY)

        # ONE day, not two. The store's grace is inside the expiry; only our allowance sits beyond it.
        assert f.expiry() == T + 31 * base.DAY
        assert backend.account_coverage_end(backend.get_user(conn, f.pkey)) == (
            T + 31 * base.DAY + base.RENEWAL_LATENCY_ALLOWANCE
        )
        # And nothing stored the store's window a second time.
        assert (
            db.query_scalar(
                conn,
                '''SELECT p.grace_period FROM payments p JOIN google_play_payment_details gd ON gd.payment_id = p.id
                   WHERE gd.payment_token = %s''',
                sub.google_payment_token,
            )
            is None
        )
    pool.close()


def test_apple_grace_is_counted_once(pg_database):
    # Apple's half of the same property: `expiresDate` is left alone and the window is declared separately,
    # so the term stays honest and the grace is a column. Coverage must still be term + grace + allowance,
    # with the term itself untouched -- folding Apple's grace into the expiry would fabricate a paid period
    # the user never bought, and it would then show as their purchased term forever.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        f.subscribe(expiry_at=T + 30 * base.DAY, grace=16 * base.DAY)

        assert f.expiry() == T + 30 * base.DAY, 'the paid term, not the grace end'
        assert backend.account_coverage_end(backend.get_user(conn, f.pkey)) == (
            T + 30 * base.DAY + 16 * base.DAY + base.RENEWAL_LATENCY_ALLOWANCE
        )
    pool.close()


def test_grace_is_dropped_the_moment_a_renewal_stops_being_attempted(pg_database):
    # Grace is the window after a renewal FAILS, so it exists only while one is still coming. A subscriber
    # who cancels mid-billing-retry keeps the value in the column -- nothing clears it, deliberately -- and
    # must be covered to the end of the paid term and not a moment longer.
    #
    # This is what makes "no mechanism to clear store grace" safe, and it is why BOTH the grace and the
    # allowance are gated on `auto_renewing` rather than just the allowance.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        sub = f.subscribe(expiry_at=T + 30 * base.DAY, grace=16 * base.DAY)
        assert backend.account_coverage_end(backend.get_user(conn, f.pkey)) == (
            T + 30 * base.DAY + 16 * base.DAY + base.RENEWAL_LATENCY_ALLOWANCE
        )

        err = base.ErrorSink()
        with db.transaction(conn) as tx:
            assert backend.update_payment_renewal_info(
                tx, payment_tx=sub, grace_period=None, auto_renewing=False, err=err
            )
        assert not err.msg_list, err.msg_list

        user = backend.get_user(conn, f.pkey)
        assert user.grace_period == 16 * base.DAY, 'still on the row: nothing clears it'
        assert backend.account_coverage_end(user) == T + 30 * base.DAY, 'and none of it applies'
    pool.close()


def test_grace_recovering_extends_from_the_new_term(pg_database):
    # Purchase -> grace -> recover. The renewal finally goes through, Play reports the next cycle, and the
    # account is covered from that term -- with no residue of the grace window, which was never a payment.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        sub = f.subscribe(expiry_at=T + 30 * base.DAY)
        _converge(conn, sub, expiry_at=T + 31 * base.DAY, auto_renewing=True, at=T + 30 * base.DAY)

        # Recovery: the retry succeeds and the term becomes the next full cycle.
        _converge(conn, sub, expiry_at=T + 60 * base.DAY, auto_renewing=True, at=T + 31 * base.DAY)

        assert f.expiry() == T + 60 * base.DAY
        assert backend.account_coverage_end(backend.get_user(conn, f.pkey)) == (
            T + 60 * base.DAY + base.RENEWAL_LATENCY_ALLOWANCE
        )
    pool.close()


def test_an_ordinary_lapse_publishes_no_revocation(pg_database):
    # Purchase -> grace -> lapse. A subscription that quietly ends is NOT a revocation: the proofs it issued
    # self-expire, and every client fetches the revocation list, so broadcasting an entry for every
    # subscriber who ever stops paying would be a serious and permanent regression.
    #
    # Nothing else in the suite catches it. The revoke decision now asks its questions of COVERAGE rather
    # than the stored expiry, and the risk of that change is exactly here: a lapse looks like a fall in
    # coverage, because it is one.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        # A term ending at midday, which is where one ordinarily falls -- see the test below for what
        # happens when it does not.
        term = T + 30 * base.DAY + 12 * base.HOUR
        sub = f.subscribe(expiry_at=term)
        _redeem_and_prove(conn, backend_key, f.master_key, rotating_key, T)

        before = len(backend.get_revocations_list(conn))

        # Into grace: Play extends its own expiry by the plan's day, still renewing because a retry is due.
        _converge(conn, sub, expiry_at=term + 1 * base.DAY, auto_renewing=True, at=term)
        # And out the far side. The retries are done, so the store stops renewing it -- but it does NOT pull
        # the term back: the subscription simply reaches the end it already stated and stops.
        _converge(conn, sub, expiry_at=term + 1 * base.DAY, auto_renewing=False, at=term + 1 * base.DAY)

        assert backend.account_coverage_end(backend.get_user(conn, f.pkey)) == term + 1 * base.DAY
        assert len(backend.get_revocations_list(conn)) == before, 'a lapse is not a revocation'
    pool.close()


def test_a_lapse_near_midnight_publishes_no_revocation(pg_database):
    # The same ordinary lapse, with the term ending inside the last hour of a UTC day -- the case that used
    # to publish a revocation.
    #
    # `refresh_entitlement_and_revoke_overreaching_proofs` skips the broadcast when the entitlement was
    # ending within the day anyway, asking `prior_coverage <= round_to_next_day(at)`. On a lapse those two
    # instants are within the allowance of each other -- the store finalises at the term end, and we serve
    # an hour past it -- so the test is really "did a midnight fall between them". For any subscription
    # whose term ends in the last hour before UTC midnight it does, the early-out misses, and an ordinary
    # lapse lands in the list every client fetches. That is roughly one lapse in twenty-four, growing a
    # retained list forever.
    #
    # NOT introduced by moving these comparisons onto coverage: the stored expiry was grace-inclusive
    # before, so the same midnight fell in the same place. Made visible by having a test for it at last.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        lapses_at = T + 30 * base.DAY + 23 * base.HOUR + pendulum.duration(minutes=30)
        f = _CreditFixture(conn, T)
        sub = f.subscribe(expiry_at=lapses_at)
        _redeem_and_prove(conn, backend_key, f.master_key, rotating_key, T)

        before = len(backend.get_revocations_list(conn))
        _converge(conn, sub, expiry_at=lapses_at, auto_renewing=False, at=lapses_at)
        assert len(backend.get_revocations_list(conn)) == before, 'a lapse is not a revocation'
    pool.close()


def test_a_mid_term_refund_still_publishes_a_revocation(pg_database):
    # The companion to the two lapse tests, and the reason they are not simply "never broadcast". Quieting
    # the lapse case must not quieten a genuine fall: a refund partway through a paid term cuts coverage by
    # far more than the bounded window the early-out accepts, so the proofs already signed overstate the
    # account and every client has to be told.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()

    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        sub = f.subscribe(expiry_at=T + 365 * base.DAY)
        _redeem_and_prove(conn, backend_key, f.master_key, rotating_key, T)

        before = len(backend.get_revocations_list(conn))
        err = base.ErrorSink()
        with db.transaction(conn) as tx:
            assert backend.add_google_revocation(
                tx, google_payment_token=sub.google_payment_token, revoke_at=T + 30 * base.DAY, err=err
            )
        assert not err.msg_list, err.msg_list
        assert len(backend.get_revocations_list(conn)) > before, 'a refund mid-term is not a lapse'
    pool.close()


def test_google_grace_keeps_the_paid_term_and_records_the_extension(pg_database):
    # Play applies grace by EXTENDING `expiryTime`, so once a renewal fails the resource no longer states the
    # paid-through date. We know it anyway: the previous notification stored it, and the row still holds it.
    # So a grace converge keeps the stored term and records the difference as the grace, which is exactly the
    # shape Apple reports natively.
    #
    # This is what lets a client say "your payment failed on the 3rd, you have Pro until the 6th" rather than
    # showing a renewal date that silently moved forward.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    with db.connection() as conn:
        T = round_datetime_to_next_day(base.utc_now())
        f = _CreditFixture(conn, T)
        term = T + 30 * base.DAY
        sub = f.subscribe(expiry_at=term)

        def row():
            return db.query_one(
                conn,
                '''SELECT p.expiry_at, p.grace_period FROM payments p
                   JOIN google_play_payment_details gd ON gd.payment_id = p.id
                   WHERE gd.payment_token = %s''',
                sub.google_payment_token,
            )

        # The renewal fails and Play extends its own expiry by the plan's day.
        _converge(conn, sub, expiry_at=term + 1 * base.DAY, auto_renewing=True, at=term, in_grace=True)

        expiry, grace = row()
        assert expiry == term, 'the paid term is preserved, not overwritten by the extension'
        assert grace == 1 * base.DAY, 'and the extension is recorded beside it'
        assert backend.account_coverage_end(backend.get_user(conn, f.pkey)) == (
            term + 1 * base.DAY + base.RENEWAL_LATENCY_ALLOWANCE
        ), 'coverage is unchanged by the split -- it is only reported differently'

        # Re-converging the same snapshot must not move anything. Anchoring on the STORED expiry rather than
        # a computed one is what makes that true, and it matters beyond tidiness: a spurious move re-draws
        # the account's proof-expiry offset, which is the privacy mechanism.
        _converge(conn, sub, expiry_at=term + 1 * base.DAY, auto_renewing=True, at=term, in_grace=True)
        assert row() == (term, 1 * base.DAY), 'idempotent'

        # Play extends further; the anchor holds, so the grace simply grows.
        _converge(conn, sub, expiry_at=term + 2 * base.DAY, auto_renewing=True, at=term, in_grace=True)
        assert row() == (term, 2 * base.DAY)

        # The payment finally goes through on the SAME cycle: state leaves grace, so the extension is
        # cleared and the term is whatever the store now says.
        _converge(conn, sub, expiry_at=term + 30 * base.DAY, auto_renewing=True, at=term, in_grace=False)
        assert row() == (term + 30 * base.DAY, None), 'out of grace, the resource is taken at its word again'
