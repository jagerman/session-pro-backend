'''
Proofs and the revocation list: what a proof certifies, where its expiry lands, and what a client
is told when it cannot have one.
'''

import itertools
import json
import nacl.signing
import nacl.bindings
import nacl.public
import pendulum
import pytest
import psycopg_pool
from vendor import onion_req
import backend
import base
import db

from tests.helpers import _grant_voucher, _redeem_and_prove, TestingContext, _grant_and_get_offset, _prove_at


def test_proof_reports_account_expiry(pg_database):
    # A proof response carries account_expiry_ts -- the account's TRUE entitlement end -- distinct from
    # the proof's clamped (~30d) validity window. Grant a 12-month entitlement: the proof caps at ~30d
    # while account_expiry_at reports the full year, and account_expiry_ts is NOT in the signed message.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = base.round_datetime_to_next_day(base.utc_now())
    account_expiry = now + 365 * base.DAY

    with db.connection() as conn:
        _grant_voucher(conn, master_key, at=now, duration=account_expiry - now, plan=base.ProPlan.TwelveMonth)
        proof = _redeem_and_prove(conn, backend_key, master_key, rotating_key, now)
        # Proof validity rides the rolling clamp (~30 days); the account entitlement runs the full year, so
        # account_expiry_ts is the TRUE expiry exactly -- max() only ever reads back the proof's own expiry
        # in the closing window where the over-provision overtakes the true end, which is nowhere near here.
        shape = base.PROOF_EXPIRY_SHAPE
        offset = backend.get_user(conn, master_key.verify_key).proof_expiry_offset
        assert proof.expiry_at == base.round_datetime_up_onto_offset_grid(
            now + shape.clamp + shape.renewal_lead, period=shape.grid, offset_seconds=offset
        )
        assert proof.account_expiry_at == account_expiry
        assert proof.expiry_at < proof.account_expiry_at

        wire = proof.to_dict()
        assert wire['account_expiry_ts'] == base.unix_seconds_from_datetime(account_expiry)
        assert wire['expiry_ts'] != wire['account_expiry_ts']

        # account_expiry_ts is advisory: it is NOT part of the signed message the verifier reconstructs.
        proof_hash = backend.build_proof_message(proof.revocation_tag, proof.rotating_pkey, proof.expiry_at)
        backend_key.verify_key.verify(smessage=proof_hash, signature=proof.sig)
    pool.close()


def test_expired_proof_fail_carries_account_expiry(pg_database):
    # A proof request against a lapsed entitlement fails with subscription_expired AND carries the
    # account's (now-past) expiry as account_expiry_ts on the error, so the client can refresh its cached
    # horizon without a separate get_pro_status.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    granted_at = base.round_datetime_to_next_day(base.utc_now())
    account_expiry = granted_at + pendulum.duration(hours=1)

    with db.connection() as conn:
        # Grant a short entitlement (valid at grant time).
        _grant_voucher(conn, master_key, at=granted_at, duration=account_expiry - granted_at)
        # Ask for a proof from after the entitlement AND its proof over-provision are spent (the offset
        # buys up to a day past the true expiry, so an hour later is not yet lapsed as far as proofs go --
        # see test_lapsed_account_keeps_proofs_through_the_over_provision) -> subscription_expired, with the
        # past TRUE expiry attached (never the over-provisioned one).
        request_at = account_expiry + base.PROOF_EXPIRY_SHAPE.max_proof_lifetime
        with db.transaction(conn) as tx:
            with pytest.raises(base.FailError) as excinfo:
                backend.build_current_entitlement_proof(
                    tx, master_key.verify_key, rotating_key.verify_key, request_at, backend_key
                )
        assert excinfo.value.code == base.ErrorCode.subscription_expired
        assert excinfo.value.data == {'account_expiry_ts': base.unix_seconds_from_datetime(account_expiry)}
    pool.close()


def test_proof_expiry_offset_is_random_per_account_and_per_cycle(pg_database):
    # The offset must be random along BOTH axes, and this exercises the real RNG on both (unlike the re-draw
    # test below, which pins the trigger with a stubbed draw). Across accounts: a shared or key-derived value
    # would herd every client's renewal onto one instant and be a stable cross-generation fingerprint.
    # Across cycles of ONE account: a value fixed for the account's lifetime would leave its expiry pinned to
    # one time-of-day forever (the fingerprint again), and would permanently hand the same accounts the ~25 h
    # of over-provisioned Pro the offset carries.
    #
    # Both assertions are near-distinctness rather than full distinctness: independent draws over 86400
    # values collide with probability ~0.3% at 24 samples, so demanding all-distinct would be flaky, while
    # near-distinctness still fails loudly for a constant, a derived, or a coarsely-quantised offset.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = base.utc_now()
    shape = base.PROOF_EXPIRY_SHAPE

    with db.connection() as conn:
        across_accounts = [
            _grant_and_get_offset(
                conn, backend_key, nacl.signing.SigningKey.generate(), rotating_key, now, now + 30 * base.DAY
            )
            for _ in range(24)
        ]
        assert all(0 <= offset < shape.offset_range for offset in across_accounts)
        assert len(set(across_accounts)) >= 20

        # One account, 24 successive cycles: each grant extends the entitlement, which moves the true expiry
        # and so re-draws the offset.
        master_key = nacl.signing.SigningKey.generate()
        across_cycles = [
            _grant_and_get_offset(conn, backend_key, master_key, rotating_key, now, now + (30 + cycle) * base.DAY)
            for cycle in range(24)
        ]
        assert all(0 <= offset < shape.offset_range for offset in across_cycles)
        assert len(set(across_cycles)) >= 20
    pool.close()


def test_proof_is_identical_for_requests_in_the_same_grid_period(pg_database):
    # Multi-device convergence, which is the reason the expiry is rounded onto a grid rather than shifted by
    # the offset. A user's devices share the derived rotating key, so two of them asking a few SECONDS apart
    # -- different seconds, same grid period -- must receive byte-identical proofs, not one proof per request
    # instant. Crossing a grid point is the only thing that changes the answer, and it changes it by exactly
    # one period.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = base.utc_now()
    shape = base.PROOF_EXPIRY_SHAPE

    with db.connection() as conn:
        # A year-long plan, so every request below sits in the sliding arm where the expiry would otherwise
        # track the request instant -- the arm the grid has to collapse.
        offset = _grant_and_get_offset(
            conn, backend_key, master_key, rotating_key, now, now + 365 * base.DAY, plan=base.ProPlan.TwelveMonth
        )
        # Aim at the grid point one period past the nearest one, so `first_at` is safely after the grant
        # whatever the drawn offset, and 5 minutes below the boundary so none of the requests straddle it.
        target = (
            base.round_datetime_up_onto_offset_grid(
                now + shape.clamp + shape.renewal_lead, period=shape.grid, offset_seconds=offset
            )
            + shape.grid
        )
        first_at = target - shape.clamp - shape.renewal_lead - pendulum.duration(minutes=5)
        assert first_at > now

        proofs = [
            _prove_at(conn, backend_key, master_key, rotating_key, first_at + pendulum.duration(seconds=delay))
            for delay in (0, 1, 7, 59, 299)
        ]
        assert proofs[0].expiry_at == target
        # Byte-identical on the wire: same expiry AND the same signature over it, so two devices cannot be
        # told apart by their proofs and neither has to prefer one over the other.
        assert all(proof.to_dict() == proofs[0].to_dict() for proof in proofs)

        # The last instant that still maps here agrees too; one second later steps by exactly one period.
        latest = target - shape.clamp - shape.renewal_lead
        assert _prove_at(conn, backend_key, master_key, rotating_key, latest).to_dict() == proofs[0].to_dict()
        stepped = _prove_at(conn, backend_key, master_key, rotating_key, latest + pendulum.duration(seconds=1))
        assert stepped.expiry_at == target + shape.grid

        # The grid belongs to the ACCOUNT, not to a key: a different rotating key gets the same expiry, just
        # a different signature over it.
        other_rotating_key = nacl.signing.SigningKey.generate()
        other = _prove_at(conn, backend_key, master_key, other_rotating_key, first_at)
        assert other.expiry_at == proofs[0].expiry_at
        assert other.sig != proofs[0].sig
    pool.close()


def test_proof_expiry_offset_redraws_only_when_true_expiry_extends(monkeypatch, pg_database):
    # The offset tracks the subscription CYCLE, not every touch of the user row. Both directions matter:
    # re-drawing on a refresh that changes nothing would hand an observer repeated samples against one true
    # expiry, and the minimum of those samples converges straight back onto it; never re-drawing would leave
    # a fixed expiry time-of-day (a stable fingerprint) and let the same accounts perpetually collect the
    # offset's bonus Pro. So: re-draw when `users.expiry_at` EXTENDS.
    #
    # The two other arms of that rule live in tests/test_google.py, since they need a store payment with a
    # real expiry to shrink: a shrink KEEPS the offset (so that reducing an entitlement cannot serve a later
    # expiry than before), except that minting a generation always re-draws.
    draws = itertools.count(1)
    monkeypatch.setattr(backend, 'new_proof_expiry_offset', lambda: next(draws))

    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = base.utc_now()

    with db.connection() as conn:
        offset = _grant_and_get_offset(conn, backend_key, master_key, rotating_key, now, now + 30 * base.DAY)

        # A refresh from the same payment list recomputes the same expiry -> the offset must NOT move. Called
        # directly because it IS the clause under test: both writers of users.expiry_at share it, and going
        # through a caller would only prove whichever path that caller happens to take.
        backend._update_user_expiry_grace_and_renew_flag_from_payment_list(conn, master_key.verify_key)
        assert backend.get_user(conn, master_key.verify_key).proof_expiry_offset == offset

        # A new payment that extends the entitlement moves the true expiry -> new cycle, new offset.
        _grant_voucher(conn, master_key, at=now, duration=60 * base.DAY)
        assert backend.get_user(conn, master_key.verify_key).proof_expiry_offset != offset
    pool.close()


def test_proof_expiry_lands_on_the_account_grid(pg_database):
    # The expiry is min(request + clamp, true) + renewal lead, rounded UP onto the account's own grid
    # (UTC midnight + its offset). Two properties pinned here: the sliding arm is STEPPED, so every device
    # asking within the same period gets an identical expiry and the value never tracks the request instant;
    # and it steps by exactly one period, never drifting.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    # A day boundary, so that `true_expiry` below is exactly what the pinned arm gets: a credit's clock
    # starts at its day-rounded redemption instant, so granting at any other time of day would run the
    # entitlement to the following midnight plus the length, and the assertion would then hold or fail
    # depending on where the account's random offset fell relative to the time of day.
    now = base.round_datetime_to_next_day(base.utc_now())
    shape = base.PROOF_EXPIRY_SHAPE

    with db.connection() as conn:
        # Sliding arm: a year-long plan, so the `min` always takes the clamp.
        sliding_key = nacl.signing.SigningKey.generate()
        offset = _grant_and_get_offset(
            conn, backend_key, sliding_key, rotating_key, now, now + 365 * base.DAY, plan=base.ProPlan.TwelveMonth
        )
        expiry = base.round_datetime_up_onto_offset_grid(
            now + shape.clamp + shape.renewal_lead, period=shape.grid, offset_seconds=offset
        )
        assert _prove_at(conn, backend_key, sliding_key, rotating_key, now).expiry_at == expiry
        # On the grid, hence an exact whole second (nothing sub-second reaches the signed message).
        assert (expiry - base.EPOCH) % shape.grid == pendulum.duration(seconds=offset)

        # Every request up to the last instant that still maps here agrees; one second later steps by
        # exactly one period.
        latest = expiry - shape.clamp - shape.renewal_lead
        assert latest >= now
        assert _prove_at(conn, backend_key, sliding_key, rotating_key, latest).expiry_at == expiry
        stepped = _prove_at(conn, backend_key, sliding_key, rotating_key, latest + pendulum.duration(seconds=1))
        assert stepped.expiry_at == expiry + shape.grid

        # Pinned arm: an entitlement inside the clamp, so the `min` takes the true expiry and the expiry
        # stops moving with the request entirely -- the same value however long the client waits.
        pinned_key = nacl.signing.SigningKey.generate()
        true_expiry = now + 5 * base.DAY
        pinned_offset = _grant_and_get_offset(conn, backend_key, pinned_key, rotating_key, now, true_expiry)
        pinned = base.round_datetime_up_onto_offset_grid(
            true_expiry + shape.renewal_lead, period=shape.grid, offset_seconds=pinned_offset
        )
        assert _prove_at(conn, backend_key, pinned_key, rotating_key, now).expiry_at == pinned
        later = _prove_at(conn, backend_key, pinned_key, rotating_key, now + pendulum.duration(hours=13))
        assert later.expiry_at == pinned
        # The over-provision is bounded by the lead plus one period, and never rounds an expiry DOWN (which
        # would advertise an end before the entitlement's, with the renewal payment possibly not yet in).
        assert true_expiry + shape.renewal_lead <= pinned < true_expiry + shape.renewal_lead + shape.grid
    pool.close()


def test_lapsed_account_keeps_proofs_through_the_over_provision(pg_database):
    # A proof we already signed runs to the over-provisioned expiry, so a lapsed account keeps being issued
    # proofs -- all with that SAME expiry, never a fresh extension -- until it is spent. That keeps us
    # consistent with the account_expiry_ts we handed the client, which is where max() reads back the
    # proof's own expiry: past the true end the two must agree rather than contradict each other.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    # A day boundary, because a credit's clock starts at its day-rounded redemption instant (see
    # to_redeemed_at): granting at an arbitrary time of day would put the account's expiry at the following
    # midnight plus the length, and this test is about the over-provision, not about that anchoring.
    now = base.round_datetime_to_next_day(base.utc_now())
    true_expiry = now + pendulum.duration(hours=1)
    shape = base.PROOF_EXPIRY_SHAPE

    with db.connection() as conn:
        offset = _grant_and_get_offset(conn, backend_key, master_key, rotating_key, now, true_expiry)
        expiry = base.round_datetime_up_onto_offset_grid(
            true_expiry + shape.renewal_lead, period=shape.grid, offset_seconds=offset
        )
        assert expiry > true_expiry

        # Past the true expiry but inside the over-provision: still served, and the expiry has not budged.
        lapsed = _prove_at(conn, backend_key, master_key, rotating_key, true_expiry + pendulum.duration(minutes=30))
        assert lapsed.expiry_at == expiry
        # account_expiry_ts is the TRUE end of the paid term and does NOT read back the proof's expiry: the
        # two answer different questions, and the old `max` bought self-consistency by handing the owner a
        # date carrying the proof's random grid offset. So the proof deliberately outlives it here.
        assert lapsed.account_expiry_at == true_expiry
        assert lapsed.expiry_at > lapsed.account_expiry_at

        # Spent: now it lapses, reporting the TRUE expiry and never the over-provisioned one.
        with pytest.raises(base.FailError) as excinfo:
            _prove_at(conn, backend_key, master_key, rotating_key, expiry + pendulum.duration(seconds=1))
        assert excinfo.value.code == base.ErrorCode.subscription_expired
        assert excinfo.value.data == {'account_expiry_ts': base.unix_seconds_from_datetime(true_expiry)}
    pool.close()


def test_status_endpoint(pg_database):
    # /status is reachable BOTH directly (a plain GET, for monitors) and over the v4 onion transport,
    # and reports the backend version + server time + signing pubkey (so a caller can fetch the key to
    # verify proofs instead of hard-coding it). No auth, no request body, no DB access.
    with TestingContext(db_url_factory=pg_database) as ctx:
        expected_pubkey = bytes(ctx.backend_key.verify_key).hex()

        def check(result: dict):
            assert result['version'] == base.BACKEND_VERSION, result
            assert result['signing_pubkey'] == expected_pubkey, result
            assert isinstance(result['timestamp'], int), result

        # (a) Direct GET
        response = ctx.flask_client.get('/status')
        assert response.status_code == 200
        body = response.get_json()
        assert body['status'] == 'ok', body
        check(body['result'])

        # (b) Through the v4 onion transport (make_request_v4 sends POST; /status accepts GET+POST)
        server_x25519_skey = ctx.backend_key.to_curve25519_private_key()
        our_x25519_skey = nacl.public.PrivateKey.generate()
        shared_key = onion_req.make_shared_key(
            our_x25519_skey=our_x25519_skey, server_x25519_pkey=server_x25519_skey.public_key
        )
        onion_request = onion_req.make_request_v4(
            our_x25519_pkey=our_x25519_skey.public_key, shared_key=shared_key, endpoint='/status', request_body={}
        )
        response = ctx.flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success
        body = json.loads(onion_response.body)
        assert body['status'] == 'ok', body
        check(body['result'])


def test_stale_revocation_is_not_served(pg_database):
    # Revocation is terminal (a set revoked_at is always in effect — there is no per-entry expiry now),
    # so relevance is governed by the server's list-level retention window: a generation revoked longer
    # ago than RETAIN_FOR drops out of the served list, independent of whether the prune sweep has run.
    # Filtering by the window (rather than depending on a prune) keeps the served answer independent of
    # housekeeping timing. This mirrors the guard in server.get_pro_revocations.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool

    RETAIN_FOR = base.seconds_from_duration(base.REVOCATION_RETAIN_FOR)
    now = base.datetime_from_unix_seconds(1_700_000_000)
    master_pkey = nacl.signing.SigningKey.generate().verify_key
    with db.connection() as conn:
        # A user with two generations: one revoked recently (still inside the window) and one revoked
        # long ago (past the window). Neither prune has run, so both rows are still present.
        with db.transaction(conn) as tx:
            user_id, gen_recent, token_recent, _created = backend.get_or_create_user_and_generation(
                tx, master_pkey, now
            )
            gen_stale, token_stale = backend.mint_generation(tx, user_id, now)
        with db.transaction(conn) as tx:
            db.query(
                tx.conn,
                "UPDATE generations SET revoked_at = %s WHERE id = %s",
                now - pendulum.duration(seconds=1),
                gen_recent,
            )
            db.query(
                tx.conn,
                "UPDATE generations SET revoked_at = %s WHERE id = %s",
                now - pendulum.duration(seconds=RETAIN_FOR + 1),
                gen_stale,
            )

        # Both are terminally revoked regardless of `now` (revocation has no per-entry expiry).
        assert backend.is_generation_revoked(conn, gen_recent, now) is True
        assert backend.is_generation_revoked(conn, gen_stale, now) is True

        # The served list applies the retention window: recent is in, stale is filtered out. Read through
        # the same helper get_pro_revocations serves from, so this exercises that filter rather than a
        # copy of it.
        retain_cutoff = now - pendulum.duration(seconds=RETAIN_FOR)
        served = {it.token for it in backend.get_revocations_list(conn, revoked_after=retain_cutoff)}
        assert bytes(token_recent) in served
        assert bytes(token_stale) not in served
        # Unfiltered, both are present — the filter is the only thing hiding the stale one.
        assert {it.token for it in backend.get_revocations_list(conn)} >= {bytes(token_recent), bytes(token_stale)}
    pool.close()


def test_expired_revocations_are_pruned_once_unservable(pg_database):
    # The prune is the exact complement of the served window: it removes a revoked generation once, and
    # only once, get_pro_revocations can no longer return it — except for one a user is still sitting on,
    # which the NOT NULL users.current_generation_id FK requires us to keep at any age.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool

    now = base.datetime_from_unix_seconds(1_700_000_000)
    cutoff = now - base.REVOCATION_RETAIN_FOR
    master_pkey = nacl.signing.SigningKey.generate().verify_key
    with db.connection() as conn:
        with db.transaction(conn) as tx:
            user_id, gen_current, token_current, _created = backend.get_or_create_user_and_generation(
                tx, master_pkey, now
            )
            gen_stale, token_stale = backend.mint_generation(tx, user_id, now)
            gen_boundary, token_boundary = backend.mint_generation(tx, user_id, now)
            gen_recent, token_recent = backend.mint_generation(tx, user_id, now)

        revoked_at = {
            gen_current: cutoff - pendulum.duration(seconds=1),  # aged out, but the user still points here
            gen_stale: cutoff - pendulum.duration(seconds=1),
            gen_boundary: cutoff,  # served filter is `revoked_at > cutoff`, so this one is already unserved
            gen_recent: cutoff + pendulum.duration(seconds=1),
        }
        with db.transaction(conn) as tx:
            for generation_id, at in revoked_at.items():
                db.query(tx.conn, "UPDATE generations SET revoked_at = %s WHERE id = %s", at, generation_id)

        assert backend.delete_expired_revocations(conn, now) == 2

        remaining = {it.token for it in backend.get_revocations_list(conn)}
        assert bytes(token_current) in remaining, 'the FK forbids deleting the generation a user is on'
        assert bytes(token_recent) in remaining
        assert bytes(token_stale) not in remaining
        assert bytes(token_boundary) not in remaining

        # Nothing the prune removed was still being served, and nothing it kept has stopped being served
        # for a reason other than the user-is-on-it exemption.
        served = {it.token for it in backend.get_revocations_list(conn, revoked_after=cutoff)}
        assert served == {bytes(token_recent)}

        # Idempotent: a second pass at the same instant has nothing left to do.
        assert backend.delete_expired_revocations(conn, now) == 0
    pool.close()


def test_bump_revocation_ticket(pg_database):
    """The manual DR bump (backing the `revoke bump-ticket` CLI command) advances the monotonic
    revocation ticket by the given amount and returns the new value. Used to recover after a DB restore
    from an older backup rolls the counter backward (see docs/deploy.md)."""
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    conn = db_engine.getconn()
    try:
        assert backend.get_revocation_ticket(conn) == 0
        assert backend.bump_revocation_ticket(conn, 1000) == 1000  # returns the new value
        assert backend.get_revocation_ticket(conn) == 1000  # and it persisted
        assert backend.bump_revocation_ticket(conn, 5) == 1005  # cumulative, not absolute
        assert backend.get_revocation_ticket(conn) == 1005
    finally:
        db_engine.putconn(conn)
        db_engine.close()
