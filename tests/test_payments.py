'''
Payment records and entitlement: claiming, stacking, auto-redeeming, and revoking.
'''

import nacl.signing
import nacl.bindings
import nacl.public
import os
import pendulum
import dataclasses
import psycopg
import psycopg_pool
from providers import google_play
import backend
import base
from providers import app_store
import db

from tests.helpers import pk_hex, derived_status, _redeem_and_prove


def test_reconcile_pending_payments(pg_database):
    # reconcile_pending_payments claims ALL unredeemed Google/Apple payments bound to a master key (the
    # store-attested account id IS a function of the key), links them, and refreshes entitlement -- and
    # touches nothing, in particular creates NO user row, for a key with no payments.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool

    master = nacl.signing.SigningKey.generate()
    other = nacl.signing.SigningKey.generate()
    now = base.round_datetime_to_next_day(base.utc_now())

    def seed_google(conn, master_vk):
        tx = base.PaymentProviderTransaction()
        tx.provider = base.PaymentProvider.GooglePlayStore
        tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        tx.google_order_id = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        err = base.ErrorSink()
        backend.add_unredeemed_payment(
            conn,
            payment_tx=tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=now,
            expiry_at=now + 30 * base.DAY,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_vk),
            err=err,
        )
        assert not err.msg_list, err.msg_list

    with db.connection() as conn:
        # Two unredeemed Google payments for the same key (e.g. a device offline across a renewal).
        seed_google(conn, master.verify_key)
        seed_google(conn, master.verify_key)

        assert backend.reconcile_pending_payments(conn, master.verify_key, redeemed_at=now) == 2  # claim-ALL
        assert backend.get_user(conn, master.verify_key).found  # user created + entitled
        # Idempotent: nothing left unredeemed.
        assert backend.reconcile_pending_payments(conn, master.verify_key, redeemed_at=now) == 0

        # A key with no payments claims nothing AND must not spawn a user row.
        assert backend.reconcile_pending_payments(conn, other.verify_key, redeemed_at=now) == 0
        assert not backend.get_user(conn, other.verify_key).found
    pool.close()


def test_generate_pro_proof_auto_redeems(pg_database):
    # The reflow core: a proof request reconciles first, so a payment the mule registered (unredeemed) is
    # bound AND proven on the client's proof call -- no separate /add_pro_payment redeem step.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = base.round_datetime_to_next_day(base.utc_now())

    with db.connection() as conn:
        # A mule-registered, unredeemed Google payment bound to the master key.
        seed_tx = base.PaymentProviderTransaction()
        seed_tx.provider = base.PaymentProvider.GooglePlayStore
        seed_tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        seed_tx.google_order_id = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        err = base.ErrorSink()
        backend.add_unredeemed_payment(
            conn,
            payment_tx=seed_tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=now,
            expiry_at=now + 30 * base.DAY,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_key.verify_key),
            err=err,
        )
        assert not err.msg_list, err.msg_list
        assert len(backend.get_unredeemed_payments_list(conn)) == 1

        # Proof request with NO explicit redeem -> auto-redeems + returns a valid proof.
        hash_to_sign = backend.make_generate_pro_proof_message(
            master_pkey=master_key.verify_key, rotating_pkey=rotating_key.verify_key, request_at=now
        )
        proof = backend.generate_pro_proof(
            conn=conn,
            signing_key=backend_key,
            master_pkey=master_key.verify_key,
            rotating_pkey=rotating_key.verify_key,
            request_at=now,
            master_sig=bytes(master_key.sign(hash_to_sign).signature),
            rotating_sig=bytes(rotating_key.sign(hash_to_sign).signature),
        )
        # The proof verifies against the backend key, and the payment is now redeemed.
        proof_hash = backend.build_proof_message(proof.revocation_tag, proof.rotating_pkey, proof.expiry_at)
        backend_key.verify_key.verify(smessage=proof_hash, signature=proof.sig)
        assert not backend.get_unredeemed_payments_list(conn)
    pool.close()


def test_provider_dry_run_redeems_google_without_egress(monkeypatch, pg_database):
    # With provider_dry_run on, a Google payment redeems to a signed proof with NO call to Google: the
    # in-function stubs (synthetic already-acknowledged fetch + no-op acknowledge) stand in for the
    # egress. Deliberately NOT monkeypatching google_play.api here — exercising the real stubs is
    # the point. (Contrast test_backend_same_user_stacks_... which monkeypatches those calls instead.)
    monkeypatch.setattr(base, 'PROVIDER_DRY_RUN', True)

    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = base.utc_now()
    redeemed_at = base.round_datetime_to_next_day(now)

    db_conn = db_engine.getconn()
    try:
        # Seed a witnessed-unredeemed Google payment (as if a purchase notification had been received).
        seed_tx = base.PaymentProviderTransaction()
        seed_tx.provider = base.PaymentProvider.GooglePlayStore
        seed_tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        seed_tx.google_order_id = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=seed_tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=now,
            expiry_at=redeemed_at + 30 * base.DAY,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_key.verify_key),
            err=err,
        )
        assert not err.msg_list, f'{err.msg_list}'

        # Client redeems it simply by requesting a proof: generate_pro_proof reconciles the pending
        # payment (bound by the master-key account-id) and returns the proof -- no explicit redeem call.
        proof = _redeem_and_prove(db_conn, backend_key, master_key, rotating_key, now)
        assert proof is not None
        assert not backend.get_unredeemed_payments_list(db_conn)
    finally:
        db_engine.putconn(db_conn)
        db_engine.close()


def test_backend_same_user_stacks_subscription_and_auto_redeem(monkeypatch, pg_database):
    monkeypatch.setattr("providers.google_play.api.subscription_v1_acknowledge", lambda *args, **kwargs: None)

    dummy_sub_v2_data = google_play.types.SubscriptionV2Data()
    monkeypatch.setattr(
        "providers.google_play.api.fetch_subscription_v2_details", lambda *args, **kwargs: dummy_sub_v2_data
    )

    # Test that the user's subscription stacks if they purchase two subscription with different
    # payment tokens.

    # Setup DB
    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    # Setup scenarios, single user who stacks a subscription
    backend_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    master_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    rotating_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    now: pendulum.DateTime = base.utc_now()
    redeemed_at: pendulum.DateTime = base.round_datetime_to_next_day(now)

    @dataclasses.dataclass
    class Scenario:
        google_payment_token: str = ''
        google_order_id: str = ''
        plan: base.ProPlan = base.ProPlan.Nil
        proof: backend.ProSubscriptionProof = dataclasses.field(default_factory=backend.ProSubscriptionProof)
        payment_provider: base.PaymentProvider = base.PaymentProvider.Nil
        expiry_at: pendulum.DateTime = base.EPOCH
        grace_period: pendulum.Duration = pendulum.duration()

    scenarios: list[Scenario] = [
        Scenario(
            google_payment_token=os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            google_order_id='DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            plan=base.ProPlan.OneMonth,
            expiry_at=redeemed_at + 30 * base.DAY,
            grace_period=pendulum.duration(),
            payment_provider=base.PaymentProvider.GooglePlayStore,
        ),
        Scenario(
            google_payment_token=os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            google_order_id='DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            plan=base.ProPlan.TwelveMonth,
            expiry_at=redeemed_at + 31 * base.DAY,
            grace_period=pendulum.duration(),
            payment_provider=base.PaymentProvider.GooglePlayStore,
        ),
    ]

    db_conn: psycopg.Connection = db_engine.getconn()
    for index, it in enumerate(scenarios):
        # Add the "unredeemed" version of the payment, e.g. mock the notification from
        # IOS App Store/Google Play Store
        assert it.payment_provider == base.PaymentProvider.GooglePlayStore, "Currently only google is mocked"
        payment_tx = base.PaymentProviderTransaction()
        payment_tx.provider = it.payment_provider
        payment_tx.google_payment_token = it.google_payment_token
        payment_tx.google_order_id = it.google_order_id

        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=payment_tx,
            plan=it.plan,
            purchased_at=now,
            expiry_at=it.expiry_at,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_key.verify_key),
            err=err,
        )
        assert not err.msg_list

        unredeemed_payment_list = backend.get_unredeemed_payments_list(db_conn)
        assert len(unredeemed_payment_list) == 1
        assert unredeemed_payment_list[0].payment_provider == it.payment_provider
        assert unredeemed_payment_list[0].purchased_at == now
        assert unredeemed_payment_list[0].redeemed_at is None
        assert unredeemed_payment_list[0].expiry_at == it.expiry_at
        assert unredeemed_payment_list[0].revoked_at is None
        assert unredeemed_payment_list[0].google_payment_token == it.google_payment_token
        assert unredeemed_payment_list[0].google_order_id == it.google_order_id
        assert unredeemed_payment_list[0].plan == it.plan

        # Client redeems by requesting a proof (reconciles the pending payment).
        proof = _redeem_and_prove(db_conn, backend_key, master_key, rotating_key, now)
        it.proof = proof

        # Verify payment was redeemed
        assert not backend.get_unredeemed_payments_list(db_conn)

        # Requesting a proof again is idempotent: a freshly-signed proof for the user's current entitlement
        # (identical to the first claim), and reconcile finds nothing new to redeem.
        proof_2nd = _redeem_and_prove(db_conn, backend_key, master_key, rotating_key, now)
        assert len(proof_2nd.revocation_tag) == backend.BLAKE2B_DIGEST_SIZE

    # Two payments stacked for one user → ONE generation, REUSED (a generation is an epoch, not a
    # per-payment value — a redeem reuses the current generation rather than rolling, since neither payment
    # was revoked). So the revocation_tag is stable across the stack.
    gen_ids: list[int] = [
        row[0]
        for row in db.query(
            db_conn,
            "SELECT g.id FROM generations g JOIN users u ON u.id = g.user_id WHERE u.master_pkey = %s ORDER BY g.id",
            bytes(master_key.verify_key),
        )
    ]
    assert len(gen_ids) == 1

    # Privacy (subscription-cadence leak): the revocation_tag a group member observes on the
    # user's proofs is STABLE across the stack. Both redeems produced proofs carrying the SAME tag (the
    # reused generation's token), so bump frequency can't leak the renewal cadence — the tag changes only
    # on a binding revocation (test_revocation_cutting_refund_rolls_generation).
    assert scenarios[0].proof.revocation_tag == scenarios[1].proof.revocation_tag

    user_list: list[backend.UserRow] = backend.get_users_list(db_conn)
    assert len(user_list) == 1
    assert user_list[0].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(user_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert user_list[0].current_generation_id == gen_ids[0]
    assert len(user_list[0].token) == backend.BLAKE2B_DIGEST_SIZE
    assert user_list[0].token == scenarios[1].proof.revocation_tag
    assert user_list[0].expiry_at == scenarios[1].expiry_at

    payment_list: list[backend.PaymentRow] = backend.get_payments_list(db_conn)
    assert len(payment_list) == 2
    assert payment_list[0].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(payment_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert payment_list[0].plan == scenarios[0].plan
    assert payment_list[0].payment_provider == scenarios[0].payment_provider
    assert payment_list[0].auto_renewing
    assert payment_list[0].redeemed_at == redeemed_at
    assert payment_list[0].expiry_at == scenarios[0].expiry_at
    assert payment_list[0].revoked_at is None
    assert payment_list[0].google_payment_token == scenarios[0].google_payment_token
    assert payment_list[0].google_order_id == scenarios[0].google_order_id
    assert not payment_list[0].apple.tx_id
    assert not payment_list[0].apple.original_tx_id
    assert not payment_list[0].apple.web_line_order_tx_id

    assert payment_list[1].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(payment_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert payment_list[1].plan == scenarios[1].plan
    assert payment_list[1].payment_provider == scenarios[1].payment_provider
    assert payment_list[1].auto_renewing
    assert payment_list[1].redeemed_at == redeemed_at
    assert payment_list[1].expiry_at == scenarios[1].expiry_at
    assert payment_list[1].revoked_at is None
    assert payment_list[1].google_payment_token == scenarios[1].google_payment_token
    assert payment_list[1].google_order_id == scenarios[1].google_order_id
    assert not payment_list[0].apple.tx_id
    assert not payment_list[0].apple.original_tx_id
    assert not payment_list[0].apple.web_line_order_tx_id

    revocation_list: list[backend.RevocationRow] = backend.get_revocations_list(db_conn)
    assert not revocation_list

    backend.delete_expired_apple_notification_uuids(db_conn, now=scenarios[0].expiry_at)
    backend.delete_expired_google_notifications(db_conn, now=scenarios[0].expiry_at)

    # NOTE: Update the latest payments grace period but set auto-renewing off
    payment_tx = base.PaymentProviderTransaction()
    payment_tx.provider = scenarios[1].payment_provider
    payment_tx.google_payment_token = scenarios[1].google_payment_token
    payment_tx.google_order_id = scenarios[1].google_order_id
    new_grace_period = pendulum.duration(milliseconds=10000)
    updated: bool = backend.update_payment_renewal_info(
        db_conn, payment_tx=payment_tx, grace_period=new_grace_period, auto_renewing=False, err=err
    )
    assert not err.has() and updated

    # NOTE: Verify that the new grace was assigned to the user
    payment_list = backend.get_payments_list(db_conn)
    assert len(payment_list) == 2
    assert payment_list[0].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(payment_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert payment_list[0].plan == scenarios[0].plan
    assert payment_list[0].payment_provider == scenarios[0].payment_provider
    assert payment_list[0].auto_renewing
    assert payment_list[0].redeemed_at == redeemed_at
    assert payment_list[0].expiry_at == scenarios[0].expiry_at
    assert payment_list[0].grace_period == scenarios[0].grace_period
    assert payment_list[0].revoked_at is None
    assert payment_list[0].google_payment_token == scenarios[0].google_payment_token
    assert payment_list[0].google_order_id == scenarios[0].google_order_id
    assert not payment_list[0].apple.tx_id
    assert not payment_list[0].apple.original_tx_id
    assert not payment_list[0].apple.web_line_order_tx_id

    assert payment_list[1].master_pkey == bytes(master_key.verify_key), 'lhs={}, rhs={}'.format(
        pk_hex(payment_list[0].master_pkey), pk_hex(master_key.verify_key)
    )
    assert payment_list[1].plan == scenarios[1].plan
    assert payment_list[1].payment_provider == scenarios[1].payment_provider
    assert not payment_list[1].auto_renewing
    assert payment_list[1].redeemed_at == redeemed_at
    assert payment_list[1].expiry_at == scenarios[1].expiry_at
    assert payment_list[1].grace_period == new_grace_period
    assert payment_list[1].revoked_at is None
    assert payment_list[1].google_payment_token == scenarios[1].google_payment_token
    assert payment_list[1].google_order_id == scenarios[1].google_order_id
    assert not payment_list[0].apple.tx_id
    assert not payment_list[0].apple.original_tx_id
    assert not payment_list[0].apple.web_line_order_tx_id

    # NOTE: Get the user and payments and verify that the expiry and grace are correct
    with db.transaction(db_conn) as tx:
        get: backend.GetUserAndPayments = backend.get_user_and_payments(tx, master_pkey=master_key.verify_key)
        assert not get.user.auto_renewing
        assert get.user.grace_period == new_grace_period

    # NOTE: Verify the DB invariants
    backend.verify_db(db_conn, err)
    if err.msg_list:
        for error in err.msg_list:
            print(f"ERROR: {error}")
        assert not err.msg_list

    # NOTE: Now test that if a user submits 2 payments with the same payment token the 2nd one gets
    # automatically redeemed (because the payment token matches the first payment) so the user
    # doesn't have to manually pair the master public key to that payment.
    auto_redeem_google_payment_token = 'fake_auto_redeem_token'
    auto_redeem_user_master_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    auto_redeem_user_rotating_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    auto_redeem_scenarios: list[Scenario] = [
        Scenario(
            google_payment_token=auto_redeem_google_payment_token,
            google_order_id='DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            plan=base.ProPlan.OneMonth,
            expiry_at=redeemed_at + 30 * base.DAY,
            grace_period=pendulum.duration(),
            payment_provider=base.PaymentProvider.GooglePlayStore,
        ),
        Scenario(
            google_payment_token=auto_redeem_google_payment_token,
            google_order_id='DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex(),
            plan=base.ProPlan.TwelveMonth,
            expiry_at=redeemed_at + 31 * base.DAY,
            grace_period=pendulum.duration(),
            payment_provider=base.PaymentProvider.GooglePlayStore,
        ),
    ]

    for index, it in enumerate(auto_redeem_scenarios):
        # Add the "unredeemed" version of the payment, e.g. mock the notification from
        # IOS App Store/Google Play Store
        assert it.payment_provider == base.PaymentProvider.GooglePlayStore, "Currently only google is mocked"
        payment_tx = base.PaymentProviderTransaction()
        payment_tx.provider = it.payment_provider
        payment_tx.google_payment_token = it.google_payment_token
        payment_tx.google_order_id = it.google_order_id
        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=payment_tx,
            plan=it.plan,
            purchased_at=now,
            expiry_at=it.expiry_at,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(auto_redeem_user_master_key.verify_key),
            err=err,
        )
        assert not err.msg_list

        # NOTE: Only for the first payment we will claim it. The 2nd one should automatically be
        # redeemed
        assert len(auto_redeem_scenarios) == 2
        if index == 0:
            unredeemed_payment_list = backend.get_unredeemed_payments_list(db_conn)
            assert len(unredeemed_payment_list) == 1

            # Client redeems the payment by requesting a proof (reconciles the pending payment).
            proof = _redeem_and_prove(
                db_conn, backend_key, auto_redeem_user_master_key, auto_redeem_user_rotating_key, now
            )

            # Verify payment was redeemed
            unredeemed_payment_list = backend.get_unredeemed_payments_list(db_conn)
            assert not unredeemed_payment_list

            payment_list = backend.get_payments_list(db_conn)
            assert len(payment_list) == 3

            # Privacy: capture the tag the manual redeem established. The proof carries it, and
            # the server-side auto-redeem below must leave it unchanged.
            with db.transaction(db_conn) as tx:
                auto_redeem_tag_after_manual = backend.get_user_and_payments(
                    tx, auto_redeem_user_master_key.verify_key
                ).user.token
            assert proof.revocation_tag == auto_redeem_tag_after_manual

        # NOTE: This is the payment that was not claimed via add_pro_payment. If we check the
        # payments table there should be 4 payments (2 from the first test, 2 from this test). The 2
        # from this test should be set to redeemed.
        if index == 1:
            unredeemed_payment_list = backend.get_unredeemed_payments_list(db_conn)
            assert not unredeemed_payment_list

            payments_list: list[backend.PaymentRow] = backend.get_payments_list(db_conn)
            assert len(payments_list) == 4
            assert derived_status(payments_list[2]) == base.PaymentStatus.Redeemed
            assert payments_list[2].google_order_id == auto_redeem_scenarios[0].google_order_id
            assert payments_list[2].google_payment_token == auto_redeem_google_payment_token
            assert payments_list[2].master_pkey == bytes(auto_redeem_user_master_key.verify_key)
            assert payments_list[2].purchased_at == now
            assert payments_list[2].auto_renewing
            assert payments_list[2].grace_period == auto_redeem_scenarios[0].grace_period

            assert derived_status(payments_list[3]) == base.PaymentStatus.Redeemed
            assert payments_list[3].google_order_id == auto_redeem_scenarios[1].google_order_id
            assert payments_list[3].google_payment_token == auto_redeem_google_payment_token
            assert payments_list[3].master_pkey == bytes(auto_redeem_user_master_key.verify_key)
            assert payments_list[3].redeemed_at == backend.to_redeemed_at(payments_list[3].purchased_at)
            assert payments_list[3].auto_renewing
            assert payments_list[3].grace_period == auto_redeem_scenarios[1].grace_period

            # Privacy (cadence leak): the SERVER-SIDE auto-redeem (the exact renewal path that
            # used to roll the generation on every cycle) must NOT change the observable revocation_tag.
            with db.transaction(db_conn) as tx:
                auto_redeem_tag_after_auto = backend.get_user_and_payments(
                    tx, auto_redeem_user_master_key.verify_key
                ).user.token
            assert auto_redeem_tag_after_auto == auto_redeem_tag_after_manual


def test_revocation_effective_ts_is_anchored_to_processing_time(monkeypatch, pg_database):
    # generations.revoked_at is OUR record stamp, and the served list turns it into
    # effective_ts = revoked_at + REVOCATION_EFFECTIVE_DELAY. Anchoring it to the store's refund date
    # instead is a real break: a notification we handle late (a backlog drained after an outage carries
    # refunds dated well back) would broadcast already-effective, so peers would reject the sender's proof
    # before it could possibly have polled and learnt of its own tag. payments.revoked_at keeps the store's
    # date regardless -- the user really was entitled until the store refunded.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    err = base.ErrorSink()
    master_key = nacl.signing.SigningKey.generate()
    recorded_at = base.utc_now()
    monkeypatch.setattr(base, 'utc_now', lambda: recorded_at)
    stale_revoke_at = recorded_at - 5 * base.DAY  # as if we had been down for five days

    def seed_google(conn, expiry_at):
        tx = base.PaymentProviderTransaction()
        tx.provider = base.PaymentProvider.GooglePlayStore
        tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        tx.google_order_id = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        backend.add_unredeemed_payment(
            conn,
            payment_tx=tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=recorded_at,
            expiry_at=expiry_at,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_key.verify_key),
            err=err,
        )
        assert not err.msg_list, err.msg_list
        return tx

    with db.connection() as conn:
        # Two payments so a surviving one keeps the account entitled: the refunded (longer) one is what a
        # live proof would have been clamped to, so revoking it really does need broadcasting.
        seed_google(conn, recorded_at + 3 * base.DAY)
        refunded = seed_google(conn, recorded_at + 40 * base.DAY)
        assert backend.reconcile_pending_payments(conn, master_key.verify_key, redeemed_at=recorded_at) == 2

        with db.transaction(conn) as tx:
            assert backend.add_google_revocation(
                tx, google_payment_token=refunded.google_payment_token, revoke_at=stale_revoke_at, err=err
            )
        assert not err.msg_list, err.msg_list

        revocations = backend.get_revocations_list(conn)
        assert len(revocations) == 1
        # Stamped with our clock, so the full delay is still ahead of the client that has to learn of it.
        # The store's date would have put effective_ts days in the past -- enforced before it could poll.
        assert revocations[0].revoked_at == recorded_at
        assert revocations[0].revoked_at + base.REVOCATION_EFFECTIVE_DELAY > recorded_at
        assert stale_revoke_at + base.REVOCATION_EFFECTIVE_DELAY < recorded_at

        # The entitlement side is unaffected: the payment carries the store's own refund date, and the fresh
        # generation minted for the surviving payment is issued at the revoke instant, not our stamp.
        refunded_row = [p for p in backend.get_payments_list(conn) if p.revoked_at is not None]
        assert len(refunded_row) == 1
        assert refunded_row[0].revoked_at == stale_revoke_at
        user = backend.get_user(conn, master_key.verify_key)
        assert user.current_generation_id != revocations[0].generation_id
        with db.transaction(conn) as tx:
            issued_at = db.query_scalar(
                tx.conn, "SELECT issued_at FROM generations WHERE id = %s", user.current_generation_id
            )
        assert issued_at == stale_revoke_at
    pool.close()


def test_renewal_binds_by_identifier_not_account_id(pg_database):
    # The renewal auto-redeem binds a payment to its owner by the payment's OWN store identifier (via the
    # subscription-continuity linkage), NOT the master-key-derived account-id -- so the mule never matches
    # on the appAccountToken UUID. Prove it: bind a payment whose stored account-id belongs to a DIFFERENT
    # key. reconcile (account-id) can't claim it; the direct bind does.
    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool
    owner = nacl.signing.SigningKey.generate()  # the payment's stored account-id
    binder = nacl.signing.SigningKey.generate()  # who we actually bind it to
    now = base.round_datetime_to_next_day(base.utc_now())

    def seed_google(conn, account_id_key):
        tx = base.PaymentProviderTransaction()
        tx.provider = base.PaymentProvider.GooglePlayStore
        tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        tx.google_order_id = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        err = base.ErrorSink()
        backend.add_unredeemed_payment(
            conn,
            payment_tx=tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=now,
            expiry_at=now + 30 * base.DAY,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(account_id_key.verify_key),
            err=err,
        )
        assert not err.msg_list, err.msg_list
        return tx

    with db.connection() as conn:
        # binder gets a user + entitlement the normal way.
        seed_google(conn, binder)
        assert backend.reconcile_pending_payments(conn, binder.verify_key, redeemed_at=now) == 1
        assert backend.get_user(conn, binder.verify_key).found

        # A payment whose stored account-id is `owner`'s key, not binder's.
        foreign = seed_google(conn, owner)
        # reconcile(binder) can't claim it — the account-id doesn't match binder's key.
        assert backend.reconcile_pending_payments(conn, binder.verify_key, redeemed_at=now) == 0
        # The direct bind binds it to binder by its own token, ignoring the account-id.
        with db.transaction(conn) as tx:
            backend._redeem_payment_for_user(tx, binder.verify_key, foreign, redeemed_at=now)

        # Everything is redeemed, and it went to binder (owner never became a user).
        assert not backend.get_unredeemed_payments_list(conn)
        assert not backend.get_user(conn, owner.verify_key).found
    pool.close()


def test_revocation_cutting_refund_rolls_generation(monkeypatch, pg_database):
    """The CUTTING refund: one that drops the user's remaining entitlement BELOW what an outstanding
    proof can still certify (a proof's reach is clamped to ~30 days) must revoke the current generation
    and roll the user onto a fresh one for the reduced-but-still-standing entitlement. This is the middle
    case between the two already covered in test_server_add_payment_flow: a non-cutting refund that leaves
    far-future entitlement (skip — no roll, no revocation entry) and a refund that leaves nothing (revoke
    without a roll — the terminally-revoked generation stays put)."""
    monkeypatch.setattr("providers.google_play.api.subscription_v1_acknowledge", lambda *a, **k: None)
    monkeypatch.setattr(
        "providers.google_play.api.fetch_subscription_v2_details",
        lambda *a, **k: google_play.types.SubscriptionV2Data(),
    )

    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = base.utc_now()
    redeemed_at = base.round_datetime_to_next_day(now)

    db_conn = db_engine.getconn()

    def seed_and_redeem(expiry_at: pendulum.DateTime) -> str:
        seed_tx = base.PaymentProviderTransaction()
        seed_tx.provider = base.PaymentProvider.GooglePlayStore
        seed_tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        seed_tx.google_order_id = 'DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=seed_tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=now,
            expiry_at=expiry_at,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_key.verify_key),
            err=err,
        )
        _redeem_and_prove(db_conn, backend_key, master_key, rotating_key, now)
        return seed_tx.google_payment_token

    try:
        # Two stacked payments on one shared generation: a long one we will refund and a short
        # survivor that leaves only ~5 days of entitlement — less than the ~30-day reach of a live proof.
        long_token = seed_and_redeem(redeemed_at + 90 * base.DAY)
        seed_and_redeem(redeemed_at + 5 * base.DAY)

        with db.transaction(db_conn) as tx:
            user_before = backend.get_user_and_payments(tx, master_key.verify_key).user
        gen_before, token_before = user_before.current_generation_id, user_before.token

        # Refund the long payment. The survivor leaves entitlement well inside the proof-reach window, so
        # an outstanding proof would now over-certify: the generation must roll.
        with db.transaction(db_conn) as tx:
            revoked = backend.add_google_revocation(tx, google_payment_token=long_token, revoke_at=now, err=err)
            assert revoked
            assert not err.has()

        with db.transaction(db_conn) as tx:
            user_after = backend.get_user_and_payments(tx, master_key.verify_key)
            assert user_after.user.current_generation_id != gen_before
            assert user_after.user.token != token_before
            assert not backend.is_generation_revoked(tx.conn, user_after.user.current_generation_id, now)
            assert backend.is_generation_revoked(tx.conn, gen_before, now)
        assert len(backend.get_revocations_list(db_conn)) == 1
    finally:
        db_engine.putconn(db_conn)
        db_engine.close()


def test_revocation_skips_broadcast_when_an_unclaimed_payment_survives(pg_database):
    """The mirror of the cutting refund: the account keeps a live payment the mule registered but the owner
    has not claimed yet, so the refund must NOT broadcast. `_lookup_user_expiry` is user-scoped and a
    user_id exists only on a redeemed payment, so that survivor is invisible to the "is a broadcast
    necessary" check unless the revoke path reconciles first -- and broadcasting would revoke every
    outstanding proof and cost an entry in the list every client fetches, for an account whose paid
    coverage never actually lapsed."""
    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=pg_database())
    assert db_engine

    backend_key = nacl.signing.SigningKey.generate()
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    now = base.utc_now()
    redeemed_at = base.round_datetime_to_next_day(now)

    db_conn = db_engine.getconn()

    def seed(expiry_at: pendulum.DateTime) -> str:
        seed_tx = base.PaymentProviderTransaction()
        seed_tx.provider = base.PaymentProvider.GooglePlayStore
        seed_tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        seed_tx.google_order_id = 'DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
        backend.add_unredeemed_payment(
            db_conn,
            payment_tx=seed_tx,
            plan=base.ProPlan.OneMonth,
            purchased_at=now,
            expiry_at=expiry_at,
            platform_refund_expiry_at=base.EPOCH,
            platform_obfuscated_account_id=bytes(master_key.verify_key),
            err=err,
        )
        assert not err.msg_list, err.msg_list
        return seed_tx.google_payment_token

    try:
        # Claim a payment first, so the account has a user, a generation and an outstanding proof.
        refunded_token = seed(redeemed_at + 30 * base.DAY)
        _redeem_and_prove(db_conn, backend_key, master_key, rotating_key, now)

        # A second, longer payment then arrives from the store. The owner has made no request since, so it
        # is registered-but-unclaimed. Far enough out that it alone keeps every outstanding proof honest.
        seed(redeemed_at + 200 * base.DAY)

        with db.transaction(db_conn) as tx:
            before = backend.get_user_and_payments(tx, master_key.verify_key).user

        with db.transaction(db_conn) as tx:
            assert backend.add_google_revocation(tx, google_payment_token=refunded_token, revoke_at=now, err=err)
            assert not err.msg_list, err.msg_list

        with db.transaction(db_conn) as tx:
            after = backend.get_user_and_payments(tx, master_key.verify_key).user
            assert after.current_generation_id == before.current_generation_id
            assert after.token == before.token
            assert not backend.is_generation_revoked(tx.conn, after.current_generation_id, now)
        assert backend.get_revocations_list(db_conn) == []

        # The survivor was bound on the way through, so it is what the account's entitlement now rests on.
        assert not backend.get_unredeemed_payments_list(db_conn)
        assert after.expiry_at == redeemed_at + 200 * base.DAY
    finally:
        db_engine.putconn(db_conn)
        db_engine.close()


def test_payment_binding_rejects_mismatched_master_key(pg_database):
    '''The store-attested account tag binds a payment to exactly one master key: a purchase tagged for
    key A cannot be claimed by a different key B. reconcile matches on the master-key-derived account-id,
    so B's reconcile claims nothing while A's claims the payment. Covers both providers -- Google's
    raw-pubkey tag and Apple's derived-UUID tag -- i.e. the property that closes the Apple tx_id
    authorization hole (the old `''` stub let any key claim any tx_id).'''
    db_engine = backend.bootstrap_db(database_url=pg_database())
    assert db_engine
    owner = nacl.signing.SigningKey.generate()
    attacker = nacl.signing.SigningKey.generate()
    now = base.utc_now()
    redeemed_at = base.round_datetime_to_next_day(now)

    db_conn = db_engine.getconn()
    try:

        def check_binding(seed_tx, owner_tag):
            err = base.ErrorSink()
            backend.add_unredeemed_payment(
                db_conn,
                payment_tx=seed_tx,
                plan=base.ProPlan.OneMonth,
                purchased_at=now,
                expiry_at=redeemed_at + 30 * base.DAY,
                platform_refund_expiry_at=base.EPOCH,
                platform_obfuscated_account_id=owner_tag,
                err=err,
            )
            assert not err.has(), err.msg_list

            # A different key claims nothing -- its derived account-id != the stored tag.
            assert backend.reconcile_pending_payments(db_conn, attacker.verify_key, redeemed_at=redeemed_at) == 0
            # The tagged owner can claim the very same payment.
            assert backend.reconcile_pending_payments(db_conn, owner.verify_key, redeemed_at=redeemed_at) == 1

        # Google: the tag is the raw 32-byte master pubkey.
        g_seed = base.PaymentProviderTransaction()
        g_seed.provider = base.PaymentProvider.GooglePlayStore
        g_seed.google_payment_token = os.urandom(8).hex()
        g_seed.google_order_id = os.urandom(8).hex()
        check_binding(g_seed, bytes(owner.verify_key))

        # Apple: the tag is the derived v4 UUID of the pubkey.
        a_seed = base.PaymentProviderTransaction()
        a_seed.provider = base.PaymentProvider.iOSAppStore
        a_seed.apple_original_tx_id = os.urandom(8).hex()
        a_seed.apple_tx_id = os.urandom(8).hex()
        a_seed.apple_web_line_order_tx_id = os.urandom(8).hex()
        check_binding(a_seed, app_store.uuid_from_master_pk(bytes(owner.verify_key)))
    finally:
        db_engine.putconn(db_conn)
        db_engine.close()
