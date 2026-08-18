'''
Development-only HTTP routes. NOT part of the wire spec and NOT safe on any real instance.

These exist so an end-to-end test can put an account into a Pro state without a payment provider: a
device sits on the buy-Pro page, the harness POSTs `/dev/add_payment` for whichever provider it wants
to exercise, the device refreshes through its normal `generate_pro_proof` path and sees Pro. No store,
no credentials, no egress.

There is no authentication here — by design. The security model is that the route does not exist in
production, enforced in three independent places:

  - it is a separate module, imported ONLY when `dev_endpoints` is set (see server.init);
  - `config.parse_args` refuses to start at all if `dev_endpoints` is on without `provider_dry_run`,
    so an instance that can still reach Apple/Google can never serve these;
  - `scripts/nginx/pro-backend.conf.example` deliberately omits `/dev` from its route allowlist, so a
    real deployment 404s these at the proxy even if the flag is misconfigured.

Anything added here must keep all three true.
'''

import logging
import typing

import flask
import nacl.bindings
import nacl.signing
import pendulum

import backend
import base
import db
import minting
import server

log = logging.getLogger('pro')

FLASK_ROUTE_DEV_ADD_PAYMENT = '/dev/add_payment'

flask_blueprint = flask.Blueprint('session-pro-backend-dev-blueprint', __name__)


@flask_blueprint.route(FLASK_ROUTE_DEV_ADD_PAYMENT, methods=['POST'])
def dev_add_payment() -> flask.Response:
    '''Mint a payment for `master_pkey` that no payment provider ever witnessed.

    Request:
      master_pkey  64-hex Ed25519 master Pro public key of the recipient (required)
      provider     "google_play" | "app_store" | "stf" (required)
      plan         "1M" | "3M" | "12M" — or the wire codes "1m"/"3m"/"1y" (required)
      duration     optional, seconds; overrides the plan's nominal length (short-expiry tests)
      redeem       optional, default true. False leaves the payment unredeemed and returns its
                   payment_id; for Google/Apple the account holder's next authenticated request
                   (generate_pro_proof / get_pro_status) then reconciles it automatically. A stf payment
                   has no store account-id, so leave redeem at its default for it.
    '''
    get_json = server.get_json_from_flask_request(flask.request)

    master_pkey = base.json_dict_require_str(get_json, 'master_pkey')
    provider_code = base.json_dict_require_str(get_json, 'provider')
    plan_code = base.json_dict_require_str(get_json, 'plan')

    master_pkey_bytes = base.hex_to_bytes(
        hex=master_pkey, label='Master public key', hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2
    )

    base.verify_payment_provider(payment_provider=provider_code)
    provider = base.PaymentProvider(provider_code)

    plan = minting.plan_from_label(plan_code)
    if plan is None:
        raise base.FailError(f'Unrecognised plan: {plan_code} (expected one of 1M, 3M, 12M)')

    # duration is optional; omitting it means "use the plan's nominal length".
    raw_duration = get_json.get('duration')
    if raw_duration is not None:
        # The type check belongs here because this is untrusted JSON. `bool` subclasses `int`, so a
        # bare isinstance(_, int) would accept `true` and then read it as 1 second.
        duration_is_whole_seconds = isinstance(raw_duration, int) and not isinstance(raw_duration, bool)
        if not duration_is_whole_seconds:
            raise base.FailError('duration must be a positive integer number of seconds')

    # The positive-value rule lives in minting, so the CLI enforces exactly the same bounds.
    duration = minting.duration_from_seconds(raw_duration)

    raw_redeem = get_json.get('redeem', True)
    if not isinstance(raw_redeem, bool):
        raise base.FailError('redeem must be a boolean')

    now = base.datetime_from_unix_ms(int(server.time_now() * 1000))

    with db.connection() as conn:
        minted: minting.MintedPayment = minting.mint_payment(
            conn,
            master_pkey=nacl.signing.VerifyKey(master_pkey_bytes),
            provider=provider,
            plan=plan,
            now=now,
            duration=duration,
            redeem=raw_redeem,
        )

    log.warning(
        f'DEV: minted a {minted.plan.value} {provider.value} payment '
        f'(redeemed={minted.redeemed}, '
        f'account_expiry={base.readable(minted.account_expiry_at) if minted.account_expiry_at else "unclaimed"})'
        f' for '
        f'{base.maybe_obfuscate_bytes(master_pkey_bytes)} — no payment provider was involved'
    )

    result: dict[str, typing.Any] = {
        'provider': provider.value,
        'payment_id': minted.payment_id,
        'plan': minted.plan.value,
        'account_expiry_ts': (
            base.unix_seconds_from_datetime(minted.account_expiry_at) if minted.account_expiry_at else 0
        ),
        'redeemed': minted.redeemed,
    }
    return server.make_success_response(dict_result=result)


FLASK_ROUTE_DEV_REVOKE = '/dev/revoke'


@flask_blueprint.route(FLASK_ROUTE_DEV_REVOKE, methods=['POST'])
def dev_revoke() -> flask.Response:
    '''Revoke `master_pkey`'s current generation, optionally already past its effective instant.

    Request:
      master_pkey          64-hex Ed25519 master Pro public key (required)
      effective_in_seconds optional, default 0. Seconds from now until peers should begin rejecting
                           proofs carrying the revoked tag. 0 means "already effective", which is what
                           a test asserting enforcement needs; a positive value lands inside the grace
                           window instead, for a test asserting a revoked-but-not-yet-effective proof
                           is still honoured.

    Why this mirrors `backend.revoke_master_pkey_proofs_and_allocate_new_gen_id` rather than calling it:
    that function stamps `revoked_at` from its own clock deliberately and refuses to take it as a
    parameter, because a real revocation broadcast already-effective would have peers rejecting a
    sender before it could have polled and learnt of it. The served list then reads
    `effective_ts = revoked_at + REVOCATION_EFFECTIVE_DELAY`, a fixed 26 hours, and the DB forbids
    re-stamping `revoked_at` once set. So an effective revocation is unreachable from the production
    path within a test, and the only lever is the first write of that column.

    Both triggers still apply and both still matter: the first NULL -> value write bumps the revocation
    ticket exactly as production does, and `generations_revoked_at_is_terminal` still forbids a second
    change, so a double-revoke through here fails the same way it would in production.
    '''
    get_json = server.get_json_from_flask_request(flask.request)

    master_pkey = base.json_dict_require_str(get_json, 'master_pkey')
    master_pkey_bytes = base.hex_to_bytes(
        hex=master_pkey, label='Master public key', hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2
    )
    verify_key = nacl.signing.VerifyKey(master_pkey_bytes)

    raw_effective_in = get_json.get('effective_in_seconds', 0)
    # `bool` subclasses `int`, so a bare isinstance would read `true` as 1 second — same trap the
    # `duration` field above documents.
    if isinstance(raw_effective_in, bool) or not isinstance(raw_effective_in, int) or raw_effective_in < 0:
        raise base.FailError('effective_in_seconds must be a non-negative integer number of seconds')

    now = base.utc_now()
    # Work backwards from when we want peers to enforce: the served list adds the delay to whatever is
    # stored, so storing `target - delay` puts the effective instant exactly where the caller asked.
    revoked_at = now + pendulum.duration(seconds=raw_effective_in) - base.REVOCATION_EFFECTIVE_DELAY

    with db.connection() as conn:
        with db.transaction(conn) as tx:
            revoked = db.query_one(
                tx.conn,
                '''
                UPDATE generations
                SET    revoked_at = %(revoked_at)s
                WHERE  id = (SELECT current_generation_id FROM users WHERE master_pkey = %(master_pkey)s)
                  AND  revoked_at IS NULL
                RETURNING id
            ''',
                master_pkey=bytes(verify_key),
                revoked_at=revoked_at,
            )

            if revoked is None:
                raise base.FailError(
                    f'No live generation to revoke for {master_pkey} '
                    f'(unknown account, or its current generation is already revoked)'
                )

            # Roll any still-usable payments onto a fresh generation, as production does — without this
            # the account has no generation to issue future proofs under, which is a different state to
            # the one a revocation produces.
            allocated = backend._ensure_active_generation(tx, verify_key, issued_at=now)

    log.warning(
        f'DEV: revoked generation {revoked[0]} for {base.maybe_obfuscate_bytes(master_pkey_bytes)}, '
        f'effective {base.readable(now + pendulum.duration(seconds=raw_effective_in))} '
        f'(revoked_at backdated to {base.readable(revoked_at)}) — no payment provider was involved'
    )

    result: dict[str, typing.Any] = {
        'revoked_generation_id': revoked[0],
        'effective_ts': base.unix_seconds_from_datetime(now + pendulum.duration(seconds=raw_effective_in)),
        'new_generation_allocated': allocated.found,
    }
    return server.make_success_response(dict_result=result)
