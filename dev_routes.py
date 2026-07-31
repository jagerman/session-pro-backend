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

import base
import db
import minting
import server

log = logging.getLogger('PRO')

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
        f'(redeemed={minted.redeemed}, expiry={base.readable(minted.expiry_at)}) for '
        f'{base.maybe_obfuscate_bytes(master_pkey_bytes)} — no payment provider was involved'
    )

    result: dict[str, typing.Any] = {
        'provider': provider.value,
        'payment_id': minted.payment_id,
        'plan': minted.plan.value,
        'expiry_ts': base.unix_seconds_from_datetime(minted.expiry_at),
        'redeemed': minted.redeemed,
    }
    return server.make_success_response(dict_result=result)
