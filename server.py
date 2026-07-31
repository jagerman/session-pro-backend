'''
Overview
  This file is the HTTP layer serving the Session Pro Backend routes on a Flask application. Its role is
  to intercept and sanitize each HTTP request, extract the JSON into valid, strongly-typed values, and
  hand them to the backend. The backend does the real validation (signature verification, DB-state
  consistency) and returns a result, which this layer pipes back in the HTTP response.

  All endpoints share the response envelope of wire spec §5 (`{"status": "ok"|"fail"|"error", ...}`; HTTP
  is always 200, the envelope `status` is authoritative). Failures raised as base.FailError /
  base.ServerError anywhere in the request path are rendered by the app error handler below. All routes
  also accept v4 onion requests at /oxen/v4/lsrpc.

  The authoritative wire/proof format — endpoints, signed-message layouts, response shapes, and the
  revocation list — is documented in docs/pro-wire-protocol.md.

  Endpoints served here: generate_pro_proof, get_pro_revocations, get_pro_status, get_payment_details,
  status, apple_notifications_v2 (Apple webhook), oxen/v4/lsrpc (onion transport).
'''

import pendulum
import enum
import flask
import json
import nacl.bindings
import nacl.public
import nacl.signing
import time
import typing
import db

import base
import backend
from vendor import onion_req


class UserProStatus(enum.StrEnum):
    # Overall Pro status of the account, emitted as the top-level `user_status` code in the get-details
    # response. A string code (not an integer) so an unknown future value passes through opaquely and
    # old clients degrade gracefully instead of hard-failing the whole parse — see the wire spec §1.
    Never = 'never'
    Active = 'active'
    Expired = 'expired'


# The backend Ed25519 signing key (nacl.signing.SigningKey), loaded from disk at startup. Kept in
# the flask config rather than the DB so it never touches the database (or its backups).
FLASK_CONFIG_BACKEND_SKEY_KEY = 'session_pro_backend_signing_key'

# The object containing routes that you register onto a Flask app to turn it
# into an app that accepts Session Pro Backend client requests.
flask_blueprint = flask.Blueprint('session-pro-backend-blueprint', __name__)


# All calls to time.time() in the server layer are now routed through the function pointer
# 'time_now'. This is primarily for unit tests which recorded real-time payment data on test
# networks that have had timestamps encoded in the past.
#
# Calls into the server layer were using the current system time (say for timestamp on signature
# validation) to prevent stale signatures that would break in those contexts. In the tests then
# the code changes the 'time_now()' implementation to "mock" the time of the server back to when the
# real-time data was being captured and tested.
def time_now():
    return time.time()


def make_success_response(dict_result: typing.Any) -> flask.Response:
    return flask.jsonify({'status': 'ok', 'result': dict_result})


@flask_blueprint.app_errorhandler(base.ApiError)
def handle_api_error(e: base.ApiError) -> flask.Response:
    # Every request-path failure is raised as a base.ApiError (FailError/ServerError) and rendered here as
    # the response envelope (wire spec §5). It fires inside Flask's dispatch — including the onion
    # subrequest's full_dispatch_request — so the envelope is produced in-band and onion-wrapped normally.
    # HTTP stays 200 (the envelope `status` is authoritative; make_subrequest warns on any non-200).
    envelope: dict[str, typing.Any] = {'status': e.wire_status, 'error_code': e.code.value, 'error': str(e)}
    # Optional extra fields carried on the error (e.g. account_expiry_ts on a subscription_expired fail).
    envelope.update(e.data)
    return flask.jsonify(envelope)


def get_json_from_flask_request(request: flask.Request) -> dict[str, typing.Any]:
    # Parse the request body as a JSON object, or raise FailError(invalid_request).
    try:
        json_dict = json.loads(request.data)
    except Exception as e:
        raise base.FailError(f'Failed to parse JSON body: {e}')
    if not isinstance(json_dict, dict):
        raise base.FailError('JSON body was not an object')
    return typing.cast(dict[str, typing.Any], json_dict)


def init(
    testing_mode: bool, database_url: str, backend_key: nacl.signing.SigningKey, dev_endpoints: bool = False
) -> flask.Flask:
    result = flask.Flask(__name__)
    result.config['TESTING'] = testing_mode
    db.set_dsn(database_url)
    result.config[FLASK_CONFIG_BACKEND_SKEY_KEY] = backend_key
    result.config[onion_req.FLASK_CONFIG_ONION_REQ_X25519_SKEY] = backend_key.to_curve25519_private_key()
    result.register_blueprint(flask_blueprint)
    result.register_blueprint(onion_req.flask_blueprint_v4)

    # NOTE: The /dev/* routes forge payments with no provider and no signature. Import AND register them
    # only when explicitly enabled — a disabled instance never even loads the module, so the routes cannot
    # exist by accident. config.parse_args additionally refuses to start if this is on without
    # provider_dry_run, and scripts/nginx/pro-backend.conf.example deliberately omits /dev from its
    # allowlist so a real deployment 404s them at the proxy regardless. DO NOT hoist this import.
    if dev_endpoints:
        import dev_routes

        result.register_blueprint(dev_routes.flask_blueprint)
    return result


@flask_blueprint.route('/status', methods=['GET', 'POST'])
def status():
    # Health/readiness probe. Unauthenticated, no DB access, no request body — reachable both directly
    # (a plain GET, for monitors) and over the v4 onion transport (GET or POST). Returns the backend
    # version, the current server time, and the Ed25519 signing public key so a caller can fetch the key
    # to verify issued proofs against instead of hard-coding it.
    backend_key: nacl.signing.SigningKey = flask.current_app.config[FLASK_CONFIG_BACKEND_SKEY_KEY]
    return make_success_response(
        dict_result={
            'version': base.BACKEND_VERSION,
            'timestamp': int(time_now()),  # integer UNIX seconds (wire spec §1)
            'signing_pubkey': bytes(backend_key.verify_key).hex(),
        }
    )


@flask_blueprint.route('/generate_pro_proof', methods=['POST'])
def generate_pro_proof() -> flask.Response:
    # Extract + validate request fields (each raises FailError(invalid_request) on the first bad field).
    get_json = get_json_from_flask_request(flask.request)
    master_pkey = base.json_dict_require_str(get_json, 'master_pkey')
    rotating_pkey = base.json_dict_require_str(get_json, 'rotating_pkey')
    ts = base.json_dict_require_int(get_json, 'ts')
    master_sig = base.json_dict_require_str(get_json, 'master_sig')
    rotating_sig = base.json_dict_require_str(get_json, 'rotating_sig')

    master_pkey_bytes = base.hex_to_bytes(
        hex=master_pkey, label='Master public key', hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2
    )
    rotating_pkey_bytes = base.hex_to_bytes(
        hex=rotating_pkey, label='Rotating public key', hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2
    )
    master_sig_bytes = base.hex_to_bytes(
        hex=master_sig, label='Master key signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2
    )
    rotating_sig_bytes = base.hex_to_bytes(
        hex=rotating_sig, label='Rotating key signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2
    )

    # Timestamp must be within tolerance of now (replay mitigation). The wire nonce is integer seconds
    # (§3); the comparison is datetime-native. Out of window → stale_request (client can re-sync + retry).
    request_at = base.datetime_from_unix_seconds(ts)
    now = base.datetime_from_unix_ms(int(time_now() * 1000))
    if abs(now - request_at) > base.DEFAULT_TIMESTAMP_TOLERANCE:
        raise base.FailError(
            f'Nonce timestamp is outside the tolerance window: {base.readable(request_at)} (now {base.readable(now)})',
            code=base.ErrorCode.stale_request,
        )

    # Request proof from the backend (raises FailError(bad_signature/revoked/expired/not_subscribed)).
    with db.connection() as conn:
        proof = backend.generate_pro_proof(
            conn=conn,
            signing_key=flask.current_app.config[FLASK_CONFIG_BACKEND_SKEY_KEY],
            master_pkey=nacl.signing.VerifyKey(master_pkey_bytes),
            rotating_pkey=nacl.signing.VerifyKey(rotating_pkey_bytes),
            request_at=request_at,
            master_sig=master_sig_bytes,
            rotating_sig=rotating_sig_bytes,
        )
        return make_success_response(dict_result=proof.to_dict())


@flask_blueprint.route('/get_pro_revocations', methods=['POST'])
def get_pro_revocations():
    get_json = get_json_from_flask_request(flask.request)
    ticket: int = base.json_dict_require_int(get_json, 'ticket')

    RETRY_IN = base.seconds_from_duration(base.REVOCATION_POLL_INTERVAL)
    # List-level window (≥ the max proof validity) after which a client drops a seen entry from its
    # in-memory revocation list (wire spec §4). Memory-only aging: a dropped entry can't reactivate
    # anything, so this has no correctness dependence.
    RETAIN_FOR = base.seconds_from_duration(base.REVOCATION_RETAIN_FOR)
    now = base.datetime_from_unix_ms(int(time_now() * 1000))
    revocation_items: list[dict[str, str | int]] = []
    revocation_ticket: int = 0
    with db.connection() as conn:
        with db.transaction(conn) as tx:
            revocation_ticket = backend.get_revocation_ticket(tx.conn)
            if ticket < revocation_ticket:
                # Served list = revoked generations still inside the retention window (`revoked_at >
                # now - retain_for`). Filtering by the window (rather than depending on a prune) keeps
                # the answer independent of whether housekeeping has run; the token IS the wire tag.
                retain_cutoff = now - pendulum.duration(seconds=RETAIN_FOR)
                for revocation in backend.get_revocations_list(tx.conn, revoked_after=retain_cutoff):
                    # `revoked_at` is when the BACKEND recorded the revocation (not the store's own
                    # refund date — see revoke_master_pkey_proofs_and_allocate_new_gen_id), so this
                    # delay is always fully ahead of the client that has to learn of it. Derived from
                    # `retry_in` but deliberately larger: that one is a poll-cadence hint, this is the
                    # guarantee that a revoked sender sees its tag before peers start rejecting it.
                    effective_at = revocation.revoked_at + base.REVOCATION_EFFECTIVE_DELAY
                    # Per-entry wire shape (spec §4): revocation_tag + effective_ts only.
                    # Clients age entries out via the list-level retain_for below, not a per-entry expiry.
                    revocation_items.append(
                        {
                            'revocation_tag': revocation.token.hex(),
                            # Integer seconds: a computed instant (wire spec §1/§4).
                            'effective_ts': base.unix_seconds_from_datetime(effective_at),
                        }
                    )

        return make_success_response(
            dict_result={
                'ticket': revocation_ticket,
                'items': revocation_items,
                'retry_in': RETRY_IN,
                'retain_for': RETAIN_FOR,
            }
        )


MAX_PAYMENT_DETAILS_PAGE = 100  # server-side cap on a get-payment-details page (client `limit` is clamped)


def _check_read_replay_window(request_at: pendulum.DateTime) -> None:
    # Timestamp anti-replay window (wire nonce is integer seconds). Out of window → stale_request. (We
    # _could_ track recent nonces to reject replays outright, but the onion transport already masks replay
    # ability for a read-only query.)
    now = base.datetime_from_unix_ms(int(time_now() * 1000))
    if abs(now - request_at) >= base.DEFAULT_TIMESTAMP_TOLERANCE:
        raise base.FailError(
            f'Timestamp is outside the tolerance window, delta was {abs(now - request_at)}',
            code=base.ErrorCode.stale_request,
        )


def _verify_master_sig(master_pkey_nacl: nacl.signing.VerifyKey, master_sig_bytes: bytes, message: bytes) -> None:
    try:
        master_pkey_nacl.verify(smessage=message, signature=master_sig_bytes)
    except Exception:
        raise base.FailError('Signature failed to be verified', code=base.ErrorCode.bad_signature)


def _payment_item_wire(
    payment: backend.PaymentRow, request_at: pendulum.DateTime
) -> dict[str, str | int | float | bool]:
    # Wire seconds (wire spec §1/§5): integer everywhere the backend computes/rounds the value; the two
    # upstream provider event instants — `purchased_ts` and `revoked_ts` — are floats carrying the
    # provider's sub-second precision. `payment_id` is the single opaque value (§5.2). Every item is a
    # payment already bound to the requesting account: both callers page through
    # backend.get_user_payments_page, which is user-scoped.
    return {
        'status': backend.derive_payment_status(payment, request_at).value,
        'plan': payment.plan.value,
        'payment_provider': payment.payment_provider.value,
        'auto_renewing': payment.auto_renewing,
        'purchased_ts': base.unix_seconds_float_from_datetime(payment.purchased_at),
        'expiry_ts': base.unix_seconds_from_datetime(payment.expiry_at),
        'grace_period_duration': (
            base.seconds_from_duration(payment.grace_period) if payment.grace_period is not None else 0
        ),
        'platform_refund_expiry_ts': base.unix_seconds_from_datetime(payment.platform_refund_expiry_at),
        'revoked_ts': base.unix_seconds_float_from_datetime(payment.revoked_at) if payment.revoked_at else 0.0,
        'payment_id': backend.payment_id_from_payment_row(payment),
    }


@flask_blueprint.route('/get_pro_status', methods=['POST'])
def get_pro_status():
    # Cheap, hot-path entitlement check: the account's Pro status + the single latest payment item. No
    # history, no pagination — this is what clients hit to render "am I Pro?" / the Pro-settings screen.
    get_json = get_json_from_flask_request(flask.request)
    master_pkey = base.json_dict_require_str(get_json, 'master_pkey')
    master_sig = base.json_dict_require_str(get_json, 'master_sig')
    ts = base.json_dict_require_int(get_json, 'ts')

    master_pkey_bytes = base.hex_to_bytes(
        hex=master_pkey, label='Master public key', hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2
    )
    master_sig_bytes = base.hex_to_bytes(
        hex=master_sig, label='Master key signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2
    )
    request_at = base.datetime_from_unix_seconds(ts)
    _check_read_replay_window(request_at)

    master_pkey_nacl = nacl.signing.VerifyKey(master_pkey_bytes)
    _verify_master_sig(
        master_pkey_nacl,
        master_sig_bytes,
        backend.make_get_pro_status_message(master_pkey=master_pkey_nacl, request_at=request_at),
    )

    user_pro_status = UserProStatus.Never
    auto_renewing = False
    expiry_ts = 0
    grace_period_duration = 0
    error_report = 0
    latest_payment: dict[str, str | int | float | bool] | None = None

    with db.connection() as conn:
        with db.transaction(conn) as tx:
            # Bind any payment the mule has registered for this key but that isn't yet redeemed, so a
            # status check right after purchase reflects it. No-op when there's nothing new.
            backend.reconcile_pending_payments(tx, master_pkey_nacl, redeemed_at=backend.to_redeemed_at(request_at))
            error_report = int(backend.has_user_error_from_master_pkey(tx, master_pkey_nacl))
            user = backend.get_user(tx.conn, master_pkey_nacl)
            if user.found:
                auto_renewing = user.auto_renewing
                # Egress: user instants/durations → integer-seconds wire values. This is the account's
                # TRUE expiry, straight from the store, so any sub-second part is floored (wire spec §1)
                # — unlike the proof's expiry, which lands on a whole second by construction (§2.3).
                expiry_ts = base.unix_seconds_from_datetime(user.expiry_at)
                grace_period_duration = base.seconds_from_duration(user.grace_period)

                # Status decided against the *request* clock (signed, anti-replay-bounded to ≈now) —
                # the same clock the latest item's derived status uses, never a second time.time().
                user_pro_status = UserProStatus.Active if request_at <= user.expiry_at else UserProStatus.Expired
                if backend.is_generation_revoked(tx.conn, user.current_generation_id, request_at):
                    user_pro_status = UserProStatus.Expired

                page = backend.get_user_payments_page(tx, master_pkey_nacl, limit=1, before_id=None)
                if page:
                    latest_payment = _payment_item_wire(page[0], request_at)

    return make_success_response(
        {
            'user_status': user_pro_status.value,
            'auto_renewing': auto_renewing,
            'expiry_ts': expiry_ts,
            'grace_period_duration': grace_period_duration if auto_renewing else 0,
            'error_report': error_report,
            'latest_payment': latest_payment,
        }
    )


@flask_blueprint.route('/get_payment_details', methods=['POST'])
def get_payment_details():
    # Extract + validate request fields (each raises FailError(invalid_request) on the first bad field).
    get_json = get_json_from_flask_request(flask.request)
    master_pkey = base.json_dict_require_str(get_json, 'master_pkey')
    master_sig = base.json_dict_require_str(get_json, 'master_sig')
    ts = base.json_dict_require_int(get_json, 'ts')
    limit = base.json_dict_require_int(get_json, 'limit')
    before = get_json.get('before', '')  # opaque cursor; '' / absent = newest page
    if not isinstance(before, str):
        raise base.FailError("'before' cursor must be a string", code=base.ErrorCode.invalid_request)

    master_pkey_bytes = base.hex_to_bytes(
        hex=master_pkey, label='Master public key', hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2
    )
    master_sig_bytes = base.hex_to_bytes(
        hex=master_sig, label='Master key signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2
    )
    request_at = base.datetime_from_unix_seconds(ts)
    _check_read_replay_window(request_at)

    master_pkey_nacl = nacl.signing.VerifyKey(master_pkey_bytes)
    _verify_master_sig(
        master_pkey_nacl,
        master_sig_bytes,
        backend.make_get_payment_details_message(
            master_pkey=master_pkey_nacl, request_at=request_at, limit=limit, before=before
        ),
    )

    # Clamp the (signed) client limit to the server page cap, and decode the opaque cursor to its boundary
    # id. A bad / forged / foreign cursor fails to decrypt → invalid_request.
    if limit <= 0:
        raise base.FailError("'limit' must be positive", code=base.ErrorCode.invalid_request)
    limit = min(limit, MAX_PAYMENT_DETAILS_PAGE)
    cursor_key = backend.payment_cursor_key(flask.current_app.config[FLASK_CONFIG_BACKEND_SKEY_KEY])
    before_id: int | None = None
    if before:
        try:
            before_id = backend.decrypt_payment_cursor(cursor_key, master_pkey_nacl, before)
        except Exception:
            raise base.FailError('Invalid pagination cursor', code=base.ErrorCode.invalid_request)

    items: list[dict[str, str | int | float | bool]] = []
    payments_total = 0
    with db.connection() as conn:
        with db.transaction(conn) as tx:
            # Bind any mule-registered-but-unredeemed payment for this key first, so a details check
            # right after purchase includes it (only redeemed payments are user-scoped/visible below).
            backend.reconcile_pending_payments(tx, master_pkey_nacl, redeemed_at=backend.to_redeemed_at(request_at))
            # One keyset page, newest-first. Each item's status is derived against the *request*
            # clock `ts` (signed, anti-replay-bounded to ≈now), never a second time.time() read.
            # The query is user-scoped and only redeemed payments carry a user_id, so unredeemed
            # rows (whose tokens are confidential until the user registers them) never appear.
            page = backend.get_user_payments_page(tx, master_pkey_nacl, limit=limit, before_id=before_id)
            payments_total = backend.get_user_payments_count(tx, master_pkey_nacl)
            items = [_payment_item_wire(payment, request_at) for payment in page]

    # A full page means there may be more: seal the oldest id on this page into a cursor so the next
    # request continues at id < that. A short (or empty) page is the end → no cursor.
    next_cursor: str | None = None
    if page and len(page) == limit:
        next_cursor = backend.encrypt_payment_cursor(cursor_key, master_pkey_nacl, page[-1].id)

    return make_success_response({'payments_total': payments_total, 'items': items, 'next_cursor': next_cursor})
