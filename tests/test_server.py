'''
The HTTP surface end to end: a payment registered by a provider, then every client route that
reads it.
'''

import flask
import json
import nacl.signing
import nacl.bindings
import nacl.public
import os
import pendulum
import pytest
import time
import werkzeug
import psycopg
import psycopg_pool
from providers import google_play
from vendor import onion_req
import backend
import base
import server
import db


def test_server_add_payment_flow(monkeypatch, pg_database):
    monkeypatch.setattr("providers.google_play.api.subscription_v1_acknowledge", lambda *args, **kwargs: None)

    dummy_sub_v2_data = google_play.types.SubscriptionV2Data()
    monkeypatch.setattr(
        "providers.google_play.api.fetch_subscription_v2_details", lambda *args, **kwargs: dummy_sub_v2_data
    )

    db_url = pg_database()
    err = base.ErrorSink()
    db_engine: psycopg_pool.ConnectionPool | None = backend.bootstrap_db(database_url=db_url)
    assert db_engine
    # Setup local flask instance. The signing key is external now (not in the DB), so generate
    # one for this test and hand it to the server; use it directly to verify signatures below.
    backend_key: nacl.signing.SigningKey = nacl.signing.SigningKey.generate()
    db_conn: psycopg.Connection = db_engine.getconn()
    flask_app: flask.Flask = server.init(testing_mode=True, database_url=db_url, backend_key=backend_key)
    flask_client: werkzeug.Client = flask_app.test_client()

    # Setup keys for onion requests
    server_x25519_skey = backend_key.to_curve25519_private_key()
    our_x25519_skey = nacl.public.PrivateKey.generate()
    shared_key: bytes = onion_req.make_shared_key(
        our_x25519_skey=our_x25519_skey, server_x25519_pkey=server_x25519_skey.public_key
    )

    # Register an unredeemed payment (by writing the the token to the DB directly)
    start_unix_ts_ms = int(time.time() * 1000)
    unix_ts_ms = start_unix_ts_ms  # ms, for the wire bodies
    request_at = base.datetime_from_unix_ms(unix_ts_ms)  # datetime, for hashes + DB seeding
    next_day_at = base.round_datetime_to_next_day(request_at)
    master_key = nacl.signing.SigningKey.generate()
    rotating_key = nacl.signing.SigningKey.generate()
    payment_tx = base.PaymentProviderTransaction()
    payment_tx.provider = base.PaymentProvider.GooglePlayStore
    payment_tx.google_payment_token = os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
    payment_tx.google_order_id = 'DEV.' + os.urandom(backend.BLAKE2B_DIGEST_SIZE).hex()
    backend.add_unredeemed_payment(
        db_conn,
        payment_tx=payment_tx,
        plan=base.ProPlan.OneMonth,
        purchased_at=request_at,
        expires_at=next_day_at + 90 * base.DAY,
        platform_refund_expires_at=base.EPOCH,
        platform_obfuscated_account_id=bytes(master_key.verify_key),
        err=err,
    )
    assert not err.msg_list, f'{err.msg_list}'

    # Grab the pro status before anything has happened
    hash_to_sign = backend.make_get_pro_status_message(
        master_pkey=master_key.verify_key, request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000)
    )
    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'ts': unix_ts_ms // 1000,
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_status',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'
    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Under the reflow, this first status touch RECONCILED the seeded (mule-registered) payment, so the
    # user is already Active and the latest payment is present -- no separate /add_pro_payment redeem.
    result_latest = result_json.get('latest_payment')
    result_status = base.json_dict_require_str(d=result_json, key='user_status', err=err)
    assert not err.msg_list, '{err.msg_list}'
    assert result_status == server.UserProStatus.Active.value, f'Response was: {json.dumps(response_json, indent=2)}'
    assert result_latest is not None, f'Response was: {json.dumps(response_json, indent=2)}'

    # Client requests a proof: generate_pro_proof reconciles (a no-op now) and returns a live proof.
    unix_ts_ms = int(time.time() * 1000)
    payment_hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000),
    )

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/generate_pro_proof',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(rotating_key.verify_key).hex(),
            'ts': unix_ts_ms // 1000,
            'master_sig': bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
            'rotating_sig': bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
        },
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    assert isinstance(result_json, dict)
    result_revocation_tag_hex = base.json_dict_require_str(d=result_json, key='revocation_tag', err=err)
    result_rotating_pkey_hex = base.json_dict_require_str(d=result_json, key='rotating_pkey', err=err)
    result_expiry_ts = base.json_dict_require_int(d=result_json, key='expiry_ts', err=err)
    result_sig_hex = base.json_dict_require_str(d=result_json, key='sig', err=err)
    assert not err.msg_list, '{err.msg_list}'

    # Parse hex fields to bytes
    result_rotating_pkey = nacl.signing.VerifyKey(
        base.hex_to_bytes(
            hex=result_rotating_pkey_hex,
            label='Rotating public key',
            hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2,
            err=err,
        )
    )
    result_sig = base.hex_to_bytes(
        hex=result_sig_hex, label='Signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2, err=err
    )
    result_revocation_tag = base.hex_to_bytes(
        hex=result_revocation_tag_hex, label='Revocation tag', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2, err=err
    )
    assert not err.msg_list, '{err.msg_list}'

    # Check the rotating key returned matches what we asked the server to sign
    assert result_rotating_pkey == rotating_key.verify_key

    # Check that the server signed our proof w/ their public key
    proof_hash = backend.build_proof_message(
        result_revocation_tag, result_rotating_pkey, base.datetime_from_unix_seconds(result_expiry_ts)
    )
    backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        assert len(get_user.user.token) == backend.BLAKE2B_DIGEST_SIZE

    # Authorise a new rotated key for the pro subscription
    new_rotating_key = nacl.signing.SigningKey.generate()
    unix_ts_ms = int(time.time() * 1000)
    hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=new_rotating_key.verify_key,
        request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000),
    )

    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'rotating_pkey': bytes(new_rotating_key.verify_key).hex(),
        'ts': unix_ts_ms // 1000,
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'rotating_sig': bytes(new_rotating_key.sign(hash_to_sign).signature).hex(),
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/generate_pro_proof',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_revocation_tag_hex = base.json_dict_require_str(d=result_json, key='revocation_tag', err=err)
    result_rotating_pkey_hex = base.json_dict_require_str(d=result_json, key='rotating_pkey', err=err)
    result_expiry_ts = base.json_dict_require_int(d=result_json, key='expiry_ts', err=err)
    result_sig_hex = base.json_dict_require_str(d=result_json, key='sig', err=err)
    assert not err.msg_list, '{err.msg_list}'

    # Parse hex fields to bytes
    result_rotating_pkey = nacl.signing.VerifyKey(
        base.hex_to_bytes(
            hex=result_rotating_pkey_hex,
            label='Rotating public key',
            hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2,
            err=err,
        )
    )
    result_sig = base.hex_to_bytes(
        hex=result_sig_hex, label='Signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2, err=err
    )
    result_revocation_tag = base.hex_to_bytes(
        hex=result_revocation_tag_hex, label='Revocation tag', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2, err=err
    )
    assert not err.msg_list, '{err.msg_list}'

    # Check the rotating key returned matches what we asked the server to sign
    assert result_rotating_pkey == new_rotating_key.verify_key

    # Check that the server signed our proof w/ their public key
    proof_hash = backend.build_proof_message(
        result_revocation_tag, result_rotating_pkey, base.datetime_from_unix_seconds(result_expiry_ts)
    )
    backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    # The payment runs 90 days, so the proof sits on the rolling clamp: request_at + the clamp + the renewal
    # lead, rounded up onto this account's own expiry grid. On a grid point, so NOT midnight-aligned.
    shape = base.proof_expiry_shape()
    with db.transaction(db_conn) as tx:
        proof_expiry_offset = backend.get_user_and_payments(tx, master_key.verify_key).user.proof_expiry_offset
    assert 0 <= proof_expiry_offset < shape.offset_range
    assert result_expiry_ts == base.unix_seconds_from_datetime(
        base.round_datetime_up_onto_offset_grid(
            base.datetime_from_unix_seconds(unix_ts_ms // 1000) + shape.clamp + shape.renewal_lead,
            period=shape.grid,
            offset_seconds=proof_expiry_offset,
        )
    )

    # Register another payment on the same user, backend will choose the latest expiring payment
    new_payment_tx = base.PaymentProviderTransaction()
    new_payment_tx.provider = base.PaymentProvider.GooglePlayStore
    new_payment_tx.google_payment_token = os.urandom(int(len(payment_tx.google_payment_token) / 2)).hex()
    new_payment_tx.google_order_id = 'DEV.' + os.urandom(int(len(payment_tx.google_payment_token) / 2)).hex()
    backend.add_unredeemed_payment(
        db_conn,
        payment_tx=new_payment_tx,
        plan=base.ProPlan.OneMonth,
        purchased_at=request_at,
        expires_at=request_at + 30 * base.DAY,
        platform_refund_expires_at=base.EPOCH,
        platform_obfuscated_account_id=bytes(master_key.verify_key),
        err=err,
    )

    # Client requests a proof again: generate_pro_proof reconciles the newly-seeded payment and returns
    # the proof for the now-extended entitlement.
    unix_ts_ms = int(time.time() * 1000)
    payment_hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000),
    )

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/generate_pro_proof',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'rotating_pkey': bytes(rotating_key.verify_key).hex(),
            'ts': unix_ts_ms // 1000,
            'master_sig': bytes(master_key.sign(payment_hash_to_sign).signature).hex(),
            'rotating_sig': bytes(rotating_key.sign(payment_hash_to_sign).signature).hex(),
        },
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_revocation_tag_hex = base.json_dict_require_str(d=result_json, key='revocation_tag', err=err)
    result_rotating_pkey_hex = base.json_dict_require_str(d=result_json, key='rotating_pkey', err=err)
    result_expiry_ts = base.json_dict_require_int(d=result_json, key='expiry_ts', err=err)
    result_sig_hex = base.json_dict_require_str(d=result_json, key='sig', err=err)
    assert not err.msg_list, '{err.msg_list}'

    # Parse hex fields to bytes
    result_rotating_pkey = nacl.signing.VerifyKey(
        base.hex_to_bytes(
            hex=result_rotating_pkey_hex,
            label='Rotating public key',
            hex_len=nacl.bindings.crypto_sign_PUBLICKEYBYTES * 2,
            err=err,
        )
    )
    result_sig = base.hex_to_bytes(
        hex=result_sig_hex, label='Signature', hex_len=nacl.bindings.crypto_sign_BYTES * 2, err=err
    )
    result_revocation_tag = base.hex_to_bytes(
        hex=result_revocation_tag_hex, label='Revocation tag', hex_len=backend.BLAKE2B_DIGEST_SIZE * 2, err=err
    )
    assert not err.msg_list, '{err.msg_list}'

    # Check the rotating key returned matches what we asked the server to sign
    assert result_rotating_pkey == rotating_key.verify_key

    # Check that the server signed our proof w/ their public key
    proof_hash = backend.build_proof_message(
        result_revocation_tag, result_rotating_pkey, base.datetime_from_unix_seconds(result_expiry_ts)
    )
    backend_key.verify_key.verify(smessage=proof_hash, signature=result_sig)

    curr_revocation_ticket: int = 0

    # Get the revocation list
    request_body = {'ticket': curr_revocation_ticket}
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_revocations',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_items = base.json_dict_require_array(d=result_json, key='items', err=err)
    result_ticket = base.json_dict_require_int(d=result_json, key='ticket', err=err)
    result_retry_in = base.json_dict_require_int(d=result_json, key='retry_in', err=err)
    assert not err.msg_list, '{err.msg_list}'
    assert result_ticket == 0
    assert result_retry_in == base.seconds_from_duration(base.REVOCATION_POLL_INTERVAL)
    curr_revocation_ticket = result_ticket

    # Check that the server returned an empty revocation list, we no longer revoke the old
    # payment but we _do_ increment the user's generation index
    assert not result_items

    # Flask did some writes using an independent connection so those writes are made visible by
    # refreshing the connection and updating the "snapshot" that the following code sees.
    db_conn = db_engine.getconn()

    # Capture the user's current generation. The manual revoke below targets only the shorter
    # (30-day) payment while the original (~90-day) payment survives, so the revocation-skip must OMIT the
    # revocation entirely: the surviving entitlement still covers everything any outstanding proof
    # can certify (≤ 30 days of reach), so the generation must NOT roll and nothing must land on
    # the (network-costly) revocation list.
    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        assert len(get_user.user.token) == backend.BLAKE2B_DIGEST_SIZE
    kept_generation_token: bytes = get_user.user.token
    kept_generation_id: int = get_user.user.current_generation_id

    # We will now manually revoke the shorter payment and check the revocation list again
    with db.transaction(db_conn) as tx:
        revoked = backend.add_google_revocation(
            tx,
            google_payment_token=new_payment_tx.google_payment_token,
            revoke_at=base.datetime_from_unix_ms(unix_ts_ms),
            err=err,
        )
        assert revoked
        assert not err.has()

    # Get the revocation list, again
    request_body = {'ticket': curr_revocation_ticket}
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_revocations',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_items = base.json_dict_require_array(d=result_json, key='items', err=err)
    result_ticket = base.json_dict_require_int(d=result_json, key='ticket', err=err)
    result_retry_in = base.json_dict_require_int(d=result_json, key='retry_in', err=err)
    result_retain_for = base.json_dict_require_int(d=result_json, key='retain_for', err=err)
    assert not err.msg_list, '{err.msg_list}'
    # The non-cutting refund produced NO revocation entry, so the ticket is unchanged.
    assert result_ticket == 0
    assert result_retry_in == base.seconds_from_duration(base.REVOCATION_POLL_INTERVAL)
    assert result_retain_for == base.seconds_from_duration(base.REVOCATION_RETAIN_FOR)
    curr_revocation_ticket = result_ticket
    assert not result_items

    # The generation must be UNCHANGED and still LIVE: no roll happened, and the current
    # generation is NOT on the revocation list (the surviving payment keeps it honest).
    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        now_dt = base.datetime_from_unix_ms(unix_ts_ms)
        assert get_user.user.current_generation_id == kept_generation_id
        assert get_user.user.token == kept_generation_token
        assert not backend.is_generation_revoked(tx.conn, get_user.user.current_generation_id, now_dt)

    assert not err.has()

    # Try grabbing the revocation again with the current ticket (we should get
    # an empty list because we passed in the most up to date ticket)
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_revocations',
        request_body={'ticket': curr_revocation_ticket},
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields
    result_items = base.json_dict_require_array(d=result_json, key='items', err=err)
    result_ticket = base.json_dict_require_int(d=result_json, key='ticket', err=err)
    result_retry_in = base.json_dict_require_int(d=result_json, key='retry_in', err=err)
    result_retain_for = base.json_dict_require_int(d=result_json, key='retain_for', err=err)
    assert not err.msg_list, '{err.msg_list}'
    # The non-cutting refund above created no revocation entry, so the ticket is still 0.
    assert result_ticket == 0, f'Response was: {json.dumps(response_json, indent=2)}'
    assert result_retry_in == base.seconds_from_duration(base.REVOCATION_POLL_INTERVAL)
    assert result_retain_for == base.seconds_from_duration(base.REVOCATION_RETAIN_FOR)

    # List should be empty because we passed in the newest revocation
    # ticket. There are no changes to the revocation list so the backend
    # will return an empty list
    assert not result_items, f'Response was: {json.dumps(response_json, indent=2)}'

    # Get the pro status now w/ a bunch of payments
    unix_ts_ms = int(time.time() * 1000)
    hash_to_sign = backend.make_get_pro_status_message(
        master_pkey=master_key.verify_key, request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000)
    )

    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'ts': unix_ts_ms // 1000,
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_status',
        request_body=request_body,
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'ok', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Parse result object is at root
    assert 'result' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
    result_json = response_json['result']

    # Extract the fields — status endpoint carries user_status + the single latest payment.
    result_latest = result_json.get('latest_payment')
    result_status = base.json_dict_require_str(d=result_json, key='user_status', err=err)
    assert not err.msg_list, '{err.msg_list}'
    assert result_status == server.UserProStatus.Active.value, f'Response was: {json.dumps(response_json, indent=2)}'
    assert result_latest is not None, f'Response was: {json.dumps(response_json, indent=2)}'

    # Retry the request but use a too old timestamp
    unix_ts_ms = int((time.time() + base.DEFAULT_TIMESTAMP_TOLERANCE.total_seconds() * 2) * 1000)
    hash_to_sign = backend.make_get_pro_status_message(
        master_pkey=master_key.verify_key, request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000)
    )
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_status',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
            'ts': unix_ts_ms // 1000,
        },
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'fail', f'Response was: {json.dumps(response_json, indent=2)}'
    assert len(response_json['error']) > 0, f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'result' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Retry the request but create a hash with the rotating key
    unix_ts_ms = int(time.time() * 1000)
    hash_to_sign = backend.make_get_pro_status_message(
        master_pkey=rotating_key.verify_key, request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000)
    )
    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_pro_status',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
            'ts': unix_ts_ms // 1000,
        },
    )

    # POST and get response
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from response
    assert response_json['status'] == 'fail', f'Response was: {json.dumps(response_json, indent=2)}'
    assert len(response_json['error']) > 0, f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'result' not in response_json, f'Response was: {json.dumps(response_json, indent=2)}'

    # Page the full payment history via the dedicated get-payment-details endpoint (keyset cursor,
    # newest-first). The user has 2 redeemed payments; walk them one page at a time.

    def get_payment_details_page(limit: int, before: str) -> dict:
        unix_ts_ms = int(time.time() * 1000)
        hash_to_sign = backend.make_get_payment_details_message(
            master_pkey=master_key.verify_key,
            request_at=base.datetime_from_unix_seconds(unix_ts_ms // 1000),
            limit=limit,
            before=before,
        )
        onion_request = onion_req.make_request_v4(
            our_x25519_pkey=our_x25519_skey.public_key,
            shared_key=shared_key,
            endpoint='/get_payment_details',
            request_body={
                'master_pkey': bytes(master_key.verify_key).hex(),
                'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
                'ts': unix_ts_ms // 1000,
                'limit': limit,
                'before': before,
            },
        )
        response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
        onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
        assert onion_response.success
        body = json.loads(onion_response.body)
        assert isinstance(body, dict) and body['status'] == 'ok', f'Response {onion_response.body!r}'
        return body['result']

    # Page 1 (newest): one item, a cursor for more, total is 2, and NO account status here
    # (that lives on get_pro_status now).
    page1 = get_payment_details_page(limit=1, before='')
    assert 'user_status' not in page1, page1
    assert base.json_dict_require_int(d=page1, key='payments_total', err=err) == 2
    page1_items = base.json_dict_require_array(d=page1, key='items', err=err)
    assert len(page1_items) == 1, page1
    cursor1 = page1.get('next_cursor')
    assert isinstance(cursor1, str) and cursor1, page1

    # Page 2 (older): the second, distinct payment.
    page2 = get_payment_details_page(limit=1, before=cursor1)
    page2_items = base.json_dict_require_array(d=page2, key='items', err=err)
    assert not err.msg_list, err.msg_list
    assert len(page2_items) == 1, page2
    assert isinstance(page1_items[0], dict) and isinstance(page2_items[0], dict)
    assert page1_items[0]['payment_id'] != page2_items[0]['payment_id'], (page1_items, page2_items)

    # Page 3: past the end → empty, no further cursor.
    page3 = get_payment_details_page(limit=1, before=(page2.get('next_cursor') or ''))
    assert not base.json_dict_require_array(d=page3, key='items', err=err), page3
    assert page3.get('next_cursor') is None, page3

    # A garbage cursor is rejected (invalid_request) — never silently treated as page 1.
    bad_ts = int(time.time() * 1000)
    bad_hash = backend.make_get_payment_details_message(
        master_pkey=master_key.verify_key,
        request_at=base.datetime_from_unix_seconds(bad_ts // 1000),
        limit=1,
        before='deadbeef',
    )
    bad_onion = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/get_payment_details',
        request_body={
            'master_pkey': bytes(master_key.verify_key).hex(),
            'master_sig': bytes(master_key.sign(bad_hash).signature).hex(),
            'ts': bad_ts // 1000,
            'limit': 1,
            'before': 'deadbeef',
        },
    )
    bad_response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=bad_onion)
    bad_onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=bad_response.data)
    assert bad_onion_response.success
    bad_body = json.loads(bad_onion_response.body)
    assert isinstance(bad_body, dict) and bad_body['status'] == 'fail', bad_body

    # NOTE: Add a grace period to the payment and check that we can still generate proofs in said
    # grace period
    # NOTE: Verify that there is no grace period set first
    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        assert get_user.user.grace_period == pendulum.duration()

    # NOTE: Grab the latest expiring payment so that we have access to the payment details
    last_payment = backend.PaymentRow()
    for payment_it in backend.get_payments_list(db_conn):
        if payment_it.expires_at > last_payment.expires_at:
            last_payment = payment_it

    # NOTE: Add a grace period
    payment_tx = base.PaymentProviderTransaction()
    payment_tx.provider = last_payment.payment_provider
    payment_tx.apple_original_tx_id = last_payment.apple.original_tx_id
    payment_tx.apple_tx_id = last_payment.apple.tx_id
    payment_tx.apple_web_line_order_tx_id = last_payment.apple.web_line_order_tx_id
    payment_tx.google_payment_token = last_payment.google_payment_token
    payment_tx.google_order_id = last_payment.google_order_id
    backend.update_payment_renewal_info(
        db_conn, payment_tx, grace_period=base.duration_from_ms(10 * 1000), auto_renewing=True, err=err
    )
    assert not err.has()

    # NOTE: Verify that the grace period is set and calculate the pro-proof deadline
    pro_proof_deadline_unix_ts_ms = 0
    with db.transaction(db_conn) as tx:
        get_user = backend.get_user_and_payments(tx, master_key.verify_key)
        assert get_user.user.grace_period > pendulum.duration()
        pro_proof_deadline_unix_ts_ms = base.unix_ms_from_datetime(get_user.user.expires_at)

    # NOTE: Try to generate a proof on the deadline timestamp (which includes grace), should be permitted
    unix_ts_ms = pro_proof_deadline_unix_ts_ms
    hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_ms(unix_ts_ms),
    )

    proof = backend.generate_pro_proof(
        conn=db_conn,
        signing_key=backend_key,
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_ms(unix_ts_ms),
        master_sig=bytes(master_key.sign(hash_to_sign).signature),
        rotating_sig=bytes(rotating_key.sign(hash_to_sign).signature),
    )

    # NOTE: Check that the proof verifies
    proof_hash = backend.build_proof_message(proof.revocation_tag, proof.rotating_pkey, proof.expires_at)
    backend_key.verify_key.verify(smessage=proof_hash, signature=proof.sig)

    # NOTE: Generating a proof once the deadline AND the proof over-provision are both spent must fail —
    # entitlement expired → FailError. The over-provision (renewal lead + the account's offset, ≤ ~25 h) is
    # what a proof issued at the deadline already certifies, so we honour re-fetches until it runs out.
    unix_ts_ms = pro_proof_deadline_unix_ts_ms + base.ms_from_duration(base.proof_expiry_shape().max_proof_lifetime)
    hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_ms(unix_ts_ms),
    )

    with pytest.raises(base.FailError) as exc_info:
        backend.generate_pro_proof(
            conn=db_conn,
            signing_key=backend_key,
            master_pkey=master_key.verify_key,
            rotating_pkey=rotating_key.verify_key,
            request_at=base.datetime_from_unix_ms(unix_ts_ms),
            master_sig=bytes(master_key.sign(hash_to_sign).signature),
            rotating_sig=bytes(rotating_key.sign(hash_to_sign).signature),
        )
    assert exc_info.value.code == base.ErrorCode.subscription_expired

    # Revoke the original payment from the user (so we have ended up revoking everything)
    with db.transaction(db_conn) as tx:
        gen_before_final_revoke = backend.get_user_and_payments(tx, master_key.verify_key).user.current_generation_id
        revoked = backend.add_google_revocation(
            tx,
            google_payment_token=payment_tx.google_payment_token,
            revoke_at=base.datetime_from_unix_ms(start_unix_ts_ms),
            err=err,
        )
    assert revoked
    assert not err.has()

    # Revoking the LAST valid payment must NOT roll onto a fresh generation — there's no remaining
    # entitlement to roll onto, so the current generation stays put and is now terminally revoked
    # (contrast the partial revoke above, which DID roll). This is the "shouldn't roll" case.
    with db.transaction(db_conn) as tx:
        get_user_after = backend.get_user_and_payments(tx, master_key.verify_key)
        assert get_user_after.user.current_generation_id == gen_before_final_revoke
        assert backend.is_generation_revoked(
            tx.conn, get_user_after.user.current_generation_id, base.datetime_from_unix_ms(start_unix_ts_ms)
        )

    # Try requesting a proof normally which should now fail as everything has been revoked
    hash_to_sign = backend.make_generate_pro_proof_message(
        master_pkey=master_key.verify_key,
        rotating_pkey=rotating_key.verify_key,
        request_at=base.datetime_from_unix_seconds(start_unix_ts_ms // 1000),
    )

    request_body = {
        'master_pkey': bytes(master_key.verify_key).hex(),
        'rotating_pkey': bytes(rotating_key.verify_key).hex(),
        'ts': start_unix_ts_ms // 1000,
        'master_sig': bytes(master_key.sign(hash_to_sign).signature).hex(),
        'rotating_sig': bytes(rotating_key.sign(hash_to_sign).signature).hex(),
    }

    onion_request = onion_req.make_request_v4(
        our_x25519_pkey=our_x25519_skey.public_key,
        shared_key=shared_key,
        endpoint='/generate_pro_proof',
        request_body=request_body,
    )

    # POST and get response for pro proof
    response = flask_client.post(onion_req.ROUTE_OXEN_V4_LSRPC, data=onion_request)
    onion_response = onion_req.make_response_v4(shared_key=shared_key, encrypted_response=response.data)
    assert onion_response.success

    # Parse the JSON from the pro proof response
    response_json = json.loads(onion_response.body)
    assert isinstance(response_json, dict), f'Response {onion_response.body!r}'

    # Parse status from the pro proof response
    assert response_json['status'] == 'fail', f'Response was: {json.dumps(response_json, indent=2)}'
    assert 'error' in response_json, f'Response was: {json.dumps(response_json, indent=2)}'
