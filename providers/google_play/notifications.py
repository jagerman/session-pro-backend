'''
Entry point for witnessing notifications from the Google Play store. This layer initiates an
asynchronous fetching operation from Google to monitor for new payments, parsing it and process said
payments into the database layer (backend.py)
'''

import pendulum
import json
import traceback
import logging
import psycopg
import threading
import dataclasses
import typing
import time
import enum
import collections.abc

from google.oauth2 import service_account

import googleapiclient.discovery
import google_auth_httplib2
import httplib2

import backend
import base
import db

from base import (
    ProPlan,
    JSONObject,
    json_dict_require_str,
    json_dict_require_str_coerce_to_int,
    safe_dump_dict_keys_or_data,
    json_dict_optional_obj,
    json_dict_require_int_coerce_to_enum,
    reflect_enum,
)

from . import api
from .api import SubscriptionPlanEventTransaction, VoidedPurchaseTxFields
from .types import (
    SubscriptionNotificationType,
    SubscriptionsV2AcknowledgementState,
    RefundType,
    ProductType,
    SubscriptionsV2State,
    SubscriptionV2Data,
)

log = logging.Logger('GOOGLE')


@dataclasses.dataclass
class ThreadContext:
    thread: threading.Thread | None = None
    kill_thread: bool = False
    sleep_event: threading.Event = threading.Event()


class ParsedNotificationPayloadType(enum.Enum):
    Nil = 0
    Subscription = 1
    Voided = 2
    Test = 3
    OneTimeProduct = 4


@dataclasses.dataclass
class ParsedNotification:
    payload_type: ParsedNotificationPayloadType = ParsedNotificationPayloadType.Nil
    payload_version: str = ''
    sub_type: SubscriptionNotificationType = SubscriptionNotificationType.NIL
    voided: VoidedPurchaseTxFields = dataclasses.field(default_factory=VoidedPurchaseTxFields)
    body_version: str = ''
    event_time_ms: int = 0
    package_name: str = ''
    purchase_token: str = ''


@dataclasses.dataclass
class SortedMessage:
    event_unix_ts_ms: int = 0
    next_retry_unix_ts_s: float = 0
    curr_retry_delay_s: float = 0
    message_id: str = ''
    ack_id: str = ''
    parse: ParsedNotification = dataclasses.field(default_factory=ParsedNotification)
    raw: object | None = None  # a pubsub ReceivedMessage at runtime; only ever str()'d, so untyped here

    def increase_retry_delay(self, now_s: float):
        MIN_RETRY_DELAY_S: float = 1
        MAX_RETRY_DELAY_S: float = 600
        self.curr_retry_delay_s = max(self.curr_retry_delay_s, MIN_RETRY_DELAY_S)
        self.curr_retry_delay_s *= 2
        self.curr_retry_delay_s = min(self.curr_retry_delay_s, MAX_RETRY_DELAY_S)
        self.next_retry_unix_ts_s = now_s + self.curr_retry_delay_s


def init(
    cloud_project_id: str,
    package_name: str,
    cloud_subscription_name: str,
    subscription_product_id: str,
    app_credentials_path: str | None,
) -> ThreadContext:
    # NOTE: Setup credentials global variable
    assert api.credentials is None and api.publisher_service is None and len(api.package_name) == 0, (
        "Initialise was called twice. Google uses callbacks with no way to pass in a per-callback context"
        " so it needs global variables"
    )

    if app_credentials_path:
        api.credentials = service_account.Credentials.from_service_account_file(
            app_credentials_path, scopes=['https://www.googleapis.com/auth/androidpublisher']
        )
        # Bound every Play API call with a socket timeout. googleapiclient's default httplib2 transport
        # has NO timeout, so a hung Google request would block the mule's single-threaded pull loop
        # indefinitely (there's no harakiri leash on the mule like there is on the request workers). 15s
        # is plenty; a timeout just fails the call, and the mule retries — nothing it does is time-critical.
        authed_http = google_auth_httplib2.AuthorizedHttp(api.credentials, http=httplib2.Http(timeout=15))
        api.publisher_service = googleapiclient.discovery.build('androidpublisher', 'v3', http=authed_http)

    api.package_name = package_name
    api.subscription_product_id = subscription_product_id

    # NOTE: Setup thread for caller to use. daemon=True is load-bearing for uWSGI reloads: the pull loop
    # blocks in client.pull() (a long-poll) and can't be interrupted mid-call, and CPython's interpreter
    # shutdown JOINS every non-daemon thread BEFORE atexit runs — so a non-daemon subscriber wedges the
    # whole mule until the pull's deadline and uWSGI NO-MERCY-kills it. As a daemon it's abandoned at
    # exit instead (stop_subscriber still gives it a brief chance to drain); an abandoned in-flight pull
    # just means those messages are never acked, so Google redelivers them — nothing is lost.
    result = ThreadContext()
    result.thread = threading.Thread(
        target=thread_entry_point,
        args=(result, app_credentials_path, cloud_project_id, cloud_subscription_name),
        daemon=True,
    )
    return result


def start_subscriber(
    cloud_project_id: str,
    package_name: str,
    cloud_subscription_name: str,
    subscription_product_id: str,
    app_credentials_path: str | None,
) -> ThreadContext:
    '''
    Initialise + start the Google Pub/Sub notification subscriber. Runs a background pull loop. All
    Google/gRPC state is constructed here, so the caller (the maintenance mule) invokes this
    post-fork.
    '''
    if base.PROVIDER_DRY_RUN:
        # Dry-run: consuming real Pub/Sub notifications is outbound provider I/O, so don't start the loop
        # (this also keeps the notification-path fetch/monetization egress from ever firing). Return an
        # inert context so the caller's stop_subscriber()/atexit teardown is still safe to call.
        log.info('Google subscriber not started (provider_dry_run)')
        return ThreadContext(kill_thread=True)

    context = init(
        cloud_project_id=cloud_project_id,
        package_name=package_name,
        cloud_subscription_name=cloud_subscription_name,
        subscription_product_id=subscription_product_id,
        app_credentials_path=app_credentials_path,
    )
    assert context.thread
    context.thread.start()
    return context


def stop_subscriber(context: ThreadContext) -> None:
    '''
    Signal the subscriber pull loop to stop and wait briefly for it to drain (idempotent; safe to
    call on shutdown even if never started). The thread is a daemon (see init): if it's blocked in a
    pull and can't drain within the window it's abandoned at interpreter exit rather than wedging the
    mule — unacked messages redeliver, so nothing is lost. The short wait is only to let a mid-batch
    cycle finish cleanly when it can.
    '''
    context.kill_thread = True
    context.sleep_event.set()
    if context.thread and context.thread.is_alive():
        context.thread.join(timeout=1)


def handle_parsed_notification(tx: db.SQLTransaction, parse: ParsedNotification, err: base.ErrorSink) -> bool:
    result = False
    match parse.payload_type:
        case ParsedNotificationPayloadType.Nil:
            pass

        case ParsedNotificationPayloadType.Subscription:
            try:
                details: SubscriptionV2Data | None = api.fetch_subscription_v2_details(
                    parse.package_name, parse.purchase_token, err
                )
                if err.has():
                    err.msg_list.append('Failed to fetch subscription V2 details from Google')
                    return result

                assert details is not None
                tx_payment = api.parse_subscription_purchase_tx(
                    purchase_token=parse.purchase_token, details=details, err=err
                )
                tx_event = api.parse_subscription_plan_event_tx(details, parse.event_time_ms, parse.sub_type, err=err)
                if err.has():
                    err.msg_list.append('Parsing data from subscription V2 details failed')
                    return result

                handle_subscription_notification(tx_payment=tx_payment, tx_event=tx_event, tx=tx, err=err)
            except Exception:
                err.msg_list.append(f"Handling notification failed: {traceback.format_exc()}")
        case ParsedNotificationPayloadType.Voided:
            try:
                handle_voided_notification(parse.voided, err)
            except Exception:
                err.msg_list.append("Handling notification failed: {traceback.format_exc()}")

        case ParsedNotificationPayloadType.OneTimeProduct:
            err.msg_list.append('One time product is not supported!')

        case ParsedNotificationPayloadType.Test:
            pass

    result = not err.has()
    if err.has():
        assert tx.cancel
    return result


def _process_notification_message(
    conn: psycopg.Connection, msg: SortedMessage, err: base.ErrorSink, now_s: float
) -> bool:
    """
    Process one queued RTDN message inside a single DB transaction and report whether it was handled
    (True → ack + drop from the queue; False → leave for retry). Marking the message handled, and
    recording or clearing the purchase token's user_error, all happen in the SAME transaction as
    handle_parsed_notification — so a handling failure that sets tx.cancel rolls back that
    bookkeeping too.  Extracted from the Pub/Sub pull loop so this transaction-composition is
    unit-testable (the loop itself, which owns the gRPC client, is not).
    """

    handled = False
    with db.transaction(conn) as tx:
        # NOTE: By definition to be in the sorted list, the message must have also been submitted into the
        # DB. So if for some reason the notification doesn't exist anymore (maybe someone deleted it
        # out-of-band, e.g. via the SET_GOOGLE_NOTIFICATION command) then we skip the notification.
        lookup = backend.google_notification_message_id_is_in_db(tx, msg.message_id)
        user_is_in_error_state = backend.has_user_error(
            conn=tx.conn, payment_provider=base.PaymentProvider.GooglePlayStore, payment_id=msg.parse.purchase_token
        )
        if not lookup.present or lookup.present and lookup.handled:
            handled = True
        else:
            handled = handle_parsed_notification(tx, msg.parse, err)

        # NOTE: Clear user error if success, or add one if we failed
        if lookup.present:
            if handled:
                backend.google_set_notification_handled(tx, message_id=msg.message_id, delete=False)
                if user_is_in_error_state:
                    backend.delete_user_errors(
                        tx.conn,
                        payment_provider=base.PaymentProvider.GooglePlayStore,
                        payment_id=msg.parse.purchase_token,
                    )
            elif not user_is_in_error_state:
                user_error = backend.UserError()
                user_error.provider = base.PaymentProvider.GooglePlayStore
                user_error.google_payment_token = msg.parse.purchase_token
                backend.add_user_error(tx, error=user_error, at=base.datetime_from_unix_ms(int(now_s * 1000)))
    return handled


def _sweep_pending_acks() -> None:
    """Acknowledge to Google every Google purchase still flagged needs_ack, then clear the flag. This is
    the SOLE acker: notification handling only records needs_ack, and the pull loop calls this once per
    iteration (right before blocking on the next pull), so a fresh purchase is acked the next cycle and a
    crash between committing a payment and acking it is picked up by the next sweep — startup included, no
    special case. Google 400s an already-acknowledged purchase with no cleanly-identifiable error, so on
    ANY ack failure we consult the authoritative acknowledgement_state and clear the flag iff Google
    already considers it acked (the "acked, then crashed before clearing" case); otherwise leave it set to
    retry. Best-effort — never raises, so it can't break the pull loop."""
    try:
        with db.connection() as conn:
            tokens = backend.google_payment_tokens_needing_ack(conn)
    except Exception:
        log.error(f'needs_ack sweep: failed to load pending acks. Error was {traceback.format_exc()}')
        return

    for token in tokens:
        ack_err = base.ErrorSink()
        api.subscription_v1_acknowledge(purchase_token=token, err=ack_err)
        acked = not ack_err.has()
        if not acked:
            # Ack failed: either a transient error, or we already acked and crashed before clearing the
            # flag. Read the authoritative state rather than trying to parse Google's ambiguous 400.
            fetch_err = base.ErrorSink()
            details = api.fetch_subscription_v2_details(api.package_name, token, fetch_err)
            acked = (
                not fetch_err.has()
                and details is not None
                and details.acknowledgement_state == SubscriptionsV2AcknowledgementState.ACKNOWLEDGED
            )
        if acked:
            try:
                with db.connection() as conn:
                    backend.google_clear_needs_ack(conn, payment_token=token)
            except Exception:
                log.error(
                    f'needs_ack sweep: acked but failed to clear flag for {base.maybe_obfuscate(token)}. '
                    f'Error was {traceback.format_exc()}'
                )
        else:
            log.warning(f'needs_ack sweep: ack still failing for {base.maybe_obfuscate(token)}; will retry next sweep')


def thread_entry_point(
    context: ThreadContext, app_credentials_path: str, cloud_project_id: str, cloud_subscription_name: str
):
    # grpcio (via google-cloud-pubsub) is imported HERE, not at module scope, deliberately: this is the
    # subscriber thread body and runs only post-fork, inside the mule. A module-level import pulls
    # grpcio's background C threads into the uWSGI master, and the forked mule then segfaults on the
    # dead inherited threads. DO NOT HOIST these to the top of the file.
    from google.cloud import pubsub_v1  # type: ignore[attr-defined]
    import google.pubsub_v1.types
    import google.api_core.exceptions

    sorted_msg_list: list[SortedMessage] = []

    # NOTE Load unhandled messages from the DB and insert it in to the list of messages to start off
    with db.connection() as conn:
        with db.transaction(conn) as tx:
            db_it: collections.abc.Iterator[backend.GoogleUnhandledNotificationIterator] = (
                backend.google_get_unhandled_notification_iterator(tx)
            )
            for row in db_it:
                message_id = row[0]
                payload: str | None = row[1]
                if not payload:
                    continue

                raw_msg = typing.cast(
                    google.pubsub_v1.types.ReceivedMessage, google.pubsub_v1.types.ReceivedMessage.from_json(payload)
                )
                message_data = json.loads(raw_msg.message.data)
                tmp_err = base.ErrorSink()
                parse = parse_notification(message_data, tmp_err)

                sorted_msg_list.append(
                    SortedMessage(
                        event_unix_ts_ms=parse.event_time_ms,
                        message_id=message_id,
                        parse=parse,
                        ack_id=raw_msg.ack_id,
                        raw=raw_msg,
                    )
                )

    # NOTE: Then connect to Google and start pulling messages
    log.info(f'Loaded {len(sorted_msg_list)} unhandled messages from the DB')
    while not context.kill_thread:
        with pubsub_v1.SubscriberClient.from_service_account_file(app_credentials_path) as client:
            sub_path = client.subscription_path(project=cloud_project_id, subscription=cloud_subscription_name)
            # NOTE: We have a little bit of a problem here in terms of ordering. Google
            # notifications for payments can come out of order and if we miss them, they can also be
            # replayed out of order. Unfortunately in our initial designs we intended events to be
            # processed in order, this is a natural tendency that seems to be ill-suited for
            # integrating with Google given these behaviours.
            #
            # In Google payment notifications do not set the ordering keys such that an order can be
            # enforced for the same user's event I have witnessed notifications coming out of order
            # in replays and out of order within the same batch of messages downloaded at a time. We
            # are forced to then sort by event timestamp after the fact with some reasonable buffer
            # which adds to latency but will produce the desired outcomes.
            #
            # What maybe the more natural way to approach this system was to build an idempotent
            # notification handling system with the following pattern:
            #
            #  - Getting a notification
            #  - Compare last event timestamp we processed for the purchase token, ignore if it's
            #    too old
            #  - Get subscription details for the notification
            #  - Create the row if it doesn't exist in the state that google says it should be in,
            #    or, if already exists- state transition it into the state that google says it
            #    should be and ignore any violations of invariants (the final state it ends up in
            #    should be valid though)
            #  - Repeat
            #
            # Example payload:
            #
            #   received_messages [{
            #     ack_id: "HxknBUxeR..."
            #     message {
            #       data: "{\"version\":\"1.0\",\"packageName\":\"network.loki.messenger\",\"eventTimeMillis\":\"1762752016420\",...}"  # noqa: E501
            #       message_id: "17064522705211191"
            #       publish_time {
            #         seconds: 1762752016
            #         nanos: 631000000
            #       }
            #     }
            #   }, ...]
            while not context.kill_thread:
                try:
                    # NOTE: Pull messages from Google
                    result: google.pubsub_v1.types.PullResponse = client.pull(
                        subscription=sub_path, return_immediately=False, max_messages=64
                    )

                    # NOTE: Parse the received_messages[].message.data into our queue of messages
                    now: float = time.time()
                    ack_ids: list[str] = []
                    for index, it in enumerate(result.received_messages):
                        err = base.ErrorSink()
                        message_data = json.loads(it.message.data)
                        published = base.readable(base.datetime_from_unix_ms(it.message.publish_time.ToMilliseconds()))
                        parse = parse_notification(message_data, err)
                        message_id = it.message.message_id  # Pub/Sub ids are opaque strings — never int()-cast
                        if err.has():
                            log.warning(
                                f'Discarding message #{index}: could not parse it '
                                f'(published at {published}).\n'
                                f'Message was:\n{base.maybe_obfuscate(str(it))}\n'
                                f'Reason was:\n{err.build()}'
                            )
                        else:
                            is_new_message = True
                            for sort_it in sorted_msg_list:
                                if sort_it.message_id == message_id:
                                    is_new_message = False
                                    break

                            # NOTE: Record it in the DB BEFORE queueing it. The dedup lookup in
                            # _process_notification_message reads an absent row as "handled" (someone
                            # removed it out-of-band) and acks the message, so a message that reaches
                            # sorted_msg_list without its row is acked to Google unprocessed — and an
                            # acked notification is never redelivered. On failure we skip the message
                            # instead, leaving it unacked so Google delivers it again.
                            def add_notification_id_to_db():
                                with db.connection() as conn:
                                    with db.transaction(conn) as tx:
                                        if not backend.google_notification_message_id_is_in_db(tx, message_id).present:
                                            # NOTE: Our message retention policy for this subscription is 7 days
                                            # (default). We add a little buffer as we don't know exactly which
                                            # timestamp Google uses.
                                            #
                                            # We always store the messages to mitigate network failures on
                                            # acknowledgement. We store this in JSON because in the
                                            # erroneous case there's highly likelihood we need human
                                            # intervention and having human-readability there will be
                                            # important.
                                            backend.google_add_notification_id(
                                                tx,
                                                message_id=message_id,
                                                expires_at=base.datetime_from_unix_ms(
                                                    parse.event_time_ms + base.MILLISECONDS_IN_DAY * 8
                                                ),
                                                payload=google.pubsub_v1.types.ReceivedMessage.to_json(it),
                                            )

                            try:
                                add_notification_id_to_db()
                            except Exception:
                                log.warning(
                                    f'Discarding message #{index}: could not record it in the DB, leaving '
                                    f'it unacknowledged for redelivery (published at {published}).\n'
                                    f'Message was:\n{base.maybe_obfuscate(str(it))}\n'
                                    f'Reason was:\n{traceback.format_exc()}'
                                )
                                continue

                            if is_new_message:
                                sorted_msg_list.append(
                                    SortedMessage(
                                        event_unix_ts_ms=parse.event_time_ms,
                                        message_id=message_id,
                                        parse=parse,
                                        ack_id=it.ack_id,
                                        raw=it,
                                    )
                                )

                    # NOTE: Sort the messages we've added
                    if len(result.received_messages):
                        sorted_msg_list.sort(key=lambda it: it.event_unix_ts_ms)

                    # NOTE: Attempt to process them in order
                    index = 0
                    while index < len(sorted_msg_list):
                        err = base.ErrorSink()
                        msg: SortedMessage = sorted_msg_list[index]
                        attempt: bool = now > msg.next_retry_unix_ts_s
                        handled: bool = False

                        # NOTE: Attempt to process the message. Just before we execute it, we also check
                        # that it hasn't been handled in the DB already. It's possible that someone
                        # out-of-band executed the SET_GOOGLE_NOTIFICATION command via environment/.ini
                        # file to mark a message as being done or handled so we check before proceeding.
                        if attempt:
                            try:
                                with db.connection() as conn:
                                    handled = _process_notification_message(conn, msg, err, now)
                            except Exception:
                                # NOTE: On any exception (e.g. the DB was momentarily unavailable) we just
                                # mark the message not handled; this bumps its retry delay and reattempts.
                                handled = False

                        # NOTE: On success, we remove the message and add it to the acknowledge list
                        # (to stop Google resending it), or otherwise configure an exponential back-off
                        # on the retry and skip the message
                        if handled:
                            sorted_msg_list.pop(index)
                            ack_ids.append(msg.ack_id)
                        else:
                            index += 1
                            if attempt:
                                # NOTE: Exponential backoff on retries. Hopefully, this gives us some time,
                                # for the out-of-order messages that this message is dependent on to arrive,
                                # get sorted into order and then executed successfully.
                                msg.increase_retry_delay(now)
                                emitted = base.readable(base.datetime_from_unix_ms(msg.event_unix_ts_ms))
                                log.error(
                                    f'Failed to handle message, retrying in {msg.curr_retry_delay_s}s '
                                    f'(message was emitted at {emitted}). '
                                    f'Reason was\n{err.build()}\n'
                                    f'Message was\n{base.maybe_obfuscate(str(msg.raw))}'
                                )

                    # NOTE: Acknowledge the messages we handled successfully to stop Google from
                    # resending it to us
                    if len(ack_ids):
                        try:
                            client.acknowledge(subscription=sub_path, ack_ids=ack_ids)
                        except google.api_core.exceptions.InvalidArgument:
                            # NOTE: Ignore double-ack, especially if the notification we had was very
                            # old and we only got around to completing it now rather than when it was
                            # still ackable
                            #
                            #  InvalidArgument: 400 Some acknowledgement ids in the request were
                            # invalid. This could be because the acknowledgement ids have expired or the
                            # acknowledgement ids were malformed. [reason: "EXACTLY_ONCE_ACKID_FAILURE"
                            pass
                except Exception:
                    log.error(f'Google notification handling failed. Error was {traceback.format_exc()}')

                # Acknowledge any purchases still owing a Google ack, right before blocking on the next
                # pull. Decoupled from handling (which only records the obligation): this is the sole
                # acker, and running it every iteration covers fresh purchases, failed-ack retries, and
                # startup/crash leftovers uniformly — no special startup path.
                _sweep_pending_acks()


def _update_payment_renewal_info(
    tx_payment: base.PaymentProviderTransaction,
    auto_renewing: bool | None,
    grace_period: pendulum.Duration | None,
    tx: db.SQLTransaction,
    err: base.ErrorSink,
) -> bool:
    assert len(tx_payment.google_payment_token) > 0 and len(tx_payment.google_order_id) > 0 and not err.has()
    return backend.update_payment_renewal_info(
        tx, payment_tx=tx_payment, grace_period=grace_period, auto_renewing=auto_renewing, err=err
    )


def set_payment_auto_renew(
    tx_payment: base.PaymentProviderTransaction, auto_renewing: bool, tx: db.SQLTransaction, err: base.ErrorSink
):
    success = _update_payment_renewal_info(tx_payment, auto_renewing, None, tx, err)
    if not success:
        err.msg_list.append(
            f'Failed to update auto_renew flag for '
            f'purchase_token: {base.maybe_obfuscate(tx_payment.google_payment_token)} '
            f'and order_id: {base.maybe_obfuscate(tx_payment.google_order_id)}'
        )


def set_purchase_grace_period_duration(
    tx_payment: base.PaymentProviderTransaction,
    grace_period: pendulum.Duration,
    tx: db.SQLTransaction,
    err: base.ErrorSink,
):
    success = _update_payment_renewal_info(tx_payment, None, grace_period, tx, err)
    if not success:
        err.msg_list.append(
            f'Failed to update grace period duration for '
            f'purchase_token: {base.maybe_obfuscate(tx_payment.google_payment_token)} '
            f'and order_id: {base.maybe_obfuscate(tx_payment.google_order_id)}'
        )


def require_obfuscated_external_account_id(tx_event: SubscriptionPlanEventTransaction, err: base.ErrorSink) -> bytes:
    # NOTE: Parse the obfuscated_external_account_id into bytes
    result: bytes = b''
    if tx_event.obfuscated_external_account_id is None:
        err.msg_list.append(
            'Google user submitted a payment and did not set a setObfuscatedAccountId, '
            'payment will not be attributed to the user'
        )
    else:
        obfuscated_external_account_id_hex = tx_event.obfuscated_external_account_id
        if obfuscated_external_account_id_hex.startswith('0x'):
            obfuscated_external_account_id_hex = obfuscated_external_account_id_hex[2:]

        if len(obfuscated_external_account_id_hex) != 64:
            err.msg_list.append(
                f'Google user submitted a payment that was not a 32 byte hash, received: {len(result)/2}b'
            )

        try:
            result = bytes.fromhex(obfuscated_external_account_id_hex)
        except Exception:
            err.msg_list.append(
                'Google user submitted a payment with a obfuscated ID that could not be parsed from hex into bytes'
            )
    return result


def handle_subscription_notification(
    tx_payment: base.PaymentProviderTransaction,
    tx_event: SubscriptionPlanEventTransaction,
    tx: db.SQLTransaction,
    err: base.ErrorSink,
):
    match tx_event.notification:
        case SubscriptionNotificationType.PURCHASED:
            """
            These are the steps documented by Google:
            When a user purchases a subscription, a SubscriptionNotification message with type
            SUBSCRIPTION_PURCHASED is sent to your RTDN client. Whether you receive this
            notification or you register a new purchase in-app through PurchasesUpdatedListener or
            manually fetching purchases in your app's onResume() method, you should process the new
            purchase in your secure backend. To do this, follow these steps:

            1. Query the purchases.subscriptionsv2.get endpoint to get a subscription resource that
               contains the latest subscription state.
            2. Make sure that the value of the subscriptionState field is SUBSCRIPTION_STATE_ACTIVE.
            3. Verify the purchase.
            4. Give the user access to the content. The user account associated with the purchase
               can be identified with the ExternalAccountIdentifiers object from the subscription
               resource if identifiers were set at purchase time using setObfuscatedAccountId and
               setObfuscatedProfileId.
            """
            if tx_event.subscription_state == SubscriptionsV2State.ACTIVE:
                assert (
                    tx_event.pro_plan != ProPlan.Nil
                ), "Plan was parsed into a valid enum when extracting notification data, but is now Nil"
                assert len(tx_payment.google_order_id) > 0 and len(tx_payment.google_payment_token) > 0

                obfuscated_external_account_id: bytes = require_obfuscated_external_account_id(tx_event, err)
                if not err.has():
                    expiry: str = base.readable(base.datetime_from_unix_ms(tx_event.expiry_time.unix_milliseconds))
                    unredeemed: str = base.readable(base.datetime_from_unix_ms(tx_event.event_ts_ms))
                    payment_label: str = backend.payment_provider_tx_log_label_safe(tx_payment)
                    log.info(
                        f'{tx_event.notification.name}+{tx_event.subscription_state.name}; '
                        f'(linked_token={base.maybe_obfuscate(tx_event.linked_purchase_token)}, '
                        f'plan={tx_event.pro_plan.name}, payment={payment_label}, '
                        f'unredeemed={unredeemed}, expiry={expiry}, acked={tx_event.purchase_acknowledged.name})'
                    )

                    # NOTE: If a linked token is in the payload, it means that the old token
                    # needs to be voided first before continuing as the link token is the new
                    # token allocated to the user.

                    # NOTE: Revoke the old token
                    if tx_event.linked_purchase_token is not None:
                        # NOTE: For google, the only information we have about the previous order
                        # is the purchase token. So we have to go and find the latest payment
                        # valid for a purchase token and void that.
                        backend.add_google_revocation(
                            tx,
                            google_payment_token=tx_event.linked_purchase_token,
                            revoke_at=base.datetime_from_unix_ms(tx_event.event_ts_ms),
                            err=err,
                        )
                    # NOTE: Register the payment. Idempotent on (token, order_id), so a Pub/Sub
                    # redelivery of an already-handled purchase re-registers harmlessly instead of
                    # erroring. needs_ack flags a fresh, not-yet-acknowledged purchase for the mule's
                    # separate ack sweep (the "confirm within 3 days or it's auto-refunded" step) — kept
                    # off this transaction so we never tell Google a payment is provisioned before our DB
                    # durably records it.
                    backend.add_unredeemed_payment(
                        tx,
                        payment_tx=tx_payment,
                        plan=tx_event.pro_plan,
                        expiry_at=base.datetime_from_unix_ms(tx_event.expiry_time.unix_milliseconds),
                        purchased_at=base.datetime_from_unix_ms(tx_event.event_ts_ms),
                        platform_refund_expiry_at=base.datetime_from_unix_ms(
                            tx_event.event_ts_ms + api.refund_deadline_duration_ms
                        ),
                        platform_obfuscated_account_id=obfuscated_external_account_id,
                        err=err,
                        needs_ack=tx_event.purchase_acknowledged != SubscriptionsV2AcknowledgementState.ACKNOWLEDGED,
                    )

                    if not err.has():
                        set_purchase_grace_period_duration(
                            tx_payment=tx_payment, tx=tx, grace_period=base.DEFAULT_GOOGLE_GRACE_PERIOD, err=err
                        )

        case SubscriptionNotificationType.IN_GRACE_PERIOD:
            if tx_event.subscription_state == SubscriptionsV2State.IN_GRACE_PERIOD:
                plan_details = api.fetch_subscription_details_for_base_plan_id(
                    base_plan_id=tx_event.base_plan_id, err=err
                )
                payment_label = backend.payment_provider_tx_log_label_safe(tx_payment)
                grace_ms: int = plan_details.grace_period.milliseconds if plan_details else 0
                log.info(
                    f'{tx_event.notification.name}+{tx_event.subscription_state.name}; '
                    f'(payment={payment_label}, grace period ms={grace_ms})'
                )

                if not err.has():
                    assert plan_details is not None
                    set_purchase_grace_period_duration(
                        tx_payment=tx_payment,
                        grace_period=base.duration_from_ms(plan_details.grace_period.milliseconds),
                        tx=tx,
                        err=err,
                    )

        case SubscriptionNotificationType.RECOVERED | SubscriptionNotificationType.RENEWED:
            if tx_event.subscription_state == SubscriptionsV2State.ACTIVE:
                expiry = base.readable(base.datetime_from_unix_ms(tx_event.expiry_time.unix_milliseconds))
                unredeemed = base.readable(base.datetime_from_unix_ms(tx_event.event_ts_ms))
                payment_label = backend.payment_provider_tx_log_label_safe(tx_payment)
                log.info(
                    f'{tx_event.notification.name}+{tx_event.subscription_state.name}; '
                    f'(payment={payment_label}, plan={tx_event.pro_plan.name}, '
                    f'unredeemed={unredeemed}, expiry={expiry})'
                )

                obfuscated_external_account_id = require_obfuscated_external_account_id(tx_event, err)
                if not err.has():
                    assert (
                        tx_event.pro_plan != ProPlan.Nil
                    ), "Plan was parsed into a valid enum when extracting notification data, but is now Nil"
                    assert len(tx_payment.google_order_id) > 0 and len(tx_payment.google_payment_token) > 0
                    backend.add_unredeemed_payment(
                        tx,
                        payment_tx=tx_payment,
                        plan=tx_event.pro_plan,
                        expiry_at=base.datetime_from_unix_ms(tx_event.expiry_time.unix_milliseconds),
                        purchased_at=base.datetime_from_unix_ms(tx_event.event_ts_ms),
                        platform_refund_expiry_at=base.datetime_from_unix_ms(
                            tx_event.event_ts_ms + api.refund_deadline_duration_ms
                        ),
                        platform_obfuscated_account_id=obfuscated_external_account_id,
                        err=err,
                        # Renewals normally arrive already acknowledged; flag for the sweep on the off
                        # chance Google reports one that isn't.
                        needs_ack=tx_event.purchase_acknowledged != SubscriptionsV2AcknowledgementState.ACKNOWLEDGED,
                    )

                    if not err.has():
                        set_purchase_grace_period_duration(
                            tx_payment=tx_payment, tx=tx, grace_period=base.DEFAULT_GOOGLE_GRACE_PERIOD, err=err
                        )

        case SubscriptionNotificationType.CANCELED:
            """
            Google mentions a case where if a user is on account hold and the canceled event happens
            they should have entitlement revoked, but entitlement is already expired so this does
            not need to be handled.
            """
            if (
                tx_event.subscription_state == SubscriptionsV2State.CANCELED
                or tx_event.subscription_state == SubscriptionsV2State.EXPIRED
            ):
                payment_label = backend.payment_provider_tx_log_label_safe(tx_payment)
                log.info(
                    f'{tx_event.notification.name}+{tx_event.subscription_state.name}; '
                    f'(payment={payment_label}, auto_renew=false)'
                )
                set_payment_auto_renew(tx_payment=tx_payment, auto_renewing=False, tx=tx, err=err)

        case SubscriptionNotificationType.RESTARTED:
            # Only happens when going from CANCELLED to ACTIVE, this is called resubscribing, or re-enabling auto-renew
            if tx_event.subscription_state == SubscriptionsV2State.ACTIVE:
                payment_label = backend.payment_provider_tx_log_label_safe(tx_payment)
                log.info(
                    f'{tx_event.notification.name}+{tx_event.subscription_state.name}; '
                    f'(payment={payment_label}, auto_renew=true)'
                )
                set_payment_auto_renew(tx_payment=tx_payment, auto_renewing=True, tx=tx, err=err)

        case SubscriptionNotificationType.REVOKED:
            if tx_event.subscription_state == SubscriptionsV2State.EXPIRED:
                payment_label = backend.payment_provider_tx_log_label_safe(tx_payment)
                log.info(
                    f'{tx_event.notification.name}+{tx_event.subscription_state.name}; '
                    f'(payment={payment_label}, auto_renew=false)'
                )
                backend.add_google_revocation(
                    tx,
                    google_payment_token=tx_payment.google_payment_token,
                    revoke_at=base.datetime_from_unix_ms(tx_event.event_ts_ms),
                    err=err,
                )

        case SubscriptionNotificationType.EXPIRED | SubscriptionNotificationType.ON_HOLD:
            """
            The revocation function only actually revokes proofs that are not going to self-expire
            at the end of the UTC day, so for the vast majority of users this function wont make any
            changes to user entitlement. An example of when a proof will actually be revoked if the
            user enters account hold and for some reason their pro proof expires some time in the
            future (later than the end of the UTC day). A user enters account hold if their billing
            method is still failing after their grace period ends.
            """
            if (
                tx_event.subscription_state == SubscriptionsV2State.EXPIRED
                or tx_event.subscription_state == SubscriptionsV2State.ON_HOLD
            ):
                payment_label = backend.payment_provider_tx_log_label_safe(tx_payment)
                log.info(
                    f'{tx_event.notification.name}+{tx_event.subscription_state.name}; '
                    f'(payment={payment_label}, '
                    f'revoke={base.readable(base.datetime_from_unix_ms(tx_event.event_ts_ms))})'
                )

                # TODO: If this function ever finds rounded(expiry_ts) > rounded(event_ts) the devs
                # need to be notified somehow.
                """
                If everything works as intended, this function should always find that
                `rounded(expiry_ts) == rounded(event_ts)` and not issue a revocation. If a payment
                is ever in a state where it should self-expire but isn't, we need to revoke it. In
                this case something has gone wrong and the user was over-entitled.
                """
                payment: backend.PaymentRow | None = backend.get_payment(tx, payment_tx=tx_payment, err=err)
                if payment is None or err.has():
                    err.msg_list.append("Failed to get payment details for potential revocation!")

                if not err.has():
                    assert payment is not None
                    rounded_expiry_at = backend.round_datetime_to_next_day_with_provider_testing_support(
                        payment_provider=tx_payment.provider, at=payment.expiry_at
                    )
                    rounded_event_at = backend.round_datetime_to_next_day_with_provider_testing_support(
                        payment_provider=tx_payment.provider, at=base.datetime_from_unix_ms(tx_event.event_ts_ms)
                    )

                    # NOTE: A payment at or past the end of the current day is expiring anyway, so it isn't
                    # worth an entry in the revocation list every client fetches. Mirrors the day-boundary
                    # early-out in backend.revoke_payments_by_id_internal — see the note there for the
                    # bounded window an outstanding proof can outlive it by.
                    if rounded_expiry_at > rounded_event_at:
                        backend.add_google_revocation(
                            tx,
                            google_payment_token=tx_payment.google_payment_token,
                            revoke_at=base.datetime_from_unix_ms(tx_event.event_ts_ms),
                            err=err,
                        )

        # NOTE: Explicitly unsupported cases
        case (
            SubscriptionNotificationType.DEFERRED
            | SubscriptionNotificationType.PAUSED
            | SubscriptionNotificationType.PAUSE_SCHEDULE_CHANGED
        ):
            err.msg_list.append(f'Subscription notificationType {reflect_enum(tx_event.notification)} is unsupported!')

        # NOTE: No-op cases
        case (
            SubscriptionNotificationType.PRICE_CHANGE_CONFIRMED
            | SubscriptionNotificationType.PRICE_CHANGE_UPDATED
            | SubscriptionNotificationType.PENDING_PURCHASE_CANCELED
            | SubscriptionNotificationType.PRICE_STEP_UP_CONSENT_UPDATED
        ):
            pass

    if err.has():
        # Purchase token logging is included in the wrapper function
        err.msg_list.append(
            f'Failed to handle {reflect_enum(tx_event.notification)} for order_id '
            f'{base.maybe_obfuscate(tx_payment.google_order_id) if len(tx_payment.google_order_id) > 0 else "N/A"}'
        )
        tx.cancel = True


def handle_voided_notification(tx: VoidedPurchaseTxFields, err: base.ErrorSink):
    assert tx.product_type != ProductType.NIL
    match tx.product_type:
        case ProductType.SUBSCRIPTION:
            assert tx.refund_type != RefundType.NIL
            match tx.refund_type:
                case RefundType.FULL_REFUND:
                    # TODO: investigate if we need to implement anything here
                    pass
                case RefundType.QUANTITY_BASED_PARTIAL_REFUND:
                    err.msg_list.append(f'voided purchase refundType {reflect_enum(tx.refund_type)} is unsupported!')
        case ProductType.ONE_TIME:
            err.msg_list.append(f'voided purchase productType {reflect_enum(tx.product_type)} is unsupported!')

    if err.has():
        err.msg_list.append(f'Failed to handle {reflect_enum(tx.refund_type)}')


def parse_notification(body: JSONObject, err: base.ErrorSink) -> ParsedNotification:
    result = ParsedNotification()
    result.body_version = json_dict_require_str(body, "version", err)
    result.package_name = json_dict_require_str(body, "packageName", err)
    result.event_time_ms = json_dict_require_str_coerce_to_int(body, "eventTimeMillis", err)

    if result.package_name != api.package_name:
        err.msg_list.append(
            f'{result.package_name} does not match google_package_name ' f'({api.package_name}) from the .INI file!'
        )

    subscription = json_dict_optional_obj(body, "subscriptionNotification", err)
    one_time_product = json_dict_optional_obj(body, "oneTimeProductNotification", err)
    voided_purchase = json_dict_optional_obj(body, "voidedPurchaseNotification", err)
    test_obj = json_dict_optional_obj(body, "testNotification", err)

    # Exactly one notification block must be present.
    notif_count = sum(notif is not None for notif in (subscription, one_time_product, voided_purchase, test_obj))
    if notif_count == 0:
        err.msg_list.append(
            f'No subscription notification for {result.package_name} {safe_dump_dict_keys_or_data(body)}'
        )
    elif notif_count > 1:
        err.msg_list.append(
            f'Multiple subscription notification for {result.package_name} {safe_dump_dict_keys_or_data(body)}'
        )

    if err.has():
        return result

    if subscription is not None:
        result.purchase_token = json_dict_require_str(subscription, "purchaseToken", err)
        result.payload_version = json_dict_require_str(subscription, "version", err)
        result.sub_type = typing.cast(
            SubscriptionNotificationType,
            json_dict_require_int_coerce_to_enum(subscription, "notificationType", SubscriptionNotificationType, err),
        )
        result.payload_type = ParsedNotificationPayloadType.Subscription

    elif voided_purchase is not None:
        result.purchase_token = json_dict_require_str(voided_purchase, "purchaseToken", err)
        order_id = json_dict_require_str(voided_purchase, "orderId", err)
        product_type = json_dict_require_int_coerce_to_enum(voided_purchase, "productType", ProductType, err)
        refund_type = json_dict_require_int_coerce_to_enum(voided_purchase, "refundType", RefundType, err)

        assert (
            refund_type is not None
            and product_type is not None
            and len(result.purchase_token) > 0
            and len(order_id) > 0
            and isinstance(product_type, ProductType)
            and isinstance(refund_type, RefundType)
        )
        result.voided = VoidedPurchaseTxFields(
            purchase_token=result.purchase_token,
            order_id=order_id,
            event_ts_ms=result.event_time_ms,
            product_type=product_type,
            refund_type=refund_type,
        )
        result.payload_type = ParsedNotificationPayloadType.Test

    elif one_time_product is not None:
        result.payload_type = ParsedNotificationPayloadType.Nil

    elif test_obj is not None:
        result.payload_type = ParsedNotificationPayloadType.Test

    return result
