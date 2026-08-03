'''
Functionality to query the Google APIs and parse it
'''

import dataclasses
import logging
import typing
import base
from base import (
    ProPlan,
    ErrorSink,
    PaymentProvider,
    PaymentProviderTransaction,
    handle_not_implemented,
    json_dict_optional_bool,
    json_dict_optional_obj,
    json_dict_optional_str,
    json_dict_require_array,
    json_dict_require_int,
    json_dict_require_obj,
    json_dict_require_str,
    json_dict_require_str_coerce_to_enum,
    safe_dump_arbitrary_value_or_type,
    validate_string_list,
)

from google.oauth2 import service_account
import googleapiclient.discovery

from .types import (
    GoogleTimestamp,
    ProductType,
    RefundType,
    SubscriptionNotificationType,
    SubscriptionV2Data,
    SubscriptionV2DataAutoRenewingPlan,
    SubscriptionV2DataLineItem,
    SubscriptionV2DataOfferDetails,
    SubscriptionV2InstallmentPlan,
    SubscriptionV2InstallmentPlanPendingCancellation,
    SubscriptionV2PriceChangeDetails,
    SubscriptionV2PriceChangeMode,
    SubscriptionV2PriceChangeState,
    SubscriptionV2PriceConsentState,
    SubscriptionsV2AcknowledgementState,
    SubscriptionsV2CanceledState,
    SubscriptionsV2SubscriptionCanceledStateContextUser,
    SubscriptionsV2UserSurveyResponse,
    SubscriptionsV2UserSurveyResponseReason,
    SubscriptionsV2PausedState,
    SubscriptionsV2State,
    json_dict_optional_google_empty_object_bool,
    json_dict_require_google_money,
    json_dict_require_google_timestamp,
)

log = logging.Logger('GOOGLE')

# NOTE: Globals specifically for interacting with the Google APIs
credentials: service_account.Credentials | None = None
publisher_service: googleapiclient.discovery.Resource | None = None
package_name: str = ''
subscription_product_id: str = ''
refund_deadline_duration_ms: int = base.MILLISECONDS_IN_DAY * 2

# Every Play API call is bounded by this (see notifications.init, which builds the transport). Named because
# the reconcile lease has to be derived from it: a lease shorter than a batch's worst-case runtime expires
# under the worker still holding it.
SOCKET_TIMEOUT_S: int = 15

# Google's testing environment compresses a "day" to 10s, so OUR renewal-latency allowance — an hour in
# production — would swamp an entire test subscription and make its lifecycle impossible to reason about.
# This replaces it under PROVIDER_TESTING_ENV (see base.RENEWAL_LATENCY_ALLOWANCE, which the mule and the
# test context assign it to).
#
# It compresses our own value to match a compressed timeline. It is NOT Google's grace period: that is
# configured per base plan in the Play Console, and Google applies it by extending the `expiryTime` it
# reports rather than by telling us a number.
testing_renewal_latency_allowance_ms: int = 10 * 1000


def get_publisher_service() -> googleapiclient.discovery.Resource:
    assert credentials, "Platform google initialisation has not been called yet"
    assert publisher_service, "Platform google initialisation has not been called yet"
    return publisher_service


def parse_get_subscription_v2_response(response: typing.Any, err: ErrorSink) -> SubscriptionV2Data | None:
    result = None
    if isinstance(response, dict):
        # Delete known PII just in case something logs somewhere
        if "subscribeWithGoogleInfo" in response:
            del response["subscribeWithGoogleInfo"]

        kind = json_dict_require_str(response, "kind", err)
        if kind != "androidpublisher#subscriptionPurchaseV2":
            err.msg_list.append(f'purchases.subscriptionsv2.get has incorrect kind: {kind}')

        line_items_arr = json_dict_require_array(response, "lineItems", err)
        if len(line_items_arr) == 0:
            err.msg_list.append('purchases.subscriptionsv2.get has no lineItems')

        if err.has():
            return result

        line_items = []
        for i in range(len(line_items_arr)):
            line_item = line_items_arr[i]
            if not isinstance(line_item, dict):
                err.msg_list.append(
                    f'purchases.subscriptionsv2.get line_item at index {i} not a dict: '
                    f'{safe_dump_arbitrary_value_or_type(line_item)}'
                )
                continue

            product_id = json_dict_require_str(line_item, "productId", err)
            expiry_time = json_dict_require_google_timestamp(line_item, "expiryTime", err)
            offer_details_obj = json_dict_require_obj(line_item, "offerDetails", err)

            offer_details_offer_tags = json_dict_require_array(offer_details_obj, "offerTags", err)
            offer_details_base_plan_id = json_dict_require_str(offer_details_obj, "basePlanId", err)
            offer_details_offer_id = json_dict_optional_str(offer_details_obj, "offerId", err)

            for tag in offer_details_offer_tags:
                if not isinstance(tag, str):
                    err.msg_list.append(f"Tag in offerTags is not a string: {safe_dump_arbitrary_value_or_type(tag)}")

            assert validate_string_list(offer_details_offer_tags)

            offer_details = (
                SubscriptionV2DataOfferDetails(
                    offer_tags=offer_details_offer_tags,
                    base_plan_id=offer_details_base_plan_id,
                    offer_id=offer_details_offer_id,
                )
                if not err.has()
                else None
            )

            # Can either be auto-renewing or prepaid
            is_auto_renewing_plan = "autoRenewingPlan" in line_item
            is_prepaid_plan = "prepaidPlan" in line_item

            # Only one of these should be true, but all three can be false
            is_deferred_replacement = "deferredItemReplacement" in line_item
            is_deferred_removal = "deferredItemRemoval" in line_item
            is_signup_promo = "signupPromotion" in line_item

            latest_successful_order_id = json_dict_optional_str(line_item, "latestSuccessfulOrderId", err)

            if is_prepaid_plan and is_auto_renewing_plan:
                err.msg_list.append(
                    'purchases.subscriptions.get line item has both auto_renewing_plan and prepaid_plan keys!'
                    ' This should never happen!'
                )

            if is_deferred_replacement + is_deferred_removal + is_signup_promo > 1:
                err.msg_list.append(
                    f'purchases.subscriptions.get line item has more than one of '
                    f'"deferred_item_replacement" ({is_deferred_replacement}), '
                    f'"deferred_item_removal" ({is_deferred_removal}), '
                    f'or "signup_promotion" ({is_signup_promo}) set! This should never happen!'
                )

            if err.has():
                continue

            auto_renewing_plan = None
            prepaid_plan = None
            deferred_item_replacement = None
            deferred_item_removal = None
            signup_promotion = None

            if is_auto_renewing_plan:
                auto_renewing_plan_obj = json_dict_require_obj(line_item, "autoRenewingPlan", err)

                auto_renew_enabled = json_dict_optional_bool(auto_renewing_plan_obj, "autoRenewEnabled", False, err)

                recurring_price = json_dict_require_google_money(auto_renewing_plan_obj, "recurringPrice", err)

                has_price_step_up_consent_details = "priceStepUpConsentDetails" in auto_renewing_plan_obj

                price_change_details = None
                price_change_details_obj = json_dict_optional_obj(auto_renewing_plan_obj, "priceChangeDetails", err)
                if price_change_details_obj is not None:
                    new_price = json_dict_require_google_money(price_change_details_obj, "newPrice", err)

                    price_change_mode = json_dict_require_str_coerce_to_enum(
                        price_change_details_obj, "priceChangeMode", SubscriptionV2PriceChangeMode, err
                    )
                    price_change_state = json_dict_require_str_coerce_to_enum(
                        price_change_details_obj, "priceChangeState", SubscriptionV2PriceChangeState, err
                    )
                    expected_new_price_charge_time = json_dict_require_google_timestamp(
                        price_change_details_obj, "expectedNewPriceChargeTime", err
                    )

                    if price_change_mode == SubscriptionV2PriceChangeMode.PRICE_CHANGE_MODE_UNSPECIFIED:
                        err.msg_list.append(
                            f'Invalid price change mode for line item price details: {price_change_mode}'
                        )

                    if price_change_state == SubscriptionV2PriceChangeState.PRICE_CHANGE_STATE_UNSPECIFIED:
                        err.msg_list.append(
                            f'Invalid price change state for line item price details: {price_change_state}'
                        )

                    if not err.has():
                        assert isinstance(price_change_mode, SubscriptionV2PriceChangeMode)
                        assert isinstance(price_change_state, SubscriptionV2PriceChangeState)

                        price_change_details = SubscriptionV2PriceChangeDetails(
                            new_price=new_price,
                            price_change_mode=price_change_mode,
                            price_change_state=price_change_state,
                            expected_new_price_charge_time=expected_new_price_charge_time,
                        )

                installment_details = None
                installment_details_obj = json_dict_optional_obj(auto_renewing_plan_obj, "installmentDetails", err)
                if installment_details_obj is not None:

                    initial_committed_payments_count = json_dict_require_int(
                        installment_details_obj, "initialCommittedPaymentsCount", err
                    )
                    subsequent_committed_payments_count = json_dict_require_int(
                        installment_details_obj, "subsequentCommittedPaymentsCount", err
                    )
                    remaining_committed_payments_count = json_dict_require_int(
                        installment_details_obj, "remainingCommittedPaymentsCount", err
                    )

                    pending_cancellation = None
                    pending_cancellation_obj = json_dict_optional_obj(
                        installment_details_obj, "pendingCancellation", err
                    )
                    if pending_cancellation_obj is not None:
                        pending_cancellation_state = json_dict_require_str_coerce_to_enum(
                            pending_cancellation_obj, "state", SubscriptionV2PriceConsentState, err
                        )

                        consent_deadline_time = json_dict_require_google_timestamp(
                            installment_details_obj, "consentDeadlineTime", err
                        )
                        new_price = json_dict_require_google_money(installment_details_obj, "newPrice", err)

                        if not err.has():
                            assert isinstance(pending_cancellation_state, SubscriptionV2PriceConsentState)
                            pending_cancellation = SubscriptionV2InstallmentPlanPendingCancellation(
                                state=pending_cancellation_state,
                                consent_deadline_time=consent_deadline_time,
                                new_price=new_price,
                            )

                    if not err.has():
                        installment_details = SubscriptionV2InstallmentPlan(
                            initial_committed_payments_count=initial_committed_payments_count,
                            subsequent_committed_payments_count=subsequent_committed_payments_count,
                            remaining_committed_payments_count=remaining_committed_payments_count,
                            pending_cancellation=pending_cancellation,
                        )

                price_step_up_consent_details = None
                if has_price_step_up_consent_details:
                    price_step_up_consent_details = json_dict_require_str_coerce_to_enum(
                        auto_renewing_plan_obj, "priceStepUpConsentDetails", SubscriptionV2PriceConsentState, err
                    )

                if not err.has():
                    auto_renewing_plan = SubscriptionV2DataAutoRenewingPlan(
                        auto_renew_enabled=auto_renew_enabled,
                        recurring_price=recurring_price,
                        price_change_details=price_change_details,
                        installment_details=installment_details,
                        price_step_up_consent_details=price_step_up_consent_details,
                    )

            elif is_prepaid_plan:
                handle_not_implemented('prepaidPlan', err)

            else:
                err.msg_list.append('No plan type in subscription')

            if not err.has():
                # We could probably enforce unique line item types, but this might be overkill.
                # "The items in the same purchase should be either all with AutoRenewingPlan or all
                # with PrepaidPlan."

                assert offer_details is not None

                line_items.append(
                    SubscriptionV2DataLineItem(
                        product_id=product_id,
                        expiry_time=expiry_time,
                        latest_successful_order_id=latest_successful_order_id,
                        auto_renewing_plan=auto_renewing_plan,
                        prepaid_plan=prepaid_plan,
                        offer_details=offer_details,
                        deferred_item_replacement=deferred_item_replacement,
                        deferred_item_removal=deferred_item_removal,
                        signup_promotion=signup_promotion,
                    )
                )

        start_time = json_dict_require_google_timestamp(response, "startTime", err)
        subscription_state = json_dict_require_str_coerce_to_enum(
            response, "subscriptionState", SubscriptionsV2State, err
        )
        linked_purchase_token = json_dict_optional_str(response, "linkedPurchaseToken", err)

        paused_state_context = None
        paused_state_context_obj = json_dict_optional_obj(response, "pausedStateContext", err)
        if paused_state_context_obj is not None:
            auto_resume_time = json_dict_require_google_timestamp(paused_state_context_obj, "autoResumeTime", err)

            if not err.has():
                paused_state_context = SubscriptionsV2PausedState(auto_resume_time=auto_resume_time)

        canceled_state_context = None
        canceled_state_context_obj = json_dict_optional_obj(response, "canceledStateContext", err)
        if canceled_state_context_obj is not None:
            user_initiated_cancellation = None
            user_initiated_cancellation_obj = json_dict_optional_obj(
                canceled_state_context_obj, "userInitiatedCancellation", err
            )
            is_user_initiated_cancellation = user_initiated_cancellation_obj is not None
            if user_initiated_cancellation_obj is not None:
                cancel_survey_result_obj = json_dict_optional_obj(
                    user_initiated_cancellation_obj, "cancelSurveyResult", err
                )

                cancel_survey_result = None
                if cancel_survey_result_obj is not None:
                    reason = json_dict_require_str_coerce_to_enum(
                        cancel_survey_result_obj, "reason", SubscriptionsV2UserSurveyResponseReason, err
                    )
                    reason_user_input = (
                        json_dict_require_str(cancel_survey_result_obj, "reasonUserInput", err)
                        if "reasonUserInput" in cancel_survey_result_obj
                        else None
                    )

                    if not err.has():
                        assert reason is not None
                        cancel_survey_result = SubscriptionsV2UserSurveyResponse(
                            reason=reason, reason_user_input=reason_user_input
                        )

                cancel_time = json_dict_require_google_timestamp(user_initiated_cancellation_obj, "cancelTime", err)

                if not err.has():
                    user_initiated_cancellation = SubscriptionsV2SubscriptionCanceledStateContextUser(
                        cancel_survey_result=cancel_survey_result, cancel_time=cancel_time
                    )

            is_system_initiated_cancellation = json_dict_optional_google_empty_object_bool(
                canceled_state_context_obj, "systemInitiatedCancellation", err
            )
            is_developer_initiated_cancellation = json_dict_optional_google_empty_object_bool(
                canceled_state_context_obj, "developerInitiatedCancellation", err
            )
            is_replacement_cancellation = json_dict_optional_google_empty_object_bool(
                response, "replacementCancellation", err
            )

            existing_keys = (
                is_user_initiated_cancellation
                + is_system_initiated_cancellation
                + is_developer_initiated_cancellation
                + is_replacement_cancellation
            )
            # NOTE: can have 0 context, this happens when a subscription is upgraded, downgraded, or crossgraded
            if existing_keys > 1:
                err.msg_list.append('Multiple cancellation state for plan. This is not possible!')

            if not err.has():
                canceled_state_context = SubscriptionsV2CanceledState(
                    user_initiated_cancellation=user_initiated_cancellation,
                    system_initiated_cancellation=is_system_initiated_cancellation,
                    developer_initiated_cancellation=is_developer_initiated_cancellation,
                    replacement_cancellation=is_replacement_cancellation,
                )

        is_test_purchase = json_dict_optional_google_empty_object_bool(response, "testPurchase", err)

        acknowledgement_state = json_dict_require_str_coerce_to_enum(
            response, "acknowledgementState", SubscriptionsV2AcknowledgementState, err
        )

        obfuscated_external_account_id: str | None = None
        if "externalAccountIdentifiers" in response:
            external_account_identifiers: base.JSONObject = base.json_dict_require_obj(
                response, "externalAccountIdentifiers", err
            )
            obfuscated_external_account_id = base.json_dict_require_str(
                external_account_identifiers, "obfuscatedExternalAccountId", err
            )

        # Optional throughout, and read with `optional` rather than `require` at every level: this whole
        # object appears only on an unacknowledged resubscription, its identifiers block only if the expired
        # subscription had one configured, and neither absence is an error. `expiredPurchaseToken` is
        # deliberately not parsed — the account id is the identifier our attribution already keys on, so
        # taking the token too would mean a second resolution path to keep correct for no extra reach.
        expired_obfuscated_external_account_id: str | None = None
        expired_purchase_token: str | None = None
        out_of_app_context = json_dict_optional_obj(response, "outOfAppPurchaseContext", err)
        if out_of_app_context is not None:
            expired_identifiers = json_dict_optional_obj(out_of_app_context, "expiredExternalAccountIdentifiers", err)
            if expired_identifiers is not None:
                # Named `obfuscatedAccountId` here, NOT `obfuscatedExternalAccountId` as on the purchase
                # itself. Same value, two spellings, one of which is easy to copy wrongly.
                expired_obfuscated_external_account_id = base.json_dict_optional_str(
                    expired_identifiers, "obfuscatedAccountId"
                )
            expired_purchase_token = base.json_dict_optional_str(out_of_app_context, "expiredPurchaseToken")

        if not err.has() and acknowledgement_state is not None:
            result = SubscriptionV2Data(
                kind=kind,
                line_items=line_items,
                start_time=start_time,
                subscription_state=subscription_state,
                linked_purchase_token=linked_purchase_token,
                paused_state_context=paused_state_context,
                canceled_state_context=canceled_state_context,
                test_purchase=is_test_purchase,
                acknowledgement_state=acknowledgement_state,
                obfuscated_external_account_id=obfuscated_external_account_id,
                expired_obfuscated_external_account_id=expired_obfuscated_external_account_id,
                expired_purchase_token=expired_purchase_token,
            )
    else:
        err.msg_list.append('Failed to get subscription details, result not a dict')

    assert result is None if err.has() else isinstance(result, SubscriptionV2Data)
    return result


def fetch_subscription_v2_details(package_name: str, purchase_token: str, err: ErrorSink) -> SubscriptionV2Data | None:
    """
    Call the purchases.subscriptionsv2.get endpoint.
    https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.subscriptionsv2/get
    """
    if base.PROVIDER_DRY_RUN:
        # Dry-run: no call to Google. This is a gating read (its acknowledgement_state decides whether we
        # acknowledge); return a synthetic active+acknowledged purchase so the caller treats it as good to
        # go and skips the acknowledge entirely.
        return SubscriptionV2Data(
            subscription_state=SubscriptionsV2State.ACTIVE,
            acknowledgement_state=SubscriptionsV2AcknowledgementState.ACKNOWLEDGED,
        )

    service = get_publisher_service()
    response = service.purchases().subscriptionsv2().get(packageName=package_name, token=purchase_token).execute()

    return parse_get_subscription_v2_response(response, err)


def subscription_v1_acknowledge(purchase_token: str, err: ErrorSink):
    """
    Call the purchases.subscriptionsv1.acknowledge endpoint.
    https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.subscriptions/acknowledge
    """
    if base.PROVIDER_DRY_RUN:
        # Dry-run: acknowledging is an outbound mutation → no-op (leave err untouched = success).
        return

    service = get_publisher_service()
    response = (
        service.purchases()
        .subscriptions()
        .acknowledge(packageName=package_name, subscriptionId="", token=purchase_token)
        .execute()
    )

    # Google returns an empty string response for a success
    if response != "":
        err.msg_list.append(
            f'Failed to acknowledge purchase for purchase_token: {base.maybe_obfuscate(purchase_token)}'
        )


def parse_line_item(details: SubscriptionV2Data, err: ErrorSink) -> SubscriptionV2DataLineItem | None:
    '''The line item the user actually OWNS, or None with the reason recorded.

    Chosen rather than assumed. This used to take `line_items[0]`, which is only correct while a
    subscription has exactly one item. Google sends a second during a deferred change — for the product
    being replaced *to* — and documents that item as having no `latestSuccessfulOrderId`, precisely because
    the user does not own it yet. Taking position 0 therefore reads whichever the response happened to list
    first, and picking the incoming one yields an item with no order id: the identity every payment row is
    keyed by.

    Ownership is the honest filter, and it is the same one Google's own field semantics imply. Among owned
    items — a multi-item subscription is legal, though nothing we sell produces one — the furthest expiry is
    the one that decides entitlement, so that is the tie-break.
    '''
    owned = [item for item in details.line_items if item.latest_successful_order_id is not None]
    if not owned:
        # Distinguished from "several": no owned item at all means the resource describes a subscription
        # the user has not been charged for yet (a pending signup), which is not something to key a payment
        # on and not an error in the response.
        err.msg_list.append(
            f'Subscription resource has no owned line item ({len(details.line_items)} present); '
            f'nothing to attribute a payment to'
        )
        return None

    if len(owned) > 1:
        log.warning(
            f'Subscription resource has {len(owned)} owned line items; taking the furthest expiry. '
            f'Nothing we sell produces this, so it is worth understanding.'
        )
    return max(owned, key=lambda item: item.expiry_time.unix_milliseconds)


def parse_valid_order_id(details: SubscriptionV2Data, err: ErrorSink) -> str:
    # Owning an item and having an order id are the same fact, so parse_line_item's filter already
    # guarantees this; the check remains because the type does not.
    line_item = parse_line_item(details, err)
    if line_item is None or line_item.latest_successful_order_id is None:
        if not err.has():
            err.msg_list.append("Order id is None is subscription but was required!")
        return ""
    return line_item.latest_successful_order_id


@dataclasses.dataclass
class SubscriptionPlanEventTransaction:
    base_plan_id: str  # ID of the Google subscription's base plan. Not the product_id.
    pro_plan: ProPlan  # Session Pro plan parsed from the `base_plan_id`
    expiry_time: GoogleTimestamp  # Time at which the subscription expires
    event_ts_ms: int  # Timestamp in ms when the event occured
    linked_purchase_token: str | None
    notification: SubscriptionNotificationType
    subscription_state: SubscriptionsV2State
    purchase_acknowledged: SubscriptionsV2AcknowledgementState
    obfuscated_external_account_id: str | None
    # The expired subscription's account id, when this is an unacknowledged resubscribe. See
    # `SubscriptionV2Data.expired_obfuscated_external_account_id` for why it is the only attribution
    # available in that case.
    expired_obfuscated_external_account_id: str | None
    expired_purchase_token: str | None


def parse_subscription_purchase_tx(purchase_token: str, details: SubscriptionV2Data, err: ErrorSink):
    order_id = parse_valid_order_id(details, err)
    return PaymentProviderTransaction(
        provider=PaymentProvider.GooglePlayStore, google_payment_token=purchase_token, google_order_id=order_id
    )


def pro_plan_from_base_plan_id(base_plan_id: str, err: ErrorSink) -> ProPlan:
    result = ProPlan.Nil
    match base_plan_id:
        case "session-pro-1-month":
            result = ProPlan.OneMonth
        case "session-pro-3-months":
            result = ProPlan.ThreeMonth
        case "session-pro-12-months":
            result = ProPlan.TwelveMonth
        case _:
            # Reported, never asserted: a base plan added in Play Console is EXTERNAL INPUT, not a broken
            # invariant, so it must reach the caller as an error it can act on. Asserting sent an
            # AssertionError through the handler's blanket except instead, losing the message text into a
            # traceback. (Under `python -O` the assert vanished, leaving exactly the behaviour written here
            # — the caller has always guarded on the sink, so `Nil` never reached a write either way.)
            #
            # The caller declines to write and leaves the notification unacked, which is the right answer:
            # we cannot invent an entitlement for a plan we do not know. Recovery is open-ended rather than
            # racing a deadline — the payload is durably stored before handling, the prune only removes
            # handled rows, and the startup drain reloads the rest — so deploying support for the plan
            # registers the purchase whenever that happens. Pub/Sub's retention bounds only Google's own
            # redelivery, which stops mattering once the payload is ours. It is still an emergency: the
            # subscriber has paid and has no Pro until that deploy.
            err.msg_list.append(f'Invalid google base_plan_id, unable to determine plan variant: {base_plan_id}')

    return result


def parse_subscription_plan_event_tx(
    details: SubscriptionV2Data, event_ts_ms: int, notification: SubscriptionNotificationType, err: ErrorSink
) -> SubscriptionPlanEventTransaction:
    line_item = parse_line_item(details, err)
    if line_item is None:
        # The sink carries the reason; hand back a zero-valued tx so the caller's `err.has()` guard is what
        # stops it, matching how every other parse failure here behaves.
        return SubscriptionPlanEventTransaction(
            base_plan_id='',
            # Never read: the populated sink is what stops the caller. Borrowed rather than fabricated,
            # because GoogleTimestamp parses RFC3339. A parsed resource always has at least one item
            # (parse_get_subscription_v2_response rejects an empty lineItems), but the PROVIDER_DRY_RUN
            # synthetic is built by hand with none, so the guard is not decorative.
            expiry_time=(
                details.line_items[0].expiry_time
                if details.line_items
                else GoogleTimestamp('1970-01-01T00:00:00Z', ErrorSink())
            ),
            pro_plan=ProPlan.Nil,
            event_ts_ms=event_ts_ms,
            notification=notification,
            subscription_state=details.subscription_state,
            linked_purchase_token=details.linked_purchase_token,
            purchase_acknowledged=details.acknowledgement_state,
            obfuscated_external_account_id=details.obfuscated_external_account_id,
            expired_obfuscated_external_account_id=details.expired_obfuscated_external_account_id,
            expired_purchase_token=details.expired_purchase_token,
        )
    result = SubscriptionPlanEventTransaction(
        base_plan_id=line_item.offer_details.base_plan_id,
        expiry_time=line_item.expiry_time,
        pro_plan=pro_plan_from_base_plan_id(line_item.offer_details.base_plan_id, err),
        event_ts_ms=event_ts_ms,
        notification=notification,
        subscription_state=details.subscription_state,
        linked_purchase_token=details.linked_purchase_token,
        purchase_acknowledged=details.acknowledgement_state,
        obfuscated_external_account_id=details.obfuscated_external_account_id,
        expired_obfuscated_external_account_id=details.expired_obfuscated_external_account_id,
        expired_purchase_token=details.expired_purchase_token,
    )
    return result


@dataclasses.dataclass
class VoidedPurchaseTxFields:
    purchase_token: str = ''
    order_id: str = ''  # Unique ID of the successful order
    product_type: ProductType = ProductType.NIL
    refund_type: RefundType = RefundType.NIL
    event_ts_ms: int = 0  # Timestamp in ms when the event occured
