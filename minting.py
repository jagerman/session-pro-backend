'''
Minting payments that no payment provider ever witnessed.

Deliberately a separate module from `backend.py` rather than functions on it: nothing on the normal
request path imports this, so an ordinary instance never loads it. Only two callers pull it in —
`cli.py voucher` (an operator granting a subscription out of band, which is what the Rangeproof
provider exists for) and `dev_routes.py` (QA staging a Google/Apple subscription with no store
involved, on an instance started with `dev_endpoints`). They share this one code path so the CLI and
the dev route cannot drift apart.

Nothing here is reachable from a production uWSGI worker.
'''

import dataclasses
import datetime
import uuid

import nacl.signing

import backend
import base
import db


@dataclasses.dataclass
class MintedPayment:
    payment_tx: base.PaymentProviderTransaction = dataclasses.field(default_factory=base.PaymentProviderTransaction)
    # The opaque wire `payment_id` (§3.5) for the minted transaction, so a caller can hand it to a client
    # that then claims the payment through the real add_pro_payment route.
    payment_id: str = ''
    plan: base.ProPlan = base.ProPlan.Nil
    expires_at: datetime.datetime = base.EPOCH
    redeemed: bool = False


# Nominal length of each billing period, used when the caller does not override the duration outright.
PLAN_DEFAULT_DURATION: dict[base.ProPlan, datetime.timedelta] = {
    base.ProPlan.OneMonth: datetime.timedelta(days=30),
    base.ProPlan.ThreeMonth: datetime.timedelta(days=90),
    base.ProPlan.TwelveMonth: datetime.timedelta(days=365),
}

# The operator-facing plan labels (CLI flags, dev-route JSON). Deliberately NOT ProPlan.from_string:
# that accepts the wire codes and the member names only, and the twelve-month code is `1y`, so it
# rejects the "12M" that every human writes. Kept in one place so the CLI and the dev route agree.
PLAN_FROM_LABEL: dict[str, base.ProPlan] = {
    '1M': base.ProPlan.OneMonth,
    '3M': base.ProPlan.ThreeMonth,
    '12M': base.ProPlan.TwelveMonth,
}


def plan_from_label(label: str) -> base.ProPlan | None:
    '''Resolve a plan from an operator-facing label ("1M"/"3M"/"12M", any case), falling back to the
    wire codes and member names via ProPlan.from_string. Returns None if nothing matches.'''
    result = PLAN_FROM_LABEL.get(label.upper())
    if result is None:
        result = base.ProPlan.from_string(label)
    return None if result == base.ProPlan.Nil else result


def duration_from_seconds(seconds: int | None) -> datetime.timedelta | None:
    '''Turn an operator-supplied duration in seconds into a timedelta, or None when it was omitted
    (meaning "use the plan's nominal length").

    Zero and negatives are rejected rather than clamped: both would mint a payment that is already
    expired at the instant it is created. Zero especially has to be rejected here rather than left to
    a caller's `if seconds:` truthiness test, which cannot tell it apart from omitted and would
    silently substitute the full plan length.'''
    if seconds is None:
        return None
    if seconds <= 0:
        raise base.FailError('duration must be a positive integer number of seconds')
    return datetime.timedelta(seconds=seconds)


@db.transactional
def mint_payment(
    tx: db.SQLTransaction,
    master_pkey: nacl.signing.VerifyKey,
    provider: base.PaymentProvider,
    plan: base.ProPlan,
    now: datetime.datetime,
    duration: datetime.timedelta | None = None,
    redeem: bool = True,
) -> MintedPayment:
    '''Create a payment that no payment provider ever witnessed, bound to `master_pkey`, and (by
    default) redeem it on the spot.

    The synthetic identifiers minted below are arbitrary, but the *account binding* is not: it has to
    equal what `backend.redeem_payment` recomputes from the master pubkey, or the redeem matches no
    row. Google binds on the raw 32-byte pubkey; Apple on `uuid_from_master_pk` of it.

    `redeem=False` stops after the unredeemed payment and hands back its `payment_id`, so a client can
    claim it through the real `add_pro_payment` route — the closest thing to a genuine store purchase
    that can be staged locally.
    '''
    if plan == base.ProPlan.Nil:
        raise base.FailError('Cannot mint a payment for the nil plan')
    # Callers should arrive via duration_from_seconds; this guards the timedelta boundary itself so a
    # caller building one directly cannot mint a payment that is expired the moment it exists.
    if duration is not None and duration <= datetime.timedelta(0):
        raise base.FailError('duration must be positive')

    master_pkey_bytes: bytes = bytes(master_pkey)
    payment_tx = base.PaymentProviderTransaction(provider=provider)
    platform_obfuscated_account_id: bytes | str

    match provider:
        case base.PaymentProvider.GooglePlayStore:
            payment_tx.google_payment_token = str(uuid.uuid4())
            payment_tx.google_order_id = f'GPA.{uuid.uuid4()}'
            platform_obfuscated_account_id = master_pkey_bytes
        case base.PaymentProvider.iOSAppStore:
            # Import the Apple provider lazily, exactly as the Apple redeem path does — importing this
            # module must not pull the Apple SDK in. DO NOT hoist.
            from providers import app_store

            # Apple transaction ids are decimal strings; any distinct value works for a minted payment.
            payment_tx.apple_tx_id = str(uuid.uuid4().int)[:18]
            payment_tx.apple_original_tx_id = payment_tx.apple_tx_id
            payment_tx.apple_web_line_order_tx_id = str(uuid.uuid4().int)[:18]
            platform_obfuscated_account_id = app_store.uuid_from_master_pk(master_pkey_bytes)
        case base.PaymentProvider.Rangeproof:
            payment_tx.rangeproof_order_id = str(uuid.uuid4())
            platform_obfuscated_account_id = b''
        case _:
            raise base.FailError(f'Cannot mint a payment for payment provider: {provider}')

    expires_at: datetime.datetime = now + (duration if duration is not None else PLAN_DEFAULT_DURATION[plan])

    err = base.ErrorSink()
    backend.add_unredeemed_payment(
        tx,
        payment_tx=payment_tx,
        plan=plan,
        expires_at=expires_at,
        purchased_at=now,
        platform_refund_expires_at=base.EPOCH,
        platform_obfuscated_account_id=platform_obfuscated_account_id,
        err=err,
    )
    if err.has():
        raise base.ServerError(f'Failed to mint payment: {err.build()}')

    result = MintedPayment(
        payment_tx=payment_tx,
        payment_id=backend.encode_payment_id(
            provider,
            google_payment_token=payment_tx.google_payment_token,
            google_order_id=payment_tx.google_order_id,
            apple_tx_id=payment_tx.apple_tx_id,
            rangeproof_order_id=payment_tx.rangeproof_order_id,
        ),
        plan=plan,
        expires_at=expires_at,
    )

    if redeem:
        # rotating_pkey/signing_key are deliberately None: this registers the entitlement (user row +
        # generation) WITHOUT minting a proof, leaving the client to request one through
        # generate_pro_proof with its own rotating key. Calls redeem_payment rather than
        # add_pro_payment on purpose — the latter's Google branch is an acknowledgement against
        # Google's servers, which has no meaning for a payment Google never saw.
        backend.redeem_payment(
            tx,
            master_pkey=master_pkey,
            rotating_pkey=None,
            signing_key=None,
            request_at=now,
            redeemed_at=backend.to_redeemed_at(now),
            payment_tx=backend.UserPaymentTransaction(
                provider=provider,
                apple_tx_id=payment_tx.apple_tx_id,
                rangeproof_order_id=payment_tx.rangeproof_order_id,
                google_payment_token=payment_tx.google_payment_token,
                google_order_id=payment_tx.google_order_id,
                payment_id=result.payment_id,
            ),
        )
        result.redeemed = True

    return result
