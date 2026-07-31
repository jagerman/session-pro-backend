import nacl.signing
import pendulum
import nacl.utils
import nacl.bindings
import functools
import hashlib
import typing
import collections.abc
import dataclasses
import logging
import enum
import csv
import io
import uuid

import base
import db
import migrations
import psycopg
import psycopg_pool

ZERO_BYTES32 = bytes(32)
BLAKE2B_DIGEST_SIZE = 32
log = logging.Logger("BACKEND")
# 16-byte domain-separation prefix on the signed MESSAGE (signatures are Ed25519 over the message
# directly — no BLAKE2b, so this is a domain prefix, not a hash personalisation; see signed_message).
DOMAIN_SIZE = 16
GENERATE_PROOF_DOMAIN = b'ProGenerateProof'
BUILD_PROOF_DOMAIN = b'ProProof_v0_____'  # the proof version lives IN the prefix, not in a signed field
GET_PAYMENT_DETAILS_DOMAIN = b'ProGetPayDetails'
GET_PRO_STATUS_DOMAIN = b'ProGetProStatus_'
assert all(
    len(p) == DOMAIN_SIZE
    for p in (GENERATE_PROOF_DOMAIN, BUILD_PROOF_DOMAIN, GET_PAYMENT_DETAILS_DOMAIN, GET_PRO_STATUS_DOMAIN)
)

# Explicit column list for payments table queries. Rows are read with `db.dict_row` and unpacked by
# name in `payment_row_from_dict`, so order here is cosmetic (no positional coupling).
# `master_pkey` lives only in `users` now, so payments reads come from `PAYMENTS_FROM` (payments LEFT
# JOIN users) and pull the pkey from the joined users row — NULL for an unredeemed payment (user_id
# NULL).
# Provider-specific ids come from the per-provider detail tables (LEFT JOINed below — a payment is in
# exactly one, the rest are NULL) and are aliased back to the historical column names so the row→PaymentRow
# mapping (payment_row_from_dict) is unchanged.
PAYMENTS_COLUMNS = ", ".join(
    (
        "p.id",
        "u.master_pkey",
        "p.plan",
        "p.payment_provider",
        "p.auto_renewing",
        "p.purchased_at",
        "p.redeemed_at",
        "p.expires_at",
        "p.grace_period",
        "p.platform_refund_expires_at",
        "p.revoked_at",
        "ad.original_tx_id AS apple_original_tx_id",
        "ad.tx_id AS apple_tx_id",
        "ad.web_line_order_tx_id AS apple_web_line_order_tx_id",
        "gd.payment_token AS google_payment_token",
        "gd.order_id AS google_order_id",
        "rd.order_id AS rangeproof_order_id",
        "gd.obfuscated_account_id AS google_obfuscated_account_id",
        "ad.app_account_token AS apple_app_account_token",
    )
)
PAYMENTS_FROM = " LEFT JOIN ".join(
    (
        "payments p",
        "users u ON u.id  = p.user_id",
        "google_play_payment_details gd ON gd.payment_id = p.id",
        "app_store_payment_details ad ON ad.payment_id = p.id",
        "rangeproof_payment_details rd ON rd.payment_id = p.id",
    )
)


# Single source of truth for reading a user row (mirrors PAYMENTS_*). The join to `generations` pulls the
# current generation's `token` (the proof's revocation_tag); it's an INNER JOIN because
# users.current_generation_id is NOT NULL, so every user always has a current generation.
USERS_COLUMNS = ", ".join(
    (
        "u.id",
        "u.master_pkey",
        "u.current_generation_id",
        "g.token",
        "u.expires_at",
        "u.grace_period",
        "u.auto_renewing",
        "u.proof_expiry_offset",
    )
)
USERS_FROM = "users u JOIN generations g ON g.id = u.current_generation_id"

# payments.payment_provider / .plan and user_errors.payment_provider store the string `code` directly
# (the lookup tables payment_providers/pro_plans use the code as their PRIMARY KEY, FK'd for validity).
# So there's no id indirection: the enum's `.value` IS the stored value, and reads map it straight back
# via base.PaymentProvider(...)/base.ProPlan(...).


class ReportPeriod(enum.Enum):
    Daily = 0
    Weekly = 1
    Monthly = 2


class ReportType(enum.Enum):
    Human = 0
    CSV = 1


@dataclasses.dataclass(frozen=True)
class ReportRow:
    period: str
    active_users: int
    unredeemed: int
    new_subs: int
    google: int
    apple: int
    rangeproof: int
    plan_1m: int
    plan_3m: int
    plan_12m: int
    revoked: int
    cancelled: int


@dataclasses.dataclass
class GoogleNotificationMessageIDInDB:
    present: bool = False
    handled: bool = False


@dataclasses.dataclass
class ProSubscriptionProof:
    version: int = 0
    revocation_tag: bytes = b''  # the generation's stored random 32-byte token
    rotating_pkey: nacl.signing.VerifyKey = nacl.signing.VerifyKey(ZERO_BYTES32)
    expires_at: pendulum.DateTime = base.EPOCH
    sig: bytes = b''

    # --- Advisory account-entitlement value: NOT signed and NOT part of the proof message (the signed
    # message is revocation_tag ‖ rotating_pkey ‖ expires_at). Populated by
    # build_current_entitlement_proof from the SAME DB snapshot that produced the proof, so a proof
    # fetch also hands the client its current subscription horizon in one response. This is the TRUE
    # entitlement end (grace-inclusive, matching what get_pro_status reports), except in the closing
    # window where the proof's over-provision runs past it and it reads back the proof's own expiry so
    # that `expires_at <= account_expires_at` always holds. Deliberately distinct from `expires_at`
    # above, which is the rolling, clamped (~30 d) proof validity — never conflate the two.
    # Display state only; the signed proof + revocation list remain authoritative.
    # Left at the default on any proof built without a user context (none today). ---
    account_expires_at: pendulum.DateTime = base.EPOCH

    def to_dict(self) -> dict[str, str | int]:
        # `version` is a PLAINTEXT field, deliberately NOT bound into the signature. It is the
        # external indicator a verifier reads to pick the domain prefix + layout it must use to
        # reconstruct and check the signed message; v0's domain prefix is BUILD_PROOF_DOMAIN
        # (`ProProof_v0_____`). The version→domain-prefix map is per-version and arbitrary — a future
        # version may choose any domain prefix (or reshape the proof entirely); a verifier simply
        # refuses a version it doesn't understand, so nothing old breaks. The version is thus a
        # verification *input*, never discovered through the signature; tampering with it just makes the
        # verifier pick the wrong domain prefix → signature fails.
        result: dict[str, str | int] = {
            "version": self.version,
            "revocation_tag": self.revocation_tag.hex(),
            "rotating_pkey": bytes(self.rotating_pkey).hex(),
            # Whole seconds by construction — a store expiry (µs-capable) only reaches here through
            # _build_proof_clamped_expiry_time, and the signed message needs an exact integer (wire §2).
            "expiry_ts": base.unix_seconds_from_datetime(self.expires_at),
            "sig": self.sig.hex(),
            # Advisory, UNSIGNED (see field comment): the account's true entitlement end, distinct from
            # the clamped proof `expiry_ts` above. Lets a proof fetch refresh the client's cached expiry.
            "account_expiry_ts": base.unix_seconds_from_datetime(self.account_expires_at),
        }
        return result


@dataclasses.dataclass
class LookupUserExpiry:
    # `None` expiry = "no such payment found yet". Durations default to zero.
    expiry_from_redeemed: pendulum.DateTime | None = None
    grace_from_redeemed: pendulum.Duration = pendulum.duration()
    auto_renewing_from_redeemed: bool = False

    best_expiry: pendulum.DateTime | None = None
    best_grace: pendulum.Duration = pendulum.duration()
    best_auto_renewing: bool = False


AddRevocationIterator: typing.TypeAlias = tuple[
    int, bytes | None, pendulum.DateTime  # (row) id  # master_pkey
]  # expires_at

GoogleUnhandledNotificationIterator: typing.TypeAlias = tuple[
    str, str | None, pendulum.DateTime  # message_id (opaque string)  # payload
]  # expires_at


@dataclasses.dataclass
class UserError:
    provider: base.PaymentProvider = base.PaymentProvider.Nil
    apple_original_tx_id: str = ''
    google_payment_token: str = ''


@dataclasses.dataclass
class UserPaymentTransaction:
    provider: base.PaymentProvider = base.PaymentProvider.Nil
    apple_tx_id: str = ''
    rangeproof_order_id: str = ''
    google_payment_token: str = ''
    google_order_id: str = ''


# Google folds its two identifiers into one opaque `payment_id` as `token | order_id`, split once on the
# first delimiter. The token is base64url and the order id is `GPA.####-…`, so neither contains `|`.
GOOGLE_PAYMENT_ID_DELIMITER = '|'


def encode_payment_id(
    provider: base.PaymentProvider,
    *,
    google_payment_token: str = '',
    google_order_id: str = '',
    apple_tx_id: str = '',
    rangeproof_order_id: str = '',
) -> str:
    # Fold a payment's provider-specific identifier(s) into the single opaque `payment_id` returned on
    # get_payment_details items (§5.2). The backend owns this encoding; clients treat it as opaque.
    match provider:
        case base.PaymentProvider.GooglePlayStore:
            return f'{google_payment_token}{GOOGLE_PAYMENT_ID_DELIMITER}{google_order_id}'
        case base.PaymentProvider.iOSAppStore:
            return apple_tx_id
        case base.PaymentProvider.Rangeproof:
            return rangeproof_order_id
        case _:
            return ''


@dataclasses.dataclass
class AppleTransaction:
    original_tx_id: str = ''
    tx_id: str = ''
    web_line_order_tx_id: str = ''


@dataclasses.dataclass
class PaymentRow:
    id: int = 0
    master_pkey: bytes | None = None
    # No stored `status`: derive it from the timestamps below via backend.derive_payment_status(row, now).
    plan: base.ProPlan = base.ProPlan.Nil
    payment_provider: base.PaymentProvider = base.PaymentProvider.Nil
    auto_renewing: bool = False
    purchased_at: pendulum.DateTime = base.EPOCH
    redeemed_at: pendulum.DateTime | None = None
    expires_at: pendulum.DateTime = base.EPOCH
    grace_period: pendulum.Duration | None = None
    platform_refund_expires_at: pendulum.DateTime = base.EPOCH
    revoked_at: pendulum.DateTime | None = None
    apple: AppleTransaction = dataclasses.field(default_factory=AppleTransaction)
    google_payment_token: str = ''
    google_order_id: str = ''
    rangeproof_order_id: str = ''
    google_obfuscated_account_id: bytes | None = None
    apple_app_account_token: str | None = None


def payment_id_from_payment_row(row: PaymentRow) -> str:
    # Egress: fold a stored payment's typed columns back into the opaque `payment_id` (§5.2).
    return encode_payment_id(
        row.payment_provider,
        google_payment_token=row.google_payment_token,
        google_order_id=row.google_order_id,
        apple_tx_id=row.apple.tx_id,
        rangeproof_order_id=row.rangeproof_order_id,
    )


@dataclasses.dataclass
class UserRow:
    found: bool = False
    id: int = 0
    master_pkey: bytes | None = None
    current_generation_id: int = 0
    token: bytes = b''  # current generation's token (proof revocation_tag)
    expires_at: pendulum.DateTime = base.EPOCH
    grace_period: pendulum.Duration = pendulum.duration()
    auto_renewing: bool = False
    # This account's private proof-expiry grid: expiries land on `UTC midnight + this + k * one day`.
    # Re-drawn whenever `expires_at` moves. See new_proof_expiry_offset / _build_proof_clamped_expiry_time.
    proof_expiry_offset: int = 0


@dataclasses.dataclass
class GetUserAndPayments:
    payments_it: db.Result
    user: UserRow = dataclasses.field(default_factory=UserRow)
    payments_count: int = 0


@dataclasses.dataclass
class RevocationRow:
    '''A revoked generation (admin/raw view of the revocation list).'''

    generation_id: int = 0
    token: bytes = b''
    revoked_at: pendulum.DateTime = base.EPOCH


@dataclasses.dataclass
class AllocatedGenID:
    found: bool = False
    expires_at: pendulum.DateTime | None = None
    grace_period: pendulum.Duration = pendulum.duration()
    generation_id: int = 0
    token: bytes = b''


def load_backend_signing_key(path: str) -> nacl.signing.SigningKey:
    '''Load the backend Ed25519 signing key from disk.

    The file holds 128 hex characters (optionally followed by whitespace): the libsodium-style
    64-byte secret key, i.e. the 32-byte seed followed by the 32-byte precomputed public key
    (matching oxen-core's on-disk ed25519 key format). The key lives ONLY on disk, never in the
    database (and therefore never in a DB backup). Raises on any problem; the caller must refuse to
    start rather than run with a missing or malformed signing key.
    '''
    with open(path, 'r') as f:
        text: str = f.read().strip()
    if len(text) != 128 or any(c not in '0123456789abcdefABCDEF' for c in text):
        raise ValueError(f'expected 128 hex characters (a 64-byte libsodium ed25519 secret key), got {len(text)}')
    raw: bytes = bytes.fromhex(text)
    seed: bytes = raw[:32]
    pub: bytes = raw[32:]
    skey = nacl.signing.SigningKey(seed)
    if bytes(skey.verify_key) != pub:
        raise ValueError('embedded public key does not match the seed; the key file is corrupt')
    return skey


def backend_signing_key_to_hex(skey: nacl.signing.SigningKey) -> str:
    '''Serialise a signing key to the 128-hex libsodium-style representation (seed || public key).'''
    return (bytes(skey) + bytes(skey.verify_key)).hex()


def payment_provider_tx_log_label_safe(tx: base.PaymentProviderTransaction) -> str:
    # Only the active provider's ids are populated; show just those (obfuscated).
    match tx.provider:
        case base.PaymentProvider.iOSAppStore:
            ids = (
                f'apple(orig/tx/web)=({base.maybe_obfuscate(tx.apple_original_tx_id)}/'
                f'{base.maybe_obfuscate(tx.apple_tx_id)}/{base.maybe_obfuscate(tx.apple_web_line_order_tx_id)})'
            )
        case base.PaymentProvider.GooglePlayStore:
            ids = f'google=({base.maybe_obfuscate(tx.google_payment_token)}/{base.maybe_obfuscate(tx.google_order_id)})'
        case base.PaymentProvider.Rangeproof:
            ids = f'rangeproof={base.maybe_obfuscate(tx.rangeproof_order_id)}'
        case _:
            ids = '(no provider ids)'
    return f'{tx.provider.name}, {ids}'


def user_payment_tx_to_safe_string(tx: UserPaymentTransaction) -> str:
    # Only the active provider's ids are populated; show just those (obfuscated).
    match tx.provider:
        case base.PaymentProvider.iOSAppStore:
            ids = f'apple={base.maybe_obfuscate(tx.apple_tx_id)}'
        case base.PaymentProvider.GooglePlayStore:
            ids = f'google=({base.maybe_obfuscate(tx.google_payment_token)}/{base.maybe_obfuscate(tx.google_order_id)})'
        case base.PaymentProvider.Rangeproof:
            ids = f'rangeproof={base.maybe_obfuscate(tx.rangeproof_order_id)}'
        case _:
            ids = '(no provider ids)'
    return f'{tx.provider.name}, {ids}'


def to_redeemed_at(at: pendulum.DateTime) -> pendulum.DateTime:
    # Round up to the next UTC-day boundary (masks the exact instant the payment was redeemed).
    return base.round_datetime_to_next_day(at)


# The bytes we Ed25519-sign directly (NO pre-hash — wire spec §1): a 16-byte domain prefix then the fields,
# each encoded by TYPE — VerifyKey/bytes verbatim (fixed-width, self-delimiting); datetime → its UNIX
# **seconds** then decimal ASCII (pass an int explicitly if you ever need other units); int as canonical
# locale-independent decimal ASCII (matches C++ std::to_chars: no grouping/leading zeros, '-' for
# negatives, so count=-1 and unbounded values Just Work); str as UTF-8. A `\0` separates two ADJACENT
# variable-length (datetime/int/str) fields; fixed-width fields need no separator. Only payment_id can
# contain a `\0` and it is always the final field, so the framing is unambiguous.
def signed_message(domain: bytes, *fields: nacl.signing.VerifyKey | bytes | pendulum.DateTime | int | str) -> bytes:
    assert len(domain) == DOMAIN_SIZE
    out = bytearray(domain)
    prev_variable = False
    for field in fields:
        if isinstance(field, (nacl.signing.VerifyKey, bytes, bytearray)):
            data, variable = bytes(field), False
        elif isinstance(field, pendulum.DateTime):
            data, variable = str(base.unix_seconds_from_datetime(field)).encode('ascii'), True  # → int seconds
        elif isinstance(field, int):
            data, variable = str(field).encode('ascii'), True  # canonical decimal
        elif isinstance(field, str):
            data, variable = field.encode('utf-8'), True
        else:
            raise TypeError(
                f'signed_message: unsupported field type {type(field).__name__} '
                f'(expected VerifyKey/bytes, datetime, int, or str)'
            )
        if variable and prev_variable:
            out += b'\x00'
        out += data
        prev_variable = variable
    return bytes(out)


def make_get_pro_status_message(master_pkey: nacl.signing.VerifyKey, request_at: pendulum.DateTime) -> bytes:
    return signed_message(GET_PRO_STATUS_DOMAIN, master_pkey, request_at)


def make_get_payment_details_message(
    master_pkey: nacl.signing.VerifyKey, request_at: pendulum.DateTime, limit: int, before: str
) -> bytes:
    return signed_message(GET_PAYMENT_DETAILS_DOMAIN, master_pkey, request_at, limit, before)


# --- get-payment-details keyset pagination cursor ------------------------------------------------
# Seek pagination keys on the payment's surrogate id, but that id is a global identity sequence, so
# handing the raw value to the client would leak system-wide payment volume/ordering (the same reason
# `payment_id` is opaque, §5.2). So we hand back the boundary id sealed in an XChaCha20-Poly1305 token
# the client echoes verbatim. The key is derived from the backend signing key via a domain-separated
# BLAKE2b — no separate secret to provision; rotating the signing key just invalidates outstanding
# cursors (harmless — the client re-fetches from the newest page). The master_pkey is the AEAD
# associated data, binding a cursor to the user it was issued to.
_CURSOR_KEY_DOMAIN = b'SeshProCursorKey'  # 16-byte BLAKE2b personalisation


@functools.lru_cache(maxsize=None)
def _derive_cursor_key(seed: bytes) -> bytes:
    return hashlib.blake2b(seed, digest_size=32, person=_CURSOR_KEY_DOMAIN).digest()


def payment_cursor_key(signing_key: nacl.signing.SigningKey) -> bytes:
    '''The 32-byte XChaCha20-Poly1305 cursor key derived from the signing seed. The derivation is constant
    for a given key and memoized, so calling this per request just returns the cached bytes.'''
    return _derive_cursor_key(bytes(signing_key))


def encrypt_payment_cursor(cursor_key: bytes, master_pkey: nacl.signing.VerifyKey, payment_id: int) -> str:
    nonce = nacl.utils.random(nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        payment_id.to_bytes(8, 'big'), bytes(master_pkey), nonce, cursor_key
    )
    return (nonce + ct).hex()


def decrypt_payment_cursor(cursor_key: bytes, master_pkey: nacl.signing.VerifyKey, cursor: str) -> int:
    '''Decrypt a pagination cursor to its boundary payment id. Raises on tamper / wrong user / garbage.'''
    raw = bytes.fromhex(cursor)
    npub = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    nonce, ct = raw[:npub], raw[npub:]
    pt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, bytes(master_pkey), nonce, cursor_key)
    return int.from_bytes(pt, 'big')


def payment_row_from_dict(row: dict[str, typing.Any]) -> PaymentRow:
    # Rows come from a dict row factory (SELECT PAYMENTS_COLUMNS FROM PAYMENTS_FROM, row_factory=
    # db.dict_row) so columns are addressed by name — adding/removing a column no longer renumbers
    # anything here. `master_pkey` is joined from users (NULL for an unredeemed payment).
    result = PaymentRow()
    result.id = row['id']
    result.master_pkey = bytes(row['master_pkey']) if row['master_pkey'] is not None else None
    result.plan = base.ProPlan(row['plan'])
    result.payment_provider = base.PaymentProvider(row['payment_provider'])
    result.auto_renewing = bool(row['auto_renewing'])
    result.purchased_at = row['purchased_at']
    result.redeemed_at = row['redeemed_at']  # NULL until redeemed
    result.expires_at = row['expires_at']
    result.grace_period = row['grace_period']  # nullable
    result.platform_refund_expires_at = row['platform_refund_expires_at']
    result.revoked_at = row['revoked_at']  # NULL unless revoked
    result.apple.original_tx_id = str(row['apple_original_tx_id']) if row['apple_original_tx_id'] else ''
    result.apple.tx_id = str(row['apple_tx_id']) if row['apple_tx_id'] else ''
    result.apple.web_line_order_tx_id = (
        str(row['apple_web_line_order_tx_id']) if row['apple_web_line_order_tx_id'] else ''
    )
    result.google_payment_token = str(row['google_payment_token']) if row['google_payment_token'] else ''
    result.google_order_id = str(row['google_order_id']) if row['google_order_id'] else ''
    result.rangeproof_order_id = str(row['rangeproof_order_id']) if row['rangeproof_order_id'] else ''
    result.google_obfuscated_account_id = (
        bytes(row['google_obfuscated_account_id']) if row['google_obfuscated_account_id'] is not None else None
    )
    result.apple_app_account_token = row['apple_app_account_token']  # nullable
    return result


def derive_payment_status(payment: PaymentRow, now: pendulum.DateTime) -> base.PaymentStatus:
    """Derive the single display status from a payment's timestamps against `now`.

    `status` is not stored; it's computed with precedence revoked > expired > redeemed. Only a payment
    bound to a user has a status at all — an unclaimed one carries no user_id, so it never reaches a
    user-scoped response; test `redeemed_at IS NULL` for that instead of asking for a status.
    """
    if payment.revoked_at is not None:
        return base.PaymentStatus.Revoked
    assert payment.redeemed_at is not None, 'an unclaimed payment has no status; test redeemed_at IS NULL'
    if now >= payment.expires_at:
        return base.PaymentStatus.Expired
    return base.PaymentStatus.Redeemed


def subscription_coverage_end(
    expires_at: pendulum.DateTime, grace_period: pendulum.Duration | None, auto_renewing: bool
) -> pendulum.DateTime:
    """The instant a subscription payment stops covering the account: its paid-through expiry, plus the
    grace period only when a renewal is going to be attempted.

    Grace is the window after a renewal payment FAILS, so it exists only for an auto-renewing payment. A
    cancelled subscription still carries the grace value in its column while `auto_renewing` has gone
    false and `expires_at` is untouched — it covers the account to the end of the paid term and not a
    moment longer.

    Shared by the entitlement fold and the credit drain deliberately: if the two disagreed about when
    coverage ends, an account could be entitled while its credits drain, or hold protected credits while
    reading as expired."""
    return expires_at + grace_period if (auto_renewing and grace_period is not None) else expires_at


@dataclasses.dataclass
class CreditToDrain:
    """One live credit as the drain sees it: its row id and how much length it still has to give."""

    payment_id: int
    remaining: pendulum.Duration


@dataclasses.dataclass
class CreditDrainResult:
    # (payment id, new remaining) for the rows that actually changed — nothing else needs writing.
    updated: list[tuple[int, pendulum.Duration]] = dataclasses.field(default_factory=list)
    # How much of the budget was actually charged. Less than the budget exactly when the credits ran out
    # partway through the window, which is what lets the caller date that moment as `checkpoint + spent`.
    spent: pendulum.Duration = dataclasses.field(default_factory=pendulum.duration)
    # The budget outran the credits: every one of them is now zero and there was still time to charge.
    exhausted: bool = False


def drain_credits(credits: list[CreditToDrain], budget: pendulum.Duration) -> CreditDrainResult:
    """Spend `budget` worth of uncovered time across `credits`, oldest first, and report what changed.

    Pure: no clock, no database. The caller decides what `budget` is (the uncovered span since the
    account's drain checkpoint, zero while a subscription covers it) and supplies the live credits in
    consumption order; everything the caller must then write back is in the result.

    Exactly one credit can be paying for any given moment, so the budget is spent down one credit at a
    time, oldest first, and spills into the next only once the current one is empty.

    Budget left over after the last credit is discarded rather than remembered: those were moments the
    account simply had no entitlement, and there is nobody to charge for them."""
    result = CreditDrainResult()
    zero = pendulum.duration()
    if budget <= zero:
        return result

    left = budget
    for credit in credits:
        if left <= zero:
            break
        charge = min(credit.remaining, left)
        if charge <= zero:
            continue
        result.updated.append((credit.payment_id, credit.remaining - charge))
        left -= charge

    result.spent = budget - left
    result.exhausted = left > zero and len(credits) > 0
    return result


def get_unredeemed_payments_list(conn: psycopg.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with db.transaction(conn):
        rows = db.query(
            conn,
            f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM}'
            ' WHERE p.redeemed_at IS NULL AND p.revoked_at IS NULL ORDER BY p.id',
            row_factory=db.dict_row,
        )
        for row in rows:
            item = payment_row_from_dict(row)
            result.append(item)
    return result


def get_payments_list(conn: psycopg.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with db.transaction(conn):
        rows = db.query(conn, f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM} ORDER BY p.id', row_factory=db.dict_row)
        for row in rows:
            item = payment_row_from_dict(row)
            result.append(item)
    return result


def get_user_and_payments(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> GetUserAndPayments:
    payments_it = db.query(
        tx.conn,
        f'''
        SELECT   {PAYMENTS_COLUMNS}
        FROM     {PAYMENTS_FROM}
        WHERE    p.user_id = (SELECT id FROM users WHERE master_pkey = %s)
        ORDER BY p.purchased_at DESC, p.id DESC
    ''',
        bytes(master_pkey),
        row_factory=db.dict_row,
    )

    result = GetUserAndPayments(payments_it=payments_it)
    result.user = get_user(tx.conn, master_pkey)

    result.payments_count = db.query_scalar(
        tx.conn,
        '''
        SELECT COUNT(*)
        FROM   payments
        WHERE  user_id = (SELECT id FROM users WHERE master_pkey = %s)
    ''',
        bytes(master_pkey),
    )
    return result


def get_user_payments_page(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, limit: int, before_id: int | None
) -> list[PaymentRow]:
    '''One keyset page of a user's (redeemed) payments, newest-first (id DESC — the registration order).
    `before_id` is the exclusive upper bound: return rows with id < before_id; None starts at the newest.
    A user_id is only ever set on a redeemed payment, so this returns only redeemed rows.'''
    sql = (
        f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM} '
        'WHERE p.user_id = (SELECT id FROM users WHERE master_pkey = %(mk)s)'
    )
    params: dict[str, typing.Any] = {'mk': bytes(master_pkey), 'lim': limit}
    if before_id is not None:
        sql += ' AND p.id < %(before)s'
        params['before'] = before_id
    sql += ' ORDER BY p.id DESC LIMIT %(lim)s'
    return [payment_row_from_dict(r) for r in db.query(tx.conn, sql, row_factory=db.dict_row, **params)]


def get_user_payments_count(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> int:
    return db.query_scalar(
        tx.conn,
        'SELECT COUNT(*) FROM payments WHERE user_id = (SELECT id FROM users WHERE master_pkey = %s)',
        bytes(master_pkey),
    )


def user_row_from_dict(row: dict[str, typing.Any]) -> UserRow:
    return UserRow(
        found=True,
        id=row['id'],
        master_pkey=bytes(row['master_pkey']),
        current_generation_id=row['current_generation_id'],
        token=bytes(row['token']),
        expires_at=row['expires_at'],
        grace_period=row['grace_period'],
        auto_renewing=bool(row['auto_renewing']),
        proof_expiry_offset=row['proof_expiry_offset'],
    )


def get_users_list(conn: psycopg.Connection) -> list[UserRow]:
    result: list[UserRow] = []
    with db.transaction(conn):
        for row in db.query(conn, f"SELECT {USERS_COLUMNS} FROM {USERS_FROM}", row_factory=db.dict_row):
            result.append(user_row_from_dict(row))
    return result


def get_user(conn: psycopg.Connection, master_pkey: nacl.signing.VerifyKey) -> UserRow:
    # Single SELECT: runs on the given connection, so a mid-transaction caller passes `tx.conn` (joins the
    # open transaction) and a standalone caller autocommits.
    result: UserRow = UserRow()
    row = db.query_one(
        conn,
        f"SELECT {USERS_COLUMNS} FROM {USERS_FROM} WHERE u.master_pkey = %s",
        bytes(master_pkey),
        row_factory=db.dict_row,
    )
    if row:
        result = user_row_from_dict(row)
    return result


def get_revocations_list(
    conn: psycopg.Connection, revoked_after: pendulum.DateTime | None = None
) -> list[RevocationRow]:
    """Revoked generations. `revoked_after` restricts them to those recorded after that instant, which is
    how the served list applies its retention window; omitted, this is the whole unfiltered set.

    Single statement, so it runs directly on the given connection: a mid-transaction caller passes
    `tx.conn` and the read joins that open transaction, a standalone caller autocommits."""
    sql = "SELECT id, token, revoked_at FROM generations WHERE revoked_at IS NOT NULL"
    args: tuple[typing.Any, ...] = ()
    if revoked_after is not None:
        sql += " AND revoked_at > %s"
        args = (revoked_after,)
    result: list[RevocationRow] = []
    for row in db.query(conn, sql, *args):
        generation_id, token, revoked_at = row
        result.append(RevocationRow(generation_id=generation_id, token=bytes(token), revoked_at=revoked_at))
    return result


def is_generation_revoked(conn: psycopg.Connection, generation_id: int, now: pendulum.DateTime) -> bool:
    # A generation is revoked iff revoked_at is set (revocation is terminal). `now` is accepted for a
    # uniform signature; a set revoked_at is always in effect (there is no per-entry expiry now — the
    # served-list retention window is list-level and memory-only on the client). Single statement, so it
    # runs directly on the given connection: a mid-transaction caller passes `tx.conn` and the read joins
    # that open transaction (sees an uncommitted revoke); a standalone caller autocommits.
    return bool(
        db.query_scalar(
            conn, "SELECT EXISTS (SELECT 1 FROM generations WHERE id = %s AND revoked_at IS NOT NULL)", generation_id
        )
    )


# Typed accessors for the `globals` key/value store (one row per app-global; see schema/000). Each
# global's type is known at the call site, so we read/write the matching value slot directly.
def get_global_int(conn: psycopg.Connection, key: str) -> int:
    row = db.query_one(conn, "SELECT int_val FROM globals WHERE key = %s", key)
    assert row is not None, f'missing int global "{key}"'
    return row[0]


def set_global_int(conn: psycopg.Connection, key: str, value: int) -> None:
    db.query(conn, "UPDATE globals SET int_val = %s WHERE key = %s", value, key)


def get_global_bytes(conn: psycopg.Connection, key: str) -> bytes:
    row = db.query_one(conn, "SELECT bytes_val FROM globals WHERE key = %s", key)
    assert row is not None, f'missing bytes global "{key}"'
    return bytes(row[0])


def get_global_datetime(conn: psycopg.Connection, key: str) -> pendulum.DateTime:
    row = db.query_one(conn, "SELECT ts_val FROM globals WHERE key = %s", key)
    assert row is not None, f'missing timestamp global "{key}"'
    return row[0]


def set_global_datetime(conn: psycopg.Connection, key: str, value: pendulum.DateTime) -> None:
    db.query(conn, "UPDATE globals SET ts_val = %s WHERE key = %s", value, key)


def get_revocation_ticket(conn: psycopg.Connection) -> int:
    return get_global_int(conn, 'revocation_ticket')


def bump_revocation_ticket(conn: psycopg.Connection, amount: int) -> int:
    """Advance the monotonic revocation ticket by `amount`, returning the new value. Manual DR tool: the
    ticket is a plain counter, so restoring the database from an older backup rolls it backward — and a
    client holding a higher cached ticket then reads the list as "unchanged" and silently stops seeing
    revocations. After such a restore, bump the ticket past its pre-restore value to force every client to
    re-fetch. See docs/deploy.md ("After ANY restore")."""
    row = db.query_one(
        conn, "UPDATE globals SET int_val = int_val + %s WHERE key = 'revocation_ticket' RETURNING int_val", amount
    )
    assert row is not None, 'missing revocation_ticket global'
    return row[0]


def migrate_schema(conn: psycopg.Connection) -> None:
    """Bootstrap/migrate the schema on `conn` if needed. Raises RuntimeError on failure."""
    try:
        migrations.apply_migrations(conn)
    except Exception as e:
        raise RuntimeError('Failed to bootstrap DB tables') from e


def bootstrap_db(database_url: str) -> psycopg_pool.ConnectionPool:
    """Open a pool for `database_url` and migrate the schema, returning the pool. Raises on failure.

    Single-process convenience (tests, CLI) where a pool is safe to open eagerly. The uWSGI master
    must NOT use this: it runs pre-fork, and a pool's worker threads inherited across fork() corrupt
    the children (see db.connect_one). The master migrates on a throwaway connection and lets each
    worker build its own pool post-fork."""
    db.set_dsn(database_url)
    try:
        pool = db.pool()
    except Exception as e:
        raise RuntimeError(f'Failed to open/connect to DB at {database_url}: {e}') from e

    with db.connection() as conn:
        migrate_schema(conn)

    return pool


def verify_db(conn: psycopg.Connection, err: base.ErrorSink) -> bool:
    unredeemed_payments: list[PaymentRow] = get_unredeemed_payments_list(conn)
    for index, it in enumerate(unredeemed_payments):
        base.verify_payment_provider(it.payment_provider, err)
        if len(it.google_payment_token) != BLAKE2B_DIGEST_SIZE:
            err.msg_list.append(
                f'Unredeeemed payment #{index} token is not 32 bytes, was {len(it.google_payment_token)}'
            )
        if it.plan == base.ProPlan.Nil:
            err.msg_list.append(
                f'Unredeemed payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})'
            )

    payments: list[PaymentRow] = get_payments_list(conn)
    for index, it in enumerate(payments):
        # NOTE: Check mandatory fields
        if it.payment_provider == base.PaymentProvider.Nil:
            err.msg_list.append(
                f'Payment #{index} payment provider is set to {it.payment_provider.name} '
                f'but it should not be. '
                f'It should have been set by the platform before added to the DB'
            )

        # NOTE: Check mandatory fields or invariants given a particular TX status. Presence/absence
        # is now modelled by NULL (redeemed_at / revoked_at), and expires_at is NOT NULL, so the old
        # "ts was 0" sentinel checks are gone — the schema enforces them.
        if it.redeemed_at is None and it.revoked_at is None:
            # Unclaimed: nothing identity-related should be set yet.
            if it.master_pkey is not None:
                err.msg_list.append(
                    f'Payment #{index} has a master pkey set but this pkey should not be set '
                    f'until it is redeemed (e.g. the user registers it)'
                )

        if it.revoked_at is None and it.redeemed_at is not None:
            # Redeemed (and not revoked): a redeemed payment must not have expired before it was redeemed.
            if it.expires_at < it.redeemed_at:
                redeemed_date = it.redeemed_at.strftime('%Y-%m-%d')
                expiry_date = it.expires_at.strftime('%Y-%m-%d')
                err.msg_list.append(
                    f'Payment #{index} was expired ({expiry_date}) before it was activated ({redeemed_date})'
                )

        # NOTE: Verify the plan, it should always be set once it enters the DB..
        if it.plan == base.ProPlan.Nil:
            err.msg_list.append(f'Payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})')
        base.verify_payment_provider(it.payment_provider, err)

        # NOTE: Check that the token is set correctly
        if it.payment_provider == base.PaymentProvider.GooglePlayStore:
            pass
        elif len(it.google_payment_token) != 0:
            err.msg_list.append(
                f'Payment #{index} specified a google payment token: '
                f'{base.maybe_obfuscate(it.google_payment_token)} for a non-google platform'
            )

    # NOTE: Verify the users
    users: list[UserRow] = get_users_list(conn)
    for index, user in enumerate(users):
        if user.master_pkey == ZERO_BYTES32:
            err.msg_list.append(f'User #{index} has a master public key set to the zero key')

    result = len(err.msg_list) == 0
    return result


def new_proof_expiry_offset() -> int:
    '''Draw a fresh per-account proof-expiry offset: uniform seconds spanning exactly one expiry grid
    period (a day, in production).

    Two properties are load-bearing, both for the same reason — an observer reads the offset off any proof
    and is trying to work backwards from it (see `_build_proof_clamped_expiry_time` for what the offset
    buys, and `schema/003_proof_expiry_offset.sql` for why it is stored and re-drawn per cycle):
    UNPREDICTABLE, so it must come from the CSPRNG and never from the clock or the account key; and
    UNIFORM over the full period, since a skew re-clusters the expiry times the offset exists to scatter.
    '''
    # Reducing a 64-bit draw modulo the period leaves a bias of ~1 part in 10^15 — far below any skew that
    # could cluster anything, so it is accepted rather than rejection-sampled away.
    return int.from_bytes(nacl.utils.random(8), 'big') % base.proof_expiry_shape().offset_range


# Re-draw `users.proof_expiry_offset` exactly when the account's true expiry MOVES. Both users of this
# clause set expires_at from the payment list, so "moved" is the honest trigger for a new subscription
# cycle: it covers a redeem, a renewal, a stacked purchase and a revocation, and skips a no-op refresh (a
# flag-only touch, a re-reconcile that claims nothing). That precision matters in both directions — never
# re-drawing against a fixed anniversary instant would leave a stable per-account fingerprint, while
# re-drawing on every touch would hand an observer repeated samples of the same true expiry, whose minimum
# converges straight back onto it.
_REDRAW_OFFSET_IF_EXPIRY_MOVED = (
    "proof_expiry_offset = CASE WHEN expires_at IS DISTINCT FROM %(expiry)s"
    " THEN %(proof_random_offset)s ELSE proof_expiry_offset END"
)


@db.transactional
def _update_user_expiry_grace_and_renew_flag_from_payment_list(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey
):
    """Update fields for the user that depend on their list of payments, like
    their latest known expiry time"""
    master_pkey_bytes: bytes = bytes(master_pkey)
    lookup: LookupUserExpiry = _lookup_user_expiry(tx, nacl.signing.VerifyKey(master_pkey_bytes))
    # NOTE: We have the latest expiry value, now update the user
    db.query(
        tx.conn,
        f'''
        UPDATE users
        SET    expires_at = %(expiry)s, grace_period = %(grace)s,
               auto_renewing = %(renewing)s,
               {_REDRAW_OFFSET_IF_EXPIRY_MOVED}
        WHERE  master_pkey = %(pkey)s
    ''',
        expiry=lookup.best_expiry,
        grace=lookup.best_grace,
        renewing=lookup.best_auto_renewing,
        proof_random_offset=new_proof_expiry_offset(),
        pkey=master_pkey_bytes,
    )


@db.transactional
def revoke_payments_by_id_internal(tx: db.SQLTransaction, rows: typing.Any, revoke_at: pendulum.DateTime) -> bool:
    result = False
    master_pkey_dict: dict[bytes, pendulum.DateTime] = {}
    for row in rows:
        result = True
        id, master_pkey_raw, expires_at = row
        master_pkey_bytes: bytes | None = bytes(master_pkey_raw) if master_pkey_raw is not None else None

        # NOTE: A payment will not have a master pkey associated with it if the user hasn't
        # redeemed it yet so the key may not be set. If it's not set we still mark the payment as
        # 'revoked', this means that it can't be activated and so a master pkey cannot be set on it
        # after the fact as well.
        if master_pkey_bytes:
            master_pkey_dict[master_pkey_bytes] = expires_at

        # NOTE: Mark the payment revoked (set revoked_at) unless it already is.
        db.query(
            tx.conn,
            '''
        UPDATE payments
        SET    revoked_at = %(revoked_ts)s, auto_renewing = FALSE
        WHERE  id = %(id)s AND revoked_at IS NULL
        ''',
            revoked_ts=revoke_at,
            id=id,
        )

    revoke_at_next_day = round_datetime_to_next_day_with_provider_testing_support(base.PaymentProvider.Nil, revoke_at)

    # The furthest into the future any outstanding proof can certify: a proof reaches at most
    # `max_proof_lifetime` past its request instant (_build_proof_clamped_expiry_time) and a request_at is
    # only accepted within DEFAULT_TIMESTAMP_TOLERANCE of the server clock, so no proof issued up to the
    # revoke instant reaches beyond this. Anchoring to `revoke_at` assumes we process the refund promptly: a
    # notification that reaches us late — a backlog drained after an outage — leaves any proof issued in the
    # interim outside this bound.
    max_outstanding_proof_expiry = (
        revoke_at + base.DEFAULT_TIMESTAMP_TOLERANCE + base.proof_expiry_shape().max_proof_lifetime
    )

    for it in master_pkey_dict:
        master_pkey = nacl.signing.VerifyKey(it)

        # Bind any payment the mule has registered for this key that the owner has not claimed yet, BEFORE
        # judging below whether this refund needs broadcasting. `_lookup_user_expiry` is user-scoped and a
        # user_id is set only at redemption, so an unclaimed-but-live survivor is invisible to that judgement:
        # we would broadcast a revocation, and revoke every outstanding proof, for an account whose paid
        # coverage never actually lapsed. Claim-all and idempotent — the same bind the owner's next request
        # performs, just early. Deliberately AFTER the revoke UPDATE above, since reconcile only claims rows
        # with `revoked_at IS NULL` and so can never claim the payment being revoked. Stamped with OUR clock,
        # never `revoke_at`: the store's refund date can be days old (same reasoning as
        # revoke_master_pkey_proofs_and_allocate_new_gen_id below).
        reconcile_pending_payments(tx, master_pkey, redeemed_at=to_redeemed_at(base.utc_now()))

        # NOTE: For each user we revoked a payment for, we have modified their 'auto_renewing' value
        # on the payment, we need to go and update their user row to track the, new, next best
        # expiry time so that the backend knows the new time-frame in which the user is allowed to
        # generate a Session Pro proof (now that one or more of their payments get revoked)
        _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, master_pkey)

        # NOTE: A payment at or past the end of the current day is on its way out anyway, so revoking it is
        # not worth an entry in the (network-costly, every-client-fetches-it) revocation list. A proof built
        # against such a payment can reach the renewal lead plus a whole grid period (≤ ~25 h) past that
        # boundary, so an outstanding proof for a nearly-expired, then-refunded payment can outlive this
        # early-out by that much. Accepted: it takes a refund of the account's *longest* payment inside that
        # payment's final day, and the outcome is bounded extra Pro on an entitlement that was ending anyway.
        #
        # For different platforms in their testing environments, they have different timespans
        # for a day, for example in Google 1 day is 10s. We handle that explicitly here.
        expires_at = master_pkey_dict[it]
        if expires_at <= revoke_at_next_day:
            continue

        # Even when the revoked payment's own proof would outlive the day boundary, a broadcast revocation
        # + generation roll is only needed if the refund drops the user's *remaining* entitlement below
        # something an outstanding proof already certifies. If enough paid time survives the refund
        # (aggregate expiry at or beyond the furthest a live proof can reach) every outstanding proof stays
        # honest, so we skip the revocation entirely. The revocation list is fetched by every client, so
        # keeping it minimal is the point.
        post_refund_expiry = _lookup_user_expiry(tx, master_pkey).best_expiry
        if post_refund_expiry is not None and post_refund_expiry >= max_outstanding_proof_expiry:
            continue

        revoke_master_pkey_proofs_and_allocate_new_gen_id(tx, master_pkey, created_at=revoke_at)

    return result


@db.transactional
def add_apple_revocation(
    tx: db.SQLTransaction, apple_original_tx_id: str, revoke_at: pendulum.DateTime, err: base.ErrorSink
) -> bool:
    """Revoke all the payments that aren't revoked that share the same original TX ID. Returns true
    if there were any rows that had the ID"""
    # TODO: Can be cleaned up more, a lot of repeated code between apple and google here, but it
    # works fine. Also, this code is very platform specific, potentially the grabbing of IDs should
    # happen in the platform layers and then the backend only deals with IDs. Potentially separating
    # such platform specific implementation concerns to the requisite platforms.

    # NOTE: Select the newest apple transaction that has been redeemed or not. apple only gives us
    # the original TX ID token in the scenarios that we call this function.
    #
    # From there we need to find the previous plan using this ID which is shared across all payments
    # by the user which we can do by finding the newest most payment that is still valid to be used.

    # NOTE: We also grab payments that are already revoked. This is because Google sends the revoked
    # notification after it may have already expired or have been revoked. If we skip those, this
    # function will return false and the caller will erroneously assume it has failed when infact
    # what we're trying to communicate to the caller is that, the payment token they were trying to
    # modified, is indeed in a revoked/expired state (e.g. its idempotent to call this function) and
    # that entitlement has been revoked where necessary.
    rows_result = db.query(
        tx.conn,
        f'''
    SELECT p.id, u.master_pkey, p.expires_at
    FROM   {PAYMENTS_FROM}
    WHERE  ad.original_tx_id = %(orig_tx)s;
    ''',
        orig_tx=apple_original_tx_id,
    )

    log.info(
        f'Revoking Apple payment (orig. TX ID={base.maybe_obfuscate(apple_original_tx_id)}, '
        f'revoke={base.readable(revoke_at)})'
    )
    rows = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal(tx, rows, revoke_at)
    if not result:
        err.msg_list.append(
            f'Failed to revoke Apple orig. TX ID {base.maybe_obfuscate(apple_original_tx_id)} '
            f'at {base.readable(revoke_at)}, '
            f'no matching payments were found'
        )

    return result


@db.transactional
def reinstate_apple_payment(
    tx: db.SQLTransaction,
    apple_original_tx_id: str,
    apple_tx_id: str,
    auto_renewing: bool,
    reinstated_at: pendulum.DateTime,
) -> bool:
    """Reverse a prior Apple REFUND for a single transaction (a REFUND_REVERSED notification) — the mirror of
    add_apple_revocation. Un-revoke the payment identified by (original_tx_id, tx_id), restore the affected
    user's entitlement snapshot, and — only when their current generation is revoked AND the restored window
    is still live — move them onto a fresh generation (the old, already-broadcast token stays on the
    revocation list; it can't be un-broadcast). Un-revoking only clears revoked_at (revoke never touched
    expires_at), so the ORIGINAL paid window is restored, never extended.

    A reversal lands days-to-weeks after the refund, so the window has often already lapsed by the time it
    arrives — then there is nothing live to serve and no generation work to do (a later renewal settles the
    generation).

    Returns whether a matching payment was found. Idempotent: a redelivery whose payment is already active is
    a no-op. An unknown transaction is logged CRITICAL and returns False but never raises/errs — a reversal
    always follows a refund we processed, so an unknown one is anomalous, yet it must not wedge the Apple
    notification pipeline / the missed-notification catch-up.
    """
    rows = db.query(
        tx.conn,
        f'''
        SELECT p.id, u.master_pkey
        FROM   {PAYMENTS_FROM}
        WHERE  ad.original_tx_id = %(orig_tx)s AND ad.tx_id = %(tx_id)s
    ''',
        orig_tx=apple_original_tx_id,
        tx_id=apple_tx_id,
    ).fetchall()

    if not rows:
        log.critical(
            f'Apple REFUND_REVERSED for an unknown transaction (orig. TX ID='
            f'{base.maybe_obfuscate(apple_original_tx_id)}, tx={base.maybe_obfuscate(apple_tx_id)}); '
            f'nothing to reinstate'
        )
        return False

    log.info(
        f'Reinstating Apple payment (orig. TX ID={base.maybe_obfuscate(apple_original_tx_id)}, '
        f'tx={base.maybe_obfuscate(apple_tx_id)}, reinstated={base.readable(reinstated_at)})'
    )

    master_pkeys: set[bytes] = set()
    for payment_id, master_pkey_raw in rows:
        # Clear the refund's revocation (idempotent) and restore auto-renew from the notification.
        db.query(
            tx.conn,
            '''
            UPDATE payments SET revoked_at = NULL, auto_renewing = %(auto_renewing)s WHERE id = %(id)s
        ''',
            auto_renewing=auto_renewing,
            id=payment_id,
        )
        if master_pkey_raw is not None:
            master_pkeys.add(bytes(master_pkey_raw))

    for master_pkey_bytes in master_pkeys:
        master_pkey = nacl.signing.VerifyKey(master_pkey_bytes)
        lookup = _lookup_user_expiry(tx, master_pkey)
        if lookup.expiry_from_redeemed is not None and lookup.expiry_from_redeemed > reinstated_at:
            # Live restored window: ensure the user is on a usable (non-revoked) generation — mints a fresh
            # one iff the refund had revoked the current one — and refresh their entitlement snapshot.
            _ensure_active_generation(tx, master_pkey, issued_at=reinstated_at)
        else:
            # The paid window has already lapsed: just restore the expiry snapshot; there are no live proofs
            # to serve, so no generation work (a later renewal will settle the generation).
            _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, master_pkey)

    return True


@db.transactional
def add_google_revocation(
    tx: db.SQLTransaction, google_payment_token: str, revoke_at: pendulum.DateTime, err: base.ErrorSink
) -> bool:
    """Revoke all the payments that aren't revoked that share the same original TX ID. Returns true
    if there were any rows that had the ID"""

    # NOTE: Select the newest google transaction that has been redeemed or not. Google only gives us
    # the purchase token in the scenarios that we call this function.

    # NOTE: We also grab payments that are already revoked. This is because Google sends the revoked
    # notification after it may have already expired or have been revoked. If we skip those, this
    # function will return false and the caller will erroneously assume it has failed when infact
    # what we're trying to communicate to the caller is that, the payment token they were trying to
    # modified, is indeed in a revoked/expired state (e.g. its idempotent to call this function) and
    # that entitlement has been revoked where necessary.
    rows_result = db.query(
        tx.conn,
        f'''
    SELECT p.id, u.master_pkey, p.expires_at
    FROM   {PAYMENTS_FROM}
    WHERE  gd.payment_token = %(token)s
    ''',
        token=google_payment_token,
    )

    log.info(
        f'Revoking Google payment (token={base.maybe_obfuscate(google_payment_token)}, '
        f'revoke={base.readable(revoke_at)})'
    )
    rows = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal(tx, rows, revoke_at)
    if not result:
        err.msg_list.append(
            f'Failed to revoke Google payment {base.maybe_obfuscate(google_payment_token)} '
            f'at {base.readable(revoke_at)}, '
            f'no matching payments were found'
        )

    return result


@db.transactional
def reconcile_pending_payments(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, redeemed_at: pendulum.DateTime
) -> int:
    """Redeem every unredeemed, unrevoked Google/Apple payment bound to `master_pkey`, link the claimed
    payments to the user, refresh entitlement, and return how many were newly claimed.

    The stores attest the account identifier AS a function of the master key — Google's
    obfuscatedAccountId is the pubkey verbatim, Apple's appAccountToken is uuid_from_master_pk(pubkey) —
    so holding the key IS the claim; there's no separate client-supplied token to match. This is the
    reconcile step every master-key-authenticated endpoint runs up front, so a payment the mule has
    already registered gets bound to its owner on the owner's next request, whichever endpoint that is.

    Claim-all: a key legitimately accumulates several unredeemed payments (e.g. a device offline across a
    couple of renewals). A no-match is not an error and touches nothing — in particular NO user row is
    created for a key with no payments, so a signed-but-payment-less status probe can't spawn users."""
    from providers import app_store

    def claim(detail_table: str, account_column: str, account_value: bytes | str) -> list[int]:
        # detail_table/account_column are module-internal literals (never request data), so interpolating
        # them is safe; the account value is always a bound parameter.
        rows = db.query(
            tx.conn,
            f'''
            UPDATE payments
            SET    redeemed_at = %(redeemed_at)s
            WHERE  id IN (SELECT payment_id FROM {detail_table} WHERE {account_column} = %(account)s)
              AND  redeemed_at IS NULL AND revoked_at IS NULL
            RETURNING id
            ''',
            redeemed_at=redeemed_at,
            account=account_value,
        )
        return [row[0] for row in rows.fetchall()]

    claimed = claim('google_play_payment_details', 'obfuscated_account_id', bytes(master_pkey))
    claimed += claim(
        'app_store_payment_details', 'app_account_token', app_store.uuid_from_master_pk(bytes(master_pkey))
    )
    if not claimed:
        return 0

    # master_pkey lives only in `users`: ensure the identity row (+ its generation) exists, link the
    # just-claimed payments to it, then refresh entitlement (reuses the current generation — a redeem
    # never rolls it, so the client's revocation_tag is untouched).
    user_id = get_or_create_user_and_generation(tx, master_pkey, issued_at=redeemed_at)[0]
    db.query(tx.conn, 'UPDATE payments SET user_id = %(user_id)s WHERE id = ANY(%(ids)s)', user_id=user_id, ids=claimed)
    _ensure_active_generation(tx, master_pkey, issued_at=redeemed_at)
    return len(claimed)


def _redeem_payment_for_user(
    tx: db.SQLTransaction,
    master_pkey: nacl.signing.VerifyKey,
    payment_tx: base.PaymentProviderTransaction,
    redeemed_at: pendulum.DateTime,
) -> None:
    """Redeem ONE specific payment and link it to master_pkey's (already-existing) user, matched by the
    payment's OWN store identifier — Google (payment_token, order_id) / Apple tx_id — NOT by the
    master-key-derived account-id.

    Used by the renewal auto-redeem, where the owner was resolved from the store's subscription-continuity
    linkage (payment_token / original_tx_id → a prior, securely-bound payment). That linkage is the
    authority, so we deliberately never touch the appAccountToken UUID: the mule stays out of UUID matching
    entirely, so a (vanishingly unlikely) 122-bit appAccountToken collision can never make a renewal bind a
    stranger's payment. The account-id match stays confined to the client path, where the caller is the
    owner and "the new payer is the next to claim their own UUID" holds."""
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        detail_where = 'google_play_payment_details WHERE payment_token = %(token)s AND order_id = %(order_id)s'
        params: dict[str, typing.Any] = {
            'token': payment_tx.google_payment_token,
            'order_id': payment_tx.google_order_id,
        }
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        detail_where = 'app_store_payment_details WHERE tx_id = %(tx_id)s'
        params = {'tx_id': payment_tx.apple_tx_id}
    else:
        return

    row_result = db.query(
        tx.conn,
        f'''
        UPDATE payments
        SET    redeemed_at = %(redeemed_at)s,
               user_id     = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
        WHERE  id IN (SELECT payment_id FROM {detail_where})
          AND  redeemed_at IS NULL AND revoked_at IS NULL
        RETURNING id
        ''',
        redeemed_at=redeemed_at,
        master_pkey=bytes(master_pkey),
        **params,
    )
    if row_result.fetchall():
        # Only refresh entitlement if we actually redeemed something (it may already be redeemed).
        _ensure_active_generation(tx, master_pkey, issued_at=redeemed_at)


def redeem_minted_payment(
    tx: db.SQLTransaction,
    master_pkey: nacl.signing.VerifyKey,
    payment_tx: base.PaymentProviderTransaction,
    redeemed_at: pendulum.DateTime,
) -> None:
    """Redeem ONE just-minted payment and bind it to master_pkey's user (creating the user + generation
    if needed), matched by the payment's OWN store identifier. This is the shared redeem for the minting
    path — the CLI `voucher` command and the `/dev/add_payment` route (see minting.py). Distinct from the
    two client-facing redeems: unlike reconcile_pending_payments it claims exactly the one minted payment
    rather than everything sharing the account-id, and unlike _redeem_payment_for_user it creates the user
    and also handles Rangeproof, which has no store account-id to reconcile against."""
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        detail_where = 'google_play_payment_details WHERE payment_token = %(token)s AND order_id = %(order_id)s'
        params: dict[str, typing.Any] = {
            'token': payment_tx.google_payment_token,
            'order_id': payment_tx.google_order_id,
        }
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        detail_where = 'app_store_payment_details WHERE tx_id = %(tx_id)s'
        params = {'tx_id': payment_tx.apple_tx_id}
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        detail_where = 'rangeproof_payment_details WHERE order_id = %(order_id)s'
        params = {'order_id': payment_tx.rangeproof_order_id}
    else:
        raise base.ServerError(f'Cannot redeem a minted payment for provider: {payment_tx.provider}')

    user_id = get_or_create_user_and_generation(tx, master_pkey, issued_at=redeemed_at)[0]
    row_result = db.query(
        tx.conn,
        f'''
        UPDATE payments
        SET    redeemed_at = %(redeemed_at)s, user_id = %(user_id)s
        WHERE  id IN (SELECT payment_id FROM {detail_where})
          AND  redeemed_at IS NULL AND revoked_at IS NULL
        RETURNING id
        ''',
        redeemed_at=redeemed_at,
        user_id=user_id,
        **params,
    )
    assert len(row_result.fetchall()) == 1, 'a freshly-minted payment must redeem exactly once'
    _ensure_active_generation(tx, master_pkey, issued_at=redeemed_at)


def verify_payment_provider_tx(payment_tx: base.PaymentProviderTransaction, err: base.ErrorSink):
    base.verify_payment_provider(payment_tx.provider, err)
    match payment_tx.provider:
        case base.PaymentProvider.GooglePlayStore:
            if len(payment_tx.google_order_id) == 0:
                err.msg_list.append('Google order id was not set')
            if len(payment_tx.google_payment_token) == 0:
                err.msg_list.append('Google payment token was not set')
        case base.PaymentProvider.iOSAppStore:
            if len(payment_tx.apple_tx_id) == 0:
                err.msg_list.append('Apple TX ID was not set')
            if len(payment_tx.apple_original_tx_id) == 0:
                err.msg_list.append('Apple original TX ID was not set')
        case base.PaymentProvider.Rangeproof:
            if len(payment_tx.rangeproof_order_id) == 0:
                err.msg_list.append('Rangeproof order ID was not set')
        case base.PaymentProvider.Nil:
            err.msg_list.append('Payment provider was set invalidly to nil')


@db.transactional
def _lookup_user_expiry(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> LookupUserExpiry:
    # NOTE: We grab the expired ones as well because if they have grace that payment's deadline
    # is later than the expiry period which may actually be the latest known expiry period
    #
    # By definition we can't lookup unredeemed payments because they don't have a master public key
    # registered for it yet (e.g. the user has not associated a master public key with the payment
    # yet by redeeming it).
    # All of a user's linked payments are redeemed-or-later (user_id is set only at redemption), so
    # filtering on user_id selects exactly those — unredeemed payments have no user_id.
    # redeemed/expired/revoked are then derived from the timestamps below.
    result_set = db.query(
        tx.conn,
        '''
        SELECT    p.expires_at, p.grace_period, p.auto_renewing, p.redeemed_at,
                  p.payment_provider, ad.original_tx_id, gd.order_id, rd.order_id, p.revoked_at,
                  p.credit_remaining, u.credits_drained_through
        FROM      payments p
                  JOIN users u ON u.id = p.user_id
                  LEFT JOIN app_store_payment_details ad      ON ad.payment_id = p.id
                  LEFT JOIN google_play_payment_details gd     ON gd.payment_id = p.id
                  LEFT JOIN rangeproof_payment_details rd ON rd.payment_id = p.id
        WHERE     u.master_pkey = %(master_pkey)s
        ORDER BY  p.id DESC
    ''',
        master_pkey=bytes(master_pkey),
    )

    # How far this account's credits have been drained; the same value on every row, carried along rather
    # than fetched separately. The credit total below is added to THIS instant rather than to `now`, so the
    # answer is a fixed instant: each drain pass advances the checkpoint by the span it charged and reduces
    # the total by the same amount, and any recompute between passes — a payment registered, a redeem, a
    # revocation — lands on the same value instead of walking forward. An account with no payments has no
    # rows here, and therefore no credits either, so the absent checkpoint cannot matter.
    credits_drained_through: pendulum.DateTime | None = None
    # Live credits are summed, not maxed: each grants a length that stacks on top of coverage. Their own
    # `expires_at` is a grant-time receipt value, so it is kept OUT of the max below — counting it there
    # as well would credit the same length twice. A SPENT credit (remaining zero) does go through the max
    # like a subscription: its window is necessarily in the past by then, so it can only ever win when
    # nothing else covers the account, which is exactly when it is the truthful answer.
    credit_total = pendulum.duration()

    used_google_order_ids: list[str] = []
    used_apple_orig_tx_ids: set[int] = set()
    used_rangeproof_order_ids: set[str] = set()

    # NOTE: Determine the user's latest expiry by enumerating all the payments and calculating
    # the expiry time (inclusive of the grace period if applicable)
    result = LookupUserExpiry()
    rows = typing.cast(list[tuple[typing.Any, ...]], result_set.fetchall())
    for row in rows:
        # Order matches the SELECT above; unpacking fails loudly if the column count ever drifts.
        (
            expires_at,
            grace_period,
            auto_renewing,
            redeemed_at,
            payment_provider,
            apple_original_tx_id,
            google_order_id,
            rangeproof_order_id,
            revoked_at,
            credit_remaining,
            credits_drained_through,
        ) = row
        # grace_period is nullable; treat "absent" as zero for the entitlement arithmetic below.
        grace = grace_period if grace_period is not None else pendulum.duration()

        # A live credit contributes its remaining length to the total and nothing to the max. A revoked
        # one contributes neither: the revoke path zeroes it, and until it does, a clawed-back credit must
        # not still be extending the account.
        if credit_remaining is not None and credit_remaining > pendulum.duration():
            if revoked_at is None:
                credit_total += credit_remaining
            continue

        # NOTE: Consecutive subscription payments are added to the DB under _roughly_ the same
        # transaction ID (this differs between platforms). We only want to consider that latest
        # subscription payment as the user's "best" payment that we should show as their entitlement
        #
        # For google they do an <order_id> but then append a suffix to disambiguate such as
        # <order_id>, <order_id>..0, <order_id>..1 and so forth
        #
        # For apple they have a <original_transaction_id> that is shared across all transactions for
        # a given subscription.
        #
        # Our SQL query sorts the user's payments by insertion order and looks for the _latest_
        # instance of the transactions associated with the user and selects those.
        seen_before = False
        if payment_provider == base.PaymentProvider.GooglePlayStore.value:
            order_split: list[str] = google_order_id.split('..')
            if len(order_split) <= 0:
                log.warning(
                    f"Failed to split order google order ID by '..' for {base.maybe_obfuscate_bytes(master_pkey)}: "
                    f"{base.maybe_obfuscate(google_order_id)}"
                )
                continue

            for used_it in used_google_order_ids:
                if used_it.startswith(order_split[0]):
                    seen_before = True
                    break

            if not seen_before:
                used_google_order_ids.append(google_order_id)
        elif payment_provider == base.PaymentProvider.iOSAppStore.value:
            if apple_original_tx_id in used_apple_orig_tx_ids:
                seen_before = True
            else:
                used_apple_orig_tx_ids.add(apple_original_tx_id)
        elif payment_provider == base.PaymentProvider.Rangeproof.value:
            if rangeproof_order_id in used_rangeproof_order_ids:
                seen_before = True
            else:
                used_rangeproof_order_ids.add(rangeproof_order_id)
        else:
            log.warning(
                f"Unrecognised payment provider in {row} for {base.maybe_obfuscate_bytes(master_pkey)}: "
                f"{payment_provider}"
            )
            continue

        if seen_before:
            continue

        # NOTE: Track the current best expiry (newest payment that entitles them to Pro). `best_*` is
        # None until the first qualifying payment. Auto-renewing payments fold the grace period into
        # their stored expiry, so strip it back off for a like-for-like comparison.
        best_wo_grace_from_redeemed = result.expiry_from_redeemed
        if best_wo_grace_from_redeemed is not None and result.auto_renewing_from_redeemed:
            best_wo_grace_from_redeemed -= result.grace_from_redeemed

        best_wo_grace = result.best_expiry
        if best_wo_grace is not None and result.best_auto_renewing:
            best_wo_grace -= result.best_grace

        # NOTE: If we're revoked, clamp the expiry to the revoke time (entitlement stops effective
        # there). `status` is derived, not stored — we work from the orthogonal facts (revoked ⟺
        # revoked_at set), never a flattened status. Whether a payment has *expired* is a separate,
        # now-relative concern handled downstream (get_pro_status / proof-expiry clamping) — it must
        # not gate what expiry the user is *entitled* to, so no wall-clock enters here.
        if revoked_at is not None:
            assert not auto_renewing
            payment_expires_at = revoked_at
            expires_at = revoked_at
        else:
            payment_expires_at = expires_at + grace if auto_renewing else expires_at

        # NOTE: A payment contributes to the "redeemed" entitlement iff it has been redeemed and not
        # revoked. (Expiry is deliberately excluded — see above.)
        is_redeemed = redeemed_at is not None and revoked_at is None
        if is_redeemed and (best_wo_grace_from_redeemed is None or expires_at > best_wo_grace_from_redeemed):
            result.expiry_from_redeemed = payment_expires_at
            result.grace_from_redeemed = grace
            result.auto_renewing_from_redeemed = bool(auto_renewing)

        if best_wo_grace is None or expires_at > best_wo_grace:
            result.best_expiry = payment_expires_at
            result.best_grace = grace
            result.best_auto_renewing = bool(auto_renewing)

    # Credits extend whatever the subscriptions above cover, from the later of that coverage and the drain
    # checkpoint (a credit cannot be paying for a moment a subscription already paid for, nor for one
    # already charged against it). `best_grace`/`best_auto_renewing` stay attributed to the subscription
    # that won the max: a subscriber holding a voucher is still auto-renewing, whatever sets their expiry.
    if credit_total > pendulum.duration():
        if credits_drained_through is None:
            # The mint sets the checkpoint, and the drain clears it only once every credit is spent, so a
            # live credit with no checkpoint is a broken invariant. Anchor on the coverage we do know
            # about rather than silently answering with 1970, and make the noise visible.
            log.warning(
                f'Live credit with no drain checkpoint for {base.maybe_obfuscate_bytes(master_pkey)}: '
                f'anchoring its remaining length on known coverage instead'
            )
        anchor = credits_drained_through if credits_drained_through is not None else base.EPOCH
        result.best_expiry = max(result.best_expiry, anchor) if result.best_expiry else anchor
        result.best_expiry += credit_total
        redeemed = result.expiry_from_redeemed
        result.expiry_from_redeemed = (max(redeemed, anchor) if redeemed else anchor) + credit_total
    return result


@db.transactional
def update_payment_renewal_info(
    tx: db.SQLTransaction,
    payment_tx: base.PaymentProviderTransaction,
    grace_period: pendulum.Duration | None,
    auto_renewing: bool | None,
    err: base.ErrorSink,
) -> bool:
    """
    Update a payment's grace period and/or auto renewing flag. Pass in `None` for the arguments
    you want to opt out of updating.
    """

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label_safe(payment_tx)
        log.info(
            f'Update renewal info (payment={payment_tx_label}, grace period ms={grace_period}, '
            f'auto_renewing={auto_renewing})'
        )

    result = False
    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return result

    if grace_period is None and auto_renewing is None:
        result = True
        return result

    # NOTE: Generate the fields to write to matching payment in the DB
    sql_set_fields: str = ''
    kwparams: dict[str, typing.Any] = {}
    if auto_renewing is not None:
        if len(sql_set_fields):
            sql_set_fields += ', '
        sql_set_fields += 'auto_renewing = %(auto_renewing)s'
        kwparams['auto_renewing'] = auto_renewing

    if grace_period is not None:
        if len(sql_set_fields):
            sql_set_fields += ', '
        sql_set_fields += 'grace_period = %(grace_period)s'
        kwparams['grace_period'] = grace_period

    # NOTE: Execute the statement
    # TODO: Improve this switch statement by writing to kwparams then have 1 single db.query()
    # statement that expands those parameters.
    result_set: db.Result | None = None
    match payment_tx.provider:
        case base.PaymentProvider.Nil:
            pass

        case base.PaymentProvider.GooglePlayStore:
            result_set = db.query(
                tx.conn,
                f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     id IN (SELECT payment_id FROM google_play_payment_details
                                   WHERE payment_token = %(token)s AND order_id = %(order_id)s)
                RETURNING (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
            ''',
                token=payment_tx.google_payment_token,
                order_id=payment_tx.google_order_id,
                **kwparams,
            )

        case base.PaymentProvider.iOSAppStore:
            result_set = db.query(
                tx.conn,
                f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     id IN (SELECT payment_id FROM app_store_payment_details
                                   WHERE original_tx_id = %(orig_tx_id)s AND tx_id = %(tx_id)s
                                     AND web_line_order_tx_id = %(line_order_tx_id)s)
                RETURNING (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
            ''',
                orig_tx_id=payment_tx.apple_original_tx_id,
                tx_id=payment_tx.apple_tx_id,
                line_order_tx_id=payment_tx.apple_web_line_order_tx_id,
                **kwparams,
            )

        case base.PaymentProvider.Rangeproof:
            result_set = db.query(
                tx.conn,
                f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     id IN (SELECT payment_id FROM rangeproof_payment_details
                                   WHERE order_id = %(rangeproof_order_id)s)
                RETURNING (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
            ''',
                rangeproof_order_id=payment_tx.rangeproof_order_id,
                **kwparams,
            )

    # NOTE: A `RETURNING` clause seems to break rowcount (returns 0 even on row modification), so we
    # use fetchone instead. The RETURNING expression resolves the payment's owner master_pkey via the
    # users FK (NULL if the payment isn't redeemed yet).
    assert result_set
    row = typing.cast(tuple[bytes] | None, result_set.fetchone())
    result = row is not None

    # NOTE: Update the user's expiry to the latest known expiry
    if row and row[0]:
        master_pkey_bytes: bytes = bytes(row[0])
        _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, nacl.signing.VerifyKey(master_pkey_bytes))

    if not result:
        payment_id = ''
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            payment_id = payment_tx.google_order_id
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            payment_id = payment_tx.apple_tx_id
        else:
            payment_id = payment_tx.rangeproof_order_id
        err.msg_list.append(
            f'Updating payment TX failed, no matching payment found for '
            f'{payment_tx.provider.name} {base.maybe_obfuscate(payment_id)}'
        )
    return result


@db.transactional
def _insert_payment_row(
    tx: db.SQLTransaction,
    payment: dict[str, typing.Any],
    detail_table: str,
    detail: dict[str, typing.Any],
    dedup_keys: list[str],
) -> bool:
    """INSERT a payment atomically IFF no row in `detail_table` already matches on `dedup_keys` (a subset of
    `detail`'s columns, which must be covered by a UNIQUE constraint). Returns whether a row was inserted.

    A single CTE writes the provider-agnostic `payment` columns into `payments` — gated on the dedup key
    being absent — then the provider-specific `detail` columns keyed by the new id, so a duplicate inserts
    *neither* row (no orphaned `payments` entry). The `NOT EXISTS` guard is only the fast path: two writers
    racing on the same key both pass it, but the loser then trips `detail_table`'s UNIQUE constraint and
    raises — the constraint, not the guard, is what actually guarantees no duplicate.

    Each dict is self-aligning — the column name lives with its value, so there is no pair of parallel
    lists to drift out of index-lock; placeholders are generated from the same keys.
    """

    def columns_and_placeholders(cols: typing.Iterable[str]) -> tuple[str, str]:
        cols = list(cols)
        return ', '.join(cols), ', '.join(f'%({column})s' for column in cols)

    p_columns, p_placeholders = columns_and_placeholders(payment)
    d_columns, d_placeholders = columns_and_placeholders(detail)
    dedup_where = ' AND '.join(f'{key} = %({key})s' for key in dedup_keys)

    inserted = db.query_one(
        tx.conn,
        f'''
        WITH inserted AS (
            INSERT INTO payments ({p_columns})
            SELECT {p_placeholders}
            WHERE NOT EXISTS (SELECT 1 FROM {detail_table} WHERE {dedup_where})
            RETURNING id
        )
        INSERT INTO {detail_table} (payment_id, {d_columns})
        SELECT inserted.id, {d_placeholders} FROM inserted
        RETURNING payment_id
    ''',
        {**payment, **detail},
    )
    return inserted is not None


@db.transactional
def add_unredeemed_payment(
    tx: db.SQLTransaction,
    payment_tx: base.PaymentProviderTransaction,
    plan: base.ProPlan,
    expires_at: pendulum.DateTime,
    purchased_at: pendulum.DateTime,
    platform_refund_expires_at: pendulum.DateTime,
    platform_obfuscated_account_id: bytes | str,
    err: base.ErrorSink,
    needs_ack: bool = False,
    credit_remaining: pendulum.Duration | None = None,
    auto_renewing: bool = True,
):
    """Record a payment nobody has claimed yet.

    `credit_remaining` marks the row as a one-shot CREDIT with that much length left to give (see
    schema/004): a store subscription leaves it None, since its `expires_at` already states an absolute
    paid-through instant.

    `auto_renewing` comes from the caller because only the caller knows. It is not derivable from the
    provider (a store sells both renewing subscriptions and one-time products) nor from whether the payment
    is a credit (a one-time store product is neither renewing nor a credit). The default suits the
    auto-renewing subscriptions that are all any provider registers today; anything else must say so."""

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label_safe(payment_tx)
        log.info(
            f'Unredeemed payment (payment={payment_tx_label}, plan={plan.name}, '
            f'expiry={base.readable(expires_at)}, unredeemed={base.readable(purchased_at)}, '
            f'refund={base.readable(platform_refund_expires_at)})'
        )

    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        assert isinstance(platform_obfuscated_account_id, bytes)
        assert len(platform_obfuscated_account_id) == 32

        # Insert IFF this (token, order_id) isn't already recorded — Google reuses payment_token across
        # billing cycles, so order_id is what distinguishes them. Dedup + atomicity come from the
        # UNIQUE(payment_token, order_id) constraint inside _insert_payment_row's CTE.
        _insert_payment_row(
            tx,
            payment={
                'plan': plan.value,
                'payment_provider': payment_tx.provider.value,
                'expires_at': expires_at,
                'platform_refund_expires_at': platform_refund_expires_at,
                'purchased_at': purchased_at,
                'auto_renewing': auto_renewing,
                'credit_remaining': credit_remaining,
            },
            detail_table='google_play_payment_details',
            detail={
                'payment_token': payment_tx.google_payment_token,
                'order_id': payment_tx.google_order_id,
                'obfuscated_account_id': platform_obfuscated_account_id,
                # Outstanding Google purchase-ack obligation. The mule's sweep acks and clears it; a
                # fresh, not-yet-acknowledged purchase sets it TRUE (renewals arrive acknowledged).
                'needs_ack': needs_ack,
            },
            dedup_keys=['payment_token', 'order_id'],
        )

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        assert isinstance(platform_obfuscated_account_id, str)
        # Insert IFF this apple payment isn't already recorded. apple_tx_id is always unique;
        # apple_web_line_order_tx_id is unique per billing cycle of the subscription; apple_original_tx_id is
        # reused across all subscriptions of the same type. Dedup + atomicity come from the
        # UNIQUE(original_tx_id, tx_id, web_line_order_tx_id) constraint inside _insert_payment_row's CTE.
        _insert_payment_row(
            tx,
            payment={
                'plan': plan.value,
                'payment_provider': payment_tx.provider.value,
                'expires_at': expires_at,
                'platform_refund_expires_at': platform_refund_expires_at,
                'purchased_at': purchased_at,
                'auto_renewing': auto_renewing,
                'credit_remaining': credit_remaining,
            },
            detail_table='app_store_payment_details',
            detail={
                'original_tx_id': payment_tx.apple_original_tx_id,
                'tx_id': payment_tx.apple_tx_id,
                'web_line_order_tx_id': payment_tx.apple_web_line_order_tx_id,
                'app_account_token': platform_obfuscated_account_id,
            },
            dedup_keys=['original_tx_id', 'tx_id', 'web_line_order_tx_id'],
        )
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        # Insert IFF this rangeproof order id isn't already recorded. Dedup + atomicity come from the
        # UNIQUE(order_id) constraint inside _insert_payment_row's CTE.
        _insert_payment_row(
            tx,
            payment={
                'plan': plan.value,
                'payment_provider': payment_tx.provider.value,
                'expires_at': expires_at,
                'platform_refund_expires_at': platform_refund_expires_at,
                'purchased_at': purchased_at,
                'auto_renewing': auto_renewing,
                'credit_remaining': credit_remaining,
            },
            detail_table='rangeproof_payment_details',
            detail={'order_id': payment_tx.rangeproof_order_id},
            dedup_keys=['order_id'],
        )

    # NOTE: Find the latest master pkey associated with the common payment identifier (google payment
    # token or apple original tx id). Then find the user if it exists, if the user is still entitled
    # to Session Pro or is in grace, or in account hold, then, we've noticed a new payment for their
    # account.
    #
    # For UX we will automatically redeem the payment in this window and assign it to that public
    # key so that they automatically continue their Pro entitlement across the billing cycle without
    # needing their originating device to be on to "claim" the payment (because only the originating
    # device and the backend knows the confidential payment data it needs to provide to redeem).
    #
    # If the user is no outside of the account hold windows or cancelled their subscription then,
    # the next time they purchase a pro membership the Session account that the purchase was made
    # under will be the one that claims the initial payment. The auto-redeeming will be disabled
    # because the user is not in the auto-redeeming window.
    #
    # So the backend tries automatically redeem the payment on behalf of the user (if it seems
    # reasonable to do so according to that heuristic) for UX.
    master_pkey_set: db.Result | None = None
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        master_pkey_set = db.query(
            tx.conn,
            ('''
            SELECT   u.master_pkey
            FROM     payments p JOIN users u ON u.id = p.user_id
                     JOIN google_play_payment_details gd ON gd.payment_id = p.id
            WHERE    gd.payment_token = %s
            ORDER BY p.id DESC
            LIMIT    1
        '''),
            payment_tx.google_payment_token,
        )
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        master_pkey_set = db.query(
            tx.conn,
            ('''
            SELECT   u.master_pkey
            FROM     payments p JOIN users u ON u.id = p.user_id
                     JOIN app_store_payment_details ad ON ad.payment_id = p.id
            WHERE    ad.original_tx_id = %s
            ORDER BY p.id DESC
            LIMIT    1
        '''),
            payment_tx.apple_original_tx_id,
        )
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        # TODO: There is currently no auto-redeeming for Rangeproof payments. These are currently
        # granted to a user directly by creating a voucher payment attributed under their master pro
        # public key. It would be possible to incorporate some UI in the clients to allow redeeming
        # via an order ID. Rangeproof would then give the user the order ID that they have to redeem
        # in their client.
        pass

    if master_pkey_set:
        master_pkey_record = typing.cast(tuple[bytes] | None, master_pkey_set.fetchone())
        if master_pkey_record and master_pkey_record[0]:
            master_pkey = nacl.signing.VerifyKey(bytes(master_pkey_record[0]))
            user: UserRow = get_user(tx.conn, master_pkey)
            if user.found:
                # TODO: Handle the situation when a user cancels
                if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
                    # NOTE: Account hold as described by google
                    #
                    #   > [...] we’re increasing the default account hold duration on December 1, 2025.
                    #   > Starting on this date, by default account hold durations will be automatically
                    #   > calculated. Initially, the calculation will be 60 days minus any grace period
                    #   > duration, but we may change these calculations in the future to further
                    #   > improve recovery performance
                    #
                    # Source: https://support.google.com/googleplay/android-developer/answer/16631229
                    auto_redeem_deadline_at = user.expires_at
                    if user.auto_renewing:
                        auto_redeem_deadline_at += 60 * base.DAY - user.grace_period
                else:
                    assert payment_tx.provider == base.PaymentProvider.iOSAppStore
                    # NOTE: We don't currently configure a grace period/account hold period for Apple
                    # hnote the grace and account hold concept is merged together in Apple).
                    auto_redeem_deadline_at = user.expires_at
                    if user.auto_renewing:
                        auto_redeem_deadline_at += user.grace_period

                # NOTE: Unredeemed unix timestamp represents now (as this is the timestamp we are marking
                # the payment as having been registered), so we compare (now) to the deadline. If we are
                # before the deadline we are eligible to auto-redeem this payment and assign it to the
                # previous known master public key.
                if purchased_at <= auto_redeem_deadline_at:
                    # Bind THIS renewal to the owner we just resolved from the store's subscription
                    # continuity, matched by the renewal's own identifier — NOT the master-key-derived
                    # account-id. We already hold the full master key, so there's no need to route through
                    # the appAccountToken UUID, and deliberately not doing so keeps a mule-side renewal from
                    # ever claiming a stranger's payment on a (vanishingly unlikely) 122-bit UUID collision.
                    #
                    # A failed auto-redeem is swallowed: the user can still claim the payment later, and
                    # propagating the failure to the platform layers (google/apple) would stall them
                    # unnecessarily. The savepoint keeps a failed redeem from poisoning the outer
                    # transaction; we log it for internal visibility.
                    try:
                        with tx.conn.transaction():
                            _redeem_payment_for_user(
                                tx, master_pkey, payment_tx, redeemed_at=to_redeemed_at(purchased_at)
                            )
                    except base.ApiError as e:
                        log.error(
                            f'Failed to auto-redeem a payment we witnessed from. '
                            f'(auto_redeem_deadline={base.readable(auto_redeem_deadline_at)}) {e}'
                        )


def mint_generation(tx: db.SQLTransaction, user_id: int, issued_at: pendulum.DateTime) -> tuple[int, bytes]:
    '''Insert a fresh generation (new random 32-byte token) for an existing user; returns
    (generation_id, token). Retries on a token-unique collision — astronomically unlikely for 32 CSPRNG
    bytes, but cheap insurance against a degraded RNG; each attempt is a savepoint so a collision can't
    poison the outer transaction.'''
    for _attempt in range(3):
        token = nacl.utils.random(BLAKE2B_DIGEST_SIZE)
        try:
            with tx.conn.transaction():
                row = db.query_one(
                    tx.conn,
                    "INSERT INTO generations (user_id, token, issued_at) VALUES (%s, %s, %s) RETURNING id",
                    user_id,
                    token,
                    issued_at,
                )
            assert row is not None
            return (row[0], token)
        except psycopg.errors.UniqueViolation:
            continue
    raise RuntimeError('mint_generation: exhausted token-collision retries (CSPRNG failure?)')


def get_or_create_user_and_generation(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, issued_at: pendulum.DateTime
) -> tuple[int, int, bytes, bool]:
    '''Ensure a user row AND its first generation exist for master_pkey. Race-free via ON CONFLICT on the
    master_pkey unique index. Returns (user_id, current_generation_id, token, was_created). Must run inside
    a transaction (the circular users<->generations FK is deferred to COMMIT).

    The caller must link at least one payment to the returned user in that SAME transaction, so a user is
    never committed without one. Nothing sweeps up a user that has no payments, so one committed without
    would be permanent.'''
    master_pkey_bytes = bytes(master_pkey)

    # Common path: the user already exists — a plain read, no id/generation allocation burned.
    existing = get_user(tx.conn, master_pkey)
    if existing.found:
        return (existing.id, existing.current_generation_id, existing.token, False)

    # New user: pre-allocate both ids so the circular NOT NULL FKs are satisfied at insert time (the
    # deferred users->generations FK is validated at COMMIT). Insert the user first (ON CONFLICT arbitrates
    # a concurrent create), then the generation it points at. The expiry here is a placeholder overwritten
    # by _allocate… below.
    seq_row = db.query_one(
        tx.conn,
        "SELECT nextval(pg_get_serial_sequence('users','id')), nextval(pg_get_serial_sequence('generations','id'))",
    )
    assert seq_row is not None
    user_id, gen_id = seq_row[0], seq_row[1]
    token = nacl.utils.random(BLAKE2B_DIGEST_SIZE)
    won = db.query_one(
        tx.conn,
        '''
        INSERT INTO users (id, master_pkey, current_generation_id, expires_at, proof_expiry_offset)
        VALUES            (%(id)s, %(master_pkey)s, %(gen_id)s, to_timestamp(0), %(proof_expiry_offset)s)
        ON CONFLICT (master_pkey) DO NOTHING
        RETURNING id
    ''',
        id=user_id,
        master_pkey=master_pkey_bytes,
        gen_id=gen_id,
        # A seed value only: the placeholder expiry above is immediately overwritten by
        # _ensure_active_generation, and that write re-draws the offset along with it.
        proof_expiry_offset=new_proof_expiry_offset(),
    )
    if won is None:
        # Lost a concurrent create — re-read the winner (our pre-allocated ids simply go unused).
        winner = get_user(tx.conn, master_pkey)
        return (winner.id, winner.current_generation_id, winner.token, False)
    db.query(
        tx.conn,
        "INSERT INTO generations (id, user_id, token, issued_at) VALUES (%s, %s, %s, %s)",
        gen_id,
        user_id,
        token,
        issued_at,
    )
    return (user_id, gen_id, token, True)


def _ensure_active_generation(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, issued_at: pendulum.DateTime
) -> AllocatedGenID:
    # Refresh the user's top-level entitlement fields from their current best payment, and settle which
    # generation they're on. A generation is an EPOCH, not a per-payment value: REUSE the user's
    # current generation across payments — stacking, renewals, auto-redeem, natural-lapse reactivation — so
    # the revocation_tag stays stable (no per-payment revocation-list churn, no subscription-cadence leak).
    # Mint a FRESH generation only when the current one is REVOKED (reusing it would mint proofs born
    # already-revoked). The revoke path depends on exactly this: it sets revoked_at first, then calls here,
    # so it rolls onto a fresh generation. The user row must already exist (redeem creates it via
    # get_or_create_user_and_generation; revoke's user exists).
    # Start the drain clock for a credit that has just become this user's, BEFORE reading the entitlement
    # below: the fold anchors a credit's remaining length on this checkpoint, so setting it afterwards would
    # store an expiry dated from the epoch. Every path that claims a payment comes through here, so this is
    # the one place it cannot be forgotten — and forgetting it would leave a live credit that never drains,
    # i.e. a voucher that never expires. Only when currently NULL: resetting an existing checkpoint would
    # forgive whatever uncovered time has accrued against the account's other credits.
    db.query(
        tx.conn,
        '''
        UPDATE users
        SET    credits_drained_through = %(at)s
        WHERE  master_pkey = %(master_pkey)s AND credits_drained_through IS NULL
          AND  EXISTS (SELECT 1 FROM payments
                       WHERE user_id = users.id AND revoked_at IS NULL
                         AND credit_remaining > '0'::interval)
    ''',
        at=issued_at,
        master_pkey=bytes(master_pkey),
    )

    result = AllocatedGenID()
    lookup: LookupUserExpiry = _lookup_user_expiry(tx, master_pkey)
    result.expires_at = lookup.expiry_from_redeemed
    if lookup.expiry_from_redeemed is None:
        return result  # no usable payment → nothing to allocate

    result.found = True
    user = get_user(tx.conn, master_pkey)
    assert user.found, "user must exist before allocating a generation"

    if is_generation_revoked(tx.conn, user.current_generation_id, issued_at):
        result.generation_id, result.token = mint_generation(tx, user.id, issued_at)
    else:
        result.generation_id, result.token = user.current_generation_id, user.token

    db.query(
        tx.conn,
        f'''
        UPDATE users
        SET    current_generation_id        = %(gen_id)s,
               expires_at                   = %(expiry)s,
               grace_period                 = %(grace)s,
               auto_renewing                = %(auto_renewing)s,
               {_REDRAW_OFFSET_IF_EXPIRY_MOVED}
        WHERE  id = %(user_id)s
    ''',
        gen_id=result.generation_id,
        user_id=user.id,
        expiry=lookup.best_expiry,
        grace=lookup.best_grace,
        auto_renewing=lookup.best_auto_renewing,
        proof_random_offset=new_proof_expiry_offset(),
    )
    result.grace_period = lookup.best_grace

    return result


@db.transactional
def drain_due_credits(tx: db.SQLTransaction, now: pendulum.DateTime, stale_after: pendulum.Duration) -> int:
    """Charge elapsed uncovered time against the credits of every account whose drain checkpoint is older
    than `stale_after`, and return how many accounts were visited.

    A credit is spent only while nothing else covers the account, so the charge is the span since that
    account's checkpoint — never an assumed interval — which makes a pass that runs late charge exactly
    what it should and a pass that runs twice charge nothing the second time. Coverage is sampled once,
    now: a subscription that lapsed part-way through the span is charged for the whole of it, and one that
    started part-way through is charged for none, each bounded by one interval and only at a genuine
    coverage transition (a renewal is not one — `expires_at` moves before the old term lapses).

    SKIP LOCKED so a second runner, or an overlapping pass, cannot charge the same account twice."""
    due = db.query(
        tx.conn,
        '''
        SELECT   id, master_pkey, credits_drained_through
        FROM     users
        WHERE    credits_drained_through IS NOT NULL AND credits_drained_through < %(cutoff)s
        ORDER BY credits_drained_through
        FOR UPDATE SKIP LOCKED
    ''',
        cutoff=now - stale_after,
    )

    visited = 0
    for user_id, master_pkey_raw, checkpoint in typing.cast(list[tuple[typing.Any, ...]], due.fetchall()):
        visited += 1
        master_pkey = nacl.signing.VerifyKey(bytes(master_pkey_raw))

        # Is a SUBSCRIPTION covering this account right now? Deliberately computed from the subscription
        # rows and NOT from users.expires_at: that already includes the credits' own remaining length, so a
        # credit would report the account as covered, protect itself from being charged, and never expire.
        coverage_rows = db.query(
            tx.conn,
            '''
            SELECT expires_at, grace_period, auto_renewing
            FROM   payments
            WHERE  user_id = %(user_id)s AND revoked_at IS NULL AND credit_remaining IS NULL
        ''',
            user_id=user_id,
        )
        covered_now = any(
            subscription_coverage_end(expires_at, grace_period, auto_renewing) > now
            for expires_at, grace_period, auto_renewing in typing.cast(
                list[tuple[typing.Any, ...]], coverage_rows.fetchall()
            )
        )

        # Clamped at zero: a checkpoint ahead of `now` (a clock stepping back, a future-dated pass) must
        # never hand length BACK to a credit.
        budget = pendulum.duration() if covered_now else max(now - checkpoint, pendulum.duration())

        live_rows = db.query(
            tx.conn,
            '''
            SELECT   id, credit_remaining
            FROM     payments
            WHERE    user_id = %(user_id)s AND revoked_at IS NULL AND credit_remaining > '0'::interval
            ORDER BY purchased_at, id
        ''',
            user_id=user_id,
        )
        live = [
            CreditToDrain(payment_id=row[0], remaining=row[1])
            for row in typing.cast(list[tuple[typing.Any, ...]], live_rows.fetchall())
        ]
        remaining_before = {credit.payment_id: credit.remaining for credit in live}
        drained = drain_credits(live, budget)

        # Walk the charges in consumption order so an emptied credit can be dated: its length ran out at the
        # checkpoint plus everything charged up to and including it. `expires_at` is a receipt value for a
        # credit (unlike a subscription, where the store owns it), and this is the one thing that writes it
        # after the mint — so that a spent credit states when it really ran out rather than what it was
        # worth on the day it was granted.
        spent_so_far = pendulum.duration()
        for payment_id, new_remaining in drained.updated:
            spent_so_far += remaining_before[payment_id] - new_remaining
            emptied_at = checkpoint + spent_so_far if new_remaining == pendulum.duration() else None
            db.query(
                tx.conn,
                '''
                UPDATE payments
                SET    credit_remaining = %(remaining)s,
                       expires_at       = COALESCE(%(emptied_at)s, expires_at)
                WHERE  id = %(payment_id)s
            ''',
                remaining=new_remaining,
                emptied_at=emptied_at,
                payment_id=payment_id,
            )

        # If the credits ran out partway through this span, the checkpoint is the instant they ran out, not
        # `now`: the account's expiry is derived as checkpoint + what remains, so with nothing remaining and
        # a checkpoint of `now` it would walk forward by an interval on every pass and hand out free time.
        checkpoint_next = checkpoint + drained.spent if drained.exhausted else now
        db.query(
            tx.conn,
            'UPDATE users SET credits_drained_through = %(at)s WHERE id = %(user_id)s',
            at=checkpoint_next,
            user_id=user_id,
        )
        _update_user_expiry_grace_and_renew_flag_from_payment_list(tx, master_pkey)

        # Stop visiting an account with nothing left to charge — but only AFTER the refresh above, which
        # needs the checkpoint to date the entitlement the credits just finished providing.
        db.query(
            tx.conn,
            '''
            UPDATE users SET credits_drained_through = NULL
            WHERE  id = %(user_id)s
              AND  NOT EXISTS (SELECT 1 FROM payments
                               WHERE user_id = %(user_id)s AND revoked_at IS NULL
                                 AND credit_remaining > '0'::interval)
        ''',
            user_id=user_id,
        )

    return visited


def make_generate_pro_proof_message(
    master_pkey: nacl.signing.VerifyKey, rotating_pkey: nacl.signing.VerifyKey, request_at: pendulum.DateTime
) -> bytes:
    '''The message the user signs to authorise a new rotating_pkey for master_pkey's Session Pro
    subscription.'''
    return signed_message(GENERATE_PROOF_DOMAIN, master_pkey, rotating_pkey, request_at)


def build_proof_message(
    revocation_tag: bytes, rotating_pkey: nacl.signing.VerifyKey, expires_at: pendulum.DateTime
) -> bytes:
    '''The message the backend signs to certify a proof.'''
    return signed_message(BUILD_PROOF_DOMAIN, revocation_tag, rotating_pkey, expires_at)


def _build_proof_clamped_expiry_time(
    request_at: pendulum.DateTime, proposed_expires_at: pendulum.DateTime, proof_expiry_offset: int
) -> pendulum.DateTime:
    '''How far ahead a proof issued at `request_at` certifies, given the account's true (grace-inclusive)
    entitlement end and its stored per-account offset:

        round_up_onto_grid( min(request_at + clamp, true) + renewal_lead )

    where the grid is this account's own, `{ UTC midnight + proof_expiry_offset + k * one day }`.

    Clamp, pad, then round up. Two arms come out of the `min`: while the subscription still has more than
    the clamp left the expiry SLIDES with the request (a rolling ~30 d proof lifetime, so a lost or leaked
    proof self-expires); as the subscription end comes into range the expiry PINS near it.

    The round-up onto the grid is what makes both arms safe to publish. Landing on a grid point means the
    expiry is constant for a whole period and then steps by exactly one: two of a user's devices asking at
    different moments in the same period get identical proofs, and the value carries only which period the
    request fell in, never the instant.

    * The offset (uniform over one period, re-drawn each cycle) is what stops the pinned expiry from BEING
      the account's exact true expiry, which would otherwise publish the precise purchase/renewal instant
      as a stable time-of-day fingerprint and, via midnight-vs-not, the plan cadence — all readable by any
      conversation partner. It equally stops clients herding into one minute at renewal time, which is what
      any deterministic expiry (a plain day boundary, or the plan anniversary) does. An observer can read
      the offset straight off the wire (`expiry_ts` modulo the period) but gains nothing by it: `true` is
      still only pinned to within one period, and the offset is a random per-cycle value, less identifying
      than the `revocation_tag` already in the proof. Note the rounding only ever goes UP — pulling an
      expiry DOWN onto a boundary would advertise an end up to a period BEFORE the entitlement really
      ends, and the renewal payment may well not have arrived by then.
    * `renewal_lead` (1 h 1 min) keeps a renewing client's attempt on the correct side of `true`. A client
      starts renewing one hour before its proof expires, so the attempt lands no earlier than
      `min(...) + 60 s` — at least a minute past `true` in the pinned arm, since rounding up only pushes it
      later — and `true` is grace-inclusive, i.e. the last instant an upstream store might still notify us
      of the renewal. The 60 s absorbs a client clock running up to a minute fast so it still cannot fire
      early. This is a LOCKED PAIR with the client's one-hour lead: a client that renews earlier needs a
      matching change here, or its attempts start landing before the renewal can have resolved.

    The cost is over-provisioning: an account is honoured for up to one period past `true + renewal_lead`.
    That is deliberate (it also buffers a late store notification), and the per-cycle re-draw keeps the luck
    from settling on the same accounts. `shape.max_proof_lifetime` bounds the resulting proof lifetime.
    '''
    shape = base.proof_expiry_shape()
    # The stored column's own range (a day — the schema CHECK), NOT the current shape's: a database written
    # before the shape changed still holds day-wide offsets, which the grid helper reduces modulo the period.
    assert 0 <= proof_expiry_offset < base.PROOF_EXPIRY_SHAPE.offset_range
    clamped_expires_at = min(request_at + shape.clamp, proposed_expires_at)
    return base.round_datetime_up_onto_offset_grid(
        clamped_expires_at + shape.renewal_lead, period=shape.grid, offset_seconds=proof_expiry_offset
    )


def build_proof(
    revocation_tag: bytes,
    rotating_pkey: nacl.signing.VerifyKey,
    expires_at: pendulum.DateTime,
    signing_key: nacl.signing.SigningKey,
) -> ProSubscriptionProof:
    # The revocation_tag is the generation's stored random token, embedded verbatim (no hashing).
    assert len(revocation_tag) == BLAKE2B_DIGEST_SIZE
    result: ProSubscriptionProof = ProSubscriptionProof()
    result.revocation_tag = revocation_tag
    result.rotating_pkey = rotating_pkey
    result.expires_at = expires_at

    message: bytes = build_proof_message(
        revocation_tag=result.revocation_tag, rotating_pkey=result.rotating_pkey, expires_at=result.expires_at
    )
    result.sig = signing_key.sign(message).signature
    return result


def internal_verify_add_payment_and_get_proof_common_arguments(
    signing_key: nacl.signing.SigningKey,
    master_pkey: nacl.signing.VerifyKey,
    rotating_pkey: nacl.signing.VerifyKey,
    message: bytes,
    master_sig: bytes,
    rotating_sig: bytes,
) -> None:
    # Verify the signatures first (authenticate that the message was not tampered with) — if these fail,
    # the rest of the payload is indeterminate, so raising bad_signature short-circuits everything else.
    # `message` is the signed message (variable length; built by make_*_message), signed directly — no
    # pre-hash — so there's no fixed-size assert here.
    try:
        master_pkey.verify(smessage=message, signature=master_sig)
    except Exception as e:
        raise base.FailError(
            f'Failed to verify signature from master key {base.maybe_obfuscate_bytes(master_pkey)}: {e}',
            code=base.ErrorCode.bad_signature,
        )

    try:
        rotating_pkey.verify(smessage=message, signature=rotating_sig)
    except Exception as e:
        raise base.FailError(
            f'Failed to verify signature from rotating key {base.maybe_obfuscate_bytes(rotating_pkey)}: {e}',
            code=base.ErrorCode.bad_signature,
        )

    # Dev/config sanity checks (the signing key never leaves the backend).
    assert bytes(signing_key) != ZERO_BYTES32 and bytes(signing_key.verify_key) != ZERO_BYTES32

    # Sanity check the signing key — a backend misconfiguration, not the client's fault.
    if signing_key.verify_key == master_pkey or signing_key.verify_key == rotating_pkey:
        raise base.ServerError('Internal key error during adding payment: please notify the devs')

    # Sanity check the user's keys and signatures (client-supplied → their fault).
    if master_pkey == rotating_pkey:
        raise base.FailError(
            f'Master and rotating key cannot be the same was: {base.maybe_obfuscate_bytes(master_pkey)}'
        )

    if bytes(master_pkey) == ZERO_BYTES32:
        raise base.FailError('Master key cannot be the zero key')

    if bytes(rotating_pkey) == ZERO_BYTES32:
        raise base.FailError('Rotating key cannot be the zero key')

    if master_sig == rotating_sig:
        raise base.FailError('Master and rotating signature cannot be the same')


@db.transactional
def revoke_master_pkey_proofs_and_allocate_new_gen_id(
    tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, created_at: pendulum.DateTime
) -> AllocatedGenID:
    # Revoke the user's current generation (terminal): sets revoked_at, which blocks every proof issued
    # under that generation and (via the trigger) bumps the revocation ticket. The `revoked_at IS NULL`
    # guard makes a double-revoke a no-op rather than tripping the terminal-immutability trigger.
    #
    # `revoked_at` is stamped with OUR clock, read here, and is deliberately NOT `created_at` and NOT a
    # parameter. The served list turns this stamp into `effective_ts = revoked_at +
    # REVOCATION_EFFECTIVE_DELAY`, so it must mean "when we recorded the revocation", never "when the store
    # says the refund happened": a notification we process late (a backlog drained after an outage carries
    # refunds dated hours or days back) would otherwise be broadcast already-effective, and peers would
    # start rejecting the sender's proof before the sender could possibly have polled and learnt of it —
    # precisely the compose-then-truncate gap the delay exists to close. Reading the clock at the single
    # write site, rather than taking it from the caller, is what makes that unrepresentable: every caller
    # here holds a provider timestamp, and one passed in by mistake looks exactly like a correct argument.
    # `created_at` is the entitlement-side revoke instant (and the new generation's issued_at below);
    # `payments.revoked_at` likewise keeps the store's own date — the user really was entitled until then.
    db.query(
        tx.conn,
        '''
        UPDATE generations
        SET    revoked_at = %(recorded_at)s
        WHERE  id = (SELECT current_generation_id FROM users WHERE master_pkey = %(master_pkey)s)
          AND  revoked_at IS NULL
    ''',
        master_pkey=bytes(master_pkey),
        recorded_at=base.utc_now(),
    )

    # If the user still has usable payments, roll them onto a fresh generation for subsequent proofs.
    # Clients see the old generation revoked (via the revocation list) and re-query for a new proof.
    result = _ensure_active_generation(tx, master_pkey, issued_at=created_at)
    return result


def round_datetime_to_next_day_with_provider_testing_support(
    payment_provider: base.PaymentProvider, at: pendulum.DateTime
) -> pendulum.DateTime:
    """Round `at` up to the next day boundary. In some platforms' testing environments a "day" is
    compressed (Google: 10 seconds); only that case differs from the normal UTC-day rounding."""
    if base.PROVIDER_TESTING_ENV and payment_provider == base.PaymentProvider.GooglePlayStore:
        google_day = pendulum.duration(seconds=10)  # in Google's test env, 1 day == 10s
        elapsed = at - base.EPOCH
        units = -((-elapsed) // google_day)  # ceil-divide the duration
        return base.EPOCH + units * google_day
    return base.round_datetime_to_next_day(at)


@db.transactional
def build_current_entitlement_proof(
    tx: db.SQLTransaction,
    master_pkey: nacl.signing.VerifyKey,
    rotating_pkey: nacl.signing.VerifyKey,
    request_at: pendulum.DateTime,
    signing_key: nacl.signing.SigningKey,
) -> ProSubscriptionProof:
    '''Sign a proof for the user's CURRENT entitlement using their existing generation token (NO roll).
    Shared by generate_pro_proof and grant_rangeproof. Raises a FailError with the matching slug when
    there is nothing to sign: `not_subscribed` (no user row), `revoked` (current generation revoked),
    `expired` (entitlement lapsed past the clamped proof window).'''
    get_user = get_user_and_payments(tx, master_pkey)
    if get_user.user.master_pkey != bytes(master_pkey):
        raise base.FailError(
            f'User {bytes(master_pkey).hex()} does not have an active payment registered for it',
            code=base.ErrorCode.not_subscribed,
        )

    if is_generation_revoked(tx.conn, get_user.user.current_generation_id, request_at):
        raise base.FailError(f'User {bytes(master_pkey).hex()} payment has been revoked', code=base.ErrorCode.revoked)

    proof_expires_at = _build_proof_clamped_expiry_time(
        request_at=request_at,
        proposed_expires_at=get_user.user.expires_at,
        proof_expiry_offset=get_user.user.proof_expiry_offset,
    )
    # The expiry we are willing to certify is the honest cut-off, so a lapsed account keeps getting proofs
    # (all with this same, stable expiry — the offset only moves when the true expiry does) until the
    # over-provision above genuinely runs out, up to ~25 h past its true expiry. That is the same
    # over-provision every live account gets, granted no further, and it keeps us consistent with the
    # `account_expiry_ts` we already handed the client.
    if request_at > proof_expires_at:
        payment_expires_at = (
            get_user.user.expires_at - get_user.user.grace_period
            if get_user.user.auto_renewing
            else get_user.user.expires_at
        )
        raise base.FailError(
            f'User {bytes(master_pkey).hex()} entitlement expired at {base.readable(get_user.user.expires_at)} '
            f'({base.readable(payment_expires_at)} + {get_user.user.grace_period})',
            code=base.ErrorCode.subscription_expired,
            # Advisory, same as the success path: carry the (now-past) account entitlement end so the
            # client can refresh its cached horizon without a separate get_pro_status. Only on this slug —
            # not_subscribed has no expiry, and revoked is a distinct state (its expiry may be future).
            data={'account_expiry_ts': base.unix_seconds_from_datetime(get_user.user.expires_at)},
        )

    proof = build_proof(
        revocation_tag=get_user.user.token,
        rotating_pkey=rotating_pkey,
        expires_at=proof_expires_at,
        signing_key=signing_key,
    )
    # Advisory (unsigned) account entitlement end, from this same snapshot — the client's true
    # subscription horizon, distinct from the clamped proof expiry above.
    #
    # `max` so `expiry_ts <= account_expiry_ts` holds by construction rather than by luck. Everywhere the
    # proof is still clamped (all of a long plan's life) this is exactly the true expiry, which is what the
    # owner should see. It only reads back the proof's own expiry in the closing window where the
    # over-provision pushes the proof past the true end — and there the two agree, to within the ≤25 h we
    # are honouring anyway, so the client is never told its subscription ended before a proof we signed
    # stops verifying.
    proof.account_expires_at = max(get_user.user.expires_at, proof.expires_at)
    return proof


def generate_pro_proof(
    conn: psycopg.Connection,
    signing_key: nacl.signing.SigningKey,
    master_pkey: nacl.signing.VerifyKey,
    rotating_pkey: nacl.signing.VerifyKey,
    request_at: pendulum.DateTime,
    master_sig: bytes,
    rotating_sig: bytes,
) -> ProSubscriptionProof:
    log.info(f'Get pro proof (master={base.maybe_obfuscate_bytes(master_pkey)}, ts={base.readable(request_at)})')

    # Authenticate the request (raises FailError(bad_signature) / invalid_request on failure).
    message: bytes = make_generate_pro_proof_message(
        master_pkey=master_pkey, rotating_pkey=rotating_pkey, request_at=request_at
    )
    internal_verify_add_payment_and_get_proof_common_arguments(
        signing_key=signing_key,
        master_pkey=master_pkey,
        rotating_pkey=rotating_pkey,
        message=message,
        master_sig=master_sig,
        rotating_sig=rotating_sig,
    )

    with db.transaction(conn) as tx:
        # Reconcile first: claim any payment the mule has already registered for this key but that hasn't
        # been redeemed yet, so a client's post-purchase proof request binds it right here — no separate
        # redeem call. A no-op when there's nothing new. Then build the proof from the current entitlement
        # (build_current_entitlement_proof raises the truthful "no Pro" slug if there's still nothing, which
        # the client treats as "not yet — retry").
        reconcile_pending_payments(tx, master_pkey, redeemed_at=to_redeemed_at(request_at))
        return build_current_entitlement_proof(tx, master_pkey, rotating_pkey, request_at, signing_key)


@db.transactional
def grant_rangeproof(
    tx: db.SQLTransaction,
    master_pkey: nacl.signing.VerifyKey,
    rotating_pkey: nacl.signing.VerifyKey,
    signing_key: nacl.signing.SigningKey,
    request_at: pendulum.DateTime,
    redeemed_at: pendulum.DateTime,
    plan: base.ProPlan,
    expires_at: pendulum.DateTime,
) -> ProSubscriptionProof:
    """Directly grant a Rangeproof (dev-house) Pro payment to `master_pkey` and return the proof.
    Admin/CLI only: there is no client-facing voucher flow — a real one-time-use voucher, with a client
    claim path, is future work. `rangeproof_payment_details.order_id` here is an internal unique row id,
    not a voucher; we create the payment already redeemed and linked to the key, then build the proof."""
    order_id = str(uuid.uuid4())
    err = base.ErrorSink()
    payment_tx = base.PaymentProviderTransaction()
    payment_tx.provider = base.PaymentProvider.Rangeproof
    payment_tx.rangeproof_order_id = order_id
    add_unredeemed_payment(
        tx,
        payment_tx=payment_tx,
        plan=plan,
        expires_at=expires_at,
        purchased_at=redeemed_at,
        platform_refund_expires_at=base.EPOCH,
        platform_obfuscated_account_id=b'',
        err=err,
    )
    if err.has():
        raise base.ServerError(f'Failed to create rangeproof payment: {err.build()}')

    row_result = db.query(
        tx.conn,
        '''
        UPDATE payments
        SET    redeemed_at = %(redeemed_at)s
        WHERE  id IN (SELECT payment_id FROM rangeproof_payment_details WHERE order_id = %(order_id)s)
          AND  redeemed_at IS NULL AND revoked_at IS NULL
        RETURNING id
        ''',
        redeemed_at=redeemed_at,
        order_id=order_id,
    )
    redeemed_ids = [row[0] for row in row_result.fetchall()]
    assert len(redeemed_ids) == 1, 'the rangeproof payment we just created must redeem exactly once'

    user_id = get_or_create_user_and_generation(tx, master_pkey, issued_at=redeemed_at)[0]
    db.query(
        tx.conn, 'UPDATE payments SET user_id = %(user_id)s WHERE id = ANY(%(ids)s)', user_id=user_id, ids=redeemed_ids
    )
    _ensure_active_generation(tx, master_pkey, issued_at=redeemed_at)
    return build_current_entitlement_proof(tx, master_pkey, rotating_pkey, request_at, signing_key)


# Housekeeping deletes, one table each. All are pure storage reclamation: nothing here affects a live
# result, because every consuming query already self-guards (payment expiry is derived on read, the served
# revocation list filters by its retention window, a notification id absent from the history is simply
# unseen). So each can run on any schedule, any number of times, in any process, and a redundant run
# deletes nothing — hence no checkpoint, no windowing, no cross-process "only one wins" guard. Each is a
# single statement on an autocommit connection, so none of them needs a transaction, and they are separate
# calls so that one failing does not roll back the others.
#
# Users and payments are never deleted. Payments are the history /get_payment_details serves, and
# payments.user_id is a RESTRICT reference, so a user cannot be deleted for as long as one of their
# payments exists — which is always (see get_or_create_user_and_generation).


def delete_expired_revocations(conn: psycopg.Connection, now: pendulum.DateTime) -> int:
    """Delete revoked generations that have aged out of the served revocation list, returning the number
    removed.

    The cutoff is exactly the complement of the window get_pro_revocations serves (`revoked_at > now -
    REVOCATION_RETAIN_FOR`), so a row is only ever deleted once it can no longer appear in any response —
    keep the two in step. Dropping it is then invisible: REVOCATION_RETAIN_FOR is at least the maximum
    proof lifetime, so no proof still carrying this generation's token can be valid, and the token was
    random, so a later generation cannot collide with it.

    The `NOT EXISTS` is what makes this safe rather than merely tidy: a generation is a user's entitlement
    epoch, and `users.current_generation_id` is a NOT NULL FK to it, so the row a user is sitting on must
    survive however old its revocation is. In practice a live user is never that row (a revoked generation
    is replaced by a fresh one on the next entitlement change), but a user whose entitlement has not been
    touched since being revoked still points at it."""
    return db.query(
        conn,
        '''
        DELETE FROM generations g
        WHERE  g.revoked_at IS NOT NULL AND g.revoked_at <= %(cutoff)s
        AND    NOT EXISTS (SELECT 1 FROM users u WHERE u.current_generation_id = g.id)
        ''',
        cutoff=now - base.REVOCATION_RETAIN_FOR,
    ).rowcount


def delete_expired_apple_notification_uuids(conn: psycopg.Connection, now: pendulum.DateTime) -> int:
    """Delete Apple notification-dedupe rows whose expiry has passed, returning the number removed."""
    return db.query(conn, '''DELETE FROM apple_notification_uuid_history WHERE %s >= expires_at''', now).rowcount


def delete_expired_google_notifications(conn: psycopg.Connection, now: pendulum.DateTime) -> int:
    """Delete handled Google notification-history rows whose expiry has passed, returning the number
    removed. An unhandled row is kept regardless of age: it is the record that the notification still
    owes processing."""
    return db.query(
        conn, '''DELETE FROM google_notification_history WHERE %s >= expires_at AND handled = TRUE''', now
    ).rowcount


@db.transactional
def add_user_error(tx: db.SQLTransaction, error: UserError, at: pendulum.DateTime):
    match error.provider:
        case base.PaymentProvider.Rangeproof:
            pass
        case base.PaymentProvider.Nil:
            pass
        case base.PaymentProvider.GooglePlayStore:
            assert len(error.google_payment_token) > 0
            db.query(
                tx.conn,
                '''
                INSERT INTO user_errors (payment_provider, payment_id, errored_at)
                VALUES (%(provider)s, %(payment_id)s, %(ts)s)
                ON CONFLICT DO NOTHING
                ''',
                provider=error.provider.value,
                payment_id=error.google_payment_token,
                ts=at,
            )
        case base.PaymentProvider.iOSAppStore:
            assert len(error.apple_original_tx_id) > 0
            db.query(
                tx.conn,
                '''
                INSERT INTO user_errors (payment_provider, payment_id, errored_at)
                VALUES (%(provider)s, %(payment_id)s, %(ts)s)
                ON CONFLICT DO NOTHING
                ''',
                provider=error.provider.value,
                payment_id=error.apple_original_tx_id,
                ts=at,
            )


@db.transactional
def has_user_error_from_master_pkey(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> bool:
    # NOTE: Rangeproof payments cannot have user errors
    return bool(
        db.query_scalar(
            tx.conn,
            (f'''
SELECT EXISTS (
    SELECT 1
    FROM payments p
    LEFT JOIN app_store_payment_details  ad ON ad.payment_id = p.id
    LEFT JOIN google_play_payment_details gd ON gd.payment_id = p.id
    LEFT JOIN user_errors ue
        ON (p.payment_provider = '{base.PaymentProvider.iOSAppStore.value}'     AND ad.original_tx_id = ue.payment_id)
        OR (p.payment_provider = '{base.PaymentProvider.GooglePlayStore.value}' AND gd.payment_token  = ue.payment_id)
    WHERE p.user_id = (SELECT id FROM users WHERE master_pkey = %s)
    AND ue.payment_id IS NOT NULL
) AS has_error;
'''),
            bytes(master_pkey),
        )
    )


def has_user_error(conn: psycopg.Connection, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    # Single SELECT on the given connection (mid-tx callers pass tx.conn). payment_provider is a string
    # code (the lookup tables key on the code itself) — compared directly, never int()-cast.
    row = db.query_one(
        conn,
        'SELECT 1 FROM user_errors WHERE payment_id = %s AND payment_provider = %s',
        payment_id,
        payment_provider.value,
    )
    return row is not None


def delete_user_errors(conn: psycopg.Connection, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    # Single statement on the given connection (mid-tx callers pass tx.conn); the pool is autocommit.
    row = db.query(
        conn,
        'DELETE FROM user_errors WHERE payment_provider = %s AND payment_id = %s',
        payment_provider.value,
        payment_id,
    )
    return row.rowcount > 0


@db.transactional
def get_payment(
    tx: db.SQLTransaction, payment_tx: base.PaymentProviderTransaction, err: base.ErrorSink
) -> PaymentRow | None:
    result = None
    verify_payment_provider_tx(payment_tx, err)
    if err.has():
        return result

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        result_set = db.query(
            tx.conn,
            f'''
            SELECT {PAYMENTS_COLUMNS}
            FROM {PAYMENTS_FROM}
            WHERE gd.payment_token = %(token)s AND gd.order_id = %(order_id)s
            ''',
            token=payment_tx.google_payment_token,
            order_id=payment_tx.google_order_id,
            row_factory=db.dict_row,
        )

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        result_set = db.query(
            tx.conn,
            f'''
            SELECT {PAYMENTS_COLUMNS}
            FROM {PAYMENTS_FROM}
            WHERE ad.original_tx_id = %(orig_tx_id)s AND ad.tx_id = %(tx_id)s
                AND ad.web_line_order_tx_id = %(line_order_tx_id)s
            ''',
            orig_tx_id=payment_tx.apple_original_tx_id,
            tx_id=payment_tx.apple_tx_id,
            line_order_tx_id=payment_tx.apple_web_line_order_tx_id,
            row_factory=db.dict_row,
        )

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        result_set = db.query(
            tx.conn,
            f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM} WHERE rd.order_id = %s',
            payment_tx.rangeproof_order_id,
            row_factory=db.dict_row,
        )

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)

    return result


@db.transactional
def apple_add_notification_uuid(tx: db.SQLTransaction, uuid: str, expires_at: pendulum.DateTime):
    # uuid is the PRIMARY KEY; DO NOTHING keeps this idempotent (and crash-free) if the caller's
    # prior existence check raced with a concurrent insert of the same notification.
    db.query(
        tx.conn,
        ('''
        INSERT INTO apple_notification_uuid_history (uuid, expires_at)
        VALUES      (%s, %s)
        ON CONFLICT (uuid) DO NOTHING
    '''),
        uuid,
        expires_at,
    )


@db.transactional
def apple_notification_uuid_is_in_db(tx: db.SQLTransaction, uuid: str) -> bool:
    row = db.query_one(
        tx.conn,
        ('''
        SELECT 1
        FROM   apple_notification_uuid_history
        WHERE  uuid = %s
    '''),
        uuid,
    )
    result = row is not None
    return result


def apple_set_notification_checkpoint_at(tx: db.SQLTransaction, checkpoint_at: pendulum.DateTime):
    set_global_datetime(tx.conn, 'apple_notification_checkpoint_at', checkpoint_at)


@db.transactional
def google_add_notification_id(tx: db.SQLTransaction, message_id: str, expires_at: pendulum.DateTime, payload: str):
    maybe_payload: str | None = None
    if len(payload):
        maybe_payload = payload

    db.query(
        tx.conn,
        ('''
            INSERT INTO google_notification_history (message_id, handled, payload, expires_at)
            VALUES      (%(message_id)s, FALSE, %(payload)s, %(expiry)s)
    '''),
        message_id=message_id,
        payload=maybe_payload,
        expiry=expires_at,
    )


def google_set_notification_handled(tx: db.SQLTransaction, message_id: str, delete: bool) -> bool:
    if delete:
        rows = db.query(tx.conn, ('''DELETE FROM google_notification_history WHERE message_id = %s'''), message_id)
    else:
        rows = db.query(
            tx.conn,
            ('''UPDATE google_notification_history SET handled = TRUE, payload = NULL WHERE message_id = %s'''),
            message_id,
        )
    result: bool = rows.rowcount >= 1
    return result


def google_get_unhandled_notification_iterator(
    tx: db.SQLTransaction,
) -> collections.abc.Iterator[GoogleUnhandledNotificationIterator]:
    result_set = db.query(
        tx.conn, ('SELECT message_id, payload, expires_at FROM google_notification_history WHERE NOT handled')
    )
    return typing.cast(collections.abc.Iterator[GoogleUnhandledNotificationIterator], result_set)


@db.transactional
def google_notification_message_id_is_in_db(tx: db.SQLTransaction, message_id: str) -> GoogleNotificationMessageIDInDB:
    row = typing.cast(
        tuple[int] | None,
        db.query_one(tx.conn, '''SELECT handled FROM google_notification_history WHERE message_id = %s''', message_id),
    )
    result = GoogleNotificationMessageIDInDB()
    if row is not None:
        result.present = True
        result.handled = row[0] > 0  # NOTE: Should always be 0 or 1 but we'll be extra careful
    return result


def google_payment_tokens_needing_ack(conn: psycopg.Connection) -> list[str]:
    """Distinct Google purchase-tokens with an outstanding acknowledgement (needs_ack). The mule's
    sweep acks each against Google and clears the flag via google_clear_needs_ack."""
    rows = db.query(conn, '''SELECT DISTINCT payment_token FROM google_play_payment_details WHERE needs_ack''')
    return [row[0] for row in rows]


@db.transactional
def google_clear_needs_ack(tx: db.SQLTransaction, payment_token: str) -> None:
    """Clear the acknowledgement obligation for every row of `payment_token` (a token is acknowledged as
    a whole, so all its billing-cycle rows clear together)."""
    db.query(
        tx.conn, '''UPDATE google_play_payment_details SET needs_ack = FALSE WHERE payment_token = %s''', payment_token
    )


def _get_date_group_expr_sql(column: str, period: ReportPeriod) -> str:
    """Group a `timestamptz` column into a UTC calendar-period label."""
    utc = f"({column} AT TIME ZONE 'UTC')"  # timestamptz → UTC wall-clock, so buckets are UTC-stable
    match period:
        case ReportPeriod.Daily:
            return f"TO_CHAR({utc}, 'YYYY-MM-DD')"
        case ReportPeriod.Weekly:
            return f"TO_CHAR({utc}, 'IYYY-IW')"
        case ReportPeriod.Monthly:
            return f"TO_CHAR({utc}, 'YYYY-MM')"


def _get_period_end_ts_sql(period_str: str, period: ReportPeriod) -> str:
    """The last instant of the given period as a `timestamptz` (UTC), for range comparisons."""
    if period == ReportPeriod.Weekly:
        year, week = period_str.split("-")
        # ISO week Monday 00:00 UTC, + 1 week - epsilon = that week's final instant.
        start = f"(TO_TIMESTAMP('{year} {week} 1', 'IYYY IW ID') AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'"
        return f"({start} + INTERVAL '1 week' - INTERVAL '1 microsecond')"
    elif period == ReportPeriod.Monthly:
        return (
            f"((DATE_TRUNC('month', '{period_str}-01'::timestamp) AT TIME ZONE 'UTC')"
            " + INTERVAL '1 month' - INTERVAL '1 microsecond')"
        )
    else:
        return f"(('{period_str}'::timestamp AT TIME ZONE 'UTC') + INTERVAL '1 day' - INTERVAL '1 microsecond')"


def _format_period_label(period_str: str, period: ReportPeriod) -> str:
    """Format period string for display."""
    if period == ReportPeriod.Weekly:
        year, week = period_str.split("-")
        date = pendulum.DateTime.fromisocalendar(year=int(year), week=int(week), day=1)
        return date.strftime('%F') + f' (W{week})'
    return period_str


def generate_report_rows(conn: psycopg.Connection, period: ReportPeriod, limit: int | None) -> list[ReportRow]:
    def fetch_counts(
        tx_conn: psycopg.Connection, period: ReportPeriod, date_column: str, where_clause: str
    ) -> dict[str, int]:
        group_by_expr = _get_date_group_expr_sql(date_column, period)

        result_set = db.query(
            tx_conn,
            f"""
            SELECT {group_by_expr} AS period, COUNT(*) AS count
            FROM payments
            WHERE {where_clause}
            GROUP BY period
            ORDER BY period DESC
        """,
        )

        result: dict[str, int] = {}
        for row in result_set:
            period_label = _format_period_label(row[0], period)
            result[period_label] = row[1]
        return result

    def fetch_active_users(tx_conn: psycopg.Connection, period: ReportPeriod) -> dict[str, int]:
        date_expr = _get_date_group_expr_sql("purchased_at", period)

        result_set = db.query(
            tx_conn,
            f"""
            SELECT DISTINCT {date_expr} AS period
            FROM payments
        """,
        )
        periods_list = [row[0] for row in result_set]
        result: dict[str, int] = {}

        for it in periods_list:
            assert isinstance(it, str)
            end_ts = _get_period_end_ts_sql(it, period)

            count = db.query_scalar(
                tx_conn,
                f"""
                SELECT COUNT(DISTINCT user_id) AS active
                FROM payments
                WHERE {end_ts} >= purchased_at
                  AND {end_ts} <= expires_at
                  AND revoked_at IS NULL
            """,
            )
            period_label = _format_period_label(it, period)
            result[period_label] = count

        return result

    result: list[ReportRow] = []
    with db.transaction(conn) as tx:
        unredeemed: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause="redeemed_at IS NULL AND revoked_at IS NULL",
        )

        plan_1m: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"plan = '{base.ProPlan.OneMonth.value}'",
        )

        plan_3m: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"plan = '{base.ProPlan.ThreeMonth.value}'",
        )

        plan_12m: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"plan = '{base.ProPlan.TwelveMonth.value}'",
        )

        google: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"payment_provider = '{base.PaymentProvider.GooglePlayStore.value}'",
        )

        apple: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"payment_provider = '{base.PaymentProvider.iOSAppStore.value}'",
        )

        rangeproof: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="purchased_at",
            where_clause=f"payment_provider = '{base.PaymentProvider.Rangeproof.value}'",
        )

        new_subs: dict[str, int] = fetch_counts(
            tx_conn=tx.conn, period=period, date_column="purchased_at", where_clause="purchased_at IS NOT NULL"
        )

        revocations: dict[str, int] = fetch_counts(
            tx_conn=tx.conn, period=period, date_column="revoked_at", where_clause="revoked_at IS NOT NULL"
        )

        cancelled: dict[str, int] = fetch_counts(
            tx_conn=tx.conn,
            period=period,
            date_column="expires_at",
            where_clause="NOT auto_renewing AND revoked_at IS NULL",
        )

        active_users: dict[str, int] = fetch_active_users(tx.conn, period)

        all_periods: set[str] = set()
        for key_list in [new_subs.keys(), revocations.keys(), cancelled.keys(), active_users.keys()]:
            for it in key_list:
                all_periods.add(it)

        sorted_periods: list[str] = sorted(all_periods, reverse=True)[:limit]
        for it in sorted_periods:
            result.append(
                ReportRow(
                    period=it,
                    active_users=active_users.get(it, 0),
                    unredeemed=unredeemed.get(it, 0),
                    new_subs=new_subs.get(it, 0),
                    google=google.get(it, 0),
                    apple=apple.get(it, 0),
                    rangeproof=rangeproof.get(it, 0),
                    plan_1m=plan_1m.get(it, 0),
                    plan_3m=plan_3m.get(it, 0),
                    plan_12m=plan_12m.get(it, 0),
                    revoked=revocations.get(it, 0),
                    cancelled=cancelled.get(it, 0),
                )
            )

    return result


def generate_report_str(period: ReportPeriod, data: list[ReportRow], type: ReportType) -> str:
    @dataclasses.dataclass(frozen=True)
    class Section:
        name: str
        width: int
        align_left: bool = False

    sections: list[Section] = [
        Section("Period", 16, align_left=True),
        Section("Active Users", 14),
        Section("Unredeemed", 12),
        Section("New Subs", 10),
        Section("Google", 8),
        Section("Apple", 7),
        Section("Rangeproof", 12),
        Section("Plan 1m", 10),
        Section("Plan 3m", 10),
        Section("Plan 12m", 10),
        Section("Revoked", 10),
        Section("Cancelling", 12),
    ]

    result: str = ''
    match type:
        case ReportType.Human:
            header_parts: list[str] = []
            for sec in sections:
                if sec.align_left:
                    header_parts.append(f"{sec.name:<{sec.width}}")
                else:
                    header_parts.append(f"{sec.name:>{sec.width}}")
            header = " ".join(header_parts)

            result = f"{period.name.upper()} REPORT\n"
            result += "-" * len(header) + "\n"
            result += header + "\n"
            result += "-" * len(header) + "\n"

            for i, row in enumerate(data):
                if i > 0:
                    result += "\n"

                human_parts: list[str] = []
                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.period:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.active_users:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.unredeemed:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.new_subs:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.google:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.apple:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.rangeproof:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_1m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_3m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_12m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.revoked:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding = part_section.width
                align = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.cancelled:{align}{padding}}")

                assert len(human_parts) == len(sections)
                result += " ".join(human_parts)

        case ReportType.CSV:
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([sec.name for sec in sections])
            for row in data:
                csv_parts: list[str | int] = [
                    row.period,
                    row.active_users,
                    row.unredeemed,
                    row.new_subs,
                    row.google,
                    row.apple,
                    row.rangeproof,
                    row.plan_1m,
                    row.plan_3m,
                    row.plan_12m,
                    row.revoked,
                    row.cancelled,
                ]
                assert len(csv_parts) == len(sections)
                writer.writerow(csv_parts)
            result = output.getvalue().strip()
    return result
