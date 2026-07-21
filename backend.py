import traceback
import nacl.signing
import nacl.utils
import hashlib
import os
import typing
import collections.abc
import datetime
import dataclasses
import logging
import enum
import csv
import io

import platform_google_api
import platform_google_types
import base
import db
import migrations
import psycopg
import psycopg_pool

ZERO_BYTES32               = bytes(32)
BLAKE2B_DIGEST_SIZE        = 32
log                        = logging.Logger("BACKEND")
# 16-byte domain-separation prefix on the signed MESSAGE (signatures are Ed25519 over the message
# directly — no BLAKE2b, so this is a domain prefix, not a hash personalisation; see signed_message).
# Kept at 16 bytes with the same values so the proof's version-selecting domain prefix (Q12) is unchanged.
DOMAIN_SIZE                         = 16
GENERATE_PROOF_DOMAIN               = b'ProGenerateProof'
BUILD_PROOF_DOMAIN                  = b'ProProof_v0_____'  # version lives IN the domain prefix (Q12), not a byte/field
ADD_PRO_PAYMENT_DOMAIN              = b'ProAddPayment___'
SET_PAYMENT_REFUND_REQUESTED_DOMAIN = b'ProSetRefundReq_'
GET_PRO_DETAILS_DOMAIN              = b'ProGetProDetReq_'
assert all(len(p) == DOMAIN_SIZE for p in (GENERATE_PROOF_DOMAIN, BUILD_PROOF_DOMAIN,
           ADD_PRO_PAYMENT_DOMAIN, SET_PAYMENT_REFUND_REQUESTED_DOMAIN, GET_PRO_DETAILS_DOMAIN))

# Explicit column list for payments table queries. Rows are read with `db.dict_row` and unpacked by
# name in `payment_row_from_dict`, so order here is cosmetic (no positional coupling).
# `master_pkey` lives only in `users` now, so payments reads come from `PAYMENTS_FROM` (payments LEFT
# JOIN users) and pull the pkey from the joined users row — NULL for an unredeemed payment (user_id
# NULL).
# Provider-specific ids come from the per-provider detail tables (LEFT JOINed below — a payment is in
# exactly one, the rest are NULL) and are aliased back to the historical column names so the row→PaymentRow
# mapping (payment_row_from_dict) is unchanged.
PAYMENTS_COLUMNS = (
    "p.id, u.master_pkey, p.plan, p.payment_provider, p.auto_renewing, "
    "p.purchased_at, p.redeemed_at, p.expires_at, "
    "p.grace_period, p.platform_refund_expires_at, p.revoked_at, "
    "ad.original_tx_id AS apple_original_tx_id, ad.tx_id AS apple_tx_id, ad.web_line_order_tx_id AS apple_web_line_order_tx_id, "
    "gd.payment_token AS google_payment_token, gd.order_id AS google_order_id, rd.order_id AS rangeproof_order_id, "
    "p.refund_requested_at, gd.obfuscated_account_id AS google_obfuscated_account_id, ad.app_account_token AS apple_app_account_token"
)
PAYMENTS_FROM = (
    "payments p "
    "LEFT JOIN users u                      ON u.id  = p.user_id "
    "LEFT JOIN google_play_payment_details gd    ON gd.payment_id = p.id "
    "LEFT JOIN app_store_payment_details ad     ON ad.payment_id = p.id "
    "LEFT JOIN rangeproof_payment_details rd ON rd.payment_id = p.id"
)

# Single source of truth for reading a user row (mirrors PAYMENTS_*). The join to `generations` pulls the
# current generation's `token` (the proof's revocation_tag); it's an INNER JOIN because
# users.current_generation_id is NOT NULL, so every user always has a current generation.
USERS_COLUMNS = (
    "u.id, u.master_pkey, u.current_generation_id, g.token, u.expires_at, u.grace_period, u.auto_renewing, "
    "u.refund_requested_at"
)
USERS_FROM = "users u JOIN generations g ON g.id = u.current_generation_id"

# payments.payment_provider / .plan and user_errors.payment_provider store the string `code` directly
# (the lookup tables payment_providers/pro_plans use the code as their PRIMARY KEY, FK'd for validity).
# So there's no id indirection: the enum's `.value` IS the stored value, and reads map it straight back
# via base.PaymentProvider(...)/base.ProPlan(...).

class ReportPeriod(enum.Enum):
    Daily   = 0
    Weekly  = 1
    Monthly = 2

class ReportType(enum.Enum):
    Human = 0
    CSV   = 1

@dataclasses.dataclass(frozen=True)
class ReportRow:
    period:            str
    active_users:      int
    unredeemed:        int
    new_subs:          int
    google:            int
    apple:             int
    rangeproof:        int
    plan_1m:           int
    plan_3m:           int
    plan_12m:          int
    refunds_initiated: int
    revoked:           int
    cancelled:         int

@dataclasses.dataclass
class GoogleNotificationMessageIDInDB:
    present: bool = False
    handled: bool = False

@dataclasses.dataclass
class ExpireResult:
    success:                         bool = False
    revocations:                     int  = 0
    users:                           int  = 0
    apple_notification_uuid_history: int  = 0
    google_notification_history:     int  = 0

@dataclasses.dataclass
class ProSubscriptionProof:
    version:        int                    = 0
    revocation_tag: bytes                  = b''   # the generation's stored random 32-byte token
    rotating_pkey:  nacl.signing.VerifyKey = nacl.signing.VerifyKey(ZERO_BYTES32)
    expires_at:     datetime.datetime      = base.EPOCH
    sig:            bytes                  = b''

    def to_dict(self) -> dict[str, str | int]:
        # `version` is a PLAINTEXT field, deliberately NOT bound into the signature (Q12). It is the
        # external indicator a verifier reads to pick the domain prefix + layout it must use to
        # reconstruct and check the signed message; v0's domain prefix is BUILD_PROOF_DOMAIN
        # (`ProProof_v0_____`). The version→domain-prefix map is per-version and arbitrary — a future
        # version may choose any domain prefix (or reshape the proof entirely); a verifier simply
        # refuses a version it doesn't understand, so nothing old breaks. The version is thus a
        # verification *input*, never discovered through the signature; tampering with it just makes the
        # verifier pick the wrong domain prefix → signature fails.
        result = {
            "version":        self.version,
            "revocation_tag": self.revocation_tag.hex(),
            "rotating_pkey":  bytes(self.rotating_pkey).hex(),
            # Proof expiry is day-aligned, so integer seconds is exact (wire spec §2).
            "expiry_ts":      base.unix_seconds_from_datetime(self.expires_at),
            "sig":            self.sig.hex(),
        }
        return result

@dataclasses.dataclass
class LookupUserExpiry:
    # `None` expiry = "no such payment found yet". Durations default to zero.
    expiry_from_redeemed:           datetime.datetime  | None = None
    grace_from_redeemed:            datetime.timedelta        = datetime.timedelta(0)
    refund_requested_from_redeemed: datetime.datetime  | None = None
    auto_renewing_from_redeemed:    bool                      = False

    best_expiry:                    datetime.datetime  | None = None
    best_grace:                     datetime.timedelta        = datetime.timedelta(0)
    best_refund_requested:          datetime.datetime  | None = None
    best_auto_renewing:             bool                      = False

class RedeemPaymentStatus(enum.Enum):
    # redeem_payment_tx now returns Success or raises (FailError(unknown_payment)/revoked/expired), so the
    # old AlreadyRedeemed/UnknownPayment result codes are gone — a re-redeem is idempotent success and a
    # missing payment is a raised fail. (Error remains only as the pre-success init sentinel.)
    Nil             = 0
    Error           = 1
    Success         = 2

@dataclasses.dataclass
class RedeemPayment:
    proof:  ProSubscriptionProof = dataclasses.field(default_factory=ProSubscriptionProof)
    status: RedeemPaymentStatus  = RedeemPaymentStatus.Nil

AddRevocationIterator:               typing.TypeAlias = tuple[int,               # (row) id
                                                              bytes | None,      # master_pkey
                                                              datetime.datetime] # expires_at

GoogleUnhandledNotificationIterator: typing.TypeAlias = tuple[str,               # message_id (opaque string)
                                                              str | None,        # payload
                                                              datetime.datetime] # expires_at

@dataclasses.dataclass
class UserError:
    provider:             base.PaymentProvider = base.PaymentProvider.Nil
    apple_original_tx_id: str = ''
    google_payment_token: str = ''

@dataclasses.dataclass
class UserPaymentTransaction:
    provider:             base.PaymentProvider = base.PaymentProvider.Nil
    apple_tx_id:          str                  = ''
    rangeproof_order_id:  str                  = ''
    google_payment_token: str                  = ''
    google_order_id:      str                  = ''
    # The opaque wire `payment_id` (§3.5), hashed verbatim. On ingress it is the exact bytes the client
    # sent (then split into the typed fields above for DB lookup); when the backend builds a request it
    # is derived from the typed fields. Kept as its own field so the signed hash is byte-identical to
    # what the client signed, never a lossy re-join of the split fields.
    payment_id:           str                  = ''

# Google folds its two identifiers into one opaque `payment_id` as `token | order_id`, split once on the
# first delimiter. The token is base64url and the order id is `GPA.####-…`, so neither contains `|`.
GOOGLE_PAYMENT_ID_DELIMITER = '|'

def encode_payment_id(provider:             base.PaymentProvider,
                      *,
                      google_payment_token: str = '',
                      google_order_id:      str = '',
                      apple_tx_id:          str = '',
                      rangeproof_order_id:  str = '') -> str:
    # Encode a payment's provider-specific identifier(s) into the single opaque wire `payment_id`
    # (§3.5). The backend owns this encoding; the client treats the result as opaque bytes.
    match provider:
        case base.PaymentProvider.GooglePlayStore:
            return f'{google_payment_token}{GOOGLE_PAYMENT_ID_DELIMITER}{google_order_id}'
        case base.PaymentProvider.iOSAppStore:
            return apple_tx_id
        case base.PaymentProvider.Rangeproof:
            return rangeproof_order_id
        case _:
            return ''

def payment_id_from_user_tx(tx: UserPaymentTransaction) -> str:
    return encode_payment_id(tx.provider,
                             google_payment_token = tx.google_payment_token,
                             google_order_id      = tx.google_order_id,
                             apple_tx_id          = tx.apple_tx_id,
                             rangeproof_order_id  = tx.rangeproof_order_id)

def apply_payment_id_to_tx(tx: UserPaymentTransaction) -> None:
    # Split the opaque wire `payment_id` back into the backend's typed fields for DB lookup (§3.5).
    # A new provider only needs a new case here; the wire/hash never learn a payment has sub-fields.
    match tx.provider:
        case base.PaymentProvider.GooglePlayStore:
            tx.google_payment_token, _, tx.google_order_id = tx.payment_id.partition(GOOGLE_PAYMENT_ID_DELIMITER)
        case base.PaymentProvider.iOSAppStore:
            tx.apple_tx_id = tx.payment_id
        case base.PaymentProvider.Rangeproof:
            tx.rangeproof_order_id = tx.payment_id
        case _:
            pass

@dataclasses.dataclass
class AppleTransaction:
    original_tx_id:       str = ''
    tx_id:                str = ''
    web_line_order_tx_id: str = ''

@dataclasses.dataclass
class PaymentRow:
    id:                          int                       = 0
    master_pkey:                 bytes | None              = None
    # No stored `status`: derive it from the timestamps below via backend.derive_payment_status(row, now).
    plan:                        base.ProPlan              = base.ProPlan.Nil
    payment_provider:            base.PaymentProvider      = base.PaymentProvider.Nil
    auto_renewing:               bool                      = False
    purchased_at:                datetime.datetime         = base.EPOCH
    redeemed_at:                 datetime.datetime | None  = None
    expires_at:                  datetime.datetime         = base.EPOCH
    grace_period:                datetime.timedelta | None = None
    platform_refund_expires_at:  datetime.datetime         = base.EPOCH
    revoked_at:                  datetime.datetime | None  = None
    apple:                       AppleTransaction          = dataclasses.field(default_factory=AppleTransaction)
    google_payment_token:        str                       = ''
    google_order_id:             str                       = ''
    refund_requested_at:         datetime.datetime | None  = None
    rangeproof_order_id:         str                       = ''
    google_obfuscated_account_id: bytes | None             = None
    apple_app_account_token:     str | None                = None

def payment_id_from_payment_row(row: PaymentRow) -> str:
    # Egress: fold a stored payment's typed columns back into the opaque wire `payment_id` (§3.5).
    return encode_payment_id(row.payment_provider,
                             google_payment_token = row.google_payment_token,
                             google_order_id      = row.google_order_id,
                             apple_tx_id          = row.apple.tx_id,
                             rangeproof_order_id  = row.rangeproof_order_id)

@dataclasses.dataclass
class UserRow:
    found:                        bool                      = False
    id:                           int                       = 0
    master_pkey:                  bytes | None              = None
    current_generation_id:        int                       = 0
    token:                        bytes                     = b''   # current generation's token (proof revocation_tag)
    expires_at:                   datetime.datetime         = base.EPOCH
    grace_period:                 datetime.timedelta        = datetime.timedelta(0)
    auto_renewing:                bool                      = False
    refund_requested_at:          datetime.datetime | None  = None

@dataclasses.dataclass
class GetUserAndPayments:
    payments_it:    db.Result
    user:           UserRow = dataclasses.field(default_factory=UserRow)
    payments_count: int     = 0

@dataclasses.dataclass
class RevocationRow:
    '''A revoked generation (admin/raw view of the revocation list).'''
    generation_id: int               = 0
    token:         bytes             = b''
    revoked_at:    datetime.datetime = base.EPOCH

@dataclasses.dataclass
class AllocatedGenID:
    found:         bool                      = False
    expires_at:    datetime.datetime | None  = None
    grace_period:  datetime.timedelta        = datetime.timedelta(0)
    generation_id: int                       = 0
    token:         bytes                     = b''

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
    raw:  bytes = bytes.fromhex(text)
    seed: bytes = raw[:32]
    pub:  bytes = raw[32:]
    skey = nacl.signing.SigningKey(seed)
    if bytes(skey.verify_key) != pub:
        raise ValueError('embedded public key does not match the seed; the key file is corrupt')
    return skey

def backend_signing_key_to_hex(skey: nacl.signing.SigningKey) -> str:
    '''Serialise a signing key to the 128-hex libsodium-style representation (seed || public key).'''
    return (bytes(skey) + bytes(skey.verify_key)).hex()

def google_obfuscated_account_id_from_master_pkey(pkey: nacl.signing.VerifyKey) -> bytes:
    result: bytes = hashlib.sha256(bytes(pkey)).digest()
    return result

def apple_obfuscated_account_id_from_master_pkey(pkey: nacl.signing.VerifyKey) -> str:
    result = '' # TODO: Figure out how we derive Apple's app token account id from the master pkey
    return result

def payment_provider_tx_log_label(tx: base.PaymentProviderTransaction):
    result = f'{tx.provider.name}, apple (orig/tx/web)=({tx.apple_original_tx_id}/{tx.apple_tx_id}/{tx.apple_web_line_order_tx_id}), google=({tx.google_payment_token}/{tx.google_order_id})'
    return result

def payment_provider_tx_log_label_safe(tx: base.PaymentProviderTransaction):
    result = f'{tx.provider.name}, apple (orig/tx/web)=({base.maybe_obfuscate(tx.apple_original_tx_id)}/{base.maybe_obfuscate(tx.apple_tx_id)}/{base.maybe_obfuscate(tx.apple_web_line_order_tx_id)}), google=({base.maybe_obfuscate(tx.google_payment_token)}/{base.maybe_obfuscate(tx.google_order_id)})'
    return result

def _add_pro_payment_user_tx_log_label(tx: UserPaymentTransaction):
    result = f'{tx.provider.name}, apple={tx.apple_tx_id}, google=({tx.google_payment_token}, {tx.google_order_id})'
    return result

def _add_pro_payment_user_tx_log_label_safe(tx: UserPaymentTransaction):
    result = f'{tx.provider.name}, apple={base.maybe_obfuscate(tx.apple_tx_id)}, google=({base.maybe_obfuscate(tx.google_payment_token)}, {base.maybe_obfuscate(tx.google_order_id)})'
    return result

def user_payment_tx_to_safe_string(tx: UserPaymentTransaction) -> str:
    return (
        f"{tx.provider.name}, "
        f"google=({base.maybe_obfuscate(tx.google_payment_token)}/{base.maybe_obfuscate(tx.google_order_id)}), "
        f"rangeproof={base.maybe_obfuscate(tx.rangeproof_order_id)}"
    )

def to_redeemed_at(at: datetime.datetime) -> datetime.datetime:
    # Round up to the next UTC-day boundary (masks the exact instant the payment was redeemed).
    return base.round_datetime_to_next_day(at)

# The bytes we Ed25519-sign directly (NO pre-hash — wire spec §1): a 16-byte domain prefix then the fields,
# each encoded by TYPE — VerifyKey/bytes verbatim (fixed-width, self-delimiting); datetime → its UNIX
# **seconds** then decimal ASCII (pass an int explicitly if you ever need other units); int as canonical
# locale-independent decimal ASCII (matches C++ std::to_chars: no grouping/leading zeros, '-' for
# negatives, so count=-1 and unbounded values Just Work); str as UTF-8. A `\0` separates two ADJACENT
# variable-length (datetime/int/str) fields; fixed-width fields need no separator. Only payment_id can
# contain a `\0` and it is always the final field, so the framing is unambiguous.
def signed_message(domain: bytes, *fields: nacl.signing.VerifyKey | bytes | datetime.datetime | int | str) -> bytes:
    assert len(domain) == DOMAIN_SIZE
    out           = bytearray(domain)
    prev_variable = False
    for field in fields:
        if isinstance(field, (nacl.signing.VerifyKey, bytes, bytearray)):
            data, variable = bytes(field), False
        elif isinstance(field, datetime.datetime):
            data, variable = str(base.unix_seconds_from_datetime(field)).encode('ascii'), True  # → int seconds
        elif isinstance(field, int):
            data, variable = str(field).encode('ascii'), True                                    # canonical decimal
        elif isinstance(field, str):
            data, variable = field.encode('utf-8'), True
        else:
            raise TypeError(f'signed_message: unsupported field type {type(field).__name__} (expected VerifyKey/bytes, datetime, int, or str)')
        if variable and prev_variable:
            out += b'\x00'
        out          += data
        prev_variable = variable
    return bytes(out)

def make_add_pro_payment_message(master_pkey:   nacl.signing.VerifyKey,
                                 rotating_pkey: nacl.signing.VerifyKey,
                                 payment_tx:    UserPaymentTransaction) -> bytes:
    return signed_message(ADD_PRO_PAYMENT_DOMAIN, master_pkey, rotating_pkey,
                          payment_tx.provider.value, payment_tx.payment_id)

def make_set_payment_refund_requested_message(master_pkey: nacl.signing.VerifyKey, request_at: datetime.datetime, refund_requested_at: datetime.datetime, payment_tx: UserPaymentTransaction) -> bytes:
    return signed_message(SET_PAYMENT_REFUND_REQUESTED_DOMAIN, master_pkey,
                          request_at, refund_requested_at,
                          payment_tx.provider.value, payment_tx.payment_id)

def make_get_pro_details_message(master_pkey: nacl.signing.VerifyKey, request_at: datetime.datetime, count: int) -> bytes:
    return signed_message(GET_PRO_DETAILS_DOMAIN, master_pkey, request_at, count)

def payment_row_from_dict(row: dict[str, typing.Any]) -> PaymentRow:
    # Rows come from a dict row factory (SELECT PAYMENTS_COLUMNS FROM PAYMENTS_FROM, row_factory=
    # db.dict_row) so columns are addressed by name — adding/removing a column no longer renumbers
    # anything here. `master_pkey` is joined from users (NULL for an unredeemed payment).
    result                              = PaymentRow()
    result.id                           = row['id']
    result.master_pkey                  = bytes(row['master_pkey']) if row['master_pkey'] is not None else None
    result.plan                         = base.ProPlan(row['plan'])
    result.payment_provider             = base.PaymentProvider(row['payment_provider'])
    result.auto_renewing                = bool(row['auto_renewing'])
    result.purchased_at                 = row['purchased_at']
    result.redeemed_at                  = row['redeemed_at']                  # NULL until redeemed
    result.expires_at                   = row['expires_at']
    result.grace_period                 = row['grace_period']                 # nullable
    result.platform_refund_expires_at   = row['platform_refund_expires_at']
    result.revoked_at                   = row['revoked_at']                   # NULL unless revoked
    result.apple.original_tx_id         = str(row['apple_original_tx_id'])       if row['apple_original_tx_id']       else ''
    result.apple.tx_id                  = str(row['apple_tx_id'])                if row['apple_tx_id']                else ''
    result.apple.web_line_order_tx_id   = str(row['apple_web_line_order_tx_id']) if row['apple_web_line_order_tx_id'] else ''
    result.google_payment_token         = str(row['google_payment_token'])      if row['google_payment_token']      else ''
    result.google_order_id              = str(row['google_order_id'])           if row['google_order_id']           else ''
    result.rangeproof_order_id          = str(row['rangeproof_order_id'])        if row['rangeproof_order_id']        else ''
    result.refund_requested_at          = row['refund_requested_at']           # NULL = none requested
    result.google_obfuscated_account_id = bytes(row['google_obfuscated_account_id']) if row['google_obfuscated_account_id'] is not None else None
    result.apple_app_account_token      = row['apple_app_account_token']       # nullable
    return result

def derive_payment_status(payment: PaymentRow, now: datetime.datetime) -> base.PaymentStatus:
    """Derive the single display status from a payment's timestamps against `now`.

    `status` is not stored; it's computed with precedence revoked > expired > redeemed > unredeemed.
    """
    if payment.revoked_at is not None:
        return base.PaymentStatus.Revoked
    if now >= payment.expires_at:
        return base.PaymentStatus.Expired
    if payment.redeemed_at is not None:
        return base.PaymentStatus.Redeemed
    return base.PaymentStatus.Unredeemed

def get_unredeemed_payments_list(conn: psycopg.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with db.transaction(conn):
        rows = db.query(conn, f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM} WHERE p.redeemed_at IS NULL AND p.revoked_at IS NULL ORDER BY p.id', row_factory=db.dict_row)
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
    payments_it = db.query(tx.conn, f'''
        SELECT   {PAYMENTS_COLUMNS}
        FROM     {PAYMENTS_FROM}
        WHERE    p.user_id = (SELECT id FROM users WHERE master_pkey = %s)
        ORDER BY p.purchased_at DESC, p.id DESC
    ''', bytes(master_pkey), row_factory=db.dict_row)

    result      = GetUserAndPayments(payments_it=payments_it)
    result.user = get_user(tx.conn, master_pkey)

    result.payments_count = db.query_scalar(tx.conn, '''
        SELECT COUNT(*)
        FROM   payments
        WHERE  user_id = (SELECT id FROM users WHERE master_pkey = %s)
    ''', bytes(master_pkey))
    return result

def user_row_from_dict(row: dict[str, typing.Any]) -> UserRow:
    return UserRow(found                        = True,
                   id                           = row['id'],
                   master_pkey                  = bytes(row['master_pkey']),
                   current_generation_id        = row['current_generation_id'],
                   token                        = bytes(row['token']),
                   expires_at                   = row['expires_at'],
                   grace_period                 = row['grace_period'],
                   auto_renewing                = bool(row['auto_renewing']),
                   refund_requested_at          = row['refund_requested_at'])

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
    row = db.query_one(conn, f"SELECT {USERS_COLUMNS} FROM {USERS_FROM} WHERE u.master_pkey = %s",
                       bytes(master_pkey), row_factory=db.dict_row)
    if row:
        result = user_row_from_dict(row)
    return result

def get_revocations_list(conn: psycopg.Connection) -> list[RevocationRow]:
    result: list[RevocationRow] = []
    with db.transaction(conn) as tx:
        for row in db.query(tx.conn, "SELECT id, token, revoked_at FROM generations WHERE revoked_at IS NOT NULL"):
            generation_id, token, revoked_at = row
            result.append(RevocationRow(generation_id=generation_id, token=bytes(token), revoked_at=revoked_at))
    return result

def is_generation_revoked(conn: psycopg.Connection, generation_id: int, now: datetime.datetime) -> bool:
    # A generation is revoked iff revoked_at is set (revocation is terminal). `now` is accepted for a
    # uniform signature; a set revoked_at is always in effect (there is no per-entry expiry now — the
    # served-list retention window is list-level and memory-only on the client). Single statement, so it
    # runs directly on the given connection: a mid-transaction caller passes `tx.conn` and the read joins
    # that open transaction (sees an uncommitted revoke); a standalone caller autocommits.
    return bool(db.query_scalar(conn, "SELECT EXISTS (SELECT 1 FROM generations WHERE id = %s AND revoked_at IS NOT NULL)", generation_id))

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

def get_global_datetime(conn: psycopg.Connection, key: str) -> datetime.datetime:
    row = db.query_one(conn, "SELECT ts_val FROM globals WHERE key = %s", key)
    assert row is not None, f'missing timestamp global "{key}"'
    return row[0]

def set_global_datetime(conn: psycopg.Connection, key: str, value: datetime.datetime) -> None:
    db.query(conn, "UPDATE globals SET ts_val = %s WHERE key = %s", value, key)

def get_revocation_ticket(conn: psycopg.Connection) -> int:
    return get_global_int(conn, 'revocation_ticket')

def bump_revocation_ticket(conn: psycopg.Connection, amount: int) -> int:
    """Advance the monotonic revocation ticket by `amount`, returning the new value. Manual DR tool: the
    ticket is a plain counter, so restoring the database from an older backup rolls it backward — and a
    client holding a higher cached ticket then reads the list as "unchanged" and silently stops seeing
    revocations. After such a restore, bump the ticket past its pre-restore value to force every client to
    re-fetch. See docs/deploy.md ("After ANY restore")."""
    row = db.query_one(conn, "UPDATE globals SET int_val = int_val + %s WHERE key = 'revocation_ticket' RETURNING int_val", amount)
    assert row is not None, 'missing revocation_ticket global'
    return row[0]

def bootstrap_db(database_url: str, err: base.ErrorSink) -> psycopg_pool.ConnectionPool | None:
    """ Opens the database pool and bootstraps/migrates the schema if needed. """
    result: psycopg_pool.ConnectionPool | None = None
    try:
        result = db.get_pool(database_url)
    except Exception as e:
        err.msg_list.append(f'Failed to open/connect to DB at {database_url}: {e}')
        return result

    try:
        with db.connection(result) as conn:
            migrations.apply_migrations(conn)
    except Exception:
        err.msg_list.append(f"Failed to bootstrap DB tables: {traceback.format_exc()}")

    return result

def verify_db(conn: psycopg.Connection, err: base.ErrorSink) -> bool:
    unredeemed_payments: list[PaymentRow] = get_unredeemed_payments_list(conn)
    for index, it in enumerate(unredeemed_payments):
        _ = base.verify_payment_provider(it.payment_provider, err)
        if len(it.google_payment_token) != BLAKE2B_DIGEST_SIZE:
            err.msg_list.append(f'Unredeeemed payment #{index} token is not 32 bytes, was {len(it.google_payment_token)}')
        if it.plan == base.ProPlan.Nil:
               err.msg_list.append(f'Unredeemed payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})')

    # NOTE: Wednesday, 27 August 2025 00:00:00 UTC, arbitrary date in the past that PRO cannot
    # possibly be before. We should update this to to the PRO release date. (Was a bare int that,
    # pre-datetime-migration, was seconds compared against millisecond values — so the guard never
    # fired; now a real instant.)
    PRO_ENABLED_AT: datetime.datetime = datetime.datetime(2025, 8, 27, tzinfo=datetime.timezone.utc)

    payments: list[PaymentRow] = get_payments_list(conn)
    now:      datetime.datetime = datetime.datetime.now(datetime.timezone.utc)
    for index, it in enumerate(payments):
        # `status` is derived (not stored) — invariants are really per-fact, but we keep the
        # per-status framing for readable diagnostics.
        status = derive_payment_status(it, now)
        # NOTE: Check mandatory fields
        if it.plan == base.ProPlan.Nil:
            err.msg_list.append(f'{status.name} payment #{index} plan is invalid. It should have been derived from the platform payment provider (e.g. by converting the unredeemedd plan ID to a plan)')
        if it.payment_provider == base.PaymentProvider.Nil:
            err.msg_list.append(f'{status.name} payment #{index} payment provider is set to {it.payment_provider.name} but it should not be. It should have been set by the platform before added to the DB')

        # NOTE: Check mandatory fields or invariants given a particular TX status. Presence/absence
        # is now modelled by NULL (redeemed_at / revoked_at), and expires_at is NOT NULL, so the old
        # "ts was 0" sentinel checks are gone — the schema enforces them.
        if it.redeemed_at is None and it.revoked_at is None:
            # Unredeemed: nothing identity-related should be set yet.
            if it.master_pkey is not None:
                err.msg_list.append(f'{status.name} payment #{index} has a master pkey set but this pkey should not be set until it is redeemed (e.g. the user registers it)')

        if it.revoked_at is None and it.redeemed_at is not None:
            # Redeemed (and not revoked): a redeemed payment must not have expired before it was redeemed.
            if it.expires_at < it.redeemed_at:
                redeemed_date = it.redeemed_at.strftime('%Y-%m-%d')
                expiry_date   = it.expires_at.strftime('%Y-%m-%d')
                err.msg_list.append(f'{status.name} payment #{index} was expired ({expiry_date}) before it was activated ({redeemed_date})')

        # NOTE: Verify the plan, it should always be set once it enters the DB..
        if it.plan == base.ProPlan.Nil:
               err.msg_list.append(f'Payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})')
        _ = base.verify_payment_provider(it.payment_provider, err)

        # NOTE: Check that the payment's redeemed ts is a reasonable value
        if it.redeemed_at is not None and it.redeemed_at < PRO_ENABLED_AT:
          err.msg_list.append(f'Payment #{index} specified a creation date before PRO was enabled: {base.readable(it.redeemed_at)}')

        # NOTE: Check that the token is set correctly
        if it.payment_provider == base.PaymentProvider.GooglePlayStore:
            pass
        elif len(it.google_payment_token) != 0:
            err.msg_list.append(f'Payment #{index} specified a google payment token: {base.maybe_obfuscate(it.google_payment_token)} for a non-google platform')

    # NOTE: Verify the users
    users: list[UserRow] = get_users_list(conn)
    for index, it in enumerate(users):
        if it.master_pkey == ZERO_BYTES32:
            err.msg_list.append(f'User #{index} has a master public key set to the zero key')
        if it.expires_at < PRO_ENABLED_AT:
          err.msg_list.append(f'Payment #{index} specified a expiry date before PRO was enabled: {base.readable(it.expires_at)}')

    result = len(err.msg_list) == 0
    return result

def _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey):
    """Update fields for the user that depend on their list of payments, like
    their latest known expiry time"""
    master_pkey_bytes: bytes                    = bytes(master_pkey)
    lookup:            LookupUserExpiry = _lookup_user_expiry_tx(tx, nacl.signing.VerifyKey(master_pkey_bytes))
    # NOTE: We have the latest expiry value, now update the user
    _ = db.query(tx.conn, '''
        UPDATE users
        SET    expires_at = %(expiry)s, grace_period = %(grace)s, auto_renewing = %(renewing)s, refund_requested_at = %(refund)s
        WHERE  master_pkey = %(pkey)s
    ''', expiry   = lookup.best_expiry,
         grace    = lookup.best_grace,
         renewing = lookup.best_auto_renewing,
         refund   = lookup.best_refund_requested,
         pkey     = master_pkey_bytes)

def revoke_payments_by_id_internal_tx(tx: db.SQLTransaction, rows: typing.Any, revoke_at: datetime.datetime) -> bool:
    result                                            = False
    master_pkey_dict: dict[bytes, datetime.datetime]  = {}
    for row in  rows:
        result                          = True
        id, master_pkey_raw, expires_at = row
        master_pkey_bytes: bytes | None = bytes(master_pkey_raw) if master_pkey_raw is not None else None

        # NOTE: A payment will not have a master pkey associated with it if the user hasn't
        # redeemed it yet so the key may not be set. If it's not set we still mark the payment as
        # 'revoked', this means that it can't be activated and so a master pkey cannot be set on it
        # after the fact as well.
        if master_pkey_bytes:
            master_pkey_dict[master_pkey_bytes] = expires_at

        # NOTE: Mark the payment revoked (set revoked_at) unless it already is.
        _ = db.query(tx.conn, '''
        UPDATE payments
        SET    revoked_at = %(revoked_ts)s, auto_renewing = FALSE
        WHERE  id = %(id)s AND revoked_at IS NULL
        ''',
            revoked_ts = revoke_at,
            id         = id)

    revoke_at_next_day = round_datetime_to_next_day_with_platform_testing_support(base.PaymentProvider.Nil, revoke_at)

    # The furthest into the future any outstanding proof can certify: a proof clamps its expiry to
    # round_up_day(request_at + 30d) (_build_proof_clamped_expiry_time) and request_at is only accepted
    # within DEFAULT_TIMESTAMP_TOLERANCE of the server clock, so no live proof reaches beyond this
    # relative to the revoke instant.
    max_outstanding_proof_expiry = base.round_datetime_to_next_day(
        revoke_at + base.DEFAULT_TIMESTAMP_TOLERANCE + datetime.timedelta(days=30))

    for it in master_pkey_dict:
        # NOTE: For each user we revoked a payment for, we have modified their 'auto_renewing' value
        # on the payment, we need to go and update their user row to track the, new, next best
        # expiry time so that the backend knows the new time-frame in which the user is allowed to
        # generate a Session Pro proof (now that one or more of their payments get revoked)
        master_pkey = nacl.signing.VerifyKey(it)
        _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx, master_pkey)

        # NOTE: expires_at in the db is not rounded, but the proof's themselves have an
        # expiry timestamp rounded to the end of the UTC day. So we only actually want to revoke
        # proofs that aren't going to self-expire by the end of the day.
        #
        # For different platforms in their testing environments, they have different timespans
        # for a day, for example in Google 1 day is 10s. We handle that explicitly here.
        expires_at = master_pkey_dict[it]
        if expires_at <= revoke_at_next_day:
            continue

        # Item 4: even when the revoked payment's own proof would outlive the day boundary, a broadcast
        # revocation + generation roll is only needed if the refund drops the user's *remaining*
        # entitlement below something an outstanding proof already certifies. If enough paid time
        # survives the refund (aggregate expiry at or beyond the furthest a live proof can reach) every
        # outstanding proof stays honest, so we skip the revocation entirely. The revocation list is
        # fetched by every client, so keeping it minimal is the point.
        post_refund_expiry = _lookup_user_expiry_tx(tx, master_pkey).best_expiry
        if post_refund_expiry is not None and post_refund_expiry >= max_outstanding_proof_expiry:
            continue

        _ = revoke_master_pkey_proofs_and_allocate_new_gen_id_tx(tx, master_pkey, created_at=revoke_at)

    return result

def add_apple_revocation_tx(tx: db.SQLTransaction, apple_original_tx_id: str, revoke_at: datetime.datetime, err: base.ErrorSink) -> bool:
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
    rows_result = db.query(tx.conn, f'''
    SELECT p.id, u.master_pkey, p.expires_at
    FROM   {PAYMENTS_FROM}
    WHERE  ad.original_tx_id = %(orig_tx)s;
    ''',
        orig_tx    = apple_original_tx_id)

    log.info(f'Revoking Apple payment (orig. TX ID={base.maybe_obfuscate(apple_original_tx_id)}, revoke={base.readable(revoke_at)})')
    rows         = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal_tx(tx, rows, revoke_at)
    if result == False:
        err.msg_list.append(f'Failed to revoke Apple orig. TX ID {base.maybe_obfuscate(apple_original_tx_id)} at {base.readable(revoke_at)}, no matching payments were found')

    return result

def add_google_revocation_tx(tx: db.SQLTransaction, google_payment_token: str, revoke_at: datetime.datetime, err: base.ErrorSink) -> bool:
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
    rows_result = db.query(tx.conn, f'''
    SELECT p.id, u.master_pkey, p.expires_at
    FROM   {PAYMENTS_FROM}
    WHERE  gd.payment_token = %(token)s
    ''',
        token=google_payment_token)

    log.info(f'Revoking Google payment (token={base.maybe_obfuscate(google_payment_token)}, revoke={base.readable(revoke_at)})')
    rows         = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal_tx(tx, rows, revoke_at)
    if result == False:
        err.msg_list.append(f'Failed to revoke Google payment {base.maybe_obfuscate(google_payment_token)} at {base.readable(revoke_at)}, no matching payments were found')

    return result

def redeem_payment_tx(tx:                  db.SQLTransaction,
                      master_pkey:         nacl.signing.VerifyKey,
                      rotating_pkey:       nacl.signing.VerifyKey | None,
                      signing_key:         nacl.signing.SigningKey | None,
                      request_at:          datetime.datetime,
                      redeemed_at: datetime.datetime,
                      payment_tx:          UserPaymentTransaction) -> RedeemPayment:
    """
    request_at: The timestamp typically accurate to the current time, used as a frame-of-reference
    to clamp the duration of the proof returned to the user to at most 1 month, also used to mask
    metadata about the type of subscription a user is currently using.

    redeemed_at: Timestamp to mark as the time in point in which the payment was redeemed.
    This timestamp is typically rounded up by using 'to_redeemed_at' to
    #mask metadata about the time the user redeemed the payment.
    """

    result                   = RedeemPayment(status=RedeemPaymentStatus.Error)
    master_pkey_bytes: bytes = bytes(master_pkey)
    # A redeem marks the matched unredeemed payment(s) Redeemed; user_id is linked separately once the
    # users row is ensured (master_pkey lives only in users now). The UPDATEs RETURN their ids so we
    # can link exactly those rows without re-matching the per-provider WHERE.
    fields                   = ['redeemed_at = %(redeemed_at)s']
    set_expr                 = ', '.join(fields) # Create '<field0> = ?, <field1> = ?, ...'

    payment_tx_label     = _add_pro_payment_user_tx_log_label_safe(payment_tx)
    rotating_pkey_label = base.maybe_obfuscate_bytes(bytes(rotating_pkey)) if rotating_pkey else '(none)'
    log.info(f'Redeeming payment (master={base.maybe_obfuscate_bytes(master_pkey)}, rotating={rotating_pkey_label}, redeemed={base.readable(redeemed_at)}, payment={payment_tx_label})')

    # NOTE: We technically always allow a redeem of an unredeemed payment as long as the user
    # knows the transaction ID (payment token/tx ID). If for example the user sits on the
    # payment and doesn't redeem it and it expires but the expiry task hasn't been run yet, the
    # user can still redeem the payment, they won't be allowed to use the proof because it has
    # expired, but, they can register their public key for the payment and associate it with
    # their account.
    #
    # The payment will now show up in their cross-platform payment history and visible across
    # all the Session devices they have.
    #
    # TODO: What if the payment was expired and it has no master public key? Following the same
    # train of thought it would be nice to let the user claim that payment so that they have
    # the ability to maintain proper-book-keeping, but it's not clear to me if its even possible
    # for that to happen. Maybe more realistically a payment could get revoked before it was
    # redeemed and it'd be nice to allow the user to claim it and get it attributed to their
    # account.

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        row_result = db.query(tx.conn, f'''
            UPDATE payments
            SET    {set_expr}
            WHERE  id IN (SELECT payment_id FROM google_play_payment_details
                          WHERE payment_token = %(token)s AND order_id = %(order_id)s AND obfuscated_account_id = %(account_id)s)
              AND  redeemed_at IS NULL AND revoked_at IS NULL
            RETURNING id
        ''', # SET values
              redeemed_at = redeemed_at,
              # WHERE values
              token               = payment_tx.google_payment_token,
              order_id            = payment_tx.google_order_id,
              account_id          = google_obfuscated_account_id_from_master_pkey(master_pkey))
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        row_result = db.query(tx.conn, f'''
            UPDATE payments
            SET    {set_expr}
            WHERE  id IN (SELECT payment_id FROM app_store_payment_details
                          WHERE tx_id = %(tx_id)s AND app_account_token = %(account_token)s)
              AND  redeemed_at IS NULL AND revoked_at IS NULL
            RETURNING id
        ''', # SET fields
              redeemed_at = redeemed_at,
              # WHERE fields
              tx_id               = payment_tx.apple_tx_id,
              account_token       = apple_obfuscated_account_id_from_master_pkey(master_pkey))
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        row_result = db.query(tx.conn, f'''
            UPDATE payments
            SET    {set_expr}
            WHERE  id IN (SELECT payment_id FROM rangeproof_payment_details WHERE order_id = %(rangeproof_order_id)s)
              AND  redeemed_at IS NULL AND revoked_at IS NULL
            RETURNING id
        ''', # SET fields
              redeemed_at = redeemed_at,
              # WHERE fields
              rangeproof_order_id = payment_tx.rangeproof_order_id,)
    else:
        raise base.FailError('Payment to register specifies an unknown payment provider')

    redeemed_ids = [row[0] for row in row_result.fetchall()]
    rowcount     = len(redeemed_ids)
    if rowcount >= 1:
        assert rowcount == 1

        # master_pkey lives only in `users`: ensure the identity row (+ its first generation) exists,
        # then link the just-redeemed payment(s) to it.
        user_id, *_ = get_or_create_user_and_generation(tx, master_pkey, issued_at=redeemed_at)
        _ = db.query(tx.conn, '''
            UPDATE payments
            SET    user_id = %(user_id)s
            WHERE  id = ANY(%(ids)s)
        ''', user_id = user_id, ids = redeemed_ids)

        # Refresh the user's entitlement to reflect the now-linked payments. A generation is an epoch
        # (item 3): this REUSES the user's current generation (brand-new user → its initial one; existing
        # user → the same one they already had), so a redeem never rolls the generation or the client's
        # revocation_tag. (_allocate mints a fresh generation only if the current one is revoked.)
        allocated: AllocatedGenID = _allocate_new_gen_id_if_master_pkey_has_payments(tx, master_pkey, issued_at=redeemed_at)
        assert allocated.found, "We just added the user's payment we expect to find the latest expiry date for the pkey"

        # NOTE: Only generate the proof if a rotating public key was given — a payment can be redeemed
        # without automatically creating the corresponding proof.
        if rotating_pkey:
            assert signing_key, "Rotating public key and signing key have to be given in tandem, either both set or both set to nil"
            proposed_proof_expires_at: datetime.datetime = base.round_datetime_to_next_day(allocated.expires_at)
            result.proof = build_proof(revocation_tag = allocated.token,
                                       rotating_pkey  = rotating_pkey,
                                       expires_at     = _build_proof_clamped_expiry_time(request_at=request_at, proposed_expires_at=proposed_proof_expires_at),
                                       signing_key    = signing_key)
            assert result.proof.expires_at == base.round_datetime_to_start_of_day(result.proof.expires_at), f"Proof expiry must land on a UTC day boundary, was {base.readable(result.proof.expires_at)}"

    else:
        # Nothing claimable matched. Distinguish "this user already redeemed this exact payment"
        # (replay/double-submit → idempotent success) from "no such payment for this user" (a genuine
        # dead-end → unknown_payment). The COUNT below only reads data the user themselves sent.
        redeemed_count = 0
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            redeemed_count = db.query_scalar(tx.conn, '''
                SELECT COUNT(*)
                FROM   payments p JOIN google_play_payment_details gd ON gd.payment_id = p.id
                WHERE  gd.payment_token = %(token)s
                  AND  gd.order_id      = %(order_id)s
                  AND  p.redeemed_at IS NOT NULL
                  AND  p.user_id        = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
            ''', token       = payment_tx.google_payment_token,
                 order_id    = payment_tx.google_order_id,
                 master_pkey = master_pkey_bytes)
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            redeemed_count = db.query_scalar(tx.conn, '''
                SELECT COUNT(*)
                FROM   payments p JOIN app_store_payment_details ad ON ad.payment_id = p.id
                WHERE  ad.tx_id = %(tx_id)s
                  AND  p.redeemed_at IS NOT NULL
                  AND  p.user_id  = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
            ''', tx_id       = payment_tx.apple_tx_id,
                 master_pkey = master_pkey_bytes)
        elif payment_tx.provider == base.PaymentProvider.Rangeproof:
            redeemed_count = db.query_scalar(tx.conn, '''
                SELECT COUNT(*)
                FROM   payments p JOIN rangeproof_payment_details rd ON rd.payment_id = p.id
                WHERE  rd.order_id = %(order_id)s
                  AND  p.redeemed_at IS NOT NULL
                  AND  p.user_id     = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
            ''', order_id    = payment_tx.rangeproof_order_id,
                 master_pkey = master_pkey_bytes)

        if redeemed_count > 0:
            # Already redeemed by this user → idempotent: hand back a proof for their CURRENT entitlement
            # via the existing generation (no roll), identical to generate_pro_proof. If that entitlement
            # is since revoked/expired the helper raises the truthful slug.
            log.info(f'Payment already redeemed for this user (idempotent): {user_payment_tx_to_safe_string(payment_tx)}')
            if rotating_pkey:
                assert signing_key, "Rotating public key and signing key have to be given in tandem"
                result.proof = build_current_entitlement_proof_tx(tx, master_pkey, rotating_pkey, request_at, signing_key)
        else:
            raise base.FailError(f'Payment was not redeemed, no payments were found matching the request tx: {user_payment_tx_to_safe_string(payment_tx)}',
                                 code=base.ErrorCode.unknown_payment)

    result.status = RedeemPaymentStatus.Success
    return result

def verify_payment_provider_tx(payment_tx: base.PaymentProviderTransaction, err: base.ErrorSink):
    _ = base.verify_payment_provider(payment_tx.provider, err)
    match payment_tx.provider:
        case base.PaymentProvider.GooglePlayStore:
            if len(payment_tx.google_order_id) == 0:
                err.msg_list.append(f'Google order id was not set')
            if len(payment_tx.google_payment_token) == 0:
                err.msg_list.append(f'Google payment token was not set')
        case base.PaymentProvider.iOSAppStore:
            if len(payment_tx.apple_tx_id) == 0:
                err.msg_list.append(f'Apple TX ID was not set')
            if len(payment_tx.apple_original_tx_id) == 0:
                err.msg_list.append(f'Apple original TX ID was not set')
        case base.PaymentProvider.Rangeproof:
            if len(payment_tx.rangeproof_order_id) == 0:
                err.msg_list.append(f'Rangeproof order ID was not set')
        case base.PaymentProvider.Nil:
            err.msg_list.append(f'Payment provider was set invalidly to nil')

def _lookup_user_expiry_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> LookupUserExpiry:
    # NOTE: We grab the expired ones as well because if they have grace that payment's deadline
    # is later than the expiry period which may actually be the latest known expiry period
    #
    # By definition we can't lookup unredeemed payments because they don't have a master public key
    # registered for it yet (e.g. the user has not associated a master public key with the payment
    # yet by redeeming it).
    # All of a user's linked payments are redeemed-or-later (user_id is set only at redemption), so
    # filtering on user_id selects exactly those — unredeemed payments have no user_id.
    # redeemed/expired/revoked are then derived from the timestamps below.
    result_set = db.query(tx.conn, ('''
        SELECT    p.expires_at, p.grace_period, p.auto_renewing, p.redeemed_at, p.refund_requested_at, p.payment_provider,
                  ad.original_tx_id, gd.order_id, rd.order_id, p.revoked_at
        FROM      payments p
                  LEFT JOIN app_store_payment_details ad      ON ad.payment_id = p.id
                  LEFT JOIN google_play_payment_details gd     ON gd.payment_id = p.id
                  LEFT JOIN rangeproof_payment_details rd ON rd.payment_id = p.id
        WHERE     p.user_id = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
        ORDER BY  p.id DESC
    '''), master_pkey = bytes(master_pkey))

    used_google_order_ids:     list[str] = []
    used_apple_orig_tx_ids:    set[int]  = set()
    used_rangeproof_order_ids: set[str]  = set()

    # NOTE: Determine the user's latest expiry by enumerating all the payments and calculating
    # the expiry time (inclusive of the grace period if applicable)
    result      = LookupUserExpiry()
    rows        = typing.cast(list[tuple[typing.Any, ...]], result_set.fetchall())
    for row in rows:
        # Order matches the SELECT above; unpacking fails loudly if the column count ever drifts.
        (expires_at, grace_period, auto_renewing, redeemed_at, refund_requested_at,
         payment_provider, apple_original_tx_id, google_order_id, rangeproof_order_id, revoked_at) = row
        # grace_period is nullable; treat "absent" as zero for the entitlement arithmetic below.
        grace = grace_period if grace_period is not None else datetime.timedelta(0)

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
                log.warning(f"Failed to split order google order ID by '..' for {base.maybe_obfuscate_bytes(master_pkey)}: {base.maybe_obfuscate(google_order_id)}")
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
            log.warning(f"Unrecognised payment provider in {row} for {base.maybe_obfuscate_bytes(master_pkey)}: {payment_provider}")
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
            assert auto_renewing == False
            payment_expires_at = revoked_at
            expires_at         = revoked_at
        else:
            payment_expires_at = expires_at + grace if auto_renewing else expires_at

        # NOTE: A payment contributes to the "redeemed" entitlement iff it has been redeemed and not
        # revoked. (Expiry is deliberately excluded — see above.)
        is_redeemed = redeemed_at is not None and revoked_at is None
        if is_redeemed and (best_wo_grace_from_redeemed is None or expires_at > best_wo_grace_from_redeemed):
            result.expiry_from_redeemed           = payment_expires_at
            result.grace_from_redeemed            = grace
            result.refund_requested_from_redeemed = refund_requested_at
            result.auto_renewing_from_redeemed    = bool(auto_renewing)

        if best_wo_grace is None or expires_at > best_wo_grace:
            result.best_expiry           = payment_expires_at
            result.best_grace            = grace
            result.best_refund_requested = refund_requested_at
            result.best_auto_renewing    = bool(auto_renewing)
    return result

def update_payment_renewal_info_tx(tx:                       db.SQLTransaction,
                                   payment_tx:               base.PaymentProviderTransaction,
                                   grace_period: datetime.timedelta  | None,
                                   auto_renewing:            bool | None,
                                   err:                      base.ErrorSink) -> bool:
    """
    Update a payment's grace period and/or auto renewing flag. Pass in `None` for the arguments
    you want to opt out of updating.
    """

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label(payment_tx)
        log.info(f'Update renewal info (payment={payment_tx_label}, grace period ms={grace_period}, auto_renewing={auto_renewing})')

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
            result_set = db.query(tx.conn, f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     id IN (SELECT payment_id FROM google_play_payment_details WHERE payment_token = %(token)s AND order_id = %(order_id)s)
                RETURNING (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
            ''', token    = payment_tx.google_payment_token,
                 order_id = payment_tx.google_order_id,
                 **kwparams)

        case base.PaymentProvider.iOSAppStore:
            result_set = db.query(tx.conn, f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     id IN (SELECT payment_id FROM app_store_payment_details WHERE original_tx_id = %(orig_tx_id)s AND tx_id = %(tx_id)s AND web_line_order_tx_id = %(line_order_tx_id)s)
                RETURNING (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
            ''', orig_tx_id       = payment_tx.apple_original_tx_id,
                 tx_id            = payment_tx.apple_tx_id,
                 line_order_tx_id = payment_tx.apple_web_line_order_tx_id,
                 **kwparams)

        case base.PaymentProvider.Rangeproof:
            result_set = db.query(tx.conn, f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     id IN (SELECT payment_id FROM rangeproof_payment_details WHERE order_id = %(rangeproof_order_id)s)
                RETURNING (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
            ''', rangeproof_order_id = payment_tx.rangeproof_order_id,
                 **kwparams)


    # NOTE: A `RETURNING` clause seems to break rowcount (returns 0 even on row modification), so we
    # use fetchone instead. The RETURNING expression resolves the payment's owner master_pkey via the
    # users FK (NULL if the payment isn't redeemed yet).
    assert result_set
    row    = typing.cast(tuple[bytes] | None, result_set.fetchone())
    result = row is not None

    # NOTE: Update the user's expiry to the latest known expiry
    if row and row[0]:
        master_pkey_bytes: bytes = bytes(row[0])
        _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx, nacl.signing.VerifyKey(master_pkey_bytes))

    if result == False:
        payment_id = ''
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            payment_id = payment_tx.google_order_id
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            payment_id = payment_tx.apple_tx_id
        else:
            payment_id = payment_tx.rangeproof_order_id
        err.msg_list.append(f'Updating payment TX failed, no matching payment found for {payment_tx.provider.name} {base.maybe_obfuscate(payment_id)}')
    return result

def update_payment_renewal_info(conn:                     psycopg.Connection,
                                payment_tx:               base.PaymentProviderTransaction,
                                grace_period: datetime.timedelta  | None,
                                auto_renewing:            bool | None,
                                err:                      base.ErrorSink) -> bool:

    result = False
    with db.transaction(conn) as sql_tx:
        result = update_payment_renewal_info_tx(sql_tx, payment_tx, grace_period, auto_renewing, err)
    return result

def _insert_payment_row_tx(tx: db.SQLTransaction, payment: dict[str, typing.Any], detail_table: str, detail: dict[str, typing.Any]) -> None:
    """INSERT a payment: the provider-agnostic `payment` columns into `payments` (RETURNING the new id),
    then the provider-specific `detail` columns into `detail_table`, keyed by that id.

    Each dict is self-aligning — the column name lives with its value, so there is no pair of parallel
    lists to drift out of index-lock; placeholders are generated from the same keys.
    """
    p_columns      = ', '.join(payment)
    p_placeholders = ', '.join(f'%({column})s' for column in payment)
    result         = db.query(tx.conn, f'INSERT INTO payments ({p_columns}) VALUES ({p_placeholders}) RETURNING id', payment)
    payment_id     = result.fetchone()[0]

    detail_row      = {'payment_id': payment_id, **detail}
    d_columns       = ', '.join(detail_row)
    d_placeholders  = ', '.join(f'%({column})s' for column in detail_row)
    _ = db.query(tx.conn, f'INSERT INTO {detail_table} ({d_columns}) VALUES ({d_placeholders})', detail_row)

def add_unredeemed_payment_tx(tx:                                db.SQLTransaction,
                              payment_tx:                        base.PaymentProviderTransaction,
                              plan:                              base.ProPlan,
                              expires_at:                 datetime.datetime,
                              purchased_at:             datetime.datetime,
                              platform_refund_expires_at: datetime.datetime,
                              platform_obfuscated_account_id:    bytes | str,
                              err:                               base.ErrorSink):

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label(payment_tx)
        log.info(f'Unredeemed payment (payment={payment_tx_label}, plan={plan.name}, expiry={base.readable(expires_at)}, unredeemed={base.readable(purchased_at)}, refund={base.readable(platform_refund_expires_at)})')

    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        assert isinstance(platform_obfuscated_account_id, bytes)
        assert len(platform_obfuscated_account_id) == 32

        # NOTE: Insert IFF this (token, order_id) isn't already recorded.
        result_set = db.query(tx.conn, '''
            SELECT 1 FROM google_play_payment_details WHERE payment_token = %s AND order_id = %s
        ''', payment_tx.google_payment_token, payment_tx.google_order_id)

        record = result_set.fetchone()
        if not record:
            _insert_payment_row_tx(tx,
                payment = {
                    'plan':                       plan.value,
                    'payment_provider':           payment_tx.provider.value,
                    'expires_at':                 expires_at,
                    'platform_refund_expires_at': platform_refund_expires_at,
                    'purchased_at':               purchased_at,
                    'auto_renewing':              True,  # on by default until Google notifies otherwise
                    'refund_requested_at':        None,
                },
                detail_table = 'google_play_payment_details',
                detail = {
                    'payment_token':         payment_tx.google_payment_token,
                    'order_id':              payment_tx.google_order_id,
                    'obfuscated_account_id': platform_obfuscated_account_id,
                })

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        assert isinstance(platform_obfuscated_account_id, str)
        # NOTE: Insert IFF this apple payment isn't already recorded.
        #
        # For Apple each apple_tx_id is always unique.
        # apple_web_line_order_tx_id is unique for the payment of the billing
        # cycle for that subscription and the apple_original_tx_id is reused
        # across all subscriptions of the same type.
        result_set = db.query(tx.conn, '''
                SELECT 1 FROM app_store_payment_details WHERE original_tx_id = %(orig_tx_id)s AND tx_id = %(tx_id)s AND web_line_order_tx_id = %(line_order_tx_id)s
        ''', orig_tx_id=payment_tx.apple_original_tx_id,
              tx_id=payment_tx.apple_tx_id,
              line_order_tx_id=payment_tx.apple_web_line_order_tx_id)

        record = result_set.fetchone()
        if not record:
            _insert_payment_row_tx(tx,
                payment = {
                    'plan':                       plan.value,
                    'payment_provider':           payment_tx.provider.value,
                    'expires_at':                 expires_at,
                    'platform_refund_expires_at': platform_refund_expires_at,
                    'purchased_at':               purchased_at,
                    'auto_renewing':              True,  # on by default until Apple notifies otherwise
                    'refund_requested_at':        None,
                },
                detail_table = 'app_store_payment_details',
                detail = {
                    'original_tx_id':       payment_tx.apple_original_tx_id,
                    'tx_id':                payment_tx.apple_tx_id,
                    'web_line_order_tx_id': payment_tx.apple_web_line_order_tx_id,
                    'app_account_token':    platform_obfuscated_account_id,
                })
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        # NOTE: Insert IFF this rangeproof order id isn't already recorded.
        result_set = db.query(tx.conn, '''
                SELECT 1 FROM rangeproof_payment_details WHERE order_id = %s
        ''', payment_tx.rangeproof_order_id)

        record = result_set.fetchone()
        if not record:
            _insert_payment_row_tx(tx,
                payment = {
                    'plan':                       plan.value,
                    'payment_provider':           payment_tx.provider.value,
                    'expires_at':                 expires_at,
                    'platform_refund_expires_at': platform_refund_expires_at,
                    'purchased_at':               purchased_at,
                    'auto_renewing':              False,  # Rangeproof vouchers never auto-renew
                    'refund_requested_at':        None,
                },
                detail_table = 'rangeproof_payment_details',
                detail = {
                    'order_id': payment_tx.rangeproof_order_id,
                })

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
    result_set: db.Result | None = None
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        result_set = db.query(tx.conn, ('''
            SELECT   u.master_pkey
            FROM     payments p JOIN users u ON u.id = p.user_id
                     JOIN google_play_payment_details gd ON gd.payment_id = p.id
            WHERE    gd.payment_token = %s
            ORDER BY p.id DESC
            LIMIT    1
        '''), payment_tx.google_payment_token)
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        result_set = db.query(tx.conn, ('''
            SELECT   u.master_pkey
            FROM     payments p JOIN users u ON u.id = p.user_id
                     JOIN app_store_payment_details ad ON ad.payment_id = p.id
            WHERE    ad.original_tx_id = %s
            ORDER BY p.id DESC
            LIMIT    1
        '''), payment_tx.apple_original_tx_id)
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        # TODO: There is currently no auto-redeeming for Rangeproof payments. These are currently
        # granted to a user directly by creating a voucher payment attributed under their master pro
        # public key. It would be possible to incorporate some UI in the clients to allow redeeming
        # via an order ID. Rangeproof would then give the user the order ID that they have to redeem
        # in their client.
        pass

    if result_set:
        master_pkey_record = typing.cast(tuple[bytes] | None, result_set.fetchone())
        if master_pkey_record and master_pkey_record[0]:
            master_pkey   = nacl.signing.VerifyKey(bytes(master_pkey_record[0]))
            user: UserRow = get_user(tx.conn, master_pkey)
            if user.found:
                auto_redeem_deadline_at: int = 0

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
                        auto_redeem_deadline_at += datetime.timedelta(days=60) - user.grace_period
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
                    add_pro_payment_user_tx                      = UserPaymentTransaction()
                    add_pro_payment_user_tx.provider             = payment_tx.provider
                    add_pro_payment_user_tx.apple_tx_id          = payment_tx.apple_tx_id
                    add_pro_payment_user_tx.google_payment_token = payment_tx.google_payment_token
                    add_pro_payment_user_tx.google_order_id      = payment_tx.google_order_id

                    # A failed auto-redeem is swallowed: the user can still claim the payment manually
                    # later, and propagating the failure to the platform layers (google/apple) would stall
                    # them unnecessarily. The savepoint keeps a failed redeem from poisoning the outer
                    # transaction; we log it for internal visibility.
                    try:
                        with tx.conn.transaction():
                            _ = redeem_payment_tx(tx            = tx,
                                                  master_pkey   = master_pkey,
                                                  rotating_pkey = None,
                                                  signing_key   = None,
                                                  request_at    = purchased_at,
                                                  redeemed_at   = to_redeemed_at(purchased_at),
                                                  payment_tx    = add_pro_payment_user_tx)
                    except base.ApiError as e:
                        log.error(f'Failed to auto-redeem a payment we witnessed from. (auto_redeem_deadline={base.readable(auto_redeem_deadline_at)}) {e}')

def add_unredeemed_payment(conn:                              psycopg.Connection,
                           payment_tx:                        base.PaymentProviderTransaction,
                           plan:                              base.ProPlan,
                           expires_at:                 datetime.datetime,
                           purchased_at:             datetime.datetime,
                           platform_refund_expires_at: datetime.datetime,
                           platform_obfuscated_account_id:    bytes | str,
                           err:                               base.ErrorSink):
    with db.transaction(conn) as tx:
        add_unredeemed_payment_tx(tx                                = tx,
                                  payment_tx                        = payment_tx,
                                  plan                              = plan,
                                  expires_at                 = expires_at,
                                  purchased_at             = purchased_at,
                                  platform_refund_expires_at = platform_refund_expires_at,
                                  platform_obfuscated_account_id    = platform_obfuscated_account_id,
                                  err                               = err)

def mint_generation(tx: db.SQLTransaction, user_id: int, issued_at: datetime.datetime) -> tuple[int, bytes]:
    '''Insert a fresh generation (new random 32-byte token) for an existing user; returns
    (generation_id, token). Retries on a token-unique collision — astronomically unlikely for 32 CSPRNG
    bytes, but cheap insurance against a degraded RNG; each attempt is a savepoint so a collision can't
    poison the outer transaction.'''
    for _attempt in range(3):
        token = nacl.utils.random(BLAKE2B_DIGEST_SIZE)
        try:
            with tx.conn.transaction():
                row = db.query_one(tx.conn,
                                   "INSERT INTO generations (user_id, token, issued_at) VALUES (%s, %s, %s) RETURNING id",
                                   user_id, token, issued_at)
            assert row is not None
            return (row[0], token)
        except psycopg.errors.UniqueViolation:
            continue
    raise RuntimeError('mint_generation: exhausted token-collision retries (CSPRNG failure?)')

def get_or_create_user_and_generation(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, issued_at: datetime.datetime) -> tuple[int, int, bytes, bool]:
    '''Ensure a user row AND its first generation exist for master_pkey. Race-free via ON CONFLICT on the
    master_pkey unique index. Returns (user_id, current_generation_id, token, was_created). Must run inside
    a transaction (the circular users<->generations FK is deferred to COMMIT).'''
    master_pkey_bytes = bytes(master_pkey)

    # Common path: the user already exists — a plain read, no id/generation allocation burned.
    existing = get_user(tx.conn, master_pkey)
    if existing.found:
        return (existing.id, existing.current_generation_id, existing.token, False)

    # New user: pre-allocate both ids so the circular NOT NULL FKs are satisfied at insert time (the
    # deferred users->generations FK is validated at COMMIT). Insert the user first (ON CONFLICT arbitrates
    # a concurrent create), then the generation it points at. The expiry here is a placeholder overwritten
    # by _allocate… below.
    seq_row = db.query_one(tx.conn, "SELECT nextval(pg_get_serial_sequence('users','id')), nextval(pg_get_serial_sequence('generations','id'))")
    assert seq_row is not None
    user_id, gen_id = seq_row[0], seq_row[1]
    token           = nacl.utils.random(BLAKE2B_DIGEST_SIZE)
    won = db.query_one(tx.conn, '''
        INSERT INTO users (id, master_pkey, current_generation_id, expires_at)
        VALUES            (%(id)s, %(master_pkey)s, %(gen_id)s, to_timestamp(0))
        ON CONFLICT (master_pkey) DO NOTHING
        RETURNING id
    ''', id          = user_id,
         master_pkey = master_pkey_bytes,
         gen_id      = gen_id)
    if won is None:
        # Lost a concurrent create — re-read the winner (our pre-allocated ids simply go unused).
        winner = get_user(tx.conn, master_pkey)
        return (winner.id, winner.current_generation_id, winner.token, False)
    db.query(tx.conn, "INSERT INTO generations (id, user_id, token, issued_at) VALUES (%s, %s, %s, %s)",
             gen_id, user_id, token, issued_at)
    return (user_id, gen_id, token, True)

def _allocate_new_gen_id_if_master_pkey_has_payments(tx:          db.SQLTransaction,
                                                     master_pkey: nacl.signing.VerifyKey,
                                                     issued_at:   datetime.datetime) -> AllocatedGenID:
    # Refresh the user's top-level entitlement fields from their current best payment, and settle which
    # generation they're on. A generation is an EPOCH, not a per-payment value (item 3): REUSE the user's
    # current generation across payments — stacking, renewals, auto-redeem, natural-lapse reactivation — so
    # the revocation_tag stays stable (no per-payment revocation-list churn, no subscription-cadence leak).
    # Mint a FRESH generation only when the current one is REVOKED (reusing it would mint proofs born
    # already-revoked). The revoke path depends on exactly this: it sets revoked_at first, then calls here,
    # so it rolls onto a fresh generation. The user row must already exist (redeem creates it via
    # get_or_create_user_and_generation; revoke's user exists).
    result: AllocatedGenID = AllocatedGenID()
    lookup: LookupUserExpiry = _lookup_user_expiry_tx(tx, master_pkey)
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

    _ = db.query(tx.conn, '''
        UPDATE users
        SET    current_generation_id        = %(gen_id)s,
               expires_at                   = %(expiry)s,
               grace_period                 = %(grace)s,
               auto_renewing                = %(auto_renewing)s,
               refund_requested_at          = %(refund_ts)s
        WHERE  id = %(user_id)s
    ''', gen_id        = result.generation_id,
         user_id       = user.id,
         expiry        = lookup.best_expiry,
         grace         = lookup.best_grace,
         auto_renewing = lookup.best_auto_renewing,
         refund_ts     = lookup.best_refund_requested)
    result.grace_period = lookup.best_grace

    return result

def make_generate_pro_proof_message(master_pkey:   nacl.signing.VerifyKey,
                                    rotating_pkey: nacl.signing.VerifyKey,
                                    request_at:    datetime.datetime) -> bytes:
    '''The message the user signs to authorise a new rotating_pkey for master_pkey's Session Pro
    subscription.'''
    return signed_message(GENERATE_PROOF_DOMAIN, master_pkey, rotating_pkey, request_at)

def build_proof_message(revocation_tag: bytes,
                        rotating_pkey:  nacl.signing.VerifyKey,
                        expires_at:     datetime.datetime) -> bytes:
    '''The message the backend signs to certify a proof.'''
    return signed_message(BUILD_PROOF_DOMAIN, revocation_tag, rotating_pkey, expires_at)

def _build_proof_clamped_expiry_time(request_at: datetime.datetime, proposed_expires_at: datetime.datetime) -> datetime.datetime:
    # NOTE: Clamp the expiry time of the proof to 1 month and also make it land on the day boundary
    # to reduce metadata leakage. If it's less than 1 month then just take the value verbatim as
    # their subscription is coming to a close.
    clamped_expires_at = base.round_datetime_to_next_day(request_at + datetime.timedelta(days=30))
    result             = min(clamped_expires_at, proposed_expires_at)
    return result

def build_proof(revocation_tag: bytes,
                rotating_pkey:  nacl.signing.VerifyKey,
                expires_at:     datetime.datetime,
                signing_key:    nacl.signing.SigningKey) -> ProSubscriptionProof:
    # The revocation_tag is the generation's stored random token, embedded verbatim (no hashing).
    assert len(revocation_tag) == BLAKE2B_DIGEST_SIZE
    result: ProSubscriptionProof = ProSubscriptionProof()
    result.revocation_tag        = revocation_tag
    result.rotating_pkey         = rotating_pkey
    result.expires_at            = expires_at

    message: bytes = build_proof_message(revocation_tag = result.revocation_tag,
                                         rotating_pkey  = result.rotating_pkey,
                                         expires_at     = result.expires_at)
    result.sig = signing_key.sign(message).signature
    return result

def internal_verify_add_payment_and_get_proof_common_arguments(signing_key:   nacl.signing.SigningKey,
                                                               master_pkey:   nacl.signing.VerifyKey,
                                                               rotating_pkey: nacl.signing.VerifyKey,
                                                               message:       bytes,
                                                               master_sig:    bytes,
                                                               rotating_sig:  bytes) -> None:
    # Verify the signatures first (authenticate that the message was not tampered with) — if these fail,
    # the rest of the payload is indeterminate, so raising bad_signature short-circuits everything else.
    # `message` is the signed message (variable length; built by make_*_message), signed directly — no
    # pre-hash — so there's no fixed-size assert here.
    try:
        _ = master_pkey.verify(smessage=message, signature=master_sig)
    except Exception as e:
        raise base.FailError(f'Failed to verify signature from master key {base.maybe_obfuscate_bytes(master_pkey)}: {e}', code=base.ErrorCode.bad_signature)

    try:
        _ = rotating_pkey.verify(smessage=message, signature=rotating_sig)
    except Exception as e:
        raise base.FailError(f'Failed to verify signature from rotating key {base.maybe_obfuscate_bytes(rotating_pkey)}: {e}', code=base.ErrorCode.bad_signature)

    # Dev/config sanity checks (the signing key never leaves the backend).
    assert bytes(signing_key) != ZERO_BYTES32 and bytes(signing_key.verify_key) != ZERO_BYTES32

    # Sanity check the signing key — a backend misconfiguration, not the client's fault.
    if signing_key.verify_key == master_pkey or signing_key.verify_key == rotating_pkey:
        raise base.ServerError('Internal key error during adding payment: please notify the devs')

    # Sanity check the user's keys and signatures (client-supplied → their fault).
    if master_pkey == rotating_pkey:
        raise base.FailError(f'Master and rotating key cannot be the same was: {base.maybe_obfuscate_bytes(master_pkey)}')

    if bytes(master_pkey) == ZERO_BYTES32:
        raise base.FailError('Master key cannot be the zero key')

    if bytes(rotating_pkey) == ZERO_BYTES32:
        raise base.FailError('Rotating key cannot be the zero key')

    if master_sig == rotating_sig:
        raise base.FailError('Master and rotating signature cannot be the same')

def add_pro_payment_tx(tx:                  db.SQLTransaction,
                       signing_key:         nacl.signing.SigningKey,
                       request_at:          datetime.datetime,
                       redeemed_at: datetime.datetime,
                       master_pkey:         nacl.signing.VerifyKey,
                       rotating_pkey:       nacl.signing.VerifyKey,
                       payment_tx:          UserPaymentTransaction) -> RedeemPayment:

    # Note being able to pass in the creation unix timestamp is mainly for
    # testing purposes to allow time-travel. User space should never be
    # specifying this argument, so clients should not be specifying this time,
    # ever, it should be generated and rounded up by the server hence the
    # assert.
    assert redeemed_at == base.round_datetime_to_start_of_day(redeemed_at), \
            "The passed in creation (and or activated) timestamp must lie on a day boundary: {}".format(base.readable(redeemed_at))

    # Redeem the payment (raises FailError(unknown_payment)/revoked/expired on failure).
    result: RedeemPayment = redeem_payment_tx(tx            = tx,
                                              master_pkey   = master_pkey,
                                              rotating_pkey = rotating_pkey,
                                              signing_key   = signing_key,
                                              request_at    = request_at,
                                              redeemed_at   = redeemed_at,
                                              payment_tx    = payment_tx)

    # For Google we acknowledge the payment against Google's servers in the SAME transaction as the
    # redeem: an ack can't be undone, so we redeem first and ack last, and if Google can't be reached we
    # raise — the exception rolls the transaction back (undoing the redeem) and the client re-attempts.
    # Acknowledging on claim binds the client's knowledge of its own payment to the backend ack in one
    # step, avoiding a client-acks-but-server-hasn't poll race. (Under provider_dry_run these Google calls
    # are stubbed in platform_google_api — a synthetic already-acknowledged fetch + no-op acknowledge.)
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        # platform_google_api is still ErrorSink-based (the deferred sweep); bridge with a local sink and
        # translate its failure into a raise.
        google_err = base.ErrorSink()
        sub_data: platform_google_types.SubscriptionV2Data | None = platform_google_api.fetch_subscription_v2_details(package_name=platform_google_api.package_name,
                                                                                                                      purchase_token=payment_tx.google_payment_token,
                                                                                                                      err=google_err)
        if sub_data is None or google_err.has():
            raise base.ServerError(f'Google subscription lookup failed during redeem: {google_err.build()}')

        payment_tx_label = _add_pro_payment_user_tx_log_label_safe(payment_tx)
        log.info(f'Google ack. payment check (master={base.maybe_obfuscate_bytes(master_pkey)}, payment={payment_tx_label}, acked={sub_data.acknowledgement_state})')

        if sub_data.acknowledgement_state != platform_google_types.SubscriptionsV2AcknowledgementState.ACKNOWLEDGED:
            platform_google_api.subscription_v1_acknowledge(purchase_token=payment_tx.google_payment_token, err=google_err)
            if google_err.has():
                raise base.ServerError(f'Google subscription acknowledgement failed during redeem: {google_err.build()}')
    return result


def add_pro_payment(conn:                psycopg.Connection,
                    signing_key:         nacl.signing.SigningKey,
                    request_at:          datetime.datetime,
                    redeemed_at: datetime.datetime,
                    master_pkey:         nacl.signing.VerifyKey,
                    rotating_pkey:       nacl.signing.VerifyKey,
                    payment_tx:          UserPaymentTransaction) -> RedeemPayment:
    result = RedeemPayment()
    with db.transaction(conn) as tx:
        result = add_pro_payment_tx(tx,
                                     signing_key,
                                     request_at,
                                     redeemed_at,
                                     master_pkey,
                                     rotating_pkey,
                                     payment_tx)
    return result

def verify_and_add_pro_payment(conn:                psycopg.Connection,
                               signing_key:         nacl.signing.SigningKey,
                               request_at:          datetime.datetime,
                               redeemed_at: datetime.datetime,
                               master_pkey:         nacl.signing.VerifyKey,
                               rotating_pkey:       nacl.signing.VerifyKey,
                               payment_tx:          UserPaymentTransaction,
                               master_sig:          bytes,
                               rotating_sig:        bytes) -> RedeemPayment:
    """
    request_at: The timestamp typically accurate to the current time, used as a frame-of-reference
    to clamp the duration of the proof returned to the user to at most 1 month, also used to mask
    metadata about the type of subscription a user is currently using.

    redeemed_at: Timestamp to mark as the time in point in which the payment was redeemed.
    This timestamp is typically rounded up by using 'to_redeemed_at' to
    #mask metadata about the time the user redeemed the payment.
    """

    payment_tx_label = _add_pro_payment_user_tx_log_label_safe(payment_tx)
    log.info(f'Add payment (redeemed={base.readable(redeemed_at)}, master={base.maybe_obfuscate_bytes(master_pkey)}, payment={payment_tx_label})')

    # Authenticate the request (raises FailError(bad_signature) / invalid_request on failure).
    message: bytes = make_add_pro_payment_message(master_pkey   = master_pkey,
                                                    rotating_pkey = rotating_pkey,
                                                    payment_tx    = payment_tx)
    internal_verify_add_payment_and_get_proof_common_arguments(signing_key   = signing_key,
                                                               master_pkey   = master_pkey,
                                                               rotating_pkey = rotating_pkey,
                                                               message       = message,
                                                               master_sig    = master_sig,
                                                               rotating_sig  = rotating_sig)

    return add_pro_payment(conn,
                           signing_key,
                           request_at,
                           redeemed_at,
                           master_pkey,
                           rotating_pkey,
                           payment_tx)

def revoke_master_pkey_proofs_and_allocate_new_gen_id_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, created_at: datetime.datetime) -> AllocatedGenID:
    # Revoke the user's current generation (terminal): sets revoked_at, which blocks every proof issued
    # under that generation and (via the trigger) bumps the revocation ticket. The `revoked_at IS NULL`
    # guard makes a double-revoke a no-op rather than tripping the terminal-immutability trigger.
    _ = db.query(tx.conn, '''
        UPDATE generations
        SET    revoked_at = %(created_at)s
        WHERE  id = (SELECT current_generation_id FROM users WHERE master_pkey = %(master_pkey)s)
          AND  revoked_at IS NULL
    ''', master_pkey = bytes(master_pkey),
         created_at  = created_at)

    # If the user still has usable payments, roll them onto a fresh generation for subsequent proofs.
    # Clients see the old generation revoked (via the revocation list) and re-query for a new proof.
    result = _allocate_new_gen_id_if_master_pkey_has_payments(tx, master_pkey, issued_at=created_at)
    return result

def round_datetime_to_next_day_with_platform_testing_support(payment_provider: base.PaymentProvider, at: datetime.datetime) -> datetime.datetime:
    """Round `at` up to the next day boundary. In some platforms' testing environments a "day" is
    compressed (Google: 10 seconds); only that case differs from the normal UTC-day rounding."""
    if base.PLATFORM_TESTING_ENV and payment_provider == base.PaymentProvider.GooglePlayStore:
        google_day = datetime.timedelta(seconds=10)          # in Google's test env, 1 day == 10s
        elapsed    = at - base.EPOCH
        units      = -((-elapsed) // google_day)             # ceil-divide the timedelta
        return base.EPOCH + units * google_day
    return base.round_datetime_to_next_day(at)

def build_current_entitlement_proof_tx(tx:            db.SQLTransaction,
                                       master_pkey:   nacl.signing.VerifyKey,
                                       rotating_pkey: nacl.signing.VerifyKey,
                                       request_at:    datetime.datetime,
                                       signing_key:   nacl.signing.SigningKey) -> ProSubscriptionProof:
    '''Sign a proof for the user's CURRENT entitlement using their existing generation token (NO roll).
    Shared by generate_pro_proof and the idempotent add_pro_payment replay path. Raises a FailError with
    the matching slug when there is nothing to sign: `not_subscribed` (no user row), `revoked` (current
    generation revoked), `expired` (entitlement lapsed past the clamped proof window).'''
    get_user = get_user_and_payments(tx, master_pkey)
    if get_user.user.master_pkey != bytes(master_pkey):
        raise base.FailError(f'User {bytes(master_pkey).hex()} does not have an active payment registered for it',
                             code=base.ErrorCode.not_subscribed)

    if is_generation_revoked(tx.conn, get_user.user.current_generation_id, request_at):
        raise base.FailError(f'User {bytes(master_pkey).hex()} payment has been revoked', code=base.ErrorCode.revoked)

    proof_expires_at = _build_proof_clamped_expiry_time(request_at=request_at, proposed_expires_at=get_user.user.expires_at)
    if request_at > proof_expires_at:
        payment_expires_at = get_user.user.expires_at - get_user.user.grace_period if get_user.user.auto_renewing else get_user.user.expires_at
        raise base.FailError(f'User {bytes(master_pkey).hex()} entitlement expired at {base.readable(get_user.user.expires_at)} ({base.readable(payment_expires_at)} + {get_user.user.grace_period})',
                             code=base.ErrorCode.subscription_expired)

    return build_proof(revocation_tag = get_user.user.token,
                       rotating_pkey  = rotating_pkey,
                       expires_at     = proof_expires_at,
                       signing_key    = signing_key)

def generate_pro_proof(conn: psycopg.Connection,
                       signing_key:    nacl.signing.SigningKey,
                       master_pkey:    nacl.signing.VerifyKey,
                       rotating_pkey:  nacl.signing.VerifyKey,
                       request_at:     datetime.datetime,
                       master_sig:     bytes,
                       rotating_sig:   bytes) -> ProSubscriptionProof:
    log.info(f'Get pro proof (master={base.maybe_obfuscate_bytes(master_pkey)}, ts={base.readable(request_at)})')

    # Authenticate the request (raises FailError(bad_signature) / invalid_request on failure).
    message: bytes = make_generate_pro_proof_message(master_pkey   = master_pkey,
                                                       rotating_pkey = rotating_pkey,
                                                       request_at    = request_at)
    internal_verify_add_payment_and_get_proof_common_arguments(signing_key   = signing_key,
                                                               master_pkey   = master_pkey,
                                                               rotating_pkey = rotating_pkey,
                                                               message       = message,
                                                               master_sig    = master_sig,
                                                               rotating_sig  = rotating_sig)

    with db.transaction(conn) as tx:
        return build_current_entitlement_proof_tx(tx, master_pkey, rotating_pkey, request_at, signing_key)

def expire_payments_revocations_and_users(conn: psycopg.Connection, now: datetime.datetime) -> ExpireResult:
    # Pure idempotent housekeeping: prune rows whose expiry has passed (and orphaned users). Nothing
    # here affects live results — payment expiry is derived on read, and every consuming query
    # self-guards on expiry (e.g. is_generation_revoked) — so this can run on any schedule, any number
    # of times, in any process, and only ever frees storage. Hence no `last_expire` checkpoint /
    # windowing / cross-process "only one wins" guard: a redundant run simply deletes nothing.
    result = ExpireResult()
    with db.transaction(conn) as tx:
        # A revocation is generations.revoked_at, and generations are entitlement history (FK'd from
        # users.current_generation_id), so they aren't deleted here — the served revocation list filters
        # by retain_for instead. (Safely pruning ancient, unreferenced revoked generations is a later item.)
        users_result  = db.query(tx.conn, '''DELETE FROM users WHERE id NOT IN (SELECT user_id FROM payments WHERE user_id IS NOT NULL)''')
        apple_result  = db.query(tx.conn, '''DELETE FROM apple_notification_uuid_history WHERE %s >= expires_at''', now)
        google_result = db.query(tx.conn, '''DELETE FROM google_notification_history WHERE %s >= expires_at AND handled = TRUE''', now)
        result.revocations                     = 0
        result.users                           = users_result.rowcount
        result.apple_notification_uuid_history = apple_result.rowcount
        result.google_notification_history     = google_result.rowcount
        result.success                         = True
    return result

def add_user_error_tx(tx: db.SQLTransaction, error: UserError, at: datetime.datetime):
    match error.provider:
        case base.PaymentProvider.Rangeproof:
            pass
        case base.PaymentProvider.Nil:
            pass
        case base.PaymentProvider.GooglePlayStore:
            assert len(error.google_payment_token) > 0
            _ = db.query(tx.conn, '''INSERT INTO user_errors (payment_provider, payment_id, errored_at) VALUES (%(provider)s, %(payment_id)s, %(ts)s) ON CONFLICT DO NOTHING''',
                 provider=int(error.provider.value),
                 payment_id=error.google_payment_token,
                 ts=at)
        case base.PaymentProvider.iOSAppStore:
            assert len(error.apple_original_tx_id) > 0
            _ = db.query(tx.conn, '''INSERT INTO user_errors (payment_provider, payment_id, errored_at) VALUES (%(provider)s, %(payment_id)s, %(ts)s) ON CONFLICT DO NOTHING''',
                 provider=int(error.provider.value),
                 payment_id=error.apple_original_tx_id,
                 ts=at)

def add_user_error(conn: psycopg.Connection, error: UserError, at: datetime.datetime):
    assert error.provider != base.PaymentProvider.Nil
    with db.transaction(conn) as tx:
        add_user_error_tx(tx, error, at)

def has_user_error_from_master_pkey_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> bool:
    # NOTE: Rangeproof payments cannot have user errors
    return bool(db.query_scalar(tx.conn, (f'''
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
'''), bytes(master_pkey)))

def has_user_error(conn: psycopg.Connection, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    # Single SELECT on the given connection (mid-tx callers pass tx.conn). payment_provider is a string
    # code (item 9) — compared directly, NOT int()-cast (that was a latent crash on the CLI path).
    row = db.query_one(conn,
                       'SELECT 1 FROM user_errors WHERE payment_id = %s AND payment_provider = %s',
                       payment_id,
                       payment_provider.value)
    return row is not None

def delete_user_errors_tx(tx: db.SQLTransaction, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    row    = db.query(tx.conn, 'DELETE FROM user_errors WHERE payment_provider = %s AND payment_id = %s', payment_provider.value, payment_id)
    result = row.rowcount > 0
    return result

def delete_user_errors(conn: psycopg.Connection, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    result = False
    with db.transaction(conn) as tx:
        result = delete_user_errors_tx(tx, payment_provider, payment_id)
    return result

def get_payment_tx(tx:          db.SQLTransaction,
                   payment_tx:  base.PaymentProviderTransaction,
                   err:         base.ErrorSink) -> PaymentRow | None:
    result = None
    verify_payment_provider_tx(payment_tx, err)
    if err.has():
        return result

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        result_set = db.query(tx.conn, f'''
            SELECT {PAYMENTS_COLUMNS}
            FROM {PAYMENTS_FROM}
            WHERE gd.payment_token = %(token)s AND gd.order_id = %(order_id)s
        ''', token    = payment_tx.google_payment_token,
              order_id = payment_tx.google_order_id, row_factory=db.dict_row)

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        result_set = db.query(tx.conn, f'''
                SELECT {PAYMENTS_COLUMNS}
                FROM {PAYMENTS_FROM}
                WHERE ad.original_tx_id = %(orig_tx_id)s AND ad.tx_id = %(tx_id)s AND ad.web_line_order_tx_id = %(line_order_tx_id)s
        ''', orig_tx_id       = payment_tx.apple_original_tx_id,
              tx_id            = payment_tx.apple_tx_id,
              line_order_tx_id = payment_tx.apple_web_line_order_tx_id, row_factory=db.dict_row)

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        result_set = db.query(tx.conn, f'''
                SELECT {PAYMENTS_COLUMNS}
                FROM {PAYMENTS_FROM}
                WHERE rd.order_id = %s
        ''', payment_tx.rangeproof_order_id, row_factory=db.dict_row)

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)

    return result

def get_payment(conn: psycopg.Connection,
                payment_tx: base.PaymentProviderTransaction,
                err:        base.ErrorSink) -> PaymentRow | None:
    with db.transaction(conn) as tx:
        return get_payment_tx(tx=tx,
                              payment_tx=payment_tx,
                              err=err)

def set_refund_requested_tx(tx: db.SQLTransaction, payment_tx: UserPaymentTransaction, refund_requested_at: datetime.datetime | None) -> bool:
    rows: db.Result | None = None
    if payment_tx.provider == base.PaymentProvider.Rangeproof or payment_tx.provider == base.PaymentProvider.Nil:
        return False

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        rows = db.query(tx.conn, '''
            UPDATE payments
            SET    refund_requested_at = %(ts)s
            WHERE  id IN (SELECT payment_id FROM google_play_payment_details WHERE payment_token = %(token)s AND order_id = %(order_id)s)
        ''', ts        = refund_requested_at,
            token    = payment_tx.google_payment_token,
            order_id = payment_tx.google_order_id)
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        rows = db.query(tx.conn, '''
            UPDATE payments
            SET    refund_requested_at = %(ts)s
            WHERE  id IN (SELECT payment_id FROM app_store_payment_details WHERE tx_id = %(tx_id)s)
        ''', ts        = refund_requested_at,
              tx_id    = payment_tx.apple_tx_id)

    assert rows and (rows.rowcount == 0 or rows.rowcount == 1)
    success = rows.rowcount > 0

    # If the refund timestamp has been set, immediately refresh the user's row.
    #
    # When a client hits /get_pro_details, that endpoint uses the user's row which caches the
    # "best" payment that should be used to entitle a user to pro. Hence if their refund
    # timestamp changes for that best payment, that metadata that is cached in the user details
    # must be updated.
    if success:
        row = None
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            row = db.query_one(tx.conn, '''
                SELECT u.master_pkey
                FROM   payments p JOIN users u ON u.id = p.user_id
                       JOIN google_play_payment_details gd ON gd.payment_id = p.id
                WHERE  gd.payment_token = %(token)s AND gd.order_id = %(order_id)s
            ''', token    = payment_tx.google_payment_token,
                 order_id = payment_tx.google_order_id)
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            row = db.query_one(tx.conn, '''
                SELECT u.master_pkey
                FROM   payments p JOIN users u ON u.id = p.user_id
                       JOIN app_store_payment_details ad ON ad.payment_id = p.id
                WHERE  ad.tx_id = %s
            ''', payment_tx.apple_tx_id)

        if row:
            master_pkey = nacl.signing.VerifyKey(bytes(row[0]))
            _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx, master_pkey)

    return success

def set_refund_requested(conn: psycopg.Connection,
                                    payment_tx: UserPaymentTransaction,
                                    refund_requested_at: datetime.datetime | None) -> bool:
    result = False
    with db.transaction(conn) as tx:
        result = set_refund_requested_tx(tx, payment_tx, refund_requested_at)
    return result

def apple_add_notification_uuid_tx(tx: db.SQLTransaction, uuid: str, expires_at: datetime.datetime):
    # uuid is the PRIMARY KEY; DO NOTHING keeps this idempotent (and crash-free) if the caller's
    # prior existence check raced with a concurrent insert of the same notification.
    _ = db.query(tx.conn, ('''
        INSERT INTO apple_notification_uuid_history (uuid, expires_at)
        VALUES      (%s, %s)
        ON CONFLICT (uuid) DO NOTHING
    '''), uuid, expires_at)

def apple_notification_uuid_is_in_db_tx(tx: db.SQLTransaction, uuid: str) -> bool:
    row = db.query_one(tx.conn, ('''
        SELECT 1
        FROM   apple_notification_uuid_history
        WHERE  uuid = %s
    '''), uuid)
    result = row is not None
    return result

def apple_set_notification_checkpoint_at(tx: db.SQLTransaction, checkpoint_at: datetime.datetime):
    set_global_datetime(tx.conn, 'apple_notification_checkpoint_at', checkpoint_at)

def google_add_notification_id_tx(tx: db.SQLTransaction, message_id: str, expires_at: datetime.datetime, payload: str):
    maybe_payload: str | None = None
    if len(payload):
        maybe_payload = payload

    _ = db.query(tx.conn, ('''
            INSERT INTO google_notification_history (message_id, handled, payload, expires_at)
            VALUES      (%(message_id)s, FALSE, %(payload)s, %(expiry)s)
    '''), message_id = message_id,
          payload    = maybe_payload,
          expiry     = expires_at)

def google_set_notification_handled(tx: db.SQLTransaction, message_id: str, delete: bool) -> bool:
    if delete:
        rows = db.query(tx.conn, ('''DELETE FROM google_notification_history WHERE message_id = %s'''), message_id)
    else:
        rows = db.query(tx.conn, ('''UPDATE google_notification_history SET handled = TRUE, payload = NULL WHERE message_id = %s'''), message_id)
    result: bool = rows.rowcount >= 1
    return result

def google_get_unhandled_notification_iterator(tx: db.SQLTransaction) -> collections.abc.Iterator[GoogleUnhandledNotificationIterator]:
    result_set = db.query(tx.conn, ('SELECT message_id, payload, expires_at FROM google_notification_history WHERE NOT handled'))
    return typing.cast(collections.abc.Iterator[GoogleUnhandledNotificationIterator], result_set)

def google_notification_message_id_is_in_db_tx(tx: db.SQLTransaction, message_id: str) -> GoogleNotificationMessageIDInDB:
    row    = typing.cast(tuple[int] | None, db.query_one(tx.conn, '''SELECT handled FROM google_notification_history WHERE message_id = %s''', message_id))
    result = GoogleNotificationMessageIDInDB()
    if row is not None:
        result.present = True
        result.handled = row[0] > 0 # NOTE: Should always be 0 or 1 but we'll be extra careful
    return result

def _get_date_group_expr_sql(column: str, period: ReportPeriod) -> str:
    """Group a `timestamptz` column into a UTC calendar-period label."""
    utc = f"({column} AT TIME ZONE 'UTC')"   # timestamptz → UTC wall-clock, so buckets are UTC-stable
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
        return f"((DATE_TRUNC('month', '{period_str}-01'::timestamp) AT TIME ZONE 'UTC') + INTERVAL '1 month' - INTERVAL '1 microsecond')"
    else:
        return f"(('{period_str}'::timestamp AT TIME ZONE 'UTC') + INTERVAL '1 day' - INTERVAL '1 microsecond')"

def _format_period_label(period_str: str, period: ReportPeriod) -> str:
    """Format period string for display."""
    if period == ReportPeriod.Weekly:
        year, week = period_str.split("-")
        date = datetime.datetime.fromisocalendar(year=int(year), week=int(week), day=1)
        return date.strftime('%F') + f' (W{week})'
    return period_str

def generate_report_rows(conn: psycopg.Connection, period: ReportPeriod, limit: int | None) -> list[ReportRow]:
    def fetch_counts(tx_conn: psycopg.Connection, period: ReportPeriod, date_column: str, where_clause: str) -> dict[str, int]:
        group_by_expr = _get_date_group_expr_sql(date_column, period)

        result_set = db.query(tx_conn, f"""
            SELECT {group_by_expr} AS period, COUNT(*) AS count
            FROM payments
            WHERE {where_clause}
            GROUP BY period
            ORDER BY period DESC
        """)

        result: dict[str, int] = {}
        for row in result_set:
            period_label = _format_period_label(row[0], period)
            result[period_label] = row[1]
        return result

    def fetch_active_users(tx_conn: psycopg.Connection, period: ReportPeriod) -> dict[str, int]:
        date_expr = _get_date_group_expr_sql("purchased_at", period)

        result_set = db.query(tx_conn, f"""
            SELECT DISTINCT {date_expr} AS period
            FROM payments
        """)
        periods_list = [row[0] for row in result_set]
        result: dict[str, int] = {}

        for it in periods_list:
            assert isinstance(it, str)
            end_ts = _get_period_end_ts_sql(it, period)

            result_set = db.query(tx_conn, f"""
                SELECT COUNT(DISTINCT user_id) AS active
                FROM payments
                WHERE {end_ts} >= purchased_at
                  AND {end_ts} <= expires_at
                  AND revoked_at IS NULL
            """)

            count        = result_set.fetchone()[0] or 0
            period_label = _format_period_label(it, period)
            result[period_label] = count

        return result

    result: list[ReportRow] = []
    with db.transaction(conn) as tx:
        unredeemed: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "purchased_at",
            where_clause      = "redeemed_at IS NULL AND revoked_at IS NULL",
        )

        plan_1m: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "purchased_at",
            where_clause      = f"plan = '{base.ProPlan.OneMonth.value}'",
        )

        plan_3m: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "purchased_at",
            where_clause      = f"plan = '{base.ProPlan.ThreeMonth.value}'",
        )

        plan_12m: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "purchased_at",
            where_clause      = f"plan = '{base.ProPlan.TwelveMonth.value}'",
        )

        google: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "purchased_at",
            where_clause      = f"payment_provider = '{base.PaymentProvider.GooglePlayStore.value}'",
        )

        apple: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "purchased_at",
            where_clause      = f"payment_provider = '{base.PaymentProvider.iOSAppStore.value}'",
        )

        rangeproof: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "purchased_at",
            where_clause      = f"payment_provider = '{base.PaymentProvider.Rangeproof.value}'",
        )

        new_subs: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "purchased_at",
            where_clause      = "purchased_at IS NOT NULL",
        )

        refunds_initiated: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "refund_requested_at",
            where_clause      = "refund_requested_at IS NOT NULL",
        )

        revocations: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "revoked_at",
            where_clause      = "revoked_at IS NOT NULL",
        )

        cancelled: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            date_column = "expires_at",
            where_clause      = f"NOT auto_renewing AND revoked_at IS NULL",
        )

        active_users: dict[str, int] = fetch_active_users(tx.conn, period)

        all_periods: set[str] = set()
        for key_list in [new_subs.keys(), refunds_initiated.keys(), revocations.keys(), cancelled.keys(), active_users.keys()]:
            for it in key_list:
                all_periods.add(it)

        sorted_periods: list[str] = sorted(all_periods, reverse=True)[:limit]
        for it in sorted_periods:
            result.append(ReportRow(
                period            = it,
                active_users      = active_users.get(it, 0),
                unredeemed        = unredeemed.get(it, 0),
                new_subs          = new_subs.get(it, 0),
                google            = google.get(it, 0),
                apple             = apple.get(it, 0),
                rangeproof        = rangeproof.get(it, 0),
                plan_1m           = plan_1m.get(it, 0),
                plan_3m           = plan_3m.get(it, 0),
                plan_12m          = plan_12m.get(it, 0),
                refunds_initiated = refunds_initiated.get(it, 0),
                revoked           = revocations.get(it, 0),
                cancelled         = cancelled.get(it, 0),
            ))

    return result

def generate_report_str(period: ReportPeriod, data: list[ReportRow], type: ReportType) -> str:
    @dataclasses.dataclass(frozen=True)
    class Section:
        name:       str
        width:      int
        align_left: bool = False

    sections: list[Section] = [
        Section("Period",            16, align_left=True),
        Section("Active Users",      14),
        Section("Unredeemed",        12),
        Section("New Subs",          10),
        Section("Google",            8),
        Section("Apple",             7),
        Section("Rangeproof",        12),
        Section("Plan 1m",           10),
        Section("Plan 3m",           10),
        Section("Plan 12m",          10),
        Section("Refunds Initiated", 20),
        Section("Revoked",           10),
        Section("Cancelling",        12),
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
                part_section           = sections[len(human_parts)]
                padding                = part_section.width
                align                  = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.period:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.active_users:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.unredeemed:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.new_subs:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.google:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.apple:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.rangeproof:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_1m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_3m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.plan_12m:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.refunds_initiated:20}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
                human_parts.append(f"{row.revoked:{align}{padding}}")

                part_section = sections[len(human_parts)]
                padding      = part_section.width
                align        = '<' if part_section.align_left else '>'
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
                    row.refunds_initiated,
                    row.revoked,
                    row.cancelled,
                ]
                assert len(csv_parts) == len(sections)
                writer.writerow(csv_parts)
            result = output.getvalue().strip()
    return result
