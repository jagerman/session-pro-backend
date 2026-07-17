import traceback
import nacl.signing
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
GENERATE_PROOF_HASH_PERSONALISATION               = b'ProGenerateProof'
BUILD_PROOF_HASH_PERSONALISATION                  = b'ProProof________'
ADD_PRO_PAYMENT_HASH_PERSONALISATION              = b'ProAddPayment___'
SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION = b'ProSetRefundReq_'
GET_PRO_DETAILS_HASH_PERSONALISATION              = b'ProGetProDetReq_'
assert len(GENERATE_PROOF_HASH_PERSONALISATION)               == hashlib.blake2b.PERSON_SIZE
assert len(BUILD_PROOF_HASH_PERSONALISATION)                  == hashlib.blake2b.PERSON_SIZE
assert len(ADD_PRO_PAYMENT_HASH_PERSONALISATION)              == hashlib.blake2b.PERSON_SIZE
assert len(SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION) == hashlib.blake2b.PERSON_SIZE
assert len(GET_PRO_DETAILS_HASH_PERSONALISATION)              == hashlib.blake2b.PERSON_SIZE

# Explicit column list for payments table queries. Rows are read with `db.dict_row` and unpacked by
# name in `payment_row_from_dict`, so order here is cosmetic (no positional coupling).
# `master_pkey` lives only in `users` now, so payments reads come from `PAYMENTS_FROM` (payments LEFT
# JOIN users) and pull the pkey from the joined users row — NULL for an unredeemed payment (user_id
# NULL), exactly as the per-row column used to be.
PAYMENTS_COLUMNS = (
    "p.id, u.master_pkey, p.plan, p.payment_provider, p.auto_renewing, "
    "p.unredeemed_unix_ts_ms, p.redeemed_unix_ts_ms, p.expiry_unix_ts_ms, "
    "p.grace_period_duration_ms, p.platform_refund_expiry_unix_ts_ms, p.revoked_unix_ts_ms, "
    "p.apple_original_tx_id, p.apple_tx_id, p.apple_web_line_order_tx_id, "
    "p.google_payment_token, p.google_order_id, p.rangeproof_order_id, "
    "p.refund_requested_unix_ts_ms, p.google_obfuscated_account_id, p.apple_app_account_token"
)
PAYMENTS_FROM = "payments p LEFT JOIN users u ON u.id = p.user_id"

# payments.payment_provider / .plan and user_errors.payment_provider store the string `code` directly
# (the lookup tables payment_providers/pro_plans use the code as their PRIMARY KEY, FK'd for validity).
# So there's no id indirection: the enum's `.value` IS the stored value, and reads map it straight back
# via base.PaymentProvider(...)/base.ProPlan(...).

@dataclasses.dataclass
class DevAddProPaymentArgs:
    plan:          base.ProPlan = base.ProPlan.OneMonth
    duration_ms:   int          = base.MILLISECONDS_IN_DAY
    auto_renewing: bool         = False

class SetRevocationResult(enum.StrEnum):
    UserDoesNotExist = 'User does not exist'
    Skipped          = 'Skipped'
    Updated          = 'Updated'
    Created          = 'Created'
    Deleted          = 'Deleted'

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
    already_done_by_someone_else:    bool = False
    success:                         bool = False
    payments:                        int  = 0
    revocations:                     int  = 0
    users:                           int  = 0
    apple_notification_uuid_history: int  = 0
    google_notification_history:     int  = 0

@dataclasses.dataclass
class ProSubscriptionProof:
    version:           int                    = 0
    gen_index_hash:    bytes                  = b''
    rotating_pkey:     nacl.signing.VerifyKey = nacl.signing.VerifyKey(ZERO_BYTES32)
    expiry_unix_ts_ms: int                    = 0
    sig:               bytes                  = b''

    def to_dict(self) -> dict[str, str | int]:
        result = {
            "version":           self.version,
            "gen_index_hash":    self.gen_index_hash.hex(),
            "rotating_pkey":     bytes(self.rotating_pkey).hex(),
            "expiry_unix_ts_ms": self.expiry_unix_ts_ms,
            "sig":               self.sig.hex(),
        }
        return result

@dataclasses.dataclass
class LookupUserExpiryUnixTsMs:
    expiry_unix_ts_ms_from_redeemed:                     int  = 0
    grace_duration_ms_from_redeemed:                     int  = 0
    refund_requested_unix_ts_ms_from_redeemed:           int  = 0
    auto_renewing_from_redeemed:                         bool = False

    best_expiry_unix_ts_ms:                              int  = 0
    best_grace_duration_ms:                              int  = 0
    best_refund_requested_unix_ts_ms:                    int  = 0
    best_auto_renewing:                                  bool = False

class RedeemPaymentStatus(enum.Enum):
    Nil             = 0
    Error           = 1
    Success         = 2
    AlreadyRedeemed = 3
    UnknownPayment  = 4

@dataclasses.dataclass
class RedeemPayment:
    proof:  ProSubscriptionProof = dataclasses.field(default_factory=ProSubscriptionProof)
    status: RedeemPaymentStatus  = RedeemPaymentStatus.Nil

AddRevocationIterator:               typing.TypeAlias = tuple[int,          # (row) id
                                                              bytes | None, # master_pkey
                                                              int]          # expiry_unix_ts_ms

GoogleUnhandledNotificationIterator: typing.TypeAlias = tuple[int,        # message_id
                                                              str | None, # payload
                                                              int]        # expiry_unix_ts_ms

UserRowTuple:                        typing.TypeAlias = tuple[bytes, # master_pkey
                                                              int,   # gen_index
                                                              int,   # expiry_unix_ts_ms
                                                              int,   # grace_period_duration_ms
                                                              int,   # auto_renewing
                                                              int,   # refund_requested_unix_ts_ms
                                                              bytes, # google_obfuscated_account_id
                                                              str,   # apple_app_account_token
                                                             ]

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

@dataclasses.dataclass
class AppleTransaction:
    original_tx_id:       str = ''
    tx_id:                str = ''
    web_line_order_tx_id: str = ''

@dataclasses.dataclass
class PaymentRow:
    id:                                 int                  = 0
    master_pkey:                        bytes | None         = None
    # No stored `status`: derive it from the timestamps below via backend.derive_payment_status(row, now).
    plan:                               base.ProPlan         = base.ProPlan.Nil
    payment_provider:                   base.PaymentProvider = base.PaymentProvider.Nil
    auto_renewing:                      bool                 = False
    unredeemed_unix_ts_ms:              int                  = 0
    redeemed_unix_ts_ms:                int | None           = None
    expiry_unix_ts_ms:                  int                  = 0
    grace_period_duration_ms:           int                  = 0
    platform_refund_expiry_unix_ts_ms:  int                  = 0
    revoked_unix_ts_ms:                 int | None           = None
    apple:                              AppleTransaction     = dataclasses.field(default_factory=AppleTransaction)
    google_payment_token:               str                  = ''
    google_order_id:                    str                  = ''
    refund_requested_unix_ts_ms:        int                  = 0
    rangeproof_order_id:                str                  = ''
    google_obfuscated_account_id:       bytes                = b''
    apple_app_account_token:            str                  = ''

@dataclasses.dataclass
class UserRow:
    found:                        bool  = False
    master_pkey:                  bytes = ZERO_BYTES32
    gen_index:                    int   = 0
    expiry_unix_ts_ms:            int   = 0
    grace_period_duration_ms:     int   = 0
    auto_renewing:                bool  = False
    refund_requested_unix_ts_ms:  int   = 0
    google_obfuscated_account_id: bytes = b''
    apple_app_account_token:      str   = ''

@dataclasses.dataclass
class GetUserAndPayments:
    payments_it:    db.Result
    user:           UserRow = dataclasses.field(default_factory=UserRow)
    payments_count: int     = 0

@dataclasses.dataclass
class RevocationRow:
    gen_index:            int   = 0
    creation_unix_ts_ms:  int   = 0
    expiry_unix_ts_ms:    int   = 0

@dataclasses.dataclass
class RevocationItem:
    '''A revocation object that has only the fields necessary for clients to block Session Pro
    subscription proofs.'''
    gen_index_hash:    bytes = b''
    expiry_unix_ts_ms: int   = 0

@dataclasses.dataclass
class RuntimeRow:
    '''The runtime table stores some metadata used for book-keeping and operations of the DB tables

    gen_index - Generation index, an index that is allocated to a user everytime a payment is added
    or removed from that user. It's monotonically increasing and shared across all users and their
    allocated index is what gets signed when Session Pro subscription proofs are generated for
    a particular user.

    Multiple proofs can be generated for a given index until a new payment is added or revoked for
    that user. A generation index can hence be revoked, thereby revoking all the proofs attributable
    to the associated user that were previously signed with the generation index to be revoked.

    gen_index_salt - The generation index gets signed after it has been hashed with this particular
    salt. This prevents leakage of metadata from the generation index which starts from 0 and counts
    upwards. The raw generation index leaks the timeframe relative to the lifetime of the protocol
    that a Session Pro subscription unredeemedd.

    The salt gets bootstrapped on creation of the DB and is stored to persist across sessions.

    revocation_ticket - A monotonically increasing index that gets incremented everytime the
    revocation table has a row added or deleted (i.e. a new ticket is allocated when the table
    changes). This ticket's purpose is to be handed out to clients when they request the revocation
    list. The client can then use this ticket to short-circuit the retrieval of the revocation list
    by comparing the current revocation list ticket with their cached ticket.

    If the tickets are the same, clients can conclude that there are no revocation entries to sync
    from the database.
    '''
    gen_index:                                int                     = 0
    gen_index_salt:                           bytes                   = b''
    last_expire_unix_ts_ms:                   int                     = 0
    apple_notification_checkpoint_unix_ts_ms: int                     = 0
    revocation_ticket:                        int                     = 0

@dataclasses.dataclass
class AllocatedGenID:
    found:             bool  = False
    expiry_unix_ts_ms: int   = 0
    grace_unix_ts_ms:  int   = 0
    gen_index:         int   = 0
    gen_index_salt:    bytes = b''

def assert_backend_is_in_dev_mode(signing_key: nacl.signing.SigningKey):
    assert bytes(signing_key) == base.DEV_BACKEND_DETERMINISTIC_SKEY, \
            "Sanity check failed, developer mode was enabled but the loaded signing key is not the development key. This is a special guard to prevent the user from activating developer mode in the wrong environment"

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

def convert_unix_ts_ms_to_redeemed_unix_ts_ms(unix_ts_ms: int):
    result: int = 0
    if base.DEV_BACKEND_MODE:
        result = unix_ts_ms
    else:
        result = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
    return result

def make_blake2b_hasher(personalisation: bytes, salt: bytes | None = None) -> hashlib.blake2b:
    final_salt      = salt  if salt else b''
    result          = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE, person=personalisation, salt=final_salt)
    return result

def make_gen_index_hash(gen_index: int, gen_index_salt: bytes) -> bytes:
    assert len(gen_index_salt) == hashlib.blake2b.SALT_SIZE
    hasher = make_blake2b_hasher(personalisation=b'', salt=gen_index_salt)
    hasher.update(gen_index.to_bytes(length=8, byteorder='little'))
    result = hasher.digest()
    return result

def make_add_pro_payment_hash(version:       int,
                              master_pkey:   nacl.signing.VerifyKey,
                              rotating_pkey: nacl.signing.VerifyKey,
                              payment_tx:    UserPaymentTransaction) -> bytes:
    hasher: hashlib.blake2b = make_blake2b_hasher(personalisation=ADD_PRO_PAYMENT_HASH_PERSONALISATION)
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_pkey))
    hasher.update(bytes(rotating_pkey))

    hasher.update(payment_tx.provider.value.encode('utf-8'))  # provider_code, UTF-8, undelimited (spec §3.2, Delta #10)
    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        hasher.update(payment_tx.google_payment_token.encode('utf-8'))
        hasher.update(payment_tx.google_order_id.encode('utf-8'))
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        hasher.update(payment_tx.apple_tx_id.encode('utf-8'))
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        hasher.update(payment_tx.rangeproof_order_id.encode('utf-8'))
    else:
        pass

    result: bytes = hasher.digest()
    return result

def make_set_payment_refund_requested_hash(version: int, master_pkey: nacl.signing.VerifyKey, unix_ts_ms: int, refund_requested_unix_ts_ms: int, payment_tx: UserPaymentTransaction) -> bytes:
    hasher: hashlib.blake2b = make_blake2b_hasher(personalisation=SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION)
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_pkey))
    hasher.update(unix_ts_ms.to_bytes(length=8, byteorder='little'))
    hasher.update(refund_requested_unix_ts_ms.to_bytes(length=8, byteorder='little'))
    hasher.update(payment_tx.provider.value.encode('utf-8'))  # provider_code, UTF-8, undelimited (spec §3.3, Delta #10)
    match payment_tx.provider:
        case base.PaymentProvider.Rangeproof:
            pass
        case base.PaymentProvider.Nil:
            pass
        case base.PaymentProvider.GooglePlayStore:
            hasher.update(payment_tx.google_payment_token.encode())
            hasher.update(payment_tx.google_order_id.encode())
        case base.PaymentProvider.iOSAppStore:
            hasher.update(payment_tx.apple_tx_id.encode())
    result: bytes = hasher.digest()
    return result

def make_get_pro_details_hash(version: int, master_pkey: nacl.signing.VerifyKey, unix_ts_ms: int, count: int) -> bytes:
    hasher: hashlib.blake2b = make_blake2b_hasher(personalisation=GET_PRO_DETAILS_HASH_PERSONALISATION)
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_pkey))
    hasher.update(unix_ts_ms.to_bytes(length=8, byteorder='little'))
    hasher.update(count.to_bytes(length=4, byteorder='little'))
    result: bytes = hasher.digest()
    return result

def payment_row_from_dict(row: dict[str, typing.Any]) -> PaymentRow:
    # Rows come from a dict row factory (SELECT PAYMENTS_COLUMNS FROM PAYMENTS_FROM, row_factory=
    # db.dict_row) so columns are addressed by name — adding/removing a column no longer renumbers
    # anything here. `master_pkey` is joined from users (NULL for an unredeemed payment).
    result                                    = PaymentRow()
    result.id                                 = row['id']
    result.master_pkey                        = bytes(row['master_pkey']) if row['master_pkey'] else None
    result.plan                               = base.ProPlan(row['plan'])
    result.payment_provider                   = base.PaymentProvider(row['payment_provider'])
    result.auto_renewing                      = bool(row['auto_renewing'])
    result.unredeemed_unix_ts_ms              = row['unredeemed_unix_ts_ms']
    result.redeemed_unix_ts_ms                = row['redeemed_unix_ts_ms'] if row['redeemed_unix_ts_ms'] else None
    result.expiry_unix_ts_ms                  = row['expiry_unix_ts_ms']
    result.grace_period_duration_ms           = row['grace_period_duration_ms']
    result.platform_refund_expiry_unix_ts_ms  = row['platform_refund_expiry_unix_ts_ms']
    result.revoked_unix_ts_ms                 = row['revoked_unix_ts_ms'] if row['revoked_unix_ts_ms'] else None
    result.apple.original_tx_id               = str(row['apple_original_tx_id'])       if row['apple_original_tx_id']       else ''
    result.apple.tx_id                        = str(row['apple_tx_id'])                if row['apple_tx_id']                else ''
    result.apple.web_line_order_tx_id         = str(row['apple_web_line_order_tx_id']) if row['apple_web_line_order_tx_id'] else ''
    result.google_payment_token               = str(row['google_payment_token'])      if row['google_payment_token']      else ''
    result.google_order_id                    = str(row['google_order_id'])           if row['google_order_id']           else ''
    result.rangeproof_order_id                = str(row['rangeproof_order_id'])        if row['rangeproof_order_id']        else ''
    result.refund_requested_unix_ts_ms        = row['refund_requested_unix_ts_ms']
    result.google_obfuscated_account_id       = bytes(row['google_obfuscated_account_id']) if row['google_obfuscated_account_id'] else b''
    result.apple_app_account_token            = str(row['apple_app_account_token'])    if row['apple_app_account_token']    else ''
    return result

def derive_payment_status(payment: PaymentRow, now_unix_ts_ms: int) -> base.PaymentStatus:
    """Derive the single display status from a payment's timestamps against `now_unix_ts_ms`.

    `status` is not stored; it's computed. Precedence matches the old stored-transition semantics:
    revoked > expired > redeemed > unredeemed.
    """
    if payment.revoked_unix_ts_ms is not None:
        return base.PaymentStatus.Revoked
    if now_unix_ts_ms >= payment.expiry_unix_ts_ms:
        return base.PaymentStatus.Expired
    if payment.redeemed_unix_ts_ms is not None:
        return base.PaymentStatus.Redeemed
    return base.PaymentStatus.Unredeemed

def get_unredeemed_payments_list(conn: psycopg.Connection) -> list[PaymentRow]:
    result: list[PaymentRow] = []
    with db.transaction(conn):
        rows = db.query(conn, f'SELECT {PAYMENTS_COLUMNS} FROM {PAYMENTS_FROM} WHERE p.redeemed_unix_ts_ms IS NULL AND p.revoked_unix_ts_ms IS NULL ORDER BY p.id', row_factory=db.dict_row)
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
        ORDER BY p.unredeemed_unix_ts_ms DESC, p.id DESC
    ''', bytes(master_pkey), row_factory=db.dict_row)

    result      = GetUserAndPayments(payments_it=payments_it)
    result.user = get_user_from_sql_tx(tx, master_pkey)

    row = db.query_one(tx.conn, '''
        SELECT COUNT(*)
        FROM   payments
        WHERE  user_id = (SELECT id FROM users WHERE master_pkey = %s)
    ''', bytes(master_pkey))
    result.payments_count = row[0] if row else 0
    return result

def _user_from_row_iterator(row: UserRowTuple) -> UserRow:
    result                              = UserRow()
    result.found                        = True
    result.master_pkey                  = bytes(row[0])
    result.gen_index                    = row[1]
    result.expiry_unix_ts_ms            = row[2]
    result.grace_period_duration_ms     = row[3]
    result.auto_renewing                = bool(row[4])
    result.refund_requested_unix_ts_ms  = row[5]
    result.google_obfuscated_account_id = row[6]
    result.apple_app_account_token      = row[7]
    return result

def get_users_list(conn: psycopg.Connection) -> list[UserRow]:
    result: list[UserRow] = []
    with db.transaction(conn):
        for row in db.query(conn,
                            ("SELECT master_pkey,"
                             "gen_index,"
                             "expiry_unix_ts_ms,"
                             "grace_period_duration_ms,"
                             "auto_renewing,"
                             "refund_requested_unix_ts_ms,"
                             "google_obfuscated_account_id,"
                             "apple_app_account_token FROM users")):
            result.append(_user_from_row_iterator(tuple(row)))
    return result

def get_user_from_sql_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> UserRow:
    result: UserRow = UserRow()
    row = db.query_one(tx.conn, ("SELECT master_pkey,"
                                 "gen_index,"
                                 "expiry_unix_ts_ms,"
                                 "grace_period_duration_ms,"
                                 "auto_renewing,"
                                 "refund_requested_unix_ts_ms,"
                                 "google_obfuscated_account_id,"
                                 "apple_app_account_token FROM users WHERE master_pkey = %s"),
                       bytes(master_pkey))
    if row:
        result = _user_from_row_iterator(tuple(row))
    return result

def get_user(conn: psycopg.Connection, master_pkey: nacl.signing.VerifyKey) -> UserRow:
    result: UserRow = UserRow()
    with db.transaction(conn) as tx:
        result = get_user_from_sql_tx(tx, master_pkey)
    return result

def get_revocations_list(conn: psycopg.Connection) -> list[RevocationRow]:
    result: list[RevocationRow] = []
    with db.transaction(conn) as tx:
        for row in db.query(tx.conn, "SELECT gen_index, creation_unix_ts_ms, expiry_unix_ts_ms FROM revocations"):
            item                     = RevocationRow()
            item.gen_index           = row[0]
            item.creation_unix_ts_ms = row[1]
            item.expiry_unix_ts_ms   = row[2]
            result.append(item)
    return result

def is_gen_index_revoked_tx(tx: db.SQLTransaction, gen_index: int) -> bool:
    row = db.query_one(tx.conn, "SELECT 1 FROM revocations WHERE gen_index = %s", gen_index)
    return row is not None

def is_gen_index_revoked(conn: psycopg.Connection, gen_index: int) -> bool:
    result: bool = False
    with db.transaction(conn) as tx:
        result = is_gen_index_revoked_tx(tx, gen_index)
    return result

def get_revocation_ticket(conn: psycopg.Connection) -> int:
    row = db.query_one(conn, "SELECT revocation_ticket FROM runtime")
    return row[0] if row else 0

def get_pro_revocations_iterator_tx(tx: db.SQLTransaction) -> collections.abc.Iterator[tuple[int, int, int]]:
    for row in db.query(tx.conn, "SELECT gen_index, creation_unix_ts_ms, expiry_unix_ts_ms FROM revocations"):
        yield (row[0], row[1], row[2])

def get_runtime_tx(tx: db.SQLTransaction) -> RuntimeRow:
    row = db.query_one(tx.conn, ("SELECT gen_index,"
                                 "gen_index_salt,"
                                 "last_expire_unix_ts_ms,"
                                 "apple_notification_checkpoint_unix_ts_ms,"
                                 "revocation_ticket FROM runtime"))
    result: RuntimeRow = RuntimeRow()
    if row:
        result.gen_index                                 = row[0]
        result.gen_index_salt                            = row[1]
        result.last_expire_unix_ts_ms                    = row[2]
        result.apple_notification_checkpoint_unix_ts_ms  = row[3]
        result.revocation_ticket                         = row[4]
    return result

def get_runtime(conn: psycopg.Connection) -> RuntimeRow:
    result: RuntimeRow = RuntimeRow()
    with db.transaction(conn) as tx:
        result = get_runtime_tx(tx)
    return result

def db_info_string(conn: psycopg.Connection, db_url: str, err: base.ErrorSink, backend_pkey: nacl.signing.VerifyKey | None = None) -> str:
    unredeemed_payments             = 0
    payments                        = 0
    users                           = 0
    revocations                     = 0
    db_size                         = 0
    user_errors                     = 0
    apple_notification_uuid_history = 0
    google_notification_history     = 0
    with db.transaction(conn) as tx:
        try:
            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM payments WHERE redeemed_unix_ts_ms IS NULL AND revoked_unix_ts_ms IS NULL')
            if row:
                unredeemed_payments = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM payments')
            if row:
                payments = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM users')
            if row:
                users = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM revocations')
            if row:
                revocations = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM user_errors')
            if row:
                user_errors = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM apple_notification_uuid_history')
            if row:
                apple_notification_uuid_history = row[0]

            row = db.query_one(tx.conn, 'SELECT COUNT(*) FROM google_notification_history')
            if row:
                google_notification_history = row[0]
        except Exception as e:
            err.msg_list.append(f"Failed to retrieve DB metadata: {e}")

    result = ''
    if len(err.msg_list) == 0:
        size_row = db.query_one(conn, 'SELECT pg_database_size(current_database())')
        if size_row:
            db_size = size_row[0]

        with db.transaction(conn) as tx:
            runtime: RuntimeRow = get_runtime_tx(tx)

        lines: list[str] = []
        lines.append('  DB:                               {} ({})'.format(db_url, base.format_bytes(db_size)))
        lines.append('  Users/Revocs/Payments/Unredeemed: {}/{}/{}/{}'.format(users, revocations, payments, unredeemed_payments))
        lines.append('  U.Errors/Google/Apple Notifs.:    {}/{}/{}'.format(user_errors, google_notification_history, apple_notification_uuid_history))
        lines.append('  Gen Index:                        {}'.format(runtime.gen_index))
        backend_key_str = bytes(backend_pkey).hex() if backend_pkey is not None else 'n/a (loaded from disk at runtime)'
        lines.append('  Backend Key:                      {}'.format(backend_key_str))
        result = '\n'.join(lines)

    return result

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

    # NOTE: Wednesday, 27 August 2025 00:00:00, arbitrary date in the past that PRO cannot
    # possibly be before. We should update this to to the PRO release date.
    PRO_ENABLED_UNIX_TS: int = 1756252800

    payments: list[PaymentRow] = get_payments_list(conn)
    now_ms:   int              = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)
    for index, it in enumerate(payments):
        # `status` is derived (not stored) — invariants are really per-fact, but we keep the
        # per-status framing for readable diagnostics.
        status = derive_payment_status(it, now_ms)
        # NOTE: Check mandatory fields
        if it.plan == base.ProPlan.Nil:
            err.msg_list.append(f'{status.name} payment #{index} plan is invalid. It should have been derived from the platform payment provider (e.g. by converting the unredeemedd plan ID to a plan)')
        if it.payment_provider == base.PaymentProvider.Nil:
            err.msg_list.append(f'{status.name} payment #{index} payment provider is set to {it.payment_provider.name} but it should not be. It should have been set by the platform before added to the DB')

        # NOTE: Check mandatory fields or invariants given a particular TX status
        if not it.redeemed_unix_ts_ms and it.revoked_unix_ts_ms is None:
            # Unredeemed: nothing identity-related should be set yet
            if it.master_pkey is not None:
                err.msg_list.append(f'{status.name} payment #{index} has a master pkey set but this pkey should not be set until it is redeemed (e.g. the user registers it)')
            if it.expiry_unix_ts_ms == 0:
                err.msg_list.append(f'{status.name} payment #{index} expired ts was 0. Expiry should be set when payment was unredeemed')
            if it.redeemed_unix_ts_ms:
                err.msg_list.append(f'{status.name} payment #{index} redeemed ts was {it.redeemed_unix_ts_ms}. The payment is not redeemed yet so it should be 0')
            if it.revoked_unix_ts_ms:
                err.msg_list.append(f'{status.name} payment #{index} revoked ts was {it.revoked_unix_ts_ms}. The payment is not refunded yet so it should be 0')

        if it.revoked_unix_ts_ms is not None:
            # Revoked: any payment can transition into the revoked state from any other, so only the
            # revoked ts itself is mandatory.
            if not it.revoked_unix_ts_ms:
                err.msg_list.append(f'{status.name} payment #{index} revoked ts was not set. The payment is refunded so it should be non-zero')
        elif it.redeemed_unix_ts_ms:
            # Redeemed (and not revoked): redeemed + expiry must be set; a redeemed payment must not
            # have expired before it was redeemed.
            if it.expiry_unix_ts_ms == 0:
                err.msg_list.append(f'{status.name} payment #{index} expired ts was 0. Expiry should be set when payment was unredeemed')
            if it.expiry_unix_ts_ms > 0 and it.expiry_unix_ts_ms < it.redeemed_unix_ts_ms:
                redeemed_date = datetime.datetime.fromtimestamp(it.redeemed_unix_ts_ms/1000).strftime('%Y-%m-%d')
                expiry_date   = datetime.datetime.fromtimestamp(it.expiry_unix_ts_ms/1000).strftime('%Y-%m-%d')
                err.msg_list.append(f'{status.name} payment #{index} was expired ({expiry_date}) before it was activated ({redeemed_date})')

        # NOTE: Verify the plan, it should always be set once it enters the DB..
        if it.plan == base.ProPlan.Nil:
               err.msg_list.append(f'Payment #{index} had an invalid plan, received ({base.reflect_enum(it.plan)})')
        _ = base.verify_payment_provider(it.payment_provider, err)

        # NOTE: Check that the payment's redeemed ts is a reasonable value
        if it.redeemed_unix_ts_ms and it.redeemed_unix_ts_ms < PRO_ENABLED_UNIX_TS:
          date_str = datetime.datetime.fromtimestamp(it.redeemed_unix_ts_ms/1000).strftime('%Y-%m-%d')
          err.msg_list.append(f'Payment #{index} specified a creation date before PRO was enabled: {it.redeemed_unix_ts_ms} ({date_str})')

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
        if it.expiry_unix_ts_ms < PRO_ENABLED_UNIX_TS:
          expiry_date_str = datetime.datetime.fromtimestamp(it.expiry_unix_ts_ms/1000).strftime('%Y-%m-%d')
          err.msg_list.append(f'Payment #{index} specified a expiry date before PRO was enabled: {it.expiry_unix_ts_ms} ({expiry_date_str})')

    result = len(err.msg_list) == 0
    return result

def _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey):
    """Update fields for the user that depend on their list of payments, like
    their latest known expiry time"""
    master_pkey_bytes: bytes                    = bytes(master_pkey)
    lookup:            LookupUserExpiryUnixTsMs = _lookup_user_expiry_unix_ts_ms_with_grace_from_payments_table_tx(tx, nacl.signing.VerifyKey(master_pkey_bytes))
    # NOTE: We have the latest expiry value, now update the user
    _ = db.query(tx.conn, '''
        UPDATE users
        SET    expiry_unix_ts_ms = %(expiry)s, grace_period_duration_ms = %(grace)s, auto_renewing = %(renewing)s, refund_requested_unix_ts_ms = %(refund)s
        WHERE  master_pkey = %(pkey)s
    ''', expiry   = lookup.best_expiry_unix_ts_ms,
         grace    = lookup.best_grace_duration_ms,
         renewing = lookup.best_auto_renewing,
         refund   = lookup.best_refund_requested_unix_ts_ms,
         pkey     = master_pkey_bytes)

def revoke_payments_by_id_internal_tx(tx: db.SQLTransaction, rows: typing.Any, revoke_unix_ts_ms: int) -> bool:
    result                             = False
    master_pkey_dict: dict[bytes, int] = {}
    for row in  rows:
        result                          = True
        id:                int          = row[0]
        master_pkey_bytes: bytes | None = bytes(row[1]) if row[1] is not None else None
        expiry_unix_ts_ms: int          = row[2]

        # NOTE: A payment will not have a master pkey associated with it if the user hasn't
        # redeemed it yet so the key may not be set. If it's not set we still mark the payment as
        # 'revoked', this means that it can't be activated and so a master pkey cannot be set on it
        # after the fact as well.
        if master_pkey_bytes:
            master_pkey_dict[master_pkey_bytes] = expiry_unix_ts_ms

        # NOTE: Mark the payment revoked (set revoked_unix_ts_ms) unless it already is.
        _ = db.query(tx.conn, '''
        UPDATE payments
        SET    revoked_unix_ts_ms = %(revoked_ts)s, auto_renewing = FALSE
        WHERE  id = %(id)s AND revoked_unix_ts_ms IS NULL
        ''',
            revoked_ts = revoke_unix_ts_ms,
            id         = id)

    revoke_unix_ts_ms_next_day = round_unix_ts_ms_to_next_day_with_platform_testing_support(base.PaymentProvider.Nil, revoke_unix_ts_ms)
    for it in master_pkey_dict:
        # NOTE: For each user we revoked a payment for, we have modified their 'auto_renewing' value
        # on the payment, we need to go and update their user row to track the, new, next best
        # expiry time so that the backend knows the new time-frame in which the user is allowed to
        # generate a Session Pro proof (now that one or more of their payments get revoked)
        _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx, nacl.signing.VerifyKey(it))

        # NOTE: expiry_unix_ts_ms in the db is not rounded, but the proof's themselves have an
        # expiry timestamp rounded to the end of the UTC day. So we only actually want to revoke
        # proofs that aren't going to self-expire by the end of the day.
        #
        # For different platforms in their testing environments, they have different timespans
        # for a day, for example in Google 1 day is 10s. We handle that explicitly here.

        expiry_unix_ts_ms = master_pkey_dict[it]
        if expiry_unix_ts_ms > revoke_unix_ts_ms_next_day:
            master_pkey = nacl.signing.VerifyKey(it)
            _ = revoke_master_pkey_proofs_and_allocate_new_gen_id_tx(tx, master_pkey, creation_unix_ts_ms=revoke_unix_ts_ms)

    return result

def set_revocation_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, creation_unix_ts_ms: int, expiry_unix_ts_ms: int, delete_item: bool) -> SetRevocationResult:
    user:   UserRow = get_user_from_sql_tx(tx, master_pkey)
    result          = SetRevocationResult.UserDoesNotExist
    if user.found:
        assert user.master_pkey == bytes(master_pkey), f"user.master_pkey={user.master_pkey.hex()} vs master_pkey={bytes(master_pkey).hex()}"
        row = db.query_one(tx.conn, "SELECT EXISTS (SELECT 1 FROM revocations WHERE gen_index = %s)", user.gen_index)
        existed = row[0] if row else False

        if delete_item:
            if existed:
                _      = db.query(tx.conn, 'DELETE FROM revocations WHERE gen_index = %s', user.gen_index)
                result = SetRevocationResult.Deleted
            else:
                result = SetRevocationResult.Skipped
        else:
            _ = db.query(tx.conn, '''
                INSERT INTO revocations (gen_index, creation_unix_ts_ms, expiry_unix_ts_ms)
                VALUES      (%(index)s, %(creation_unix_ts_ms)s, %(expiry_unix_ts_ms)s)
                ON CONFLICT (gen_index) DO UPDATE SET
                    expiry_unix_ts_ms   = excluded.expiry_unix_ts_ms,
                    creation_unix_ts_ms = excluded.creation_unix_ts_ms
            ''', index       = user.gen_index,
                 creation_unix_ts_ms = creation_unix_ts_ms,
                 expiry_unix_ts_ms   = expiry_unix_ts_ms)
            result = SetRevocationResult.Updated if existed else SetRevocationResult.Created
    return result

def add_apple_revocation_tx(tx: db.SQLTransaction, apple_original_tx_id: str, revoke_unix_ts_ms: int, err: base.ErrorSink) -> bool:
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
    SELECT p.id, u.master_pkey, p.expiry_unix_ts_ms
    FROM   {PAYMENTS_FROM}
    WHERE  p.apple_original_tx_id  = %(orig_tx)s AND
           p.payment_provider      = %(provider)s;
    ''',
        orig_tx    = apple_original_tx_id,
        provider   = base.PaymentProvider.iOSAppStore.value)

    log.info(f'Revoking Apple payment (orig. TX ID={base.maybe_obfuscate(apple_original_tx_id)}, revoke={base.readable_unix_ts_ms(revoke_unix_ts_ms)})')
    rows         = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal_tx(tx, rows, revoke_unix_ts_ms)
    if result == False:
        err.msg_list.append(f'Failed to revoke Apple orig. TX ID {base.maybe_obfuscate(apple_original_tx_id)} at {base.readable_unix_ts_ms(revoke_unix_ts_ms)}, no matching payments were found')

    return result

def add_google_revocation_tx(tx: db.SQLTransaction, google_payment_token: str, revoke_unix_ts_ms: int, err: base.ErrorSink) -> bool:
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
    SELECT p.id, u.master_pkey, p.expiry_unix_ts_ms
    FROM   {PAYMENTS_FROM}
    WHERE  p.google_payment_token = %(token)s AND
           p.payment_provider     = %(provider)s
    ''',
        token=google_payment_token,
        provider   = base.PaymentProvider.GooglePlayStore.value)

    log.info(f'Revoking Google payment (token={base.maybe_obfuscate(google_payment_token)}, revoke={base.readable_unix_ts_ms(revoke_unix_ts_ms)})')
    rows         = rows_result.fetchall()
    result: bool = revoke_payments_by_id_internal_tx(tx, rows, revoke_unix_ts_ms)
    if result == False:
        err.msg_list.append(f'Failed to revoke Google payment {base.maybe_obfuscate(google_payment_token)} at {base.readable_unix_ts_ms(revoke_unix_ts_ms)}, no matching payments were found')

    return result

def redeem_payment_tx(tx:                  db.SQLTransaction,
                      master_pkey:         nacl.signing.VerifyKey,
                      rotating_pkey:       nacl.signing.VerifyKey | None,
                      signing_key:         nacl.signing.SigningKey | None,
                      unix_ts_ms:          int,
                      redeemed_unix_ts_ms: int,
                      payment_tx:          UserPaymentTransaction,
                      err:                 base.ErrorSink) -> RedeemPayment:
    """
    unix_ts_ms: The timestamp typically accurate to the current time, used as a frame-of-reference
    to clamp the duration of the proof returned to the user to at most 1 month, also used to mask
    metadata about the type of subscription a user is currently using.

    redeemed_unix_ts_ms: Timestamp to mark as the time in point in which the payment was redeemed.
    This timestamp is typically rounded up by using 'convert_unix_ts_ms_to_redeemed_unix_ts_ms' to
    #mask metadata about the time the user redeemed the payment.
    """

    result                   = RedeemPayment(status=RedeemPaymentStatus.Error)
    master_pkey_bytes: bytes = bytes(master_pkey)
    # A redeem marks the matched unredeemed payment(s) Redeemed; user_id is linked separately once the
    # users row is ensured (master_pkey lives only in users now). The UPDATEs RETURN their ids so we
    # can link exactly those rows without re-matching the per-provider WHERE.
    fields                   = ['redeemed_unix_ts_ms = %(redeemed_unix_ts_ms)s']
    set_expr                 = ', '.join(fields) # Create '<field0> = ?, <field1> = ?, ...'

    payment_tx_label     = _add_pro_payment_user_tx_log_label_safe(payment_tx)
    rotating_pkey_label = base.maybe_obfuscate_bytes(bytes(rotating_pkey)) if rotating_pkey else '(none)'
    log.info(f'Redeeming payment (master={base.maybe_obfuscate_bytes(master_pkey)}, rotating={rotating_pkey_label}, redeemed={base.readable_unix_ts_ms(redeemed_unix_ts_ms)}, payment={payment_tx_label})')

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
            WHERE  payment_provider             = %(provider)s
              AND  google_payment_token         = %(token)s
              AND  google_order_id              = %(order_id)s
              AND  redeemed_unix_ts_ms IS NULL AND revoked_unix_ts_ms IS NULL
              AND  google_obfuscated_account_id = %(account_id)s
            RETURNING id
        ''', # SET values
              redeemed_unix_ts_ms = redeemed_unix_ts_ms,
              # WHERE values
              provider            = payment_tx.provider.value,
              token               = payment_tx.google_payment_token,
              order_id            = payment_tx.google_order_id,
              account_id          = google_obfuscated_account_id_from_master_pkey(master_pkey))
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        row_result = db.query(tx.conn, f'''
            UPDATE payments
            SET    {set_expr}
            WHERE  payment_provider       = %(provider)s
              AND apple_tx_id             = %(tx_id)s
              AND  redeemed_unix_ts_ms IS NULL AND revoked_unix_ts_ms IS NULL
              AND apple_app_account_token = %(account_token)s
            RETURNING id
        ''', # SET fields
              redeemed_unix_ts_ms = redeemed_unix_ts_ms,
              # WHERE fields
              provider            = payment_tx.provider.value,
              tx_id               = payment_tx.apple_tx_id,
              account_token       = apple_obfuscated_account_id_from_master_pkey(master_pkey))
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        row_result = db.query(tx.conn, f'''
            UPDATE payments
            SET    {set_expr}
            WHERE payment_provider    = %(provider)s
              AND rangeproof_order_id = %(rangeproof_order_id)s
              AND  redeemed_unix_ts_ms IS NULL AND revoked_unix_ts_ms IS NULL
            RETURNING id
        ''', # SET fields
              redeemed_unix_ts_ms = redeemed_unix_ts_ms,
              # WHERE fields
              provider            = payment_tx.provider.value,
              rangeproof_order_id = payment_tx.rangeproof_order_id,)
    else:
        err.msg_list.append('Payment to register specifies an unknown payment provider')
        return result

    redeemed_ids = [row[0] for row in row_result.fetchall()]
    rowcount     = len(redeemed_ids)
    if rowcount >= 1:
        assert rowcount == 1
        if rowcount > 1:
            err.msg_list.append(f'Payment was redeemed for {base.maybe_obfuscate_bytes(master_pkey)} at {redeemed_unix_ts_ms/1000} but more than 1 row was updated, updated {rowcount}')

        # master_pkey lives only in `users`: ensure the identity row exists, then link the
        # just-redeemed payment(s) to it. The placeholder gen/expiry here are overwritten by
        # _allocate_new_gen_id… below (which recomputes them from the now-linked payment set).
        _ = db.query(tx.conn, '''
            INSERT INTO users (master_pkey, gen_index, expiry_unix_ts_ms, grace_period_duration_ms, google_obfuscated_account_id, apple_app_account_token)
            VALUES            (%(master_pkey)s, 0, 0, 0, %(google_id)s, %(apple_id)s)
            ON CONFLICT (master_pkey) DO NOTHING
        ''', master_pkey = master_pkey_bytes,
             google_id   = google_obfuscated_account_id_from_master_pkey(master_pkey),
             apple_id    = apple_obfuscated_account_id_from_master_pkey(master_pkey))
        _ = db.query(tx.conn, '''
            UPDATE payments
            SET    user_id = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
            WHERE  id = ANY(%(ids)s)
        ''', master_pkey = master_pkey_bytes, ids = redeemed_ids)

        # proofs will be given a new gen index hash. We used to revoke the old gen index hash
        # but there's no need for that and creates churn in the revoke list. The user will hold
        # onto their proof until it expires and simply request a new one.
        #
        # The key change leading to not requiring a revoke is that we separated the idea that a
        # proof is related to, but not representative of a user's pro payment information (e.g.
        #the proof expiry may or may not co-incide with the pro-plan they are entitled to).
        allocated: AllocatedGenID = _allocate_new_gen_id_if_master_pkey_has_payments(tx, master_pkey)
        if allocated.found:
            # NOTE: Only generate the proof if a rotating public key otherwise skip it (i.e.
            # its possible to redeem a payment without automatically creating the corresponding proof)
            if rotating_pkey:
                assert signing_key, "Rotating public key and signing key have to be given in tandem, either both set or both set to nil"
                proposed_proof_expiry_unix_ts_ms: int = base.round_unix_ts_ms_to_next_day(allocated.expiry_unix_ts_ms)

                # NOTE: In dev mode we don't round up to the next day as we want these proofs to
                # expire quickly for testing.
                if base.DEV_BACKEND_MODE:
                    proposed_proof_expiry_unix_ts_ms = allocated.expiry_unix_ts_ms

                result.proof = build_proof(gen_index         = allocated.gen_index,
                                           rotating_pkey     = rotating_pkey,
                                           expiry_unix_ts_ms = _build_proof_clamped_expiry_time(unix_ts_ms=unix_ts_ms, proposed_expiry_unix_ts_ms=proposed_proof_expiry_unix_ts_ms),
                                           signing_key       = signing_key,
                                           gen_index_salt    = allocated.gen_index_salt)

                if not base.DEV_BACKEND_MODE:
                    assert result.proof.expiry_unix_ts_ms % base.SECONDS_IN_DAY == 0, f"Proof expiry must be on a day boundary, 30 days, 365 days ...e.t.c, was {result.proof.expiry_unix_ts_ms}"
        else:
            err.msg_list.append(f'Failed to update DB after new payment was redeemed for {base.maybe_obfuscate_bytes(master_pkey)}')

        assert allocated.found, "We just added the user's payment we expect to find the latest expiry date for the pkey"

    else:
        # NOTE: We dump the payment TX to the error list. This does not leak
        # any information because this is all data populated by the user who
        # is sending the redeeming request.
        if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            row_result = db.query(tx.conn, '''
                SELECT COUNT(*)
                FROM   payments
                WHERE  payment_provider     = %(provider)s
                  AND  google_payment_token = %(token)s
                  AND  google_order_id      = %(order_id)s
                  AND  redeemed_unix_ts_ms IS NOT NULL
                  AND  user_id              = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
            ''', provider    = payment_tx.provider.value,
                 token       = payment_tx.google_payment_token,
                 order_id    = payment_tx.google_order_id,
                 master_pkey = master_pkey_bytes)
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            row_result = db.query(tx.conn, '''
                SELECT COUNT(*)
                FROM   payments
                WHERE  payment_provider = %(provider)s
                  AND  apple_tx_id      = %(tx_id)s
                  AND  redeemed_unix_ts_ms IS NOT NULL
                  AND  user_id          = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
            ''', provider    = payment_tx.provider.value,
                 tx_id       = payment_tx.apple_tx_id,
                 master_pkey = master_pkey_bytes)
        elif payment_tx.provider == base.PaymentProvider.Rangeproof:
            row_result = db.query(tx.conn, '''
                SELECT COUNT(*)
                FROM   payments
                WHERE  payment_provider    = %(provider)s
                  AND  rangeproof_order_id = %(order_id)s
                  AND  redeemed_unix_ts_ms IS NOT NULL
                  AND  user_id             = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
            ''', provider    = payment_tx.provider.value,
                 order_id    = payment_tx.rangeproof_order_id,
                 master_pkey = master_pkey_bytes)

        first_row = row_result.fetchone()
        if first_row and first_row[0] > 0:
            err.msg_list.append(f'Payment was not redeemed, already redeemed TX: {user_payment_tx_to_safe_string(payment_tx)}')
            result.status = RedeemPaymentStatus.AlreadyRedeemed
        else:
            err.msg_list.append(f'Payment was not redeemed, no payments were found matching the request tx: {user_payment_tx_to_safe_string(payment_tx)}')
            result.status = RedeemPaymentStatus.UnknownPayment

    if not err.has():
        assert result.status == RedeemPaymentStatus.Error
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

def _lookup_user_expiry_unix_ts_ms_with_grace_from_payments_table_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> LookupUserExpiryUnixTsMs:
    # NOTE: We grab the expired ones as well because if they have grace that payment's deadline
    # is later than the expiry period which may actually be the latest known expiry period
    #
    # By definition we can't lookup unredeemed payments because they don't have a master public key
    # registered for it yet (e.g. the user has not associated a master public key with the payment
    # yet by redeeming it).
    # All of a user's linked payments are redeemed-or-later (user_id is set only at redemption), so the
    # user_id filter alone replaces the old `status IN (redeemed, revoked, expired)` — unredeemed
    # payments have no user_id. redeemed/expired/revoked are derived from the timestamps below.
    result_set = db.query(tx.conn, ('''
        SELECT    expiry_unix_ts_ms, grace_period_duration_ms, auto_renewing, redeemed_unix_ts_ms, refund_requested_unix_ts_ms, payment_provider, apple_original_tx_id, google_order_id, rangeproof_order_id, revoked_unix_ts_ms
        FROM      payments
        WHERE     user_id = (SELECT id FROM users WHERE master_pkey = %(master_pkey)s)
        ORDER BY  id DESC
    '''), master_pkey = bytes(master_pkey))

    used_google_order_ids:     list[str] = []
    used_apple_orig_tx_ids:    set[int]  = set()
    used_rangeproof_order_ids: set[str]  = set()

    # NOTE: Determine the user's latest expiry by enumerating all the payments and calculating
    # the expiry time (inclusive of the grace period if applicable)
    result      = LookupUserExpiryUnixTsMs()
    rows        = typing.cast(list[tuple[typing.Any, ...]], result_set.fetchall())
    for row in rows:
        expiry_unix_ts_ms:           int        = row[0]
        grace_period_duration_ms:    int        = row[1]
        auto_renewing:               int        = row[2]
        redeemed_unix_ts_ms:         int | None = row[3]
        refund_requested_unix_ts_ms: int        = row[4]
        payment_provider:            str        = row[5]
        apple_original_tx_id:        int        = row[6]
        google_order_id:             str        = row[7]
        rangeproof_order_id:         str        = row[8]
        revoked_unix_ts_ms:          int | None = row[9]

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

        # NOTE: Calculate the current best timestamp (newest payment that entitles them to Pro)
        best_expiry_wo_grace_unix_ts_ms_from_redeemed: int = result.expiry_unix_ts_ms_from_redeemed
        best_expiry_wo_grace_unix_ts_ms:               int = result.best_expiry_unix_ts_ms
        if result.auto_renewing_from_redeemed:
            best_expiry_wo_grace_unix_ts_ms_from_redeemed -= result.grace_duration_ms_from_redeemed

        if result.best_auto_renewing:
            best_expiry_wo_grace_unix_ts_ms -= result.best_grace_duration_ms

        # NOTE: If we're revoked, the expiry and payment expiry that we store into the result is
        # clamped to the revoke timestamp (e.g. the user entitlement is stopped effective at the
        # revoke time). `status` is not stored — it's derived from the timestamps (see
        # derive_payment_status). Here we work from the orthogonal facts directly, NOT the flattened
        # display status: `revoked` ⟺ revoked_unix_ts_ms set. Whether a payment has *expired* is a
        # separate, now-relative concern handled downstream (get_pro_status / proof-expiry clamping) —
        # it must not gate what expiry the user is *entitled* to, so no wall-clock enters here.
        if revoked_unix_ts_ms is not None:
            assert auto_renewing == False
            payment_expiry_unix_ts_ms = revoked_unix_ts_ms
            expiry_unix_ts_ms         = revoked_unix_ts_ms
        else:
            payment_expiry_unix_ts_ms = expiry_unix_ts_ms
            if auto_renewing:
                payment_expiry_unix_ts_ms += grace_period_duration_ms

        # NOTE: A payment contributes to the "redeemed" entitlement iff it has been redeemed and not
        # revoked. (Expiry is deliberately excluded — see above.)
        is_redeemed = redeemed_unix_ts_ms is not None and revoked_unix_ts_ms is None
        if is_redeemed:
            if expiry_unix_ts_ms > best_expiry_wo_grace_unix_ts_ms_from_redeemed:
                result.expiry_unix_ts_ms_from_redeemed           = payment_expiry_unix_ts_ms
                result.grace_duration_ms_from_redeemed           = grace_period_duration_ms
                result.refund_requested_unix_ts_ms_from_redeemed = refund_requested_unix_ts_ms
                result.auto_renewing_from_redeemed               = bool(auto_renewing)

        if expiry_unix_ts_ms > best_expiry_wo_grace_unix_ts_ms:
            result.best_expiry_unix_ts_ms           = payment_expiry_unix_ts_ms
            result.best_grace_duration_ms           = grace_period_duration_ms
            result.best_refund_requested_unix_ts_ms = refund_requested_unix_ts_ms
            result.best_auto_renewing               = bool(auto_renewing)
    return result

def update_payment_renewal_info_tx(tx:                       db.SQLTransaction,
                                   payment_tx:               base.PaymentProviderTransaction,
                                   grace_period_duration_ms: int  | None,
                                   auto_renewing:            bool | None,
                                   err:                      base.ErrorSink) -> bool:
    """
    Update a payment's grace period and/or auto renewing flag. Pass in `None` for the arguments
    you want to opt out of updating.
    """

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label(payment_tx)
        log.info(f'Update renewal info (payment={payment_tx_label}, grace period ms={grace_period_duration_ms}, auto_renewing={auto_renewing})')

    result = False
    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return result

    if grace_period_duration_ms is None and auto_renewing is None:
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

    if grace_period_duration_ms is not None:
        if len(sql_set_fields):
            sql_set_fields += ', '
        sql_set_fields += 'grace_period_duration_ms = %(grace_period_duration_ms)s'
        kwparams['grace_period_duration_ms'] = grace_period_duration_ms

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
                WHERE     google_payment_token = %(token)s AND google_order_id = %(order_id)s
                RETURNING (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
            ''', token    = payment_tx.google_payment_token,
                 order_id = payment_tx.google_order_id,
                 **kwparams)

        case base.PaymentProvider.iOSAppStore:
            result_set = db.query(tx.conn, f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     apple_original_tx_id = %(orig_tx_id)s AND apple_tx_id = %(tx_id)s AND apple_web_line_order_tx_id = %(line_order_tx_id)s
                RETURNING (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
            ''', orig_tx_id       = payment_tx.apple_original_tx_id,
                 tx_id            = payment_tx.apple_tx_id,
                 line_order_tx_id = payment_tx.apple_web_line_order_tx_id,
                 **kwparams)

        case base.PaymentProvider.Rangeproof:
            result_set = db.query(tx.conn, f'''
                UPDATE    payments
                SET       {sql_set_fields}
                WHERE     rangeproof_order_id = %(rangeproof_order_id)s
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
                                grace_period_duration_ms: int  | None,
                                auto_renewing:            bool | None,
                                err:                      base.ErrorSink) -> bool:

    result = False
    with db.transaction(conn) as sql_tx:
        result = update_payment_renewal_info_tx(sql_tx, payment_tx, grace_period_duration_ms, auto_renewing, err)
    return result

def _insert_payment_row_tx(tx: db.SQLTransaction, row: dict[str, typing.Any]) -> None:
    """INSERT a payments row from a column→value mapping.

    A dict is self-aligning: the column name and its value live together, so there is no pair of
    parallel lists to drift out of index-lock. Placeholders are generated from the same keys.
    """
    columns      = ', '.join(row)
    placeholders = ', '.join(f'%({column})s' for column in row)
    _ = db.query(tx.conn, f'INSERT INTO payments ({columns}) VALUES ({placeholders})', row)

def add_unredeemed_payment_tx(tx:                                db.SQLTransaction,
                              payment_tx:                        base.PaymentProviderTransaction,
                              plan:                              base.ProPlan,
                              expiry_unix_ts_ms:                 int,
                              unredeemed_unix_ts_ms:             int,
                              platform_refund_expiry_unix_ts_ms: int,
                              platform_obfuscated_account_id:    bytes | str,
                              err:                               base.ErrorSink):

    if log.getEffectiveLevel() <= logging.INFO:
        payment_tx_label = payment_provider_tx_log_label(payment_tx)
        log.info(f'Unredeemed payment (payment={payment_tx_label}, plan={plan.name}, expiry={base.readable_unix_ts_ms(expiry_unix_ts_ms)}, unredeemed={base.readable_unix_ts_ms(unredeemed_unix_ts_ms)}, refund={base.readable_unix_ts_ms(platform_refund_expiry_unix_ts_ms)})')

    verify_payment_provider_tx(payment_tx, err)
    if len(err.msg_list) > 0:
        return

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        assert isinstance(platform_obfuscated_account_id, bytes)
        assert len(platform_obfuscated_account_id) == 32

        # NOTE: Insert into the table, IFF, the payment token hash doesn't already exist in the
        # payments table
        result_set = db.query(tx.conn, '''
            SELECT 1
            FROM payments
            WHERE payment_provider = %(provider)s AND google_payment_token = %(token)s AND google_order_id = %(order_id)s
        ''', provider=payment_tx.provider.value, token=payment_tx.google_payment_token, order_id=payment_tx.google_order_id)

        record = result_set.fetchone()
        if not record:
            _insert_payment_row_tx(tx, {
                'plan':                              plan.value,
                'payment_provider':                 payment_tx.provider.value,
                'google_payment_token':             payment_tx.google_payment_token,
                'google_order_id':                  payment_tx.google_order_id,
                'expiry_unix_ts_ms':                expiry_unix_ts_ms,
                'platform_refund_expiry_unix_ts_ms': platform_refund_expiry_unix_ts_ms,
                'grace_period_duration_ms':         0,
                'unredeemed_unix_ts_ms':            unredeemed_unix_ts_ms,
                'auto_renewing':                    True,  # on by default until Google notifies otherwise
                'refund_requested_unix_ts_ms':      0,
                'google_obfuscated_account_id':     platform_obfuscated_account_id,
                'apple_app_account_token':          '',    # n/a for Google
            })

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        assert isinstance(platform_obfuscated_account_id, str)
        # NOTE: Insert into the table, IFF, the apple payment doesn't already exist somewhere else.
        #
        # For Apple each apple_tx_id is always unique.
        # apple_web_line_order_tx_id is unique for the payment of the billing
        # cycle for that subscription and the apple_original_tx_id is reused
        # across all subscriptions of the same type.
        result_set = db.query(tx.conn, '''
                SELECT 1
                FROM payments
                WHERE payment_provider = %(provider)s AND apple_original_tx_id = %(orig_tx_id)s AND apple_tx_id = %(tx_id)s AND apple_web_line_order_tx_id = %(line_order_tx_id)s
        ''', provider=payment_tx.provider.value,
              orig_tx_id=payment_tx.apple_original_tx_id,
              tx_id=payment_tx.apple_tx_id,
              line_order_tx_id=payment_tx.apple_web_line_order_tx_id)

        record = result_set.fetchone()
        if not record:
            _insert_payment_row_tx(tx, {
                'plan':                              plan.value,
                'payment_provider':                 payment_tx.provider.value,
                'apple_original_tx_id':             payment_tx.apple_original_tx_id,
                'apple_tx_id':                      payment_tx.apple_tx_id,
                'apple_web_line_order_tx_id':       payment_tx.apple_web_line_order_tx_id,
                'expiry_unix_ts_ms':                expiry_unix_ts_ms,
                'platform_refund_expiry_unix_ts_ms': platform_refund_expiry_unix_ts_ms,
                'grace_period_duration_ms':         0,
                'unredeemed_unix_ts_ms':            unredeemed_unix_ts_ms,
                'auto_renewing':                    True,  # on by default until Apple notifies otherwise
                'refund_requested_unix_ts_ms':      0,
                'apple_app_account_token':          platform_obfuscated_account_id,
            })
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        # NOTE: Insert into the table, IFF, the rangeproof order id doesn't already exist somewhere else.
        result_set = db.query(tx.conn, '''
                SELECT 1
                FROM payments
                WHERE payment_provider = %s AND rangeproof_order_id = %s
        ''', payment_tx.provider.value, payment_tx.rangeproof_order_id)

        record = result_set.fetchone()
        if not record:
            _insert_payment_row_tx(tx, {
                'plan':                              plan.value,
                'payment_provider':                 payment_tx.provider.value,
                'rangeproof_order_id':              payment_tx.rangeproof_order_id,
                'expiry_unix_ts_ms':                expiry_unix_ts_ms,
                'platform_refund_expiry_unix_ts_ms': platform_refund_expiry_unix_ts_ms,
                'grace_period_duration_ms':         0,
                'unredeemed_unix_ts_ms':            unredeemed_unix_ts_ms,
                'auto_renewing':                    False,  # Rangeproof vouchers never auto-renew
                'refund_requested_unix_ts_ms':      0,
                'apple_app_account_token':          '',     # n/a for Rangeproof
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
            WHERE    p.payment_provider = %s AND p.google_payment_token = %s
            ORDER BY p.id DESC
            LIMIT    1
        '''), payment_tx.provider.value, payment_tx.google_payment_token)
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        result_set = db.query(tx.conn, ('''
            SELECT   u.master_pkey
            FROM     payments p JOIN users u ON u.id = p.user_id
            WHERE    p.payment_provider = %s AND p.apple_original_tx_id = %s
            ORDER BY p.id DESC
            LIMIT    1
        '''), payment_tx.provider.value, payment_tx.apple_original_tx_id)
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
            user: UserRow = get_user_from_sql_tx(tx, master_pkey)
            if user.found:
                auto_redeem_deadline_unix_ts_ms: int = 0

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
                    auto_redeem_deadline_unix_ts_ms = user.expiry_unix_ts_ms
                    if user.auto_renewing:
                        auto_redeem_deadline_unix_ts_ms += 60 * base.MILLISECONDS_IN_DAY - user.grace_period_duration_ms
                else:
                    assert payment_tx.provider == base.PaymentProvider.iOSAppStore
                    # NOTE: We don't currently configure a grace period/account hold period for Apple
                    # hnote the grace and account hold concept is merged together in Apple).
                    auto_redeem_deadline_unix_ts_ms = user.expiry_unix_ts_ms
                    if user.auto_renewing:
                        auto_redeem_deadline_unix_ts_ms += user.grace_period_duration_ms

                # NOTE: Unredeemed unix timestamp represents now (as this is the timestamp we are marking
                # the payment as having been registered), so we compare (now) to the deadline. If we are
                # before the deadline we are eligible to auto-redeem this payment and assign it to the
                # previous known master public key.
                if unredeemed_unix_ts_ms <= auto_redeem_deadline_unix_ts_ms:
                    add_pro_payment_user_tx                      = UserPaymentTransaction()
                    add_pro_payment_user_tx.provider             = payment_tx.provider
                    add_pro_payment_user_tx.apple_tx_id          = payment_tx.apple_tx_id
                    add_pro_payment_user_tx.google_payment_token = payment_tx.google_payment_token
                    add_pro_payment_user_tx.google_order_id      = payment_tx.google_order_id

                    # NOTE: We use a temp error sink as we don't mind if auto-redeeming failed the user
                    # can always try manually by claiming the payment themselves. If this errors
                    # returning that to the platform layers (google and apple) can stall them
                    # unnecessarily.
                    #
                    # For internal logging though however, we can report this
                    tmp_err = base.ErrorSink()
                    _ = redeem_payment_tx(tx                  = tx,
                                          master_pkey         = master_pkey,
                                          rotating_pkey       = None,
                                          signing_key         = None,
                                          unix_ts_ms          = unredeemed_unix_ts_ms,
                                          redeemed_unix_ts_ms = convert_unix_ts_ms_to_redeemed_unix_ts_ms(unredeemed_unix_ts_ms),
                                          payment_tx          = add_pro_payment_user_tx,
                                          err                 = tmp_err)

                    if tmp_err.has():
                        err_str = '\n'.join(tmp_err.msg_list)
                        log.error(f'Failed to auto-redeem a payment we witnessed from. (auto_redeem_deadline={base.readable_unix_ts_ms(auto_redeem_deadline_unix_ts_ms)}) {err_str}')

def add_unredeemed_payment(conn:                              psycopg.Connection,
                           payment_tx:                        base.PaymentProviderTransaction,
                           plan:                              base.ProPlan,
                           expiry_unix_ts_ms:                 int,
                           unredeemed_unix_ts_ms:             int,
                           platform_refund_expiry_unix_ts_ms: int,
                           platform_obfuscated_account_id:    bytes | str,
                           err:                               base.ErrorSink):
    with db.transaction(conn) as tx:
        add_unredeemed_payment_tx(tx                                = tx,
                                  payment_tx                        = payment_tx,
                                  plan                              = plan,
                                  expiry_unix_ts_ms                 = expiry_unix_ts_ms,
                                  unredeemed_unix_ts_ms             = unredeemed_unix_ts_ms,
                                  platform_refund_expiry_unix_ts_ms = platform_refund_expiry_unix_ts_ms,
                                  platform_obfuscated_account_id    = platform_obfuscated_account_id,
                                  err                               = err)

def _allocate_new_gen_id_if_master_pkey_has_payments(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> AllocatedGenID:
    result:            AllocatedGenID = AllocatedGenID()
    master_pkey_bytes: bytes          = bytes(master_pkey)

    lookup: LookupUserExpiryUnixTsMs = _lookup_user_expiry_unix_ts_ms_with_grace_from_payments_table_tx(tx, master_pkey)
    result.expiry_unix_ts_ms         = lookup.expiry_unix_ts_ms_from_redeemed
    if lookup.expiry_unix_ts_ms_from_redeemed > 0:
        # NOTE: Master pkey has a payment we can use. Allocate a new generation ID in the runtime table
        result.found = True
        runtime_result = db.query(tx.conn, '''
            UPDATE    runtime
            SET       gen_index = gen_index + 1
            RETURNING gen_index - 1, gen_index_salt
        ''')
        runtime_row           = typing.cast(tuple[int, bytes], runtime_result.fetchone())
        result.gen_index      = runtime_row[0]
        result.gen_index_salt = runtime_row[1]

        # NOTE: Also update the user table with this payment we found that is currently the "best"
        # payment (e.g. the latest and most up to date payment and hence has the best expiry time)
        # for the user into their user record.
        #
        # This means that for the most part, consumers can just rely on the top level object to
        # determine the current state of the user subscription payment.
        _ = db.query(tx.conn, '''
            INSERT INTO users (master_pkey, gen_index, expiry_unix_ts_ms, grace_period_duration_ms, auto_renewing, refund_requested_unix_ts_ms, google_obfuscated_account_id, apple_app_account_token)
            VALUES            (%(master_pkey)s, %(gen_index)s, %(expiry)s, %(grace)s, %(auto_renewing)s, %(refund_ts)s, %(google_id)s, %(apple_id)s)
            ON CONFLICT (master_pkey) DO UPDATE SET
                gen_index                    = excluded.gen_index,
                expiry_unix_ts_ms            = excluded.expiry_unix_ts_ms,
                grace_period_duration_ms     = excluded.grace_period_duration_ms,
                auto_renewing                = excluded.auto_renewing,
                refund_requested_unix_ts_ms  = excluded.refund_requested_unix_ts_ms,
                google_obfuscated_account_id = excluded.google_obfuscated_account_id,
                apple_app_account_token      = excluded.apple_app_account_token
        ''', master_pkey   = master_pkey_bytes,
             gen_index     = result.gen_index,
             expiry        = lookup.best_expiry_unix_ts_ms,
             grace         = lookup.best_grace_duration_ms,
             auto_renewing = lookup.best_auto_renewing,
             refund_ts     = lookup.best_refund_requested_unix_ts_ms,
             google_id     = google_obfuscated_account_id_from_master_pkey(master_pkey),
             apple_id      = apple_obfuscated_account_id_from_master_pkey(master_pkey),
             )

    return result

def make_generate_pro_proof_hash(version:       int,
                                 master_pkey:   nacl.signing.VerifyKey,
                                 rotating_pkey: nacl.signing.VerifyKey,
                                 unix_ts_ms:    int) -> bytes:
    '''Make the hash to sign for a pre-existing subscription by authorising
    a new rotating_pkey to be used for the Session Pro subscription associated
    with master_pkey'''
    hasher: hashlib.blake2b = make_blake2b_hasher(personalisation=GENERATE_PROOF_HASH_PERSONALISATION)
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(bytes(master_pkey))
    hasher.update(bytes(rotating_pkey))
    hasher.update(unix_ts_ms.to_bytes(length=8, byteorder='little'))
    result: bytes = hasher.digest()
    return result

def build_proof_hash(version:           int,
                     gen_index_hash:    bytes,
                     rotating_pkey:     nacl.signing.VerifyKey,
                     expiry_unix_ts_ms: int) -> bytes:
    '''Make the hash to the backend signs for to certify the proof'''
    hasher: hashlib.blake2b = make_blake2b_hasher(personalisation=BUILD_PROOF_HASH_PERSONALISATION)
    hasher.update(version.to_bytes(length=1, byteorder='little'))
    hasher.update(gen_index_hash)
    hasher.update(bytes(rotating_pkey))
    hasher.update(expiry_unix_ts_ms.to_bytes(length=8, byteorder='little'))
    result: bytes = hasher.digest()
    return result

def _build_proof_clamped_expiry_time(unix_ts_ms: int, proposed_expiry_unix_ts_ms: int):
    # NOTE: Clamp the expiry time of the proof to 1 month and also make it land on the day boundary
    # to reduce metadata leakage. If it's less than 1 month then just take the value verbatim as
    # their subscription is coming to a close.
    clamped_expiry_unix_ts_ms = base.round_unix_ts_ms_to_next_day(unix_ts_ms + base.MILLISECONDS_IN_MONTH)
    result: int               = min(clamped_expiry_unix_ts_ms, proposed_expiry_unix_ts_ms)
    return result

def build_proof(gen_index:         int,
                rotating_pkey:     nacl.signing.VerifyKey,
                expiry_unix_ts_ms: int,
                signing_key:       nacl.signing.SigningKey,
                gen_index_salt:    bytes) -> ProSubscriptionProof:
    assert len(gen_index_salt) == hashlib.blake2b.SALT_SIZE
    result: ProSubscriptionProof = ProSubscriptionProof()
    result.version               = 0
    result.gen_index_hash        = make_gen_index_hash(gen_index=gen_index, gen_index_salt=gen_index_salt)
    result.rotating_pkey         = rotating_pkey
    result.expiry_unix_ts_ms     = expiry_unix_ts_ms

    hash_to_sign: bytes = build_proof_hash(version           = result.version,
                                           gen_index_hash    = result.gen_index_hash,
                                           rotating_pkey     = result.rotating_pkey,
                                           expiry_unix_ts_ms = result.expiry_unix_ts_ms)
    result.sig = signing_key.sign(hash_to_sign).signature
    return result

def internal_verify_add_payment_and_get_proof_common_arguments(signing_key:   nacl.signing.SigningKey,
                                                               master_pkey:   nacl.signing.VerifyKey,
                                                               rotating_pkey: nacl.signing.VerifyKey,
                                                               hash_to_sign:  bytes,
                                                               master_sig:    bytes,
                                                               rotating_sig:  bytes,
                                                               err:           base.ErrorSink) -> bool:
    # Verify the signatures first (authenticate that the message was not
    # tampered with first) if these fail, early exit as the contents of the rest
    # of the payload is indeterminate.
    try:
        _ = master_pkey.verify(smessage=hash_to_sign, signature=master_sig)
    except Exception as e:
        err.msg_list.append(f'Failed to verify signature from master key {base.maybe_obfuscate_bytes(master_pkey)}: {e}');
        return False

    try:
        _ = rotating_pkey.verify(smessage=hash_to_sign, signature=rotating_sig)
    except Exception as e:
        err.msg_list.append(f'Failed to verify signature from rotating key {base.maybe_obfuscate_bytes(rotating_pkey)}: {e}');
        return False

    # The hash to sign is only passed by internal code, the user never passes
    # the hash so this assert guards for a development error. Similar with the
    # signing key check.
    assert len(hash_to_sign) == BLAKE2B_DIGEST_SIZE and hash_to_sign != ZERO_BYTES32
    assert bytes(signing_key) != ZERO_BYTES32 and bytes(signing_key.verify_key) != ZERO_BYTES32

    # Sanity check the signing key
    if signing_key.verify_key == master_pkey or signing_key.verify_key == rotating_pkey:
        err.msg_list.append(f'Internal key error during adding payment: please notify the devs')

    # Sanity check the user key's and their signatures
    if master_pkey == rotating_pkey:
        err.msg_list.append(f'Master and rotating key cannot be the same was: {base.maybe_obfuscate_bytes(master_pkey)}')

    if bytes(master_pkey) == ZERO_BYTES32:
        err.msg_list.append(f'Master key cannot be the zero key')

    if bytes(rotating_pkey) == ZERO_BYTES32:
        err.msg_list.append(f'Rotating key cannot be the zero key')

    if master_sig == rotating_sig:
        err.msg_list.append(f'Master and rotating signature cannot be the same')

    result = len(err.msg_list) == 0
    return result

def add_pro_payment_tx(tx:                  db.SQLTransaction,
                       version:             int,
                       signing_key:         nacl.signing.SigningKey,
                       unix_ts_ms:          int,
                       redeemed_unix_ts_ms: int,
                       master_pkey:         nacl.signing.VerifyKey,
                       rotating_pkey:       nacl.signing.VerifyKey,
                       payment_tx:          UserPaymentTransaction,
                       err:                 base.ErrorSink,
                       THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION: bool) -> RedeemPayment:

    # Note being able to pass in the creation unix timestamp is mainly for
    # testing purposes to allow time-travel. User space should never be
    # specifying this argument, so clients should not be specifying this time,
    # ever, it should be generated and rounded up by the server hence the
    # assert.
    if not base.DEV_BACKEND_MODE:
        assert redeemed_unix_ts_ms % (base.SECONDS_IN_DAY * 1000) == 0, \
                "The passed in creation (and or activated) timestamp must lie on a day boundary: {}".format(redeemed_unix_ts_ms)

    # All verified. Redeem the payment
    result: RedeemPayment = redeem_payment_tx(tx                  = tx,
                                              master_pkey         = master_pkey,
                                              rotating_pkey       = rotating_pkey,
                                              signing_key         = signing_key,
                                              unix_ts_ms          = unix_ts_ms,
                                              redeemed_unix_ts_ms = redeemed_unix_ts_ms,
                                              payment_tx          = payment_tx,
                                              err                 = err)

    # NOTE: We put this _inside_ the transaction block, because, for Google Payments we ack
    # the payment against Google's servers. If we have a network failure, this will throw an
    # exception and we want the transaction to be reverted because, redeeming and
    # acknowledgement must be done atomically.
    #
    # Ack-ing should be done after redeeming because we can't undo an ack on Google, so first we
    # make sure we can redeem it safely before lastly notifying Google that the payment is good
    # to go.
    if result.status == RedeemPaymentStatus.Success and payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        # NOTE: For Google, we acknowledge the payment here on demand when the user claims the payment
        # Unfortunately this leaks in platform details into the DB layer but acknowledgement on claim is
        # the most sensible option and binds the Session client's knowledge of their own payment and
        # that the backend acknowledges the payment in the same step which simplifies implementation
        # greatly. It avoids race conditions such as the client acknowledging but the server hasn't
        # acknowledged yet so it needs to poll the server e.t.c.
        #
        # Yes generating proofs for Google then blocks on the subscription acknowledge, that is
        # unfortunate but intentional, if Google can't be contacted, we can't approve and so the payment
        # cannot be claimed and should be re-attempted.
        if THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION == False:
            sub_data: platform_google_types.SubscriptionV2Data | None = platform_google_api.fetch_subscription_v2_details(package_name=platform_google_api.package_name,
                                                                                                                          purchase_token=payment_tx.google_payment_token,
                                                                                                                          err=err)
            if not sub_data:
                tx.cancel = True
                return result

            payment_tx_label = _add_pro_payment_user_tx_log_label_safe(payment_tx)
            log.info(f'Google ack. payment check (dev={base.DEV_BACKEND_MODE}, version={version}, master={base.maybe_obfuscate_bytes(master_pkey)}, payment={payment_tx_label}, acked={sub_data.acknowledgement_state})')

            if sub_data.acknowledgement_state != platform_google_types.SubscriptionsV2AcknowledgementState.ACKNOWLEDGED:
                platform_google_api.subscription_v1_acknowledge(purchase_token=payment_tx.google_payment_token, err=err)
                if len(err.msg_list) > 0:
                    tx.cancel = True
                    return result
    return result


def add_pro_payment(conn:                psycopg.Connection,
                    version:             int,
                    signing_key:         nacl.signing.SigningKey,
                    unix_ts_ms:          int,
                    redeemed_unix_ts_ms: int,
                    master_pkey:         nacl.signing.VerifyKey,
                    rotating_pkey:       nacl.signing.VerifyKey,
                    payment_tx:          UserPaymentTransaction,
                    err:                 base.ErrorSink,
                    THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION: bool) -> RedeemPayment:
    result = RedeemPayment()
    with db.transaction(conn) as tx:
        result = add_pro_payment_tx(tx,
                                     version,
                                     signing_key,
                                     unix_ts_ms,
                                     redeemed_unix_ts_ms,
                                     master_pkey,
                                     rotating_pkey,
                                     payment_tx,
                                     err,
                                     THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION)
    return result

def verify_and_add_pro_payment(conn:                psycopg.Connection,
                               version:             int,
                               signing_key:         nacl.signing.SigningKey,
                               unix_ts_ms:          int,
                               redeemed_unix_ts_ms: int,
                               master_pkey:         nacl.signing.VerifyKey,
                               rotating_pkey:       nacl.signing.VerifyKey,
                               payment_tx:          UserPaymentTransaction,
                               master_sig:          bytes,
                               rotating_sig:        bytes,
                               err:                 base.ErrorSink,
                               dev_args:            DevAddProPaymentArgs) -> RedeemPayment:
    """
    unix_ts_ms: The timestamp typically accurate to the current time, used as a frame-of-reference
    to clamp the duration of the proof returned to the user to at most 1 month, also used to mask
    metadata about the type of subscription a user is currently using.

    redeemed_unix_ts_ms: Timestamp to mark as the time in point in which the payment was redeemed.
    This timestamp is typically rounded up by using 'convert_unix_ts_ms_to_redeemed_unix_ts_ms' to
    #mask metadata about the time the user redeemed the payment.
    """

    payment_tx_label = _add_pro_payment_user_tx_log_label_safe(payment_tx)
    log.info(f'Add payment (dev={base.DEV_BACKEND_MODE}, version={version}, redeemed={base.readable_unix_ts_ms(redeemed_unix_ts_ms)}, master={base.maybe_obfuscate_bytes(master_pkey)}, payment={payment_tx_label})')

    result        = RedeemPayment()
    result.status = RedeemPaymentStatus.Error

    # In developer mode, the server is intended to be launched locally and we
    # typically run libsession tests against it (to get accurate request and
    # response payloads) from the server. In these tests we try and register
    # a payment, but the design of the pro backend is that it pulls payment
    # tokens from the 3rd party storefronts.
    #
    # It must have pulled the token first before permitting the payment token to
    # be registered. Here we skipping the pulling step by implicitly registering
    # the token into our unredeemed queue, then process the payment from the
    # unredeemed queue immediately.
    #
    # There is a sanity check to _only_ allow this in developer mode. In
    # any other context having this turn on would be a critical failure and
    # would allow someone to register arbitrary Session Pro subscriptions
    # without a valid payment.
    THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION: bool = False
    if base.DEV_BACKEND_MODE and (payment_tx.google_order_id.startswith('DEV.') or payment_tx.apple_tx_id.startswith('DEV.') or payment_tx.rangeproof_order_id.startswith('DEV.')):
        assert_backend_is_in_dev_mode(signing_key)

        # Convert the user payment transaction into the backend native representation. Note that
        # this is testing code for the unit tests so for example for Apple we just provide stub data
        # for transaction data.
        #
        # For the order id, we duplicate the unredeemed token to mock that
        internal_payment_tx          = base.PaymentProviderTransaction()
        internal_payment_tx.provider = payment_tx.provider

        if internal_payment_tx.provider == base.PaymentProvider.GooglePlayStore:
            internal_payment_tx.google_payment_token        = payment_tx.google_payment_token
            internal_payment_tx.google_order_id             = payment_tx.google_order_id
        elif internal_payment_tx.provider == base.PaymentProvider.iOSAppStore:
            internal_payment_tx.apple_tx_id                 = payment_tx.apple_tx_id
            internal_payment_tx.apple_web_line_order_tx_id  = ''
            internal_payment_tx.apple_original_tx_id        = payment_tx.apple_tx_id
        elif internal_payment_tx.provider == base.PaymentProvider.Rangeproof:
            internal_payment_tx.rangeproof_order_id         = payment_tx.rangeproof_order_id

        already_exists = False
        for it in get_unredeemed_payments_list(conn):
            if internal_payment_tx.provider == base.PaymentProvider.GooglePlayStore:
                if it.google_payment_token == payment_tx.google_payment_token and it.google_order_id == payment_tx.google_order_id:
                    already_exists = True
            elif internal_payment_tx.provider == base.PaymentProvider.iOSAppStore:
                if it.apple.tx_id == payment_tx.apple_tx_id:
                    already_exists = True
            elif internal_payment_tx.provider == base.PaymentProvider.Rangeproof:
                if it.rangeproof_order_id == payment_tx.rangeproof_order_id:
                    already_exists = True

            if already_exists:
                break

        if not already_exists:
            THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION = True
            expiry_unix_ts_ms = redeemed_unix_ts_ms + dev_args.duration_ms

            platform_obfuscated_account_id: bytes | str = b''
            if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
                platform_obfuscated_account_id = google_obfuscated_account_id_from_master_pkey(master_pkey)
            elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
                platform_obfuscated_account_id = apple_obfuscated_account_id_from_master_pkey(master_pkey)
            elif payment_tx.provider == base.PaymentProvider.Rangeproof:
                pass
            else:
                assert False, "Invalid code path"

            add_unredeemed_payment(conn                              = conn,
                                   payment_tx                        = internal_payment_tx,
                                   plan                              = dev_args.plan,
                                   unredeemed_unix_ts_ms             = redeemed_unix_ts_ms,
                                   platform_refund_expiry_unix_ts_ms = 0,
                                   platform_obfuscated_account_id    = platform_obfuscated_account_id,
                                   expiry_unix_ts_ms                 = expiry_unix_ts_ms,
                                   err                               = err)

            _ = update_payment_renewal_info(conn                     = conn,
                                            payment_tx               = internal_payment_tx,
                                            grace_period_duration_ms = (60 * 1000) if dev_args.auto_renewing else 0,
                                            auto_renewing            = dev_args.auto_renewing,
                                            err                      = err)

    # Verify some of the request parameters
    hash_to_sign: bytes = make_add_pro_payment_hash(version       = version,
                                                    master_pkey   = master_pkey,
                                                    rotating_pkey = rotating_pkey,
                                                    payment_tx    = payment_tx)

    _ = internal_verify_add_payment_and_get_proof_common_arguments(signing_key   = signing_key,
                                                                   master_pkey   = master_pkey,
                                                                   rotating_pkey = rotating_pkey,
                                                                   hash_to_sign  = hash_to_sign,
                                                                   master_sig    = master_sig,
                                                                   rotating_sig  = rotating_sig,
                                                                   err           = err)
    # Then verify version and time
    if version != 0:
        err.msg_list.append(f'Unrecognised version {version} was given')

    if len(err.msg_list) > 0:
        return result

    # Pre-verification steps complete, continue to add the payment
    result = add_pro_payment(conn,
                             version,
                             signing_key,
                             unix_ts_ms,
                             redeemed_unix_ts_ms,
                             master_pkey,
                             rotating_pkey,
                             payment_tx,
                             err,
                             THIS_WAS_A_DEBUG_PAYMENT_THAT_THE_DB_MADE_A_FAKE_UNCLAIMED_PAYMENT_TO_REDEEM_DO_NOT_USE_IN_PRODUCTION)
    return result

def revoke_master_pkey_proofs_and_allocate_new_gen_id_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey, creation_unix_ts_ms: int) -> AllocatedGenID:
    # Revoke the generation index allocated to the master pkey. This blocks all of the proofs
    # generated by the client that were using that payment.
    _ = db.query(tx.conn, ('''
        WITH prev_user AS (
            SELECT gen_index, expiry_unix_ts_ms
            FROM   users
            WHERE  master_pkey = %(master_pkey)s
        )
        INSERT INTO revocations (gen_index, creation_unix_ts_ms, expiry_unix_ts_ms)
        SELECT      gen_index, %(creation_unix_ts_ms)s, expiry_unix_ts_ms
        FROM        prev_user
    '''), master_pkey         = bytes(master_pkey),
          creation_unix_ts_ms = creation_unix_ts_ms)

    # If the use had any left over payments that are valid to use, we can allocate them a new
    # generation ID for subsequent proofs to be generated under. Clients will notice that their
    # current proofs on the old generation ID are revoked (via the previous function here) and
    # re-query the backend to generate a new one.
    result = _allocate_new_gen_id_if_master_pkey_has_payments(tx, master_pkey)
    return result

def expire_by_unix_ts_ms(tx: db.SQLTransaction, unix_ts_ms: int, last_expire_unix_ts_ms: int) -> set[nacl.signing.VerifyKey]:
    log.info(f'Expire by ts (ts={base.readable_unix_ts_ms(unix_ts_ms)})')

    # `status` is no longer stored: a payment's expiry is derived from expiry_unix_ts_ms (see
    # derive_payment_status), so "expiring" mutates no rows. We only enumerate the payments that
    # crossed their expiry within this run's window (last_expire, now] and are not revoked, so the
    # caller can report how many users just lost an entitlement. Windowing on the *previous*
    # last_expire keeps each payment counted exactly once across successive runs (the row itself is
    # untouched, so without the window every run would re-count every already-expired payment).
    result_set = db.query(tx.conn, ('''
        SELECT (SELECT master_pkey FROM users WHERE users.id = payments.user_id)
        FROM   payments
        WHERE  %(now)s >= expiry_unix_ts_ms
          AND  expiry_unix_ts_ms > %(last_expire)s
          AND  revoked_unix_ts_ms IS NULL
    '''), now         = unix_ts_ms,
          last_expire = last_expire_unix_ts_ms)

    result: set[nacl.signing.VerifyKey] = set()
    for row in result_set:
        if row[0]:
            master_pkey = nacl.signing.VerifyKey(bytes(row[0]))
            result.add(master_pkey)
    return result

def round_unix_ts_ms_to_next_day_with_platform_testing_support(payment_provider: base.PaymentProvider, unix_ts_ms: int):
    result_unix_ts_ms = unix_ts_ms
    """For different platforms in their testing environments, they have different timespans
    for a day, for example in Google 1 day is 10s. We handle that explicitly here."""
    if base.PLATFORM_TESTING_ENV:
        match payment_provider:
            case base.PaymentProvider.Rangeproof:
                result_unix_ts_ms = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
            case base.PaymentProvider.Nil:
                result_unix_ts_ms = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
            case base.PaymentProvider.GooglePlayStore:
                ms_in_google_day: int = 10 * 1000 # NOTE: In google 1 day is 10s
                result_unix_ts_ms = ((unix_ts_ms + (ms_in_google_day - 1)) // ms_in_google_day) * ms_in_google_day
            case base.PaymentProvider.iOSAppStore:
                result_unix_ts_ms = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
    else:
        result_unix_ts_ms = base.round_unix_ts_ms_to_next_day(unix_ts_ms)
    return result_unix_ts_ms

def generate_pro_proof(conn: psycopg.Connection,
                       version:        int,
                       signing_key:    nacl.signing.SigningKey,
                       gen_index_salt: bytes,
                       master_pkey:    nacl.signing.VerifyKey,
                       rotating_pkey:  nacl.signing.VerifyKey,
                       unix_ts_ms:     int,
                       master_sig:     bytes,
                       rotating_sig:   bytes,
                       err:            base.ErrorSink) -> ProSubscriptionProof:
    result: ProSubscriptionProof = ProSubscriptionProof()
    log.info(f'Get pro proof (version={version}, master={base.maybe_obfuscate_bytes(master_pkey)}, ts={base.readable_unix_ts_ms(unix_ts_ms)})')

    # Verify some of the request parameters
    hash_to_sign: bytes = make_generate_pro_proof_hash(version       = version,
                                                       master_pkey   = master_pkey,
                                                       rotating_pkey = rotating_pkey,
                                                       unix_ts_ms    = unix_ts_ms)

    _ = internal_verify_add_payment_and_get_proof_common_arguments(signing_key   = signing_key,
                                                                   master_pkey   = master_pkey,
                                                                   rotating_pkey = rotating_pkey,
                                                                   hash_to_sign  = hash_to_sign,
                                                                   master_sig    = master_sig,
                                                                   rotating_sig  = rotating_sig,
                                                                   err           = err)
    if len(err.msg_list) > 0:
        return result

    # Then verify version
    if version != 0:
        err.msg_list.append(f'Unrecognised version {version} was given')
    if len(err.msg_list) > 0:
        return result

    # All verified, now generate proof
    get_user: GetUserAndPayments | None = None
    with db.transaction(conn) as tx:
        get_user = get_user_and_payments(tx, master_pkey)
    assert get_user

    if get_user.user.master_pkey == bytes(master_pkey):
        # Check that the gen index hash is not revoked
        if is_gen_index_revoked(conn, get_user.user.gen_index):
            err.msg_list.append(f'User {bytes(master_pkey).hex()} payment has been revoked')
        else:
            proof_expiry_unix_ts_ms: int = _build_proof_clamped_expiry_time(unix_ts_ms=unix_ts_ms, proposed_expiry_unix_ts_ms=get_user.user.expiry_unix_ts_ms)
            if unix_ts_ms <= proof_expiry_unix_ts_ms:
                result = build_proof(gen_index         = get_user.user.gen_index,
                                     rotating_pkey     = rotating_pkey,
                                     expiry_unix_ts_ms = proof_expiry_unix_ts_ms,
                                     signing_key       = signing_key,
                                     gen_index_salt    = gen_index_salt);
            else:
                payment_expiry_unix_ts_ms = get_user.user.expiry_unix_ts_ms - get_user.user.grace_period_duration_ms if get_user.user.auto_renewing else 0
                err.msg_list.append(f'User {bytes(master_pkey).hex()} entitlement expired at {base.readable_unix_ts_ms(get_user.user.expiry_unix_ts_ms)} ({base.readable_unix_ts_ms(payment_expiry_unix_ts_ms)} + {get_user.user.grace_period_duration_ms})')
    else:
        err.msg_list.append(f'User {bytes(master_pkey).hex()} does not have an active payment registered for it')

    return result

def expire_payments_revocations_and_users(conn: psycopg.Connection, unix_ts_ms: int) -> ExpireResult:
    result = ExpireResult()
    with db.transaction(conn) as tx:
        # Retrieve the last expiry time that was executed
        runtime_result                     = db.query_one(tx.conn, '''SELECT last_expire_unix_ts_ms FROM runtime''')
        assert runtime_result

        last_expire_unix_ts_ms:       int  = runtime_result[0]
        already_done_by_someone_else: bool = last_expire_unix_ts_ms >= unix_ts_ms
        log.info(f'Expire payments/revocs/users (pid={os.getpid()}, ts={base.readable_unix_ts_ms(unix_ts_ms)}, last_expire={last_expire_unix_ts_ms}, already_done_by_someone_else={already_done_by_someone_else})')
        if not already_done_by_someone_else:
            # Update the timestamp that we executed DB expiry
            _ = db.query(tx.conn, '''UPDATE runtime SET last_expire_unix_ts_ms = %s''', unix_ts_ms)

            # Count payments that newly crossed their (derived) expiry this run. Pass the *previous*
            # last_expire (read above, before the UPDATE) so the window is (last_expire, now].
            master_pkeys: set[nacl.signing.VerifyKey] = expire_by_unix_ts_ms(tx=tx, unix_ts_ms=unix_ts_ms, last_expire_unix_ts_ms=last_expire_unix_ts_ms)
            result.payments                           = len(master_pkeys)

            # Delete expired revocations
            rev_result                                = db.query(tx.conn, '''DELETE FROM revocations WHERE %s >= expiry_unix_ts_ms''', unix_ts_ms)
            result.revocations                        = rev_result.rowcount

            # Delete expired users
            users_result                              = db.query(tx.conn, '''DELETE FROM users WHERE id NOT IN (SELECT user_id FROM payments WHERE user_id IS NOT NULL)''')
            result.users                              = users_result.rowcount

            # Delete expired apple notification UUIDs
            apple_result                              = db.query(tx.conn, '''DELETE FROM apple_notification_uuid_history WHERE %s >= expiry_unix_ts_ms''', unix_ts_ms)
            result.apple_notification_uuid_history    = apple_result.rowcount

            # Delete expired google notifications (but only if they have been handled)
            google_result                      = db.query(tx.conn, '''DELETE FROM google_notification_history WHERE %s >= expiry_unix_ts_ms AND handled = TRUE''', unix_ts_ms)
            result.google_notification_history = google_result.rowcount

        result.already_done_by_someone_else = already_done_by_someone_else
        result.success                      = True
    return result

def add_user_error_tx(tx: db.SQLTransaction, error: UserError, unix_ts_ms: int):
    match error.provider:
        case base.PaymentProvider.Rangeproof:
            pass
        case base.PaymentProvider.Nil:
            pass
        case base.PaymentProvider.GooglePlayStore:
            assert len(error.google_payment_token) > 0
            _ = db.query(tx.conn, '''INSERT INTO user_errors (payment_provider, payment_id, unix_ts_ms) VALUES (%(provider)s, %(payment_id)s, %(ts)s) ON CONFLICT DO NOTHING''',
                 provider=int(error.provider.value),
                 payment_id=error.google_payment_token,
                 ts=unix_ts_ms)
        case base.PaymentProvider.iOSAppStore:
            assert len(error.apple_original_tx_id) > 0
            _ = db.query(tx.conn, '''INSERT INTO user_errors (payment_provider, payment_id, unix_ts_ms) VALUES (%(provider)s, %(payment_id)s, %(ts)s) ON CONFLICT DO NOTHING''',
                 provider=int(error.provider.value),
                 payment_id=error.apple_original_tx_id,
                 ts=unix_ts_ms)

def add_user_error(conn: psycopg.Connection, error: UserError, unix_ts_ms: int):
    assert error.provider != base.PaymentProvider.Nil
    with db.transaction(conn) as tx:
        add_user_error_tx(tx, error, unix_ts_ms)

def has_user_error_tx(tx: db.SQLTransaction, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    row = db.query_one(tx.conn,
                       'SELECT 1 FROM user_errors WHERE payment_id = %s AND payment_provider = %s',
                       payment_id,
                       int(payment_provider.value))
    result = row is not None
    return result

def has_user_error_from_master_pkey_tx(tx: db.SQLTransaction, master_pkey: nacl.signing.VerifyKey) -> bool:
    # NOTE: Rangeproof payments cannot have user errors
    row = db.query_one(tx.conn, (f'''
SELECT EXISTS (
    SELECT 1
    FROM payments p
    LEFT JOIN user_errors ue
        ON (p.payment_provider = '{base.PaymentProvider.iOSAppStore.value}'     AND p.apple_original_tx_id = ue.payment_id)
        OR (p.payment_provider = '{base.PaymentProvider.GooglePlayStore.value}' AND p.google_payment_token = ue.payment_id)
    WHERE p.user_id = (SELECT id FROM users WHERE master_pkey = %s)
    AND ue.payment_id IS NOT NULL
) AS has_error;
'''), bytes(master_pkey))
    result = bool(row[0] == 1) if row else False
    return result

def has_user_error(conn: psycopg.Connection, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    result = False
    with db.transaction(conn) as tx:
        result = has_user_error_tx(tx, payment_provider, payment_id)
    return result;

def delete_user_errors_tx(tx: db.SQLTransaction, payment_provider: base.PaymentProvider, payment_id: str) -> bool:
    row    = db.query(tx.conn, 'DELETE FROM user_errors WHERE payment_provider = %s AND payment_id = %s', int(payment_provider.value), payment_id)
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
            WHERE p.payment_provider = %(provider)s AND p.google_payment_token = %(token)s AND p.google_order_id = %(order_id)s
        ''', provider  = payment_tx.provider.value,
              token    = payment_tx.google_payment_token,
              order_id = payment_tx.google_order_id, row_factory=db.dict_row)

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)

    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        result_set = db.query(tx.conn, f'''
                SELECT {PAYMENTS_COLUMNS}
                FROM {PAYMENTS_FROM}
                WHERE p.payment_provider = %(provider)s AND p.apple_original_tx_id = %(orig_tx_id)s AND p.apple_tx_id = %(tx_id)s AND p.apple_web_line_order_tx_id = %(line_order_tx_id)s
        ''', provider          = payment_tx.provider.value,
              orig_tx_id       = payment_tx.apple_original_tx_id,
              tx_id            = payment_tx.apple_tx_id,
              line_order_tx_id = payment_tx.apple_web_line_order_tx_id, row_factory=db.dict_row)

        record = result_set.fetchone()
        if record:
            result = payment_row_from_dict(record)
    elif payment_tx.provider == base.PaymentProvider.Rangeproof:
        result_set = db.query(tx.conn, f'''
                SELECT {PAYMENTS_COLUMNS}
                FROM {PAYMENTS_FROM}
                WHERE p.payment_provider = %s AND p.rangeproof_order_id = %s
        ''', payment_tx.provider.value, payment_tx.rangeproof_order_id, row_factory=db.dict_row)

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

def set_refund_requested_unix_ts_ms_tx(tx: db.SQLTransaction, payment_tx: UserPaymentTransaction, unix_ts_ms: int) -> bool:
    rows: db.Result | None = None
    if payment_tx.provider == base.PaymentProvider.Rangeproof or payment_tx.provider == base.PaymentProvider.Nil:
        return False

    if payment_tx.provider == base.PaymentProvider.GooglePlayStore:
        rows = db.query(tx.conn, '''
            UPDATE payments
            SET    refund_requested_unix_ts_ms = %(ts)s
            WHERE  payment_provider = %(provider)s AND google_payment_token = %(token)s AND google_order_id = %(order_id)s
        ''', ts        = unix_ts_ms,
            provider = payment_tx.provider.value,
            token    = payment_tx.google_payment_token,
            order_id = payment_tx.google_order_id)
    elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
        rows = db.query(tx.conn, '''
            UPDATE payments
            SET    refund_requested_unix_ts_ms = %(ts)s
            WHERE  payment_provider = %(provider)s AND apple_tx_id = %(tx_id)s
        ''', ts        = unix_ts_ms,
              provider = payment_tx.provider.value,
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
                WHERE  p.payment_provider = %(provider)s AND p.google_payment_token = %(token)s AND p.google_order_id = %(order_id)s
            ''', provider = payment_tx.provider.value,
                 token    = payment_tx.google_payment_token,
                 order_id = payment_tx.google_order_id)
        elif payment_tx.provider == base.PaymentProvider.iOSAppStore:
            row = db.query_one(tx.conn, '''
                SELECT u.master_pkey
                FROM   payments p JOIN users u ON u.id = p.user_id
                WHERE  p.payment_provider = %s AND p.apple_tx_id = %s
            ''', payment_tx.provider.value, payment_tx.apple_tx_id)

        if row:
            master_pkey = nacl.signing.VerifyKey(bytes(row[0]))
            _update_user_expiry_grace_and_renew_flag_from_payment_list_tx(tx, master_pkey)

    return success

def set_refund_requested_unix_ts_ms(conn: psycopg.Connection,
                                    payment_tx: UserPaymentTransaction,
                                    unix_ts_ms: int) -> bool:
    result = False
    with db.transaction(conn) as tx:
        result = set_refund_requested_unix_ts_ms_tx(tx, payment_tx, unix_ts_ms)
    return result

def apple_add_notification_uuid_tx(tx: db.SQLTransaction, uuid: str, expiry_unix_ts_ms: int):
    # uuid is the PRIMARY KEY; DO NOTHING keeps this idempotent (and crash-free) if the caller's
    # prior existence check raced with a concurrent insert of the same notification.
    _ = db.query(tx.conn, ('''
        INSERT INTO apple_notification_uuid_history (uuid, expiry_unix_ts_ms)
        VALUES      (%s, %s)
        ON CONFLICT (uuid) DO NOTHING
    '''), uuid, expiry_unix_ts_ms)

def apple_notification_uuid_is_in_db_tx(tx: db.SQLTransaction, uuid: str) -> bool:
    row = db.query_one(tx.conn, ('''
        SELECT 1
        FROM   apple_notification_uuid_history
        WHERE  uuid = %s
    '''), uuid)
    result = row is not None
    return result

def apple_set_notification_checkpoint_unix_ts_ms(tx: db.SQLTransaction, checkpoint_unix_ts_ms: int):
    _ = db.query(tx.conn, ('''
        UPDATE runtime
        SET    apple_notification_checkpoint_unix_ts_ms = %s
    '''), checkpoint_unix_ts_ms)

def google_add_notification_id_tx(tx: db.SQLTransaction, message_id: int, expiry_unix_ts_ms: int, payload: str):
    maybe_payload: str | None = None
    if len(payload):
        maybe_payload = payload

    _ = db.query(tx.conn, ('''
            INSERT INTO google_notification_history (message_id, handled, payload, expiry_unix_ts_ms)
            VALUES      (%(message_id)s, FALSE, %(payload)s, %(expiry)s)
    '''), message_id = message_id,
          payload    = maybe_payload,
          expiry     = expiry_unix_ts_ms)

def google_set_notification_handled(tx: db.SQLTransaction, message_id: int, delete: bool) -> bool:
    if delete:
        rows = db.query(tx.conn, ('''DELETE FROM google_notification_history WHERE message_id = %s'''), message_id)
    else:
        rows = db.query(tx.conn, ('''UPDATE google_notification_history SET handled = TRUE, payload = NULL WHERE message_id = %s'''), message_id)
    result: bool = rows.rowcount >= 1
    return result

def google_get_unhandled_notification_iterator(tx: db.SQLTransaction) -> collections.abc.Iterator[GoogleUnhandledNotificationIterator]:
    result_set = db.query(tx.conn, ('SELECT message_id, payload, expiry_unix_ts_ms FROM google_notification_history WHERE NOT handled'))
    return typing.cast(collections.abc.Iterator[GoogleUnhandledNotificationIterator], result_set)

def google_notification_message_id_is_in_db_tx(tx: db.SQLTransaction, message_id: int) -> GoogleNotificationMessageIDInDB:
    row    = typing.cast(tuple[int] | None, db.query_one(tx.conn, '''SELECT handled FROM google_notification_history WHERE message_id = %s''', message_id))
    result = GoogleNotificationMessageIDInDB()
    if row is not None:
        result.present = True
        result.handled = row[0] > 0 # NOTE: Should always be 0 or 1 but we'll be extra careful
    return result

def _get_date_group_expr_sql(column: str, period: ReportPeriod) -> str:
    """Generate the date-grouping SQL expression for a report period."""
    match period:
        case ReportPeriod.Daily:
            return f"TO_CHAR(TO_TIMESTAMP({column}/1000), 'YYYY-MM-DD')"
        case ReportPeriod.Weekly:
            return f"TO_CHAR(TO_TIMESTAMP({column}/1000), 'IYYY-IW')"
        case ReportPeriod.Monthly:
            return f"TO_CHAR(TO_TIMESTAMP({column}/1000), 'YYYY-MM')"

def _get_period_end_ts_sql(period_str: str, period: ReportPeriod) -> str:
    """Generate the period-end timestamp SQL expression for a report period."""
    if period == ReportPeriod.Weekly:
        year, week = period_str.split("-")
        return f"(TO_TIMESTAMP('{year}-01-01', 'YYYY-MM-DD') + INTERVAL '{(int(week)+1)*7 - 3} days' - INTERVAL '1 day' + INTERVAL '1 day' - INTERVAL '1 second')::bigint * 1000 + 86399"
    elif period == ReportPeriod.Monthly:
        return f"(DATE_TRUNC('month', '{period_str}-01'::date) + INTERVAL '1 month' - INTERVAL '1 second')::bigint * 1000 + 86399"
    else:
        return f"(DATE_TRUNC('day', '{period_str}'::date) + INTERVAL '1 day' - INTERVAL '1 second')::bigint * 1000 + 86399"

def _format_period_label(period_str: str, period: ReportPeriod) -> str:
    """Format period string for display."""
    if period == ReportPeriod.Weekly:
        year, week = period_str.split("-")
        date = datetime.datetime.fromisocalendar(year=int(year), week=int(week), day=1)
        return date.strftime('%F') + f' (W{week})'
    return period_str

def generate_report_rows(conn: psycopg.Connection, period: ReportPeriod, limit: int | None) -> list[ReportRow]:
    def fetch_counts(tx_conn: psycopg.Connection, period: ReportPeriod, unix_ts_ms_column: str, where_clause: str) -> dict[str, int]:
        group_by_expr = _get_date_group_expr_sql(unix_ts_ms_column, period)

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
        date_expr = _get_date_group_expr_sql("unredeemed_unix_ts_ms", period)

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
                WHERE {end_ts} >= unredeemed_unix_ts_ms
                  AND {end_ts} <= expiry_unix_ts_ms
                  AND revoked_unix_ts_ms IS NULL
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
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = "redeemed_unix_ts_ms IS NULL AND revoked_unix_ts_ms IS NULL",
        )

        plan_1m: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"plan = '{base.ProPlan.OneMonth.value}'",
        )

        plan_3m: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"plan = '{base.ProPlan.ThreeMonth.value}'",
        )

        plan_12m: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"plan = '{base.ProPlan.TwelveMonth.value}'",
        )

        google: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"payment_provider = '{base.PaymentProvider.GooglePlayStore.value}'",
        )

        apple: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"payment_provider = '{base.PaymentProvider.iOSAppStore.value}'",
        )

        rangeproof: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = f"payment_provider = '{base.PaymentProvider.Rangeproof.value}'",
        )

        new_subs: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "unredeemed_unix_ts_ms",
            where_clause      = "unredeemed_unix_ts_ms IS NOT NULL AND unredeemed_unix_ts_ms > 0",
        )

        refunds_initiated: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "refund_requested_unix_ts_ms",
            where_clause      = "refund_requested_unix_ts_ms > 0",
        )

        revocations: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "revoked_unix_ts_ms",
            where_clause      = "revoked_unix_ts_ms IS NOT NULL AND revoked_unix_ts_ms > 0",
        )

        cancelled: dict[str, int] = fetch_counts(
            tx_conn           = tx.conn,
            period            = period,
            unix_ts_ms_column = "expiry_unix_ts_ms",
            where_clause      = f"NOT auto_renewing AND revoked_unix_ts_ms IS NULL",
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
