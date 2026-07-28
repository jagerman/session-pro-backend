'''
The base layer contains common utilities that is useful to other files in the project and should
have no dependency on any project files, only, native Python packages. Typically useful to share
functionality from the testing suite and the project but not limited to.
'''

import dataclasses
import datetime
import enum
import glob
import json
import logging
import math
import os
import pathlib
import sys
import threading
import time
import typing
import typing_extensions
import urllib.request

# NOTE: Constants
# Backend software version, reported by the /status health endpoint. Bump on release; there is no other
# version marker in the system (the wire/proof formats are versioned separately — see the wire spec).
BACKEND_VERSION: str = '0.2.0'
SECONDS_IN_DAY: int = 60 * 60 * 24
MILLISECONDS_IN_DAY: int = 60 * 60 * 24 * 1000
MILLISECONDS_IN_MONTH: int = MILLISECONDS_IN_DAY * 30
SECONDS_IN_MONTH: int = SECONDS_IN_DAY * 30
MILLISECONDS_IN_YEAR: int = MILLISECONDS_IN_DAY * 365
SECONDS_IN_YEAR: int = SECONDS_IN_DAY * 365

# How far the timestamp in a signed request may differ from the backend's clock. This currently matches
# the storage server's store tolerance for onion-request forwarded messages as per:
#
#   https://github.com/session-foundation/session-storage-server/blob/3d159a10d465678d758131c1075c9a6e5b4d95cc/oxenss/rpc/request_handler.h#L48
#
# We choose the upper-bound of tolerance for requests for maximum compatibility. Currently, in the flask
# context, no information is available to indicate if the request was forwarded or not so we default to
# assuming it is. All platforms are designed to interact with the backend using onion requests.
#
# It is a protocol constant, not merely a server-side check: the backend's revocation-skip math
# (revoke_payments_by_id_internal) depends on the same skew bound, so both must read this one value.
DEFAULT_TIMESTAMP_TOLERANCE: datetime.timedelta = datetime.timedelta(seconds=70)

# Every instant in this codebase is a tz-aware UTC `datetime` and every duration a `timedelta`. Integer
# epochs live ONLY in the converters below, at two kinds of boundary with distinct units:
#   - MILLISECONDS: the payment providers (Apple/Google App Store APIs) genuinely speak ms, so their
#     ingest/egress uses the `*_ms` pair.
#   - SECONDS: our own wire + proof format is seconds (the wire spec's unit, item 5b), so every
#     client-facing boundary and every signed hash uses the `*_seconds` pair. Wire seconds are integer
#     everywhere except two upstream provider event instants (`purchased_ts`, `revoked_ts`) that keep
#     the provider's sub-second precision as a float via `unix_seconds_float_from_datetime` — see the
#     wire spec §1. Nothing hashed is ever a float.
# The two never mix: a value crossing the provider boundary is ms, a value crossing our wire is seconds.
EPOCH: datetime.datetime = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def datetime_from_unix_ms(unix_ms: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(milliseconds=unix_ms)


def unix_ms_from_datetime(value: datetime.datetime) -> int:
    # Exact integer milliseconds via integer division — never float `.timestamp()` truncation.
    return (value - EPOCH) // datetime.timedelta(milliseconds=1)


def timedelta_from_ms(ms: int) -> datetime.timedelta:
    return datetime.timedelta(milliseconds=ms)


def ms_from_timedelta(value: datetime.timedelta) -> int:
    return value // datetime.timedelta(milliseconds=1)


def datetime_from_unix_seconds(unix_s: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(seconds=unix_s)


def unix_seconds_from_datetime(value: datetime.datetime) -> int:
    # Exact integer seconds via integer division — never float `.timestamp()` truncation. Sub-second
    # precision (a provider ms value) is floored: our wire is second-resolution by spec.
    return (value - EPOCH) // datetime.timedelta(seconds=1)


def timedelta_from_seconds(s: int) -> datetime.timedelta:
    return datetime.timedelta(seconds=s)


def seconds_from_timedelta(value: datetime.timedelta) -> int:
    return value // datetime.timedelta(seconds=1)


def unix_seconds_float_from_datetime(value: datetime.datetime) -> float:
    # Fractional UNIX seconds (true division) — preserves the sub-second precision of an upstream
    # provider instant on the wire. ONLY for the enumerated float display fields (wire spec §1); never
    # for a hashed value, which must be integer seconds via `unix_seconds_from_datetime`.
    return (value - EPOCH) / datetime.timedelta(seconds=1)


# NOTE: Default grace period we add to the subscription payments because in real world situations
# no payment processor/billing cycle is going to bill exactly on the dot due to real-world
# extenuating circumstances. In those cases we provide a small but reasonable grace period of 1
# hour to cover that.
#
# For Google we are not informed of the user's grace period until they enter the renewing state.
# What this means then is if the user is observing their Pro state at the boundary of expiry they
# may witness their account flicker from Pro to not-pro, to Pro again once they enter the renewal
# phase (and that the Session Pro Backend server is awaiting for the notification from Google which
# tells us of their _real_ grace period).
#
# In this situation having a small, temporary grace period of 1 hour prevents that edge case.
#
# For Apple no grace period is configured but again due to extenuating circumstances the time at
# which the billing for the end of the subscription cycle is executed can vary and similarly, users
# may encounter that they lose Pro because the billing was late. The 1 hour grace period looks to
# minimise that.
DEFAULT_APPLE_GRACE_PERIOD: datetime.timedelta = datetime.timedelta(hours=1)

# NOTE: Always the same as Apple, unless we're in a testing environment where this gets changed
DEFAULT_GOOGLE_GRACE_PERIOD: datetime.timedelta = DEFAULT_APPLE_GRACE_PERIOD

# NOTE: Global variables
DB_URL = ''
UNSAFE_LOGGING = False
PROVIDER_TESTING_ENV = False
# When set, every payment provider treats all of its OUTBOUND interactions as already-succeeded and
# performs no external side-effect: mutations (e.g. Google acknowledge) become no-ops and gating reads
# return a synthetic success. Each provider module owns what dry-run means for it (see providers/).
# It does NOT fabricate payments — a real witnessed payment must still exist — so it is not a "grant
# arbitrary Pro" backdoor; worst-case misuse breaks real subscriptions, it does not mint entitlements.
PROVIDER_DRY_RUN = False

# NOTE: Restricted type-set, JSON obviously supports much more than this, but
# our use-case only needs a small subset of it as of current so KISS.
JSONPrimitive: typing.TypeAlias = str | int | float | bool | None
JSONValue: typing.TypeAlias = JSONPrimitive | dict[str, 'JSONValue'] | list['JSONValue']
JSONObject: typing.TypeAlias = dict[str, JSONValue]
JSONArray: typing.TypeAlias = list[JSONValue]


@dataclasses.dataclass
class BackupRotationDryRun:
    to_keep: list[pathlib.Path] = dataclasses.field(default_factory=list)
    to_delete: list[pathlib.Path] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class PaymentProviderData:
    id: int = 0


class PaymentProvider(enum.StrEnum):
    # Values are the wire/DB `code` strings (see docs/pro-wire-protocol.md §1). Nil is an in-Python
    # sentinel only — it is never a wire value and is never seeded into the payment_providers lookup.
    Nil = 'nil'
    GooglePlayStore = 'google_play'
    iOSAppStore = 'app_store'
    Rangeproof = 'rangeproof'


@dataclasses.dataclass
class PaymentProviderTransaction:
    provider: PaymentProvider = PaymentProvider.Nil
    apple_original_tx_id: str = ''
    apple_tx_id: str = ''
    apple_web_line_order_tx_id: str = ''
    google_payment_token: str = ''
    google_order_id: str = ''
    rangeproof_order_id: str = ''


class PaymentStatus(enum.StrEnum):
    # A DERIVED display value (wire/logging), NOT a stored column — computed from a payment's
    # redeemed/revoked/expiry timestamps against a caller-supplied clock (see
    # backend.derive_payment_status). Values are the wire `code`s (docs/pro-wire-protocol.md §1).
    Nil = 'nil'
    Unredeemed = 'unredeemed'
    Redeemed = 'redeemed'
    Expired = 'expired'
    Revoked = 'revoked'


class ProPlan(enum.StrEnum):
    """Universal Pro Plan Identifier.

    Values are the wire/DB `code` strings — compact billing-period codes (see
    docs/pro-wire-protocol.md §1). Nil is an in-Python sentinel only (never a wire/DB value).
    """

    Nil = 'nil'
    OneMonth = '1m'
    ThreeMonth = '3m'
    TwelveMonth = '1y'

    @classmethod
    def from_string(cls, val: str):
        # Accept either the member name ("OneMonth") or the code value ("1m"), case-insensitively.
        val_lower = val.lower()
        for it in ProPlan:
            if it.name.lower() == val_lower or it.value == val_lower:
                return it
        return None


class LogFormatter(logging.Formatter):
    @typing_extensions.override
    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None):
        dt = datetime.datetime.fromtimestamp(record.created)
        result = dt.strftime('%y-%m-%d %H:%M:%S.%f')[:-3]
        return result


@dataclasses.dataclass
class ErrorSink:
    '''
    Helper class to pass to functions that want to return error messages without unwinding the stack
    by using throwing exceptions.

    The typical pattern in that this construct is used is calling a sequence of functions that can
    error but have no dependency on each other. Errors are accumulated into the sink and checked at
    the end where it reports the error from the sink and returns a failure if there is one.

    See the parsing code in server.py for an example of where this is useful.
    '''

    msg_list: list[str] = dataclasses.field(default_factory=list)

    def has(self) -> bool:
        result = len(self.msg_list) > 0
        return result

    def build(self) -> str:
        result = '\n  '.join(self.msg_list)
        return result


class ErrorCode(enum.StrEnum):
    '''Machine slugs for the response envelope's `error_code` (wire spec §5.1). Stable, additive: a client
    keys its localized (Crowdin) message off these; an unrecognised one degrades to status-level handling.'''

    invalid_request = 'invalid_request'  # fail:  malformed/missing/wrong-type field, bad hex, bad provider
    bad_signature = 'bad_signature'  # fail:  a request signature failed to verify
    stale_request = 'stale_request'  # fail:  request timestamp outside the replay-tolerance window
    # NB: `subscription_expired`, NOT `expired` — the error_code vocabulary is deliberately DISJOINT from
    # get-details `user_status` {never,active,expired}, so no token identifies two different fields.
    subscription_expired = 'subscription_expired'  # fail:  the user's entitlement has lapsed
    not_subscribed = 'not_subscribed'  # fail:  no entitlement on record (never subscribed / pruned)
    revoked = 'revoked'  # fail:  the user's current entitlement was revoked
    internal_error = 'internal_error'  # error: backend fault


class ApiError(Exception):
    '''An error that renders as a response envelope `{status, error_code, error}` (server.py's error
    handler catches it). Raise these instead of threading an ErrorSink through the HTTP request path.'''

    wire_status: str = 'error'
    default_code: ErrorCode = ErrorCode.internal_error

    def __init__(self, message: str, code: ErrorCode | None = None):
        super().__init__(message)
        self.code: ErrorCode = code if code is not None else self.default_code


class FailError(ApiError):
    '''The request was understood but rejected by the client's input or a state precondition (wire
    `status: "fail"`). Default slug `invalid_request`; pass a more specific `code` where one applies.'''

    wire_status = 'fail'
    default_code = ErrorCode.invalid_request


class ServerError(ApiError):
    '''The backend faulted handling the request (wire `status: "error"`). The client did nothing wrong.'''

    wire_status = 'error'
    default_code = ErrorCode.internal_error


@dataclasses.dataclass
class TableStrings:
    name: str = ''
    contents: list[list[str]] = dataclasses.field(default_factory=list)


class AsyncSessionWebhookLogHandler(logging.Handler):
    webhook_url: str
    display_name: str
    _submit_thread: threading.Thread
    timeout: int = 2

    def __init__(self, url: str, name: str):
        super().__init__()
        self.webhook_url = url
        self.display_name = name
        assert len(self.display_name) <= 100, f'Display name must be less than 100 characters: {len(self.display_name)}'
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._queue_dirtied = threading.Event()
        self.msg_queue: list[str] = []
        self._submit_thread = threading.Thread(target=self._worker, daemon=True)
        self._stop_event = threading.Event()
        self._submit_thread.start()

    def emit_text(self, text: str, date_prefix: bool = True):
        prefix: str = ''
        if date_prefix:
            date = datetime.datetime.fromtimestamp(time.time())
            prefix = date.strftime('%y-%m-%d %H:%M:%S.%f')[:-3]

        max_size = 128
        with self._lock:
            if len(self.msg_queue) >= max_size:
                self.msg_queue = self.msg_queue[-(max_size - 2) :]
                self.msg_queue.append(f"{prefix} Message queue was full, overwriting old message")
            self.msg_queue.append(f"{prefix} {text}"[:2000])
        self._queue_dirtied.set()

    @typing_extensions.override
    def emit(self, record: logging.LogRecord):
        if record.levelno < logging.WARNING:
            return
        self.emit_text(self.format(record)[:2000], date_prefix=False)

    def _worker(self):
        while True:
            self._queue_dirtied.wait()
            if self._stop_event.is_set():
                break
            self._queue_dirtied.clear()

            # Extract batch of messages to send with lock
            while True:
                batch: list[str] = []
                with self._lock:
                    batch_size = min(len(self.msg_queue), 8)  # Pump at most, 8 at a time then yield
                    batch = self.msg_queue[:batch_size]
                    self.msg_queue = self.msg_queue[batch_size:]

                for it in batch:  # Blocking send
                    payload: dict[str, str] = {"text": "```\n" + it + "\n```", "display_name": self.display_name}
                    request = urllib.request.Request(
                        self.webhook_url,
                        data=json.dumps(payload).encode('utf-8'),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    try:
                        urllib.request.urlopen(request, timeout=self.timeout)
                    except Exception as e:
                        print(f"Session webhook send failed: {e}", file=sys.stderr)

                with self._lock:
                    if len(self.msg_queue) == 0:
                        break

    @typing_extensions.override
    def close(self):
        self._stop_event.set()
        self._queue_dirtied.set()
        if self._submit_thread.is_alive():
            self._submit_thread.join(timeout=2)
        super().close()


def verify_payment_provider(payment_provider: PaymentProvider | str, err: ErrorSink | None = None) -> bool:
    if isinstance(payment_provider, PaymentProvider):
        provider = payment_provider
    else:
        try:
            provider = PaymentProvider(payment_provider)
        except ValueError:
            _require_fail('Unrecognised payment provider: {}'.format(payment_provider), err)
            return False

    if provider == PaymentProvider.Nil:
        _require_fail('Nil payment provider is invalid, must be set to a provider', err)
        return False

    return True


def hex_to_bytes(hex: str, label: str, hex_len: int, err: ErrorSink | None = None) -> bytes:
    if len(hex) != hex_len:
        _require_fail(f'{label} was not {hex_len} characters, was {len(hex)} characters', err)
        return b''
    try:
        return bytes.fromhex(hex)
    except Exception as e:
        _require_fail(f'{label} was not valid hex: {e}', err)
    return b''


def readable(value: datetime.datetime) -> str:
    # Compact UTC timestamp for logs, millisecond precision (no strftime %f-slice hack).
    return value.astimezone(datetime.timezone.utc).isoformat(sep=' ', timespec='milliseconds')


def print_unicode_table(rows: list[list[str]]) -> None:
    # Calculate maximum width for each column
    col_widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]

    # Print top border
    line = '┌'
    for i, width in enumerate(col_widths):
        line += '─' * (width + 2)  # +2 for padding spaces
        if i < len(col_widths) - 1:
            line += '┬'
    line += '┐'
    print(line)

    # Print header (first row)
    header_row = '│'
    for i, field in enumerate(rows[0]):
        header_row += f' {field:<{col_widths[i]}} │'
    print(header_row)

    # Print separator between header and data
    separator = '├'
    for i, width in enumerate(col_widths):
        separator += '─' * (width + 2)
        if i < len(col_widths) - 1:
            separator += '┼'
    separator += '┤'
    print(separator)

    # Print data rows
    for row in rows[1:]:
        row_str = '│'
        for i, field in enumerate(row):
            row_str += f' {field:<{col_widths[i]}} │'
        print(row_str)

    # Print bottom border
    bottom = '└'
    for i, width in enumerate(col_widths):
        bottom += '─' * (width + 2)
        if i < len(col_widths) - 1:
            bottom += '┴'
    bottom += '┘'
    print(bottom)


def round_datetime_to_start_of_day(value: datetime.datetime) -> datetime.datetime:
    return value.astimezone(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def round_datetime_to_next_day(value: datetime.datetime) -> datetime.datetime:
    # Ceil to the next UTC midnight; a value already exactly at midnight stays put (matches the old
    # `(ms + DAY-1)//DAY*DAY` ceil semantics).
    start = round_datetime_to_start_of_day(value)
    return start if start == value else start + datetime.timedelta(days=1)


def format_bytes(size: int):
    units = [(1 << 40, 'TB'), (1 << 30, 'GB'), (1 << 20, 'MB'), (1 << 10, 'kB'), (1, 'B')]
    for base, prefix in units:
        if size >= base:
            formatted_size = size / base
            return f'{formatted_size:.2f} {prefix}'
    return '0.00 B'


def format_seconds(duration_s: float) -> str:
    hours = int(duration_s // 3600)
    minutes = int((duration_s % 3600) // 60)
    seconds = duration_s % 60
    result = ''
    if hours > 0:
        result += f"{hours}h"
    if minutes > 0:
        result += f"{' ' if result else ''}{minutes}m"
    # For seconds: show decimals only if there's a fractional part
    if seconds >= 1 or result == '':  # Always show seconds if no higher units
        if seconds == int(seconds):
            sec_str = str(int(seconds))
        else:
            # Show up to 3 decimal places, strip trailing zeros
            sec_str = f"{seconds:.3f}".rstrip('0').rstrip('.')
        result += f"{' ' if result else ''}{sec_str}s"
    return result if result else '0s'


def obfuscate(val: str) -> str:
    """
    Obfuscate a string by masking the contents preserving the prefix and suffix. If the string is
    less than 3 characters, the original string is retuned.
    """
    if len(val) < 3:
        return val
    n_ends = max(math.floor(len(val) * 0.3), 1)
    return f"{val[:n_ends]}…{val[-n_ends:]}"


def maybe_obfuscate(val: typing.Any) -> str:
    if UNSAFE_LOGGING:
        return str(val) if val is not None else 'None'
    if val is None:
        return 'None'
    return obfuscate(str(val))


def maybe_obfuscate_bytes(val: typing.Any) -> str:
    return maybe_obfuscate(bytes(val).hex())


def payment_provider_tx_to_safe_string(tx: PaymentProviderTransaction) -> str:
    # Only the active provider's ids are populated; show just those rather than dumping every
    # provider's (mostly-empty) fields.
    match tx.provider:
        case PaymentProvider.iOSAppStore:
            detail = (
                f"apple(orig/tx/web)=({maybe_obfuscate(tx.apple_original_tx_id)}/"
                f"{maybe_obfuscate(tx.apple_tx_id)}/{maybe_obfuscate(tx.apple_web_line_order_tx_id)})"
            )
        case PaymentProvider.GooglePlayStore:
            detail = f"google=({maybe_obfuscate(tx.google_payment_token)}/{maybe_obfuscate(tx.google_order_id)})"
        case PaymentProvider.Rangeproof:
            detail = f"rangeproof={maybe_obfuscate(tx.rangeproof_order_id)}"
        case _:
            detail = "(no provider ids)"
    return f"{tx.provider.name}, {detail}"


def reflect_enum(enum_value: enum.Enum) -> str:
    name = enum_value.name
    value = None
    if isinstance(enum_value, enum.IntEnum):
        value = enum_value.value
    return f'{name} ({value})' if value is not None else name


def extract_keys_recursive(d: dict[str, typing.Any]) -> str:
    """
    Recursively extract keys from a nested dictionary and format them.

    Args:
        d: Dictionary to extract keys from

    Returns:
        The keys as a comma-separated string, nested dicts shown as `key: {subkeys}`, e.g.
        "key1, key2: {subkey1, subkey2}, key3: {subkey: {subsubkey}}". No outer braces — the
        caller wraps them (see safe_dump_dict_keys_or_data).
    """

    return ", ".join(
        f"{key}: {{{extract_keys_recursive(value)}}}" if isinstance(value, dict) else key for key, value in d.items()
    )


def safe_dump_dict_keys_or_data(d: dict[str, typing.Any] | None) -> str:
    """Dump the dict or just the keys if UNSAFE_LOGGING is set"""
    if d is None:
        return "None"
    if UNSAFE_LOGGING:
        return json.dumps(d)
    return "dictionary w/ keys: {" + extract_keys_recursive(d) + "}"


def safe_dump_arbitrary_value_or_type(v: typing.Any) -> str:
    """Dump the value or just its type if UNSAFE_LOGGING is set"""
    result = f'({type(v)}) {v}' if UNSAFE_LOGGING else f'{type(v)}'
    return result


def safe_get_dict_value_type(d: dict[str, typing.Any], key: str) -> str:
    v = d.get(key)
    return safe_dump_arbitrary_value_or_type(v)


# Typed JSON accessors. Two callers, two error models, ONE branch point (`_require_fail`): the HTTP
# request path (server.py) omits `err` → the first bad field raises a client-facing FailError; the
# provider-notification parsers (providers.google_play*) pass an `err` sink → errors accumulate. (The `err`
# arm is transitional — it retires when google_play's error flow moves to exceptions in the
# ErrorSink-removal sweep; see the refactor plan.)
def _require_fail(msg: str, err: ErrorSink | None) -> None:
    if err is not None:
        err.msg_list.append(msg)
    else:
        raise FailError(msg, code=ErrorCode.invalid_request)


# A JSON bool is-a int in Python; exclude it so `true` never satisfies an int/number field.
def _json_is_int(v: typing.Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _json_is_number(v: typing.Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# Single core for every typed accessor below: `ok` tests the value, `convert` normalises it. `required`
# selects the missing-key behaviour — an error (require_*) vs. return `default` (optional_*).
def _json_get(
    d: JSONObject,
    key: str,
    type_name: str,
    ok: typing.Callable[[typing.Any], bool],
    convert: typing.Callable[[typing.Any], typing.Any],
    default: typing.Any,
    required: bool,
    err: ErrorSink | None,
) -> typing.Any:
    if key not in d:
        if required:
            _require_fail(f'Required key "{key}" is missing from JSON: {safe_dump_dict_keys_or_data(d)}', err)
        return default
    if ok(d[key]):
        return convert(d[key])
    _require_fail(f'Key "{key}" value was not {type_name}: "{safe_get_dict_value_type(d, key)}"', err)
    return default


def json_dict_require_str(d: JSONObject, key: str, err: ErrorSink | None = None) -> str:
    return _json_get(d, key, 'a string', lambda v: isinstance(v, str), lambda v: v, '', True, err)


def json_dict_require_int(d: JSONObject, key: str, err: ErrorSink | None = None) -> int:
    return _json_get(d, key, 'an integer', _json_is_int, lambda v: v, 0, True, err)


def json_dict_require_float(d: JSONObject, key: str, err: ErrorSink | None = None) -> float:
    # Accepts a JSON int or float (the wire's fractional-second fields may serialise as `X` or `X.0`).
    return _json_get(d, key, 'a number', _json_is_number, float, 0.0, True, err)


def json_dict_require_bool(d: JSONObject, key: str, err: ErrorSink | None = None) -> bool:
    return _json_get(d, key, 'a bool', lambda v: isinstance(v, bool), lambda v: v, False, True, err)


def json_dict_require_array(d: JSONObject, key: str, err: ErrorSink | None = None) -> JSONArray:
    return _json_get(d, key, 'an array', lambda v: isinstance(v, list), lambda v: v, [], True, err)


def json_dict_require_obj(d: dict[str, JSONValue], key: str, err: ErrorSink | None = None) -> JSONObject:
    return _json_get(d, key, 'an object', lambda v: isinstance(v, dict), lambda v: v, {}, True, err)


def json_dict_optional_bool(d: JSONObject, key: str, default: bool, err: ErrorSink | None = None) -> bool:
    return _json_get(d, key, 'a bool', lambda v: isinstance(v, bool), lambda v: v, default, False, err)


def json_dict_optional_str(d: JSONObject, key: str, err: ErrorSink | None = None) -> str | None:
    return _json_get(d, key, 'a string', lambda v: isinstance(v, str), lambda v: v, None, False, err)


def json_dict_optional_obj(d: JSONObject, key: str, err: ErrorSink | None = None) -> JSONObject | None:
    return _json_get(d, key, 'an object', lambda v: isinstance(v, dict), lambda v: v, None, False, err)


def json_dict_require_str_coerce_to_int(d: JSONObject, key: str, err: ErrorSink | None = None) -> int:
    result_str = json_dict_require_str(d, key, err)
    try:
        return int(result_str)
    except Exception as e:
        _require_fail(f'Unable to parse {key} type to an int: {e}', err)
    return 0


def json_dict_require_str_coerce_to_enum(
    d: JSONObject, key: str, my_enum: typing.Type[enum.StrEnum], err: ErrorSink | None = None
):
    result = my_enum._value2member_map_.get(json_dict_require_str(d, key, err))
    if result is None:
        _require_fail(f'Unable to parse {key} type to an enum', err)
    return result


def json_dict_require_int_coerce_to_enum(
    d: JSONObject, key: str, my_enum: typing.Type[enum.IntEnum], err: ErrorSink | None = None
):
    result = my_enum._value2member_map_.get(json_dict_require_int(d, key, err))
    if result is None:
        _require_fail(f'Unable to parse {key} type to an enum', err)
    return result


def validate_string_list(items: list[JSONValue]) -> typing.TypeGuard[list[str]]:
    return all(isinstance(item, str) for item in items)


def handle_not_implemented(name: str, err: ErrorSink):
    err.msg_list.append(f"'{name}' is not implemented!")


def os_get_boolean_env(var_name: str, default: bool = False):
    value = os.getenv(var_name, str(int(default)))  # Default to 0 or 1
    if value == '1':
        return True
    elif value == '0':
        return False
    else:
        raise ValueError(f"Invalid value for environment variable '{var_name}': {value}. Allowed values are 0 or 1.")


def backup_file_path(base_file_path: pathlib.Path, now: datetime.datetime) -> str:
    date: str = now.strftime("%Y-%m-%d_%H%M%S")
    file_name: str = base_file_path.name
    parent: pathlib.Path = base_file_path.parent
    result = str(parent / f'{date}_{file_name}.bak')
    return result


def backup_rotation_from_dated_files_dry_run(
    backup_files_listing: list[str], now: datetime.datetime
) -> BackupRotationDryRun:
    """
    Given a list of files in the format "YYYY-MM-DD_HHMMSS_<rest_of_file_name_and>.<extension>"
    return the list of those files to delete to fulfill the rotating backup criteria:

    - Keep the last 180 days worth of backups
    - AND Keep the earliest backup for each month

    The rotating date filter to all files in the list even if "<rest_of_file_name_and>.<extension>"
    are different from each other.
    """

    @dataclasses.dataclass
    class BackupItem:
        date: datetime.datetime
        path: pathlib.Path
        keep: bool = False

    # NOTE: Parse the list of on-disk backups into (year) -> (month) -> [(date, path)] entries
    year_backups: dict[int, dict[int, list[BackupItem]]] = {}
    for item in backup_files_listing:
        try:
            file_name: str = pathlib.Path(item).name  # Extract file name
            # Extract timestamp from filename of format
            # "YYYY-MM-DD_HHMMSS_<rest_of_file_name_and>.<extension>"
            expected_prefix: str = "YYYY-MM-DD_HHMMSS"
            ts_str: str = file_name[: len(expected_prefix)]
            dt = datetime.datetime.strptime(ts_str, "%Y-%m-%d_%H%M%S")  # Parse the timestamp
            if dt.year not in year_backups:
                year_backups[dt.year] = {}
            if dt.month not in year_backups[dt.year]:
                year_backups[dt.year][dt.month] = []
            year_backups[dt.year][dt.month].append(BackupItem(date=dt, path=pathlib.Path(item)))
        except Exception:
            continue  # skip malformed

    # NOTE: Sort each list of backups belonging to the (year, month)
    for year in year_backups:
        for month in year_backups[year]:
            year_backups[year][month] = sorted(year_backups[year][month], key=lambda it: it.date)

    # NOTE: Determine which backup to keep
    cutoff_unix_ts_s: int = int(now.timestamp()) - (SECONDS_IN_DAY * 180)
    for year in year_backups:
        for month in year_backups[year]:
            backups: list[BackupItem] = year_backups[year][month]

            # NOTE: If we're within the recent cutoff date, keep the file
            for backup_it in backups:
                if backup_it.date.timestamp() >= cutoff_unix_ts_s:
                    backup_it.keep = True

            # NOTE: We keep the earliest one we have for that month
            backups[0].keep = True

    # NOTE: Generate the final result (the 2 lists, keep or delete)
    result = BackupRotationDryRun()
    for year in year_backups:
        for month in year_backups[year]:
            backups = year_backups[year][month]
            for backup_it in backups:
                if backup_it.keep:
                    result.to_keep.append(backup_it.path)
                else:
                    result.to_delete.append(backup_it.path)

    return result


def backup_rotation_dry_run(base_file_path: pathlib.Path, now: datetime.datetime) -> BackupRotationDryRun:
    """
    Given a path to the file denoted by 'base_file_path' enumerate for other files in the directory
    with the format "YYYY-MM-DD_HHMMSS_<base_file_name>" and return the list of those files to
    keep and delete for the rotating backup criteria (see: dry_run_backup_rotation_from_dated_files)
    """

    backup_dir: pathlib.Path = pathlib.Path(base_file_path).parent
    backup_name: str = pathlib.Path(base_file_path).name

    # NOTE: Retrieve the list of backups
    backup_files_listing: list[str] = glob.glob(str(backup_dir / f"*_{backup_name}.bak"))
    result: BackupRotationDryRun = backup_rotation_from_dated_files_dry_run(backup_files_listing, now)
    return result
