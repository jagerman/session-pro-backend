#!/usr/bin/env python3
"""
Command Line Interface for manipulating the Session Pro Backend database like adding revocations,
flushing historical notifications received, generating reports e.t.c
"""

import argparse
import configparser
import dataclasses
import datetime
import os
import pathlib
import sys
import time
import typing

import nacl.signing

import base
import backend
import db
import minting

# Epilog definitions
BRIEF_EPILOG = """
QUICK START EXAMPLES (all commands require --config):
  voucher                     --master-pkey <hex> --plan <1M|3M|12M>
                              [--provider <p>] [--rotating-pkey <hex>] [--duration <s>]
  user-error set              <provider>:<payment-id>=<true|false>[,...]
  user-error delete           <provider>:<payment-id>[,...]
  google-notification handle  <msgid>[,...]
  google-notification delete  <msgid>[,...]
  google-notification list
  revoke list                 <master_pkey_hex>
  revoke user                 [--creation-unix-ts-s <ts>] <master_pkey_hex>
  revoke bump-ticket          <amount>
  report generate             <daily|weekly|monthly> [--format <human|csv>] [--count <n>]

Run with --help-full for detailed command formats.
"""

DETAILED_EPILOG = """
COMMAND FORMATS DETAILED:
  user-error set "<provider>:<payment_id>=<flag>[,...]" (requires --config)
    A ',' delimited string to instruct the DB to delete the specified rows from the user errors table
    in the DB on startup. This value must be of the format

      "<payment_provider integer>:<payment_id>=[true|false], ..."

    For example

      "1:the_google_order_id=true,2:the_apple_order_id=false"

    Which will add the row that has a payment provider of 1 (which corresponds to the Google Play
    Store) and has a payment ID that matches "google_order_id" to have an error. For the next entry
    similarly it will set the Apple row to false (e.g. delete the row from the DB)

    This is intended to be used to flush errors from the DB if they are encountered during the
    handling of payment notifications for a specific user. Platform clients may be using the error
    table to populate UI that indicates that a user should contact support, hence clearing this
    value may clear the error prompt for said user.

    Examples:
      python cli.py user-error set "1:abc123token=true"
      python cli.py user-error set "1:token1=true,1:token2=true,2:apple1=false"

  user-error set "<provider>:<payment_id>=<flag>[,...]" (requires --config)
    A ',' delimited string to instruct the DB to delete the specified rows from the user errors table
    in the DB on startup. This value must be of the format

      "<payment_provider integer>:<payment_id>=[true|false], ..."

    For example

      "1:the_google_order_id=true,2:the_apple_order_id=false"

    Which will add the row that has a payment provider of 1 (which corresponds to the Google Play
    Store) and has a payment ID that matches "google_order_id" to have an error. For the next entry
    similarly it will set the Apple row to false (e.g. delete the row from the DB)

    This is intended to be used to flush errors from the DB if they are encountered during the
    handling of payment notifications for a specific user. Platform clients may be using the error
    table to populate UI that indicates that a user should contact support, hence clearing this
    value may clear the error prompt for said user.

    Options:
      provider:     Integer (1=Google Play Store, 2=iOS App Store)
      payment_id:   String (google_payment_token or apple_original_tx_id)
      flag:         true to add error, false to delete

    Examples:
      python cli.py --config config.ini user-error set "1:abc123token=true"
      python cli.py --config config.ini user-error set "1:token1=true,1:token2=true,2:apple1=false"

  user-error delete "<provider>:<payment_id>[,...]" (requires --config)
    Same format as 'set' but only deletes (no =true/false)

    Examples:
      python cli.py --config config.ini user-error delete "1:abc123token"
      python cli.py --config config.ini user-error delete "1:token1,1:token2,2:apple1"

  voucher --config <ini> --master-pkey <hex> --plan <1M|3M|12M>
          [--provider <p>] [--rotating-pkey <hex>] [--duration <s>]
    Create a voucher payment and auto-redeem it. This is an admin command for granting
    promotional or complimentary Session Pro subscriptions directly in the database.

    Required:
      --config <ini>          Path to config.ini file
      --master-pkey <hex>     64-char hex master public key of the recipient
      --plan <1M|3M|12M>      Subscription plan duration

    Optional:
      --provider <p>          rangeproof (default) | google_play | app_store. The non-rangeproof
                              providers mint a payment the store never saw, for testing the
                              per-provider code paths, and require provider_dry_run
      --rotating-pkey <hex>   64-char hex rotating public key (generates new if omitted)
      --duration <s>          Override duration in seconds

    Examples:
      python cli.py voucher --config config.ini --master-pkey abcdef... --plan 1M
      python cli.py voucher --config config.ini --master-pkey abcdef... --plan 3M --rotating-pkey fedcba...
      python cli.py voucher --config config.ini --master-pkey abcdef... --plan 12M --duration 5
      python cli.py voucher --config config.ini --master-pkey abcdef... --plan 1M --provider google_play

  google-notification handle "<message_id>[,...]" (requires --config)
    A ',' delimited string of message IDs to instruct the DB to mark the specified rows as handled
    from the google notification history table in the DB on startup.

      "8392,1234"

    Which will mark the notifications with the ID 8392 and 1234 as to being handled (which stops the
    backend from trying to process the message). Note that when you handle a message, this also
    wipes the notification payload from the table (since the backend does not need to parse and
    process the message anymore).

    Handled notifications will get deleted at the expiry date and persist in the database just incase
    Google redelivers the notification. Duplicated notifications are de-duped by their message ID.

    This is intended to flush out bad notifications that may be invalid or no longer necessary to
    process/impossible to process due to inconsistent DB state, otherwise, do not use unless you
    know the intended consequences! Make a backup of the DB before proceeding!

    Options:
      message_id: Google's notification message ID (an opaque string, but typically an integer)

    Examples:
      python cli.py --config config.ini google-notification handle "12345"
      python cli.py --config config.ini google-notification handle "12345,67890,11111"

  google-notification delete "<message_id>[,...]" (requires --config)
    Same format as 'handle', but deletes the notification entirely

  google-notification list (requires --config)
    Lists all unhandled notifications with message_id and expiry

  revoke list <master_pkey_hex> (requires --config)
    Shows all revocable payments for the user

    Options:
      master_pkey_hex:  64-character hex string (optionally prefixed with 0x)

    Examples:
      python cli.py --config config.ini revoke list aaaa...aaaa
      python cli.py --config config.ini revoke list 0xaaaa...aaaa

  revoke user [--creation-unix-ts-s <ts>] <master_pkey_hex> (requires --config)
    Revoke the user's current generation and roll them onto a fresh one (if they still have valid
    payments). Revocation is terminal: once a generation is revoked it can never be un-revoked, so
    there is no delete/timestamp-edit counterpart.

    The user's current generation is looked up from their master public key and its token is added to
    the served revocation list. If the user is not known to the database (never existed, or their
    master public key mapping was pruned after a period of inactivity) then no action is taken.

    Options:
      master_pkey_hex:      64-character hex string
      --creation-unix-ts-s: Unix timestamp in seconds for the revocation instant (default: now)

    Examples:
      python cli.py --config config.ini revoke user aaaa...aaaa
      python cli.py --config config.ini revoke user --creation-unix-ts-s 1741170600 aaaa...aaaa

  report generate <period> [--format <format>] [--count <n>] (requires --config)
    Generate a report of the payments for the given report type, period and optional count. The
    fields of the report are defined as follows:

      Active Users: Number of Session Pro payments that were still active (i.e. not expired or
      revoked) at the end of the reporting period.

      Cancelling: Number of Session Pro payments that are scheduled to expire and not be renewed in
      that reporting period.

    Options:
      period:   daily, weekly, or monthly
      format:   human (default) or csv
      count:    Number of periods to report (default: 7)

    Examples:
      python cli.py --config config.ini report generate daily
      python cli.py --config config.ini report generate weekly --format csv --count 4
      python cli.py --config config.ini report generate monthly --count 3
"""


def parse_set_user_error_arg(arg: str) -> list[tuple[base.PaymentProvider, str, bool]]:
    """Parse a comma-separated string of errors into a list of (payment_provider, payment_id, set_flag)
    tuples. Raises ValueError on malformed input."""
    result: list[tuple[base.PaymentProvider, str, bool]] = []
    if len(arg) == 0:
        return result

    for item in arg.split(','):
        item = item.strip()
        if ':' not in item or '=' not in item:
            raise ValueError(
                f"Invalid format for user error: '{item}'. Expected '<payment_provider>:<payment_id>=[true|false]'."
            )
        payment_provider_str, remainder = item.split(':', 1)
        payment_id, set_flag_str = remainder.split('=', 1)
        payment_provider_str = payment_provider_str.strip()

        try:
            payment_provider = base.PaymentProvider(payment_provider_str)
        except Exception:
            raise ValueError(f'Failed to parse payment provider ({payment_provider_str}) for item {item}')

        if payment_provider == base.PaymentProvider.Nil:
            raise ValueError(f'Nil payment provider cannot be used for errors (item {item})')
        if payment_provider == base.PaymentProvider.Rangeproof:
            raise ValueError(f'Rangeproof payment provider does not support errors (item {item})')

        set_flag = False
        if set_flag_str.lower() == 'true':
            set_flag = True
        elif set_flag_str.lower() == 'false':
            set_flag = False
        else:
            raise ValueError(f'Failed to parse set flag ({set_flag_str}) for item {item}')

        result.append((payment_provider, payment_id, set_flag))
    return result


def parse_payment_id_list(arg: str) -> list[tuple[base.PaymentProvider, str]]:
    """Parse a comma-separated string of payment IDs for deletion. Raises ValueError on malformed input."""
    result: list[tuple[base.PaymentProvider, str]] = []
    if len(arg) == 0:
        return result

    for item in arg.split(','):
        item = item.strip()
        if ':' not in item:
            raise ValueError(f"Invalid format for payment ID: '{item}'. Expected '<payment_provider>:<payment_id>'.")
        payment_provider_str, payment_id = item.split(':', 1)
        payment_provider_str = payment_provider_str.strip()

        try:
            payment_provider = base.PaymentProvider(payment_provider_str)
        except Exception:
            raise ValueError(f'Failed to parse payment provider ({payment_provider_str}) for item {item}')

        result.append((payment_provider, payment_id))
    return result


def parse_message_id_list(arg: str) -> list[str]:
    """Parse a comma-separated string of message IDs. Pub/Sub message ids are opaque strings, so entries
    are taken verbatim (no numeric parsing). Raises ValueError on malformed input."""
    result: list[str] = []
    if len(arg) == 0:
        return result

    for item in arg.split(','):
        item = item.strip()
        if len(item) == 0:
            raise ValueError('Empty message_id in list')
        result.append(item)
    return result


def parse_master_pkey(hex_str: str) -> nacl.signing.VerifyKey:
    """Parse a hex string into a VerifyKey. Raises ValueError on malformed input."""
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]

    if len(hex_str) != 64:
        raise ValueError(f"Expected 64 hex chars for master public key, received {len(hex_str)}")

    try:
        hex_bytes = bytes.fromhex(hex_str)
        return nacl.signing.VerifyKey(hex_bytes)
    except Exception as e:
        raise ValueError(f"Failed to parse hex as master public key: {e}")


@dataclasses.dataclass
class CLIConfig:
    db_url: str = ''
    backend_key_path: str = ''
    log_path: str = ''
    provider_dry_run: bool = False


def _fail_config(reason: str) -> typing.NoReturn:
    print(f"ERROR: Failed to load config:\n  {reason}", file=sys.stderr)
    sys.exit(1)


def require_config(args: argparse.Namespace) -> CLIConfig:
    if not args.config:
        print("ERROR: --config is required for this command", file=sys.stderr)
        sys.exit(1)

    config_path: str = args.config
    if not pathlib.Path(config_path).exists():
        _fail_config(f'Config file "{config_path}" does not exist or is not readable')

    result = CLIConfig()
    try:
        parser = configparser.ConfigParser()
        parser.read(config_path)
    except Exception as e:
        _fail_config(f'Failed to parse config file: {e}')

    if 'base' not in parser:
        _fail_config(f'Config file "{config_path}" is missing [base] section')

    base_section = parser['base']
    result.db_url = base_section.get('db_url', '')
    result.backend_key_path = base_section.get('backend_key_path', '')
    result.log_path = base_section.get('log_path', '')
    result.provider_dry_run = base_section.getboolean('provider_dry_run', fallback=False)

    # Allow environment variable override
    result.db_url = os.getenv('SESH_PRO_BACKEND_DB_URL', result.db_url)
    result.backend_key_path = os.getenv('SESH_PRO_BACKEND_KEY_PATH', result.backend_key_path)
    result.provider_dry_run = base.os_get_boolean_env('SESH_PRO_BACKEND_PROVIDER_DRY_RUN', result.provider_dry_run)

    if not result.db_url:
        print("ERROR: No database URL configured in config file", file=sys.stderr)
        sys.exit(1)

    return result


def cmd_user_error_set(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
    try:
        items = parse_set_user_error_arg(args.items)
    except ValueError as e:
        print(f"ERROR: Failed to parse arguments:\n  {e}", file=sys.stderr)
        return 1

    if len(items) == 0:
        print("No items to process")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                count = 0
                label = ''

                for index, (payment_provider, payment_id, set_flag) in enumerate(items):
                    if index:
                        label += '\n'
                    label += f'  {index:02d} {payment_provider.value}:{payment_id} = {set_flag}'

                    if dry_run:
                        label += ' (dry-run)'
                        count += 1
                        continue

                    if set_flag:
                        error = backend.UserError(provider=payment_provider)
                        if payment_provider == base.PaymentProvider.GooglePlayStore:
                            error.google_payment_token = payment_id
                        else:
                            assert payment_provider == base.PaymentProvider.iOSAppStore
                            error.apple_original_tx_id = payment_id

                        if backend.has_user_error(conn=conn, payment_provider=payment_provider, payment_id=payment_id):
                            label += ' (skipped - already exists)'
                        else:
                            backend.add_user_error(
                                conn, error=error, at=base.datetime_from_unix_ms(int(time.time() * 1000))
                            )
                            count += 1
                            label += ' (added)'
                    else:
                        if backend.delete_user_errors(
                            conn=conn, payment_provider=payment_provider, payment_id=payment_id
                        ):
                            count += 1
                            label += ' (deleted)'
                        else:
                            label += ' (skipped - not found)'

                print(f"Set {count}/{len(items)} user errors\n{label}")
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_user_error_delete(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
    try:
        items = parse_payment_id_list(args.items)
    except ValueError as e:
        print(f"ERROR: Failed to parse arguments:\n  {e}", file=sys.stderr)
        return 1

    if len(items) == 0:
        print("No items to process")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                count = 0
                label = ''

                for index, (payment_provider, payment_id) in enumerate(items):
                    if index:
                        label += '\n'
                    label += f'  {index:02d} {payment_provider.value}:{payment_id}'

                    if dry_run:
                        label += ' (dry-run)'
                        count += 1
                        continue

                    if backend.delete_user_errors(conn=conn, payment_provider=payment_provider, payment_id=payment_id):
                        count += 1
                        label += ' (deleted)'
                    else:
                        label += ' (skipped - not found)'

                print(f"Deleted {count}/{len(items)} user errors\n{label}")
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_google_notification_handle(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
    try:
        message_ids = parse_message_id_list(args.items)
    except ValueError as e:
        print(f"ERROR: Failed to parse arguments:\n  {e}", file=sys.stderr)
        return 1

    if len(message_ids) == 0:
        print("No message IDs to process")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                count = 0
                label = ''

                for index, message_id in enumerate(message_ids):
                    if index:
                        label += '\n'
                    label += f'  {index:02d} {message_id} = Handled'

                    if dry_run:
                        label += ' (dry-run)'
                        count += 1
                        continue

                    with db.transaction(conn) as tx:
                        updated = backend.google_set_notification_handled(tx=tx, message_id=message_id, delete=False)
                        if updated:
                            count += 1
                        else:
                            label += ' (skipped - not found)'

                print(f"Marked {count}/{len(message_ids)} google notifications as handled\n{label}")
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_google_notification_delete(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
    try:
        message_ids = parse_message_id_list(args.items)
    except ValueError as e:
        print(f"ERROR: Failed to parse arguments:\n  {e}", file=sys.stderr)
        return 1

    if len(message_ids) == 0:
        print("No message IDs to process")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                count = 0
                label = ''

                for index, message_id in enumerate(message_ids):
                    if index:
                        label += '\n'
                    label += f'  {index:02d} {message_id} = Delete'

                    if dry_run:
                        label += ' (dry-run)'
                        count += 1
                        continue

                    with db.transaction(conn) as tx:
                        updated = backend.google_set_notification_handled(tx=tx, message_id=message_id, delete=True)
                        if updated:
                            count += 1
                        else:
                            label += ' (skipped - not found)'

                print(f"Deleted {count}/{len(message_ids)} google notifications\n{label}")
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_google_notification_list(args: argparse.Namespace) -> int:
    config = require_config(args)
    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    unhandled_it = backend.google_get_unhandled_notification_iterator(tx)

                    items = list(unhandled_it)
                    if len(items) == 0:
                        print("No unhandled google notifications")
                        return 0

                    print(f"Found {len(items)} unhandled google notifications:")
                    for index, item in enumerate(items):
                        message_id, payload, expires_at = item
                        expiry_str = base.readable(expires_at)
                        print(f"  {index:02d} message_id={message_id}, expiry={expiry_str}")

                    return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_revoke_list(args: argparse.Namespace) -> int:
    config = require_config(args)
    try:
        master_pkey = parse_master_pkey(args.master_pkey)
    except ValueError as e:
        print(f"ERROR: Failed to parse arguments:\n  {e}", file=sys.stderr)
        return 1

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    user_and_payments = backend.get_user_and_payments(tx=tx, master_pkey=master_pkey)

                    eligible_count = 0
                    list_label = ''
                    now = datetime.datetime.now(datetime.timezone.utc)

                    for row in user_and_payments.payments_it:
                        payment: backend.PaymentRow = backend.payment_row_from_dict(row)

                        plan_label = ''
                        match payment.plan:
                            case base.ProPlan.Nil:
                                plan_label = '??'
                            case base.ProPlan.OneMonth:
                                plan_label = '1M'
                            case base.ProPlan.ThreeMonth:
                                plan_label = '3M'
                            case base.ProPlan.TwelveMonth:
                                plan_label = '12M'

                        payment_id = ''
                        match payment.payment_provider:
                            case base.PaymentProvider.Nil:
                                pass
                            case base.PaymentProvider.GooglePlayStore:
                                payment_id = f'{payment.google_payment_token}-{payment.google_order_id}'
                            case base.PaymentProvider.iOSAppStore:
                                payment_id = f'{payment.apple.original_tx_id}'
                            case base.PaymentProvider.Rangeproof:
                                payment_id = f'{payment.rangeproof_order_id}'

                        if now >= payment.expires_at:
                            continue

                        status_label = backend.derive_payment_status(payment, now).name
                        list_label += (
                            f'\n    {eligible_count:02d} RevokeID={payment.payment_provider.name}-{payment_id}; '
                            f'Status={status_label}; '
                            f'Plan={plan_label}; '
                            f'Unredeemed={base.readable(payment.purchased_at)}; '
                            f'Expiry={base.readable(payment.expires_at)};'
                        )
                        eligible_count += 1

                    print(f"User {args.master_pkey} has {eligible_count} revocable payments{list_label}")
                    return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_revoke(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)
    try:
        master_pkey = parse_master_pkey(args.master_pkey)
    except ValueError as e:
        print(f"ERROR: Failed to parse arguments:\n  {e}", file=sys.stderr)
        return 1

    # Revocation is terminal, so there is no un-revoke; the manual revoke uses the one real revoke path
    # (revoke the user's current generation + roll them onto a fresh one if they still have valid payments).
    revoke_at = (
        base.datetime_from_unix_ms(args.creation_unix_ts_s * 1000)
        if args.creation_unix_ts_s
        else datetime.datetime.now(datetime.timezone.utc)
    )

    if dry_run:
        print(f"(DRY RUN) Would revoke {args.master_pkey} at {base.readable(revoke_at)}")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    backend.revoke_master_pkey_proofs_and_allocate_new_gen_id(tx, master_pkey, created_at=revoke_at)
                print(f"Revoked current generation for {args.master_pkey} at {base.readable(revoke_at)}")
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_revoke_bump_ticket(args: argparse.Namespace, dry_run: bool) -> int:
    config = require_config(args)

    # The ticket only ever moves forward (clients treat "my cached ticket < server's" as "list changed").
    if args.amount < 1:
        print("ERROR: amount must be a positive integer", file=sys.stderr)
        return 1

    if dry_run:
        print(f"(DRY RUN) Would advance the revocation ticket by {args.amount}")
        return 0

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    new_ticket = backend.bump_revocation_ticket(tx.conn, args.amount)
                print(f"Advanced the revocation ticket by {args.amount} to {new_ticket}")
                return 0
    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_report_generate(args: argparse.Namespace) -> int:
    config = require_config(args)
    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                report_type = backend.ReportType.Human
                if args.format.lower() == 'csv':
                    report_type = backend.ReportType.CSV

                report_period = backend.ReportPeriod.Daily
                if args.period.lower() == 'weekly':
                    report_period = backend.ReportPeriod.Weekly
                elif args.period.lower() == 'monthly':
                    report_period = backend.ReportPeriod.Monthly

                count = args.count
                report_rows = backend.generate_report_rows(conn, report_period, limit=count)
                report_str = backend.generate_report_str(report_period, report_rows, report_type)

                print(report_str)
                return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        return 1


def cmd_voucher(args: argparse.Namespace) -> int:
    """Handle voucher command - mints a payment for the chosen provider and auto-redeems it."""
    config = require_config(args)

    # Synthetic non-Rangeproof payments are only permitted on a throwaway (provider_dry_run) instance —
    # enforced below. Propagate the flag into this CLI process (nothing else sets it here) so any
    # dry-run-gated provider egress stays stubbed.
    base.PROVIDER_DRY_RUN = config.provider_dry_run

    # Parse master public key
    try:
        master_pkey_hex = args.master_pkey
        if master_pkey_hex.startswith("0x"):
            master_pkey_hex = master_pkey_hex[2:]
        master_pkey = nacl.signing.VerifyKey(bytes.fromhex(master_pkey_hex))
    except Exception as e:
        print(f"ERROR: Failed to parse master public key: {e}", file=sys.stderr)
        return 1

    provider = base.PaymentProvider(args.provider)
    if provider != base.PaymentProvider.Rangeproof and not config.provider_dry_run:
        # A minted google_play/app_store payment is fiction as far as the store is concerned, so it must
        # only ever be created on a throwaway instance. Rangeproof is a genuine out-of-band dev-house
        # grant with no store behind it, so it needs no such guard.
        print(
            f"ERROR: --provider {provider.value} requires provider_dry_run to be enabled "
            f"(the payment is synthetic and must not be minted on a live instance)",
            file=sys.stderr,
        )
        return 1

    # Handle rotating key
    rotating_skey = None
    rotating_pkey = None
    if args.rotating_pkey:
        try:
            rotating_pkey_hex = args.rotating_pkey
            if rotating_pkey_hex.startswith("0x"):
                rotating_pkey_hex = rotating_pkey_hex[2:]
            rotating_pkey = nacl.signing.VerifyKey(bytes.fromhex(rotating_pkey_hex))
        except Exception as e:
            print(f"ERROR: Failed to parse rotating public key: {e}", file=sys.stderr)
            return 1
    else:
        # Generate a throwaway rotating keypair
        rotating_skey = nacl.signing.SigningKey.generate()
        rotating_pkey = rotating_skey.verify_key
        print(f'Generated Rotating SKey: {bytes(rotating_skey).hex()}')
        print(f'Generated Rotating PKey: {bytes(rotating_pkey).hex()}')

    plan = minting.plan_from_label(args.plan)
    assert plan is not None, f'argparse restricts --plan to the known labels, got {args.plan}'
    try:
        duration = minting.duration_from_seconds(args.duration)
    except base.FailError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Load the backend signing key from disk (not stored in the DB) before opening the transaction.
    if not config.backend_key_path:
        print("ERROR: No backend signing key configured ([base] backend_key_path)", file=sys.stderr)
        return 1
    try:
        backend_key = backend.load_backend_signing_key(config.backend_key_path)
    except Exception as e:
        print(f"ERROR: Failed to load backend signing key: {e}", file=sys.stderr)
        return 1

    try:
        with db.open_database(config.db_url) as engine:
            with db.connection(engine) as conn:
                with db.transaction(conn) as tx:
                    request_at = base.datetime_from_unix_ms(int(time.time() * 1000))

                    # Step 1: mint the payment and redeem it (shared with the /dev/add_payment route).
                    # Redemption registers the entitlement (user row + generation) without minting a proof.
                    print(f'\nStep 1: Minting and redeeming {provider.value} payment...')
                    minted = minting.mint_payment(
                        tx,
                        master_pkey=master_pkey,
                        provider=provider,
                        plan=plan,
                        now=request_at,
                        duration=duration,
                        redeem=True,
                    )
                    print(f"Success: payment redeemed (payment_id: {minted.payment_id})")

                    # Step 2: build the proof over the now-active entitlement.
                    print('\nStep 2: Generating pro proof...')
                    proof = backend.build_current_entitlement_proof(
                        tx, master_pkey, rotating_pkey, request_at, backend_key
                    )

                    print(f"Success: {provider.value} payment granted and pro proof generated")
                    print('\nProof Details:')
                    print(f'  Expiry: {base.readable(proof.expires_at)}')
                    print(f'  Revocation Tag: {proof.revocation_tag.hex()}')

                    return 0

    except Exception as e:
        print(f"ERROR: Database error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Session Pro Backend CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=DETAILED_EPILOG if '--help-full' in sys.argv else BRIEF_EPILOG,
        add_help=False,
    )

    # Global options
    parser.add_argument('--help', action='help', default=argparse.SUPPRESS, help='Show brief help message and exit')
    parser.add_argument(
        '--help-full', action='help', default=argparse.SUPPRESS, help='Show detailed help with full documentation'
    )
    parser.add_argument('--config', required=False, help='Path to config.ini file (required for DB operations)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without executing')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Voucher command (mints a payment for the chosen provider and auto-redeems it)
    voucher_parser = subparsers.add_parser('voucher', help='Create a voucher payment (requires --config)')
    voucher_parser.add_argument('--master-pkey', required=True, help='64-char hex master public key of the recipient')
    voucher_parser.add_argument(
        '--plan', required=True, choices=['1M', '3M', '12M'], help='Subscription plan (1M/3M/12M)'
    )
    voucher_parser.add_argument(
        '--provider',
        default=base.PaymentProvider.Rangeproof.value,
        choices=[
            base.PaymentProvider.Rangeproof.value,
            base.PaymentProvider.GooglePlayStore.value,
            base.PaymentProvider.iOSAppStore.value,
        ],
        help='Payment provider to attribute the voucher to (default: rangeproof). google_play and '
        'app_store mint a synthetic payment the provider never saw, so they require provider_dry_run',
    )
    voucher_parser.add_argument('--rotating-pkey', help='64-char hex rotating public key (generates new if omitted)')
    voucher_parser.add_argument('--duration', type=int, help='Override duration in seconds')

    # User error commands
    user_error_parser = subparsers.add_parser('user-error', help='Manage user errors')
    user_error_subparsers = user_error_parser.add_subparsers(dest='user_error_command', help='User error subcommands')

    user_error_set = user_error_subparsers.add_parser(
        'set', help='Set user errors (format: <provider>:<payment-id>=true|false,...)'
    )
    user_error_set.add_argument('items', help='Comma-separated list of errors')

    user_error_delete = user_error_subparsers.add_parser(
        'delete', help='Delete user errors (format: <provider>:<payment-id>,...)'
    )
    user_error_delete.add_argument('items', help='Comma-separated list of payment IDs')

    # Google notification commands
    google_notif_parser = subparsers.add_parser(
        'google-notification', help='Manage the list of Google notifications received in the database'
    )
    google_notif_subparsers = google_notif_parser.add_subparsers(
        dest='google_notif_command', help='Google notification subcommands'
    )

    google_notif_handle = google_notif_subparsers.add_parser('handle', help='Mark notifications as handled')
    google_notif_handle.add_argument('items', help='Comma-separated list of message IDs')

    google_notif_delete = google_notif_subparsers.add_parser('delete', help='Delete notifications')
    google_notif_delete.add_argument('items', help='Comma-separated list of message IDs')
    google_notif_subparsers.add_parser('list', help='List unhandled notifications')

    # Revoke commands
    revoke_parser = subparsers.add_parser('revoke', help='Manage revocations')
    revoke_subparsers = revoke_parser.add_subparsers(dest='revoke_command', help='Revocation subcommands')

    revoke_list = revoke_subparsers.add_parser('list', help='List revocable payments for a user')
    revoke_list.add_argument('master_pkey', help='Master public key (64 hex chars)')

    revoke_now = revoke_subparsers.add_parser(
        'user', help="Revoke a user's current generation (terminal — no un-revoke)"
    )
    revoke_now.add_argument('master_pkey', help='Master public key (64 hex chars)')
    revoke_now.add_argument(
        '--creation-unix-ts-s',
        type=int,
        default=int(time.time()),
        help='Revocation instant in unix seconds (default: now)',
    )

    revoke_bump_ticket = revoke_subparsers.add_parser(
        'bump-ticket',
        help='Advance the revocation ticket forward (DR: run after restoring the DB from an older backup)',
    )
    revoke_bump_ticket.add_argument('amount', type=int, help='Positive integer to add to the current revocation ticket')

    # Report commands
    report_parser = subparsers.add_parser('report', help='Generate reports')
    report_subparsers = report_parser.add_subparsers(dest='report_command', help='Report subcommands')

    report_generate = report_subparsers.add_parser('generate', help='Generate a report')
    report_generate.add_argument('period', choices=['daily', 'weekly', 'monthly'], help='Report period')
    report_generate.add_argument('--format', choices=['human', 'csv'], default='human', help='Report format')
    report_generate.add_argument('--count', type=int, default=7, help='Number of periods to report')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Dispatch to command handler - commands that need config will load it themselves
    dry_run = args.dry_run

    if args.command == 'voucher':
        return cmd_voucher(args)

    elif args.command == 'user-error':
        if args.user_error_command == 'set':
            return cmd_user_error_set(args, dry_run)
        elif args.user_error_command == 'delete':
            return cmd_user_error_delete(args, dry_run)
        else:
            user_error_parser.print_help()
            return 1

    elif args.command == 'google-notification':
        if args.google_notif_command == 'handle':
            return cmd_google_notification_handle(args, dry_run)
        elif args.google_notif_command == 'delete':
            return cmd_google_notification_delete(args, dry_run)
        elif args.google_notif_command == 'list':
            return cmd_google_notification_list(args)
        else:
            google_notif_parser.print_help()
            return 1

    elif args.command == 'revoke':
        if args.revoke_command == 'list':
            return cmd_revoke_list(args)
        elif args.revoke_command == 'user':
            return cmd_revoke(args, dry_run)
        elif args.revoke_command == 'bump-ticket':
            return cmd_revoke_bump_ticket(args, dry_run)
        else:
            revoke_parser.print_help()
            return 1

    elif args.command == 'report':
        if args.report_command == 'generate':
            return cmd_report_generate(args)
        else:
            report_parser.print_help()
            return 1

    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
