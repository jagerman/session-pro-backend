'''
The operator surface: CLI argument handling, configuration parsing, backups and DB migrations.
'''

import argparse
import nacl.signing
import nacl.bindings
import nacl.public
import os
import pathlib
import pendulum
import pytest
import re
import backend
import base
import cli
import config
import migrations
import db


def test_dry_run_backup_rotation():
    now = pendulum.DateTime(2025, 6, 1, 12, 0, 0)
    files = [
        "/b/2025-05-30_100000_a.sql",
        "/b/2025-01-01_000000_b.sql",
        "/b/2024-12-15_235959_c.sql",
        "/b/2024-12-01_000000_d.sql",
        "/b/2024-12-30_235959_e.sql",
        "/b/2024-11-05_080000_f.sql",
        "/b/2024-11-20_150000_g.sql",
        "/b/2025-01-10_090000_h.sql",
        "/b/2025-01-20_100000_i.sql",
        "invalid.txt",
        "/b/2024-11-01_000000_j.sql",
        "/b/2024-11-15_000000_k.sql",
    ]
    result = base.backup_rotation_from_dated_files_dry_run(files, now)
    keep = {p.name for p in result.to_keep}
    delete = {p.name for p in result.to_delete}
    assert keep == {
        # NOTE: Earliest of each month after the 180 day cutoff
        "2024-11-01_000000_j.sql",
        "2024-12-01_000000_d.sql",
        # NOTE: Because within the last 180 days
        "2024-12-15_235959_c.sql",
        "2024-12-30_235959_e.sql",
        "2025-01-01_000000_b.sql",
        "2025-01-10_090000_h.sql",
        "2025-01-20_100000_i.sql",
        "2025-05-30_100000_a.sql",
    }
    assert delete == {"2024-11-05_080000_f.sql", "2024-11-20_150000_g.sql", "2024-11-15_000000_k.sql"}
    assert len(result.to_keep) == 8 and len(result.to_delete) == 3


def test_cli_parse_helpers():
    # The CLI arg parsers raise ValueError on malformed input (no ErrorSink); command handlers catch it,
    # print "Failed to parse arguments", and exit 1. Here we pin the parse contract directly.

    # parse_set_user_error_arg: "<provider>:<payment_id>=[true|false]", comma-separated.
    assert cli.parse_set_user_error_arg('') == []
    assert cli.parse_set_user_error_arg('google_play:tok1=true, app_store:otx2=false') == [
        (base.PaymentProvider.GooglePlayStore, 'tok1', True),
        (base.PaymentProvider.iOSAppStore, 'otx2', False),
    ]
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('google_play-tok1-true')  # no ':' / '='
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('notaprovider:tok=true')  # bad provider (was swallowed into the sink)
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('google_play:tok=maybe')  # bad flag
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('nil:tok=true')  # Nil provider rejected
    with pytest.raises(ValueError):
        cli.parse_set_user_error_arg('stf:tok=true')  # a directly granted payment cannot error

    # parse_payment_id_list: "<provider>:<payment_id>", comma-separated.
    assert cli.parse_payment_id_list('') == []
    assert cli.parse_payment_id_list('google_play:tok1, stf:ord2') == [
        (base.PaymentProvider.GooglePlayStore, 'tok1'),
        (base.PaymentProvider.SessionFoundation, 'ord2'),
    ]
    with pytest.raises(ValueError):
        cli.parse_payment_id_list('missing-colon')
    with pytest.raises(ValueError):
        cli.parse_payment_id_list('notaprovider:tok')

    # parse_message_id_list: opaque strings, taken verbatim.
    assert cli.parse_message_id_list('') == []
    assert cli.parse_message_id_list('a, b ,c') == ['a', 'b', 'c']
    with pytest.raises(ValueError):
        cli.parse_message_id_list('a,,b')  # empty entry

    # parse_master_pkey: 64 hex chars (optionally 0x-prefixed), returns a VerifyKey (never None).
    good_hex = '00' * 32
    assert isinstance(cli.parse_master_pkey(good_hex), nacl.signing.VerifyKey)
    assert isinstance(cli.parse_master_pkey('0x' + good_hex), nacl.signing.VerifyKey)
    with pytest.raises(ValueError):
        cli.parse_master_pkey('abcd')  # too short
    with pytest.raises(ValueError):
        cli.parse_master_pkey('zz' * 32)  # right length, not hex


def test_cli_require_config(tmp_path, monkeypatch):
    # require_config resolves the [base] config or exits(1) with a clear message — no ErrorSink, and (the
    # bug the sink hid) a missing file now exits instead of silently returning an empty config. Env
    # overrides are cleared so the file alone drives the result.
    monkeypatch.delenv('SESH_PRO_BACKEND_DB_URL', raising=False)
    monkeypatch.delenv('SESH_PRO_BACKEND_KEY_PATH', raising=False)

    def ns(config):
        return argparse.Namespace(config=config)

    with pytest.raises(SystemExit):
        cli.require_config(ns(None))  # no --config

    with pytest.raises(SystemExit):
        cli.require_config(ns(str(tmp_path / 'nope.ini')))  # nonexistent file (was a silent empty config)

    no_base = tmp_path / 'no_base.ini'
    no_base.write_text('[other]\nx = 1\n')
    with pytest.raises(SystemExit):
        cli.require_config(ns(str(no_base)))  # missing [base]

    no_url = tmp_path / 'no_url.ini'
    no_url.write_text('[base]\nlog_path = /var/log/x\n')
    with pytest.raises(SystemExit):
        cli.require_config(ns(str(no_url)))  # [base] but no db_url

    good = tmp_path / 'good.ini'
    good.write_text('[base]\ndb_url = postgresql:///x\nbackend_key_path = /k\nlog_path = /l\n')
    cfg = cli.require_config(ns(str(good)))
    assert cfg.db_url == 'postgresql:///x' and cfg.backend_key_path == '/k' and cfg.log_path == '/l'


def test_config_parse_args(monkeypatch):
    # parse_args accumulates field problems and raises them together as a ConfigError (an is-a ValueError)
    # rather than threading an ErrorSink. Clear the ambient SESH_PRO_BACKEND_* so the env alone drives it.
    for k in list(os.environ):
        if k.startswith('SESH_PRO_BACKEND_'):
            monkeypatch.delenv(k, raising=False)

    # Nothing enabled -> clean parse, no raise.
    parsed = config.parse_args()
    assert isinstance(parsed, config.ParsedArgs)
    assert parsed.with_provider_app_store is False and parsed.with_provider_google_play is False

    # Enable Apple with no [apple] config -> every missing field is reported at once in one ConfigError.
    monkeypatch.setenv('SESH_PRO_BACKEND_WITH_PROVIDER_APP_STORE', '1')
    with pytest.raises(config.ConfigError) as excinfo:
        config.parse_args()
    assert isinstance(excinfo.value, ValueError)  # ConfigError is-a ValueError
    assert len(excinfo.value.errors) >= 5  # accumulates ALL problems, not just the first
    assert all('app_store' in m for m in excinfo.value.errors)


def test_voucher_processing_window_config(tmp_path, monkeypatch):
    # The one voucher knob an operator has: how stale an account's checkpoint must be before it is charged
    # again. Defaults to a day, is read from the .INI, and a negative value is reported rather than accepted
    # (it would make every account perpetually due). Zero is allowed on purpose: "every pass" is a
    # legitimate thing to want in a test deployment.
    for k in list(os.environ):
        if k.startswith('SESH_PRO_BACKEND_'):
            monkeypatch.delenv(k, raising=False)

    assert config.parse_args().voucher_processing_window == base.DAY

    def parse_with(value: str) -> config.ParsedArgs:
        ini = tmp_path / f'w{value.strip("-")}.ini'
        body = f'db_url = postgresql:///x\nbackend_key_path = /k\nvoucher_processing_window = {value}\n'
        ini.write_text(f'[base]\n{body}')
        monkeypatch.setenv('SESH_PRO_BACKEND_INI_PATH', str(ini))
        return config.parse_args()

    assert parse_with('43200').voucher_processing_window == base.duration_from_seconds(43200)
    assert parse_with('0').voucher_processing_window == pendulum.duration()

    with pytest.raises(config.ConfigError) as excinfo:
        parse_with('-1')
    assert any('voucher_processing_window' in m for m in excinfo.value.errors)


def test_migrations_bootstrap_and_idempotency(pg_database):
    # bootstrap_db runs the schema/ migrations; every migration file should be recorded, the globals
    # rows seeded exactly once, and a second pass must be a clean no-op (nothing re-run or duplicated).
    schema_dir = pathlib.Path(migrations.__file__).parent / 'schema'
    expected = {p.name for p in schema_dir.iterdir() if re.match(r'^\d+_.*\.(sql|py)$', p.name)}
    assert expected, 'expected some migration files to exist'

    pool = backend.bootstrap_db(database_url=pg_database())
    assert pool

    with db.connection() as conn:
        applied = {row[0] for row in db.query(conn, 'SELECT name FROM migrations_applied')}
        assert applied == expected
        assert db.query_scalar(conn, 'SELECT COUNT(*) FROM globals') == 2

        # The provider vocabulary a fresh database ends up with, after every migration that renames one.
        # A rename that seeds the new code but leaves the old row behind is invisible to everything else.
        codes = {row[0] for row in db.query(conn, 'SELECT code FROM payment_providers')}
        assert codes == {p.value for p in base.PaymentProvider if p != base.PaymentProvider.Nil}, codes

        # Idempotent: re-running applies nothing new and does not duplicate the globals seed.
        migrations.apply_migrations(conn)
        assert {row[0] for row in db.query(conn, 'SELECT name FROM migrations_applied')} == expected
        assert db.query_scalar(conn, 'SELECT COUNT(*) FROM globals') == 2
    pool.close()


def test_migrations_reject_duplicate_basename(tmp_path, monkeypatch):
    (tmp_path / '005_foo.sql').write_text('SELECT 1;')
    (tmp_path / '005_foo.py').write_text('def apply_005_foo(conn): pass\n')
    monkeypatch.setattr(migrations, 'SCHEMA_DIR', tmp_path)
    with pytest.raises(RuntimeError):
        migrations._migration_files()
