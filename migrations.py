"""
One-time database migration runner.

Migrations live in the sibling ``schema/`` directory as ascii-sorted ``NNN_*.sql`` (structural) or
``NNN_*.py`` (data/semantic) files; see ``schema/README``. Each is applied exactly once, inside its
own transaction, and its filename is recorded in the ``migrations_applied`` ledger. A named ledger
(rather than a single integer version) means migrations are identified by what they are, and adding
one is just dropping a new file in the directory.
"""
import importlib.util
import logging
import pathlib
import re
import types

import psycopg

import db

log = logging.getLogger('PRO')

SCHEMA_DIR = pathlib.Path(__file__).parent / 'schema'

# A migration file: a numeric prefix, an underscore, a description, then .sql or .py.
_MIGRATION_RE = re.compile(r'^\d+_.*\.(sql|py)$')


def _migration_files() -> list[pathlib.Path]:
    files = sorted((p for p in SCHEMA_DIR.iterdir() if _MIGRATION_RE.match(p.name)),
                   key=lambda p: p.name)
    # The same base name must not be both a .sql and a .py migration (ambiguous ordering/identity).
    by_stem: dict[str, list[str]] = {}
    for p in files:
        by_stem.setdefault(p.stem, []).append(p.name)
    dupes = {stem: names for stem, names in by_stem.items() if len(names) > 1}
    if dupes:
        raise RuntimeError(f'Migration base name used by more than one file: {dupes}')
    return files


def _apply_py_migration(path: pathlib.Path, conn: psycopg.Connection) -> None:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    func_name = 'apply_' + re.sub(r'\W', '_', path.stem)
    func = getattr(module, func_name, None)
    if not isinstance(func, types.FunctionType):
        raise RuntimeError(f'{path.name} does not define {func_name}(conn)')
    func(conn)


def apply_migrations(conn: psycopg.Connection) -> None:
    """Apply every not-yet-recorded migration in ``schema/``, in ascii order."""
    with db.transaction(conn) as tx:
        _ = db.query(tx.conn, '''
            CREATE TABLE IF NOT EXISTS migrations_applied (
                name       TEXT        PRIMARY KEY NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        ''')

    applied = {row[0] for row in db.query(conn, 'SELECT name FROM migrations_applied')}

    for path in _migration_files():
        if path.name in applied:
            continue
        with db.transaction(conn) as tx:
            if path.suffix == '.sql':
                _ = db.query(tx.conn, path.read_text())
            else:
                _apply_py_migration(path, tx.conn)
            _ = db.query(tx.conn, 'INSERT INTO migrations_applied (name) VALUES (%s)', path.name)
        log.info(f'Applied migration {path.name}')
