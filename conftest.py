# conftest.py — ephemeral PostgreSQL for the test suite (item 8 groundwork).
#
# pytest-postgresql boots a throwaway cluster and hands each test a *fresh database*.
# The current SQLAlchemy layer already speaks postgresql://, so this lets the existing
# suite run on real PG *before* the psycopg3 rewrite — a green baseline to refactor against.
import glob
import shutil
import subprocess
import uuid

import pytest
from pytest_postgresql import factories
from pytest_postgresql.janitor import DatabaseJanitor


def _pg_ctl_path() -> str:
    # initdb/pg_ctl aren't on PATH on Debian; locate the versioned bin dir robustly so this
    # survives a PG minor/major bump (e.g. from an in-progress sid upgrade).
    try:
        bindir = subprocess.check_output(["pg_config", "--bindir"], text=True).strip()
        if bindir and glob.glob(f"{bindir}/pg_ctl"):
            return f"{bindir}/pg_ctl"
    except Exception:
        pass
    for cand in sorted(glob.glob("/usr/lib/postgresql/*/bin/pg_ctl"), reverse=True):
        return cand
    return shutil.which("pg_ctl") or "pg_ctl"


postgresql_proc = factories.postgresql_proc(executable=_pg_ctl_path())


@pytest.fixture
def pg_database(postgresql_proc):
    """Factory that mints fresh, empty databases on the running cluster.

    Each call returns a ``postgresql://`` URL for a brand-new database. A single test
    often needs several (every ``TestingContext`` and inline setup wants a clean slate),
    so this hands back a factory rather than one URL. Every database created during a
    test is dropped at teardown — the janitor force-terminates leftover connections, so
    engines left open by the code under test don't block the drop.
    """
    proc = postgresql_proc
    janitors: list[DatabaseJanitor] = []

    def make() -> str:
        dbname = f"test_{uuid.uuid4().hex}"
        janitor = DatabaseJanitor(user=proc.user, host=proc.host, port=proc.port, version=proc.version, dbname=dbname)
        janitor.init()
        janitors.append(janitor)
        return f"postgresql://{proc.user}@/{dbname}?host={proc.host}&port={proc.port}"

    yield make

    for janitor in reversed(janitors):
        janitor.drop()
