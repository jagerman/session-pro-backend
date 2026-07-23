"""
PostgreSQL access layer (psycopg 3) for the Session Pro backend.

Connections come from a per-DSN `psycopg_pool.ConnectionPool` (autocommit). Pools are
created on demand, cached by connection string, reset across `fork()` so each worker
builds its own, and closed at interpreter exit. The public shape mirrors the old
SQLAlchemy layer so callers are unchanged:

    with db.open_database(dsn) as pool:      # process-wide pool for this DSN
        with db.connection(pool) as conn:    # a pooled connection
            with db.transaction(conn) as tx: # BEGIN ... COMMIT (or ROLLBACK on cancel)
                db.query(tx.conn, 'UPDATE users SET status = %s WHERE master_pkey = %s', status, pkey)
                if should_rollback:
                    tx.cancel = True

Placeholders are psycopg's `%s` (positional) or `%(name)s` (named) — pick whichever
keeps a given query readable; use `%(name)s` when a value repeats. Rows come back as
plain tuples (index access), matching how the callers already read them.
"""

import atexit
import collections.abc
import contextlib
import dataclasses
import functools
import logging
import os
import threading
import traceback
import typing

import psycopg
import psycopg_pool
from psycopg.rows import dict_row as dict_row  # noqa: F401  (re-exported: query(..., row_factory=db.dict_row))

# Pools are cached by DSN: production drives a single DSN (so a single pool), while the
# test suite spins up many throwaway databases (a pool each). The lock guards the cache;
# the pools themselves are internally thread-safe.
_pools: dict[str, psycopg_pool.ConnectionPool] = {}
_pools_lock: threading.Lock = threading.Lock()


def _make_pool(conninfo: str, *, min_size: int = 0, max_size: int = 16) -> psycopg_pool.ConnectionPool:
    pool = psycopg_pool.ConnectionPool(
        conninfo,
        min_size=min_size,
        max_size=max_size,
        open=True,
        # Hand out only connections that survived a liveness check, so a PG restart
        # (or a dropped test database) self-heals instead of surfacing a dead socket.
        check=psycopg_pool.ConnectionPool.check_connection,
        kwargs={"autocommit": True},
    )
    pool.wait()
    return pool


def get_pool(conninfo: str) -> psycopg_pool.ConnectionPool:
    """Return the process-wide pool for `conninfo`, creating it on first use."""
    with _pools_lock:
        pool = _pools.get(conninfo)
        if pool is None:
            pool = _make_pool(conninfo)
            _pools[conninfo] = pool
        return pool


def close_pools() -> None:
    with _pools_lock:
        pools = list(_pools.values())
        _pools.clear()
    for pool in pools:
        try:
            pool.close()
        except Exception:
            pass  # e.g. a test database was already dropped out from under us


atexit.register(close_pools)


def _reset_pools_after_fork() -> None:
    # A pool's connections belong to the process that opened them; a forked child must
    # never touch the parent's sockets. Drop the references (without closing them from
    # the child) so each child lazily builds its own pool on next use.
    global _pools, _pools_lock
    _pools = {}
    _pools_lock = threading.Lock()


os.register_at_fork(after_in_child=_reset_pools_after_fork)


@contextlib.contextmanager
def open_database(conninfo: str) -> collections.abc.Iterator[psycopg_pool.ConnectionPool]:
    """Yield the process-wide pool for `conninfo`.

    The pool outlives the `with` block (it is process-global and closed at exit); this
    context manager exists to preserve the historical call shape, not to own lifetime.
    """
    yield get_pool(conninfo)


@contextlib.contextmanager
def connection(pool: psycopg_pool.ConnectionPool) -> collections.abc.Iterator[psycopg.Connection]:
    """Check a connection out of `pool` for the duration of the block."""
    with pool.connection() as conn:
        yield conn


@dataclasses.dataclass
class SQLTransaction:
    conn: psycopg.Connection
    cancel: bool = False


@contextlib.contextmanager
def transaction(conn: psycopg.Connection) -> collections.abc.Iterator[SQLTransaction]:
    """Run the block inside a transaction. Set `tx.cancel = True` to roll back."""
    result = SQLTransaction(conn=conn)
    # psycopg.Rollback unwinds conn.transaction() cleanly (rolls back, no propagation).
    with conn.transaction():
        yield result
        if result.cancel:
            raise psycopg.Rollback


_TxP = typing.ParamSpec('_TxP')
_TxR = typing.TypeVar('_TxR')


def transactional(
    fn: typing.Callable[typing.Concatenate[SQLTransaction, _TxP], _TxR],
) -> typing.Callable[typing.Concatenate['psycopg.Connection | SQLTransaction', _TxP], _TxR]:
    """Write a multi-statement DB function ONCE as `def fn(tx: SQLTransaction, …)` and call it with EITHER a
    Connection or an existing SQLTransaction as the first argument. A Connection opens a fresh transaction
    for the call (committed / rolled back here); an existing SQLTransaction passes straight through — no
    nested transaction, no commit — so the outer owner keeps the lifecycle. This collapses the old
    foo()/foo_tx() pairs into one function.

    The wrapper's first parameter is named `tx` (though it accepts a Connection too) so callers already
    written as `foo(tx=…)` keep binding; a Connection can be passed positionally or as `tx=conn`. Reserve
    this for work that must be atomic when called standalone — a single-statement helper needs none of it
    and should just take a `Connection` (a mid-transaction caller passes `tx.conn`)."""

    @functools.wraps(fn)
    def wrapper(tx: 'psycopg.Connection | SQLTransaction', *args: _TxP.args, **kwargs: _TxP.kwargs) -> _TxR:
        if isinstance(tx, SQLTransaction):
            return fn(tx, *args, **kwargs)
        with transaction(tx) as opened:
            return fn(opened, *args, **kwargs)

    return wrapper


class Result:
    """Eagerly-materialised query result.

    The rows are fetched up front so the underlying cursor can close immediately; that
    decouples a result from cursor lifetime and lets callers hold several at once on one
    connection (e.g. an outstanding payments iterator alongside a follow-up COUNT).
    """

    def __init__(self, cursor: psycopg.Cursor) -> None:
        self.rowcount: int = cursor.rowcount
        self.columns: list[str] = [c.name for c in cursor.description] if cursor.description else []
        self._rows: list[typing.Any] = cursor.fetchall() if cursor.description is not None else []
        self._index: int = 0

    def __iter__(self) -> collections.abc.Iterator[typing.Any]:
        return iter(self._rows)

    def fetchone(self) -> typing.Any | None:
        if self._index < len(self._rows):
            row = self._rows[self._index]
            self._index += 1
            return row
        return None

    def fetchall(self) -> list[typing.Any]:
        return self._rows


def _params(args: tuple[typing.Any, ...], kwargs: dict[str, typing.Any]) -> typing.Any:
    if kwargs:
        assert not args, 'Pass positional (%s) OR named (%(name)s) params, not both'
        return kwargs
    if len(args) == 1 and isinstance(args[0], (dict, tuple, list)):
        return args[0]  # a pre-built sequence/mapping passed as a single argument
    return args or None


def query(
    conn: psycopg.Connection, sql: str, *args: typing.Any, row_factory: typing.Any = None, **kwargs: typing.Any
) -> Result:
    # row_factory (e.g. db.dict_row) makes rows accessed by column name rather than position; default
    # is psycopg's tuple rows.
    cursor = conn.cursor(row_factory=row_factory) if row_factory is not None else conn.cursor()
    with cursor:
        cursor.execute(sql, _params(args, kwargs))
        return Result(cursor)


def query_one(
    conn: psycopg.Connection, sql: str, *args: typing.Any, row_factory: typing.Any = None, **kwargs: typing.Any
) -> typing.Any | None:
    return query(conn, sql, *args, row_factory=row_factory, **kwargs).fetchone()


def query_scalar(conn: psycopg.Connection, sql: str, *args: typing.Any, **kwargs: typing.Any) -> typing.Any:
    """Run a query that always returns exactly one row of one column — an aggregate (`COUNT`/`SUM`),
    an `EXISTS`, or a `RETURNING` on a guaranteed row — and return that scalar. Asserts the row is present
    (it can't be absent for these shapes), so callers don't need the `if row:` guard that `query_one`'s
    `Optional` forces. Use `query_one` for lookups that genuinely might miss (find-by-key, etc.)."""
    row = query(conn, sql, *args, **kwargs).fetchone()
    assert row is not None, 'query_scalar: expected exactly one row, got none'
    return row[0]


def run_and_log_errors(callback: typing.Callable[[], typing.Any], log: logging.Logger, error_prefix: str) -> None:
    """Run `callback`, logging (and swallowing) any exception under `error_prefix`."""
    try:
        callback()
    except Exception:
        log.error(f"{error_prefix}. Error was: {traceback.format_exc()}")
