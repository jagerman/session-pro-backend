"""Seed the single `runtime` row (app-global singletons) with defaults.

A data migration rather than SQL because `gen_index_salt` is random. Idempotent: a database that
predates the migration ledger already has the row, so this no-ops there.
"""
import hashlib
import os

import db


def apply_001_seed_runtime(conn):
    row = db.query_one(conn, 'SELECT EXISTS (SELECT 1 FROM runtime)')
    if row and row[0]:
        return
    _ = db.query(conn, '''
        INSERT INTO runtime (gen_index, gen_index_salt, last_expire_unix_ts_ms, apple_notification_checkpoint_unix_ts_ms, revocation_ticket)
        VALUES (0, %s, 0, 0, 0)
    ''', os.urandom(hashlib.blake2b.SALT_SIZE))
