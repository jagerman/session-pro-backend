"""Seed the app-global singleton rows into `globals` with their defaults.

A data migration rather than SQL because `gen_index_salt` is random. Idempotent: a database that
predates this migration already has the rows, so this no-ops there.
"""
import hashlib
import os

import db


def apply_001_seed_globals(conn):
    row = db.query_one(conn, "SELECT EXISTS (SELECT 1 FROM globals WHERE key = 'gen_index')")
    if row and row[0]:
        return
    db.query(conn, "INSERT INTO globals (key, int_val)   VALUES ('gen_index', 0)")
    db.query(conn, "INSERT INTO globals (key, bytes_val) VALUES ('gen_index_salt', %s)", os.urandom(hashlib.blake2b.SALT_SIZE))
    db.query(conn, "INSERT INTO globals (key, int_val)   VALUES ('revocation_ticket', 0)")
    db.query(conn, "INSERT INTO globals (key, ts_val)    VALUES ('apple_notification_checkpoint_at', 'epoch'::timestamptz)")
