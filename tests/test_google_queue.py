'''
The Google reconcile queue: the durable record that a purchase token owes work, which is what lets a
notification be acked the moment it arrives.
'''

import pendulum

import backend
import base
import db

from tests.helpers import TestingContext


def _queue(ctx) -> list[tuple]:
    with ctx.connection() as conn:
        return db.query(
            conn, 'SELECT payment_token, due_at, attempts, last_error FROM google_reconcile_queue ORDER BY due_at'
        ).fetchall()


def test_enqueueing_a_token_collapses(pg_database):
    # The unit of work is the token, not the notification. Ten RTDNs for one subscription are one piece of
    # work, because the resource is fetched at reconcile time: whatever the tenth would have told us is
    # already in the snapshot the first fetch returns. So the token is the primary key and enqueueing is
    # idempotent -- a burst costs one fetch, not ten.
    with TestingContext(pg_database) as ctx:
        at = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            for offset in range(10):
                with db.transaction(conn) as tx:
                    backend.google_enqueue_reconcile(tx, 'tok', at + offset * base.HOUR)

        rows = _queue(ctx)
        assert len(rows) == 1
        # And it holds the EARLIEST of them: a fresh notification pulls work forward, never pushes it back.
        assert rows[0][1] == at


def test_a_new_notification_pulls_a_backed_off_token_forward_without_forgiving_it(pg_database):
    # A token waiting out a backoff should be retried promptly when new information arrives -- but the
    # arrival says nothing about whether the reason it was failing has gone away. So the due time moves
    # earlier and the failure count does not reset; otherwise a permanently stuck token that keeps
    # receiving notifications would retry at full speed forever.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)
            with db.transaction(conn) as tx:
                backend.google_claim_due_reconciles(tx, now=now, lease_until=now + 1 * base.HOUR, limit=10)
            with db.transaction(conn) as tx:
                backend.google_reconcile_failed(tx, 'tok', retry_at=now + 10 * base.HOUR, error='boom')

            assert _queue(ctx)[0][2] == 1 and _queue(ctx)[0][3] == 'boom'

            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now + 1 * base.HOUR)

        token, due_at, attempts, last_error = _queue(ctx)[0]
        assert due_at == now + 1 * base.HOUR, 'the new notification pulled it forward'
        assert attempts == 1, 'but did not forgive the failure'
        assert last_error == 'boom'


def test_claiming_leases_rather_than_locking_across_the_fetch(pg_database):
    # Reconciling makes a network call, so the claim cannot hold row locks across it the way the credit
    # drain does. It pushes due_at out to a lease instead and commits, leaving the work to happen outside
    # any transaction. A second runner therefore sees nothing due, and a worker that dies mid-fetch simply
    # lets the lease lapse -- no in-progress state to reap, and no way to lose the work.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        lease_until = now + pendulum.duration(minutes=15)
        with ctx.connection() as conn:
            for token in ('tok-a', 'tok-b'):
                with db.transaction(conn) as tx:
                    backend.google_enqueue_reconcile(tx, token, now)

            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(tx, now=now, lease_until=lease_until, limit=10)
            assert sorted(c.payment_token for c in claimed) == ['tok-a', 'tok-b']
            assert all(c.attempts == 0 for c in claimed)

            # A second pass while the lease is live finds nothing.
            with db.transaction(conn) as tx:
                assert backend.google_claim_due_reconciles(tx, now=now, lease_until=lease_until, limit=10) == []

            # Once it lapses, the work comes back on its own.
            with db.transaction(conn) as tx:
                again = backend.google_claim_due_reconciles(
                    tx, now=lease_until, lease_until=lease_until + pendulum.duration(minutes=15), limit=10
                )
            assert sorted(c.payment_token for c in again) == ['tok-a', 'tok-b']


def test_a_finished_token_leaves_the_queue(pg_database):
    # The row is an obligation, not a record: the notification history keeps what arrived, and this table
    # only ever answers "what still owes work". So success deletes rather than marking done.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            with db.transaction(conn) as tx:
                backend.google_enqueue_reconcile(tx, 'tok', now)
            with db.transaction(conn) as tx:
                backend.google_reconcile_done(tx, 'tok')
        assert _queue(ctx) == []


def test_the_claim_takes_the_most_overdue_first_and_respects_its_limit(pg_database):
    # Ordered by due_at so a backlog drains oldest-first rather than starving whatever fell behind, and
    # limited so one pass cannot pull an unbounded batch into memory.
    with TestingContext(pg_database) as ctx:
        now = base.datetime_from_unix_ms(1767225600000)
        with ctx.connection() as conn:
            for index in range(5):
                with db.transaction(conn) as tx:
                    backend.google_enqueue_reconcile(tx, f'tok-{index}', now - (5 - index) * base.HOUR)

            with db.transaction(conn) as tx:
                claimed = backend.google_claim_due_reconciles(tx, now=now, lease_until=now + 1 * base.HOUR, limit=2)
        assert [c.payment_token for c in claimed] == ['tok-0', 'tok-1']
