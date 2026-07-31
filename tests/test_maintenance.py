'''
The maintenance mule: task scheduling, and the pure credit-drain arithmetic it drives.
'''

import pendulum
import threading
import time
import backend
import base
import maintenance


def test_drain_credits():
    # The pure half of credit consumption: spend a budget of uncovered time across live credits, oldest
    # first. No clock, no DB, so every shape can be enumerated cheaply -- including the ones that only
    # arise after an outage (a budget far larger than the credits) or a clock stepping backwards.
    def credits(*amounts: pendulum.Duration) -> list[backend.CreditToDrain]:
        return [backend.CreditToDrain(payment_id=i, remaining=a) for i, a in enumerate(amounts, start=1)]

    D = base.DAY
    ZERO = pendulum.duration()

    # (name, credits, budget, expected updated rows, expected spent, expected exhausted)
    cases = [
        ('nothing to charge', credits(30 * D), ZERO, [], ZERO, False),
        # The caller clamps, but a checkpoint ahead of `now` (clock step, a future-dated pass) must never
        # hand length BACK to a credit.
        ('negative budget is inert', credits(30 * D), -5 * D, [], ZERO, False),
        ('no credits at all', [], 5 * D, [], ZERO, False),
        ('partial charge', credits(30 * D), 5 * D, [(1, 25 * D)], 5 * D, False),
        ('charged exactly empty', credits(30 * D), 30 * D, [(1, ZERO)], 30 * D, False),
        ('budget outruns the only credit', credits(30 * D), 45 * D, [(1, ZERO)], 30 * D, True),
        # Oldest-first: the first credit absorbs everything it can before the next is touched at all.
        (
            'spills into the second only',
            credits(10 * D, 30 * D, 30 * D),
            25 * D,
            [(1, ZERO), (2, 15 * D)],
            25 * D,
            False,
        ),
        ('untouched credits are not reported', credits(30 * D, 30 * D, 30 * D), 5 * D, [(1, 25 * D)], 5 * D, False),
        (
            'budget outruns all three',
            credits(10 * D, 10 * D, 10 * D),
            100 * D,
            [(1, ZERO), (2, ZERO), (3, ZERO)],
            30 * D,
            True,
        ),
        # A multi-day catch-up after the drain was down: one pass charges the whole elapsed span.
        ('five-day catch-up', credits(3 * D, 30 * D), 5 * D, [(1, ZERO), (2, 28 * D)], 5 * D, False),
        # Sub-day credits (the --dev-duration-ms path) are the same arithmetic.
        (
            'seconds, not days',
            credits(base.duration_from_seconds(5), base.duration_from_seconds(30)),
            base.duration_from_seconds(20),
            [(1, ZERO), (2, base.duration_from_seconds(15))],
            base.duration_from_seconds(20),
            False,
        ),
    ]

    for name, cs, budget, want_updated, want_spent, want_exhausted in cases:
        before_total = sum((c.remaining for c in cs), ZERO)
        got = backend.drain_credits(cs, budget)
        assert got.updated == want_updated, name
        assert got.spent == want_spent, name
        assert got.exhausted == want_exhausted, name

        # Invariants that must hold for EVERY shape, not just the ones enumerated above:
        # spend what was asked for or all there is, whichever is less -- never more, never less.
        assert got.spent == min(max(budget, ZERO), before_total), name
        # The credits' total falls by exactly what was spent.
        new_by_id = dict(got.updated)
        after_total = sum((new_by_id.get(c.payment_id, c.remaining) for c in cs), ZERO)
        assert after_total == before_total - got.spent, name
        # No credit is ever driven negative, and none gains length.
        for c in cs:
            assert ZERO <= new_by_id.get(c.payment_id, c.remaining) <= c.remaining, name
        # `exhausted` means precisely "the budget outran the credits", i.e. nothing is left to charge.
        assert got.exhausted == (after_total == ZERO and got.spent < max(budget, ZERO) and len(cs) > 0), name

    # Draining is idempotent once everything is spent: a second pass over already-empty credits with more
    # budget reports no writes (there is nothing to update) and charges nothing.
    empty = credits(ZERO, ZERO)
    again = backend.drain_credits(empty, 10 * D)
    assert again.updated == []
    assert again.spent == ZERO
    assert again.exhausted is True


def test_maintenance_loop_runs_due_tasks_and_survives_a_raising_one():
    # The mule has no harakiri leash, so the loop must treat its tasks as independent: one that raises is
    # logged and left behind, never allowed to take the loop (or the tasks after it) down with it. A task
    # that isn't due yet is skipped without running -- checked BEFORE the task that stops the loop, so a
    # skip can't be confused with the loop having already exited.
    calls: list[str] = []
    stop = threading.Event()

    def boom() -> None:
        calls.append('boom')
        raise RuntimeError('task blew up')

    def not_due() -> None:
        calls.append('not-due')

    def stopper() -> None:
        calls.append('stopper')
        stop.set()  # one pass over the task list is all this test needs

    tasks = [
        maintenance.Task(name='boom', interval_s=0.0, run=boom),
        maintenance.Task(name='not-due', interval_s=3600.0, run=not_due, last_run_s=time.monotonic()),
        maintenance.Task(name='stopper', interval_s=0.0, run=stopper),
    ]
    maintenance.loop(tasks, stop)

    assert calls == ['boom', 'stopper']
    # The raiser's last_run_s still advanced, so a permanently failing task backs off to its interval
    # instead of re-running every tick.
    assert tasks[0].last_run_s is not None
