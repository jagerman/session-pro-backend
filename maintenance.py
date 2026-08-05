'''
Maintenance mule: all of the backend's periodic housekeeping, in one place, off the request workers.
Run as a uWSGI mule (`mule = maintenance:run` in the vassal ini).

Each task carries its own interval and is due when that much time has elapsed since it last ran; the loop
wakes once a second and runs whatever is due. That is deliberately not a uWSGI `@timer`: a timer must be
registered against a worker (a mule cannot register uWSGI signals), which put singleton housekeeping on
worker 1 and left it competing with request handling. A plain loop needs no signal registration, so it can
live in a mule — and it also runs under a bare `python -m`/`flask run`, where the `@timer` decorator was a
no-op and the prune therefore never fired at all.

Scheduling uses `time.monotonic()`, never the wall clock: an NTP step backwards would otherwise stall every
task by the size of the jump, and a step forwards would fire all of them at once. The wall clock belongs
only to the tasks themselves, which record what they have processed in their own durable checkpoints.

`last_run` is in-memory and deliberately not persisted. Every task that needs durability across a restart
already carries its own checkpoint (Apple's `apple_notification_checkpoint_at`), and the prune is
idempotent, so a restart re-running a task early is harmless — a scheduler with its own persisted state
would only add a second source of truth.

`run()` executes in the mule *post-fork*, so the DB pool and any provider clients are built here rather
than inherited from the master.
'''

import atexit
import dataclasses
import logging
import sys
import threading
import time
import traceback
import typing

import pendulum

import base
import backend
import config
import db

log = logging.getLogger('pro')

# How often the loop wakes to look for due tasks. Well below every task interval, so a task runs within a
# second of becoming due; a wake with nothing due costs a few comparisons.
TICK_S = 1.0

PRUNE_INTERVAL_S = 600  # ~10 min; a no-op prune is a cheap indexed empty scan
# Apple's own webhook retries are hours apart (1, 12, 24, 48, 72), so polling this often is what decides
# how soon a notification we failed to accept gets applied. A poll that finds nothing is one empty API
# call, so the interval is cheap; see catchup_on_missed_notifications for the window it asks for.
APPLE_CATCHUP_INTERVAL_S = 300  # 5 min

# How often the drain LOOKS for work. WHICH accounts it finds is a separate matter, set per-account by
# `voucher_processing_window` in the config: a frequent task with a day-long window spreads the accounts
# coming due thinly across the day rather than letting them land in one spike. Neither number affects what
# gets charged — that is always the span since the account's own checkpoint.
CREDIT_DRAIN_INTERVAL_S = 120  # 2 min

# How often the Google reconcile queue is drained as a BACKSTOP. The pull loop triggers a drain itself after
# every pull, so this is not the latency path — it covers what that cannot: a token enqueued while the
# subscriber was down, a backlog left by a crash mid-pass, and the linked-token markers a reconcile writes
# for a superseded subscription. It cannot be omitted, and not because of proof latency: `needs_ack` is
# written only when the drain registers a payment, and Google auto-refunds a purchase left unacknowledged
# for three days.
GOOGLE_RECONCILE_INTERVAL_S = 60  # 1 min


@dataclasses.dataclass
class Task:
    name: str  # Appears in the log line if the task raises
    interval_s: float
    run: typing.Callable[[], None]
    # Monotonic instant of the last run; None means "never ran", so every task fires once on startup. That
    # is wanted, not merely tolerated: a mule start is exactly when a catch-up should look for whatever was
    # missed while we were down.
    last_run_s: float | None = None

    def due(self, now_s: float) -> bool:
        return self.last_run_s is None or (now_s - self.last_run_s) >= self.interval_s


def _prune() -> None:
    now = base.utc_now()
    with db.connection() as conn:
        # The deletes are unrelated, so one failing (a lock timeout, a transient error) must not hold the
        # others back until the next tick: attempt and report each separately. Safe to keep using `conn`
        # after a failure because it is autocommit — a failed statement is its own rolled-back transaction,
        # not an aborted block that poisons everything after it.
        deletes: list[tuple[str, typing.Callable[[], int]]] = [
            ('revocations', lambda: backend.delete_expired_revocations(conn, now)),
            ('apple', lambda: backend.delete_expired_apple_notification_uuids(conn, now)),
            ('google', lambda: backend.delete_expired_google_notifications(conn, now)),
        ]
        counts: list[str] = []
        for name, delete in deletes:
            try:
                counts.append(f'{name}={delete()}')
            except Exception:
                log.error(f'Prune of {name} failed:\n{traceback.format_exc()}')
                counts.append(f'{name}=FAILED')
    log.debug(f'Pruned expired rows ({", ".join(counts)})')


def _drain_credits(window: pendulum.Duration) -> None:
    now = base.utc_now()
    with db.connection() as conn:
        visited = backend.drain_due_credits(conn, now=now, stale_after=window)
    if visited:
        # How many accounts the pass LOOKED at, which is not a payment event -- an account is visited on
        # every window whether or not its credits had anything to give. What was actually charged, and any
        # credit that ran out, is reported by the drain itself.
        log.debug(f'Drained credits for {visited} account(s)')


def loop(tasks: list[Task], stop: threading.Event) -> None:
    '''Run due tasks forever, waking every TICK_S, until `stop` is set. Exposed separately from run() so it
    can be driven directly in a test with a pre-set event or a stub task.

    A task that raises is logged and skipped, never allowed to kill the loop or the tasks behind it: the
    tasks are independent, and a mule has no harakiri leash to fall back on.'''
    while not stop.is_set():
        now_s = time.monotonic()
        for task in tasks:
            if stop.is_set():
                break
            if not task.due(now_s):
                continue
            task.last_run_s = now_s
            try:
                task.run()
            except Exception:
                log.error(f'Maintenance task {task.name} raised:\n{traceback.format_exc()}')
        stop.wait(TICK_S)


def run() -> None:
    # The mule forks from the uWSGI master *after* main.entry_point() ran, so the shared loggers arrive with
    # the master's handlers already attached; `configure_logging` clears them, otherwise every line is
    # emitted once per inherited handler. uWSGI's `logto` captures this process's stderr into the vassal
    # log, same as the workers. Bootstrap first so a config failure has somewhere to go.
    base.bootstrap_logging()

    try:
        parsed = config.parse_args()
    except config.ConfigError as e:
        log.error(f'Maintenance mule failed to start, invalid configuration:\n  {e}')
        sys.exit(1)
    base.configure_logging(parsed.log_level, parsed.log_levels)
    base.UNSAFE_LOGGING = parsed.unsafe_logging
    db.set_dsn(parsed.db_url)
    base.RENEWAL_LATENCY_ALLOWANCE = parsed.renewal_latency_allowance
    base.PROVIDER_DRY_RUN = parsed.provider_dry_run

    tasks: list[Task] = [
        Task(name='prune', interval_s=PRUNE_INTERVAL_S, run=_prune),
        Task(
            name='credit-drain',
            interval_s=CREDIT_DRAIN_INTERVAL_S,
            run=lambda: _drain_credits(parsed.voucher_processing_window),
        ),
    ]

    if parsed.with_provider_app_store:
        # Import and construct the Apple provider only if enabled — zero footprint when disabled. `core`
        # is built HERE rather than inherited: the mule forks from the master, which never builds it.
        from providers import app_store

        core: app_store.Core = app_store.init(
            key_id=parsed.apple_key_id,
            issuer_id=parsed.apple_issuer_id,
            bundle_id=parsed.apple_bundle_id,
            app_id=None if parsed.apple_sandbox_env else parsed.apple_app_id,
            key_bytes=parsed.apple_key,
            root_certs=parsed.apple_root_certs,
            sandbox_env=parsed.apple_sandbox_env,
        )

        def _apple_catchup() -> None:
            with db.connection() as conn:
                app_store.catchup_on_missed_notifications(core=core, sql_conn=conn)

        tasks.append(Task(name='apple-catchup', interval_s=APPLE_CATCHUP_INTERVAL_S, run=_apple_catchup))

    if parsed.with_provider_google_play and not parsed.provider_dry_run:
        # Same import-only-if-enabled shape as Apple above. Skipped under provider_dry_run for the reason
        # start_subscriber is: the drain FETCHES from Google, and the dry-run stub answers with a synthetic
        # active subscription that would be converged onto real rows.
        from providers import google_play

        def _drain_google_reconciles() -> None:
            drained = google_play.drain_due_reconciles(at=base.utc_now())
            if drained:
                # A count of tokens looked at; most converge to what we already had. The ones that changed
                # something say so individually, at INFO, from the converge.
                log.debug(f'Reconciled {drained} Google subscription(s)')

        tasks.append(
            Task(name='google-reconcile', interval_s=GOOGLE_RECONCILE_INTERVAL_S, run=_drain_google_reconciles)
        )

    stop = threading.Event()
    atexit.register(stop.set)
    log.info(f'Maintenance mule started ({", ".join(t.name for t in tasks)})')
    loop(tasks, stop)
