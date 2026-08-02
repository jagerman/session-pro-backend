# Working on the Session Pro backend

Flask + raw psycopg 3 backend that signs Session Pro entitlement proofs, ingests Apple/Google store
notifications, and serves a proof-revocation list. Deployed as a uWSGI Emperor vassal (`docs/deploy.md`).

Names, comments and docs in this repository have a track record of being confidently wrong. Verify what
they claim against the code rather than believing it — especially that a function does what it is called and
that a stated constraint is real.

## Verify your work

Work on a branch. `dev` receives merges, never commits.

All four must pass; CI (`.drone.jsonnet`) runs them as separate pipelines:

```bash
pytest tests       # needs pytest-postgresql; conftest boots a throwaway PG cluster, one database per test
mypy .
black --check .    # 120 cols, single quotes preserved (pyproject.toml)
flake8
```

A new dependency goes in **three** places: `requirements.txt`, `.drone.jsonnet`'s apt list, and
`scripts/deploy.sh`'s apt list. Prefer a Debian package; pip installs only what Debian lacks.

## Invariants a change can silently break

**Instants and durations are pendulum, never stdlib.** Adding a stdlib `timedelta` to an aware `datetime`
is wall-clock arithmetic, so a span crossing a DST transition moves the wrong amount of real time — and no
choice of units avoids it, because `timedelta` normalises `hours=24` to `days=1` and keeps no record of
which you meant. Pendulum can express the difference: a `Duration` from **hours or smaller** is an exact
span, from days or larger it is a calendar step. Every duration here is a span, composed from `base.HOUR` /
`base.DAY` (e.g. `29 * base.DAY`). `test_duration_constants_are_exact_spans` and
`test_no_stdlib_datetime_arithmetic_in_source` enforce this, because a calendar-denominated `Duration` is
indistinguishable from an exact one by repr, by `==`, and by `.days`/`.seconds`.

**Pools must be created after `fork()`.** A pool spawns threads and forking a threaded process corrupts the
children, so `db.set_dsn()` records the DSN and creates nothing; the pool is built lazily on first use in a
worker or the mule, and the pre-fork uWSGI master uses `db.connect_one()`. Do not add eager pool creation
at startup, and do not enable uWSGI `lazy-apps` (it segfaults the mule).

**The wire and proof format is implemented twice** — here, and in libsession-util as verifier.
`docs/pro-wire-protocol.md` is authoritative for both. Any change to a signed message, a field name or a
protocol timing constant has to be coordinated with that side. The format is still mutable while
`base.BACKEND_VERSION` begins with `0.`; it freezes at launch, after which changes need a new proof version.

**SQL lives in `backend.py`.** `server.py` validates input, calls the backend and renders the response
envelope; it holds no SQL and should stay that way.

**Migrations are `schema/NNN_*.sql`** (or `NNN_*.py` for a data/semantic step that needs real logic),
tracked by filename in a ledger, each applied once in its own transaction by the pre-fork master at
startup. Write them idempotently — `schema/README` has the rules.

**Provider notification handlers must not wedge on one bad message.** Notifications are unrelated events:
give each its own transaction, and let a failure be logged and skipped rather than aborting the batch or
holding back a checkpoint. Several handler branches raise rather than reporting an error, so isolate the
decode too.

**A Google notification is a hint; the fetched subscription resource is the truth.** Google sets no
ordering keys, so RTDNs arrive out of order and the subscriber only sorts within a batch. What makes that
safe is that every mutating branch in `handle_subscription_notification` gates on the `subscription_state`
of a freshly fetched resource, so a notification whose type no longer matches the store's current state
does nothing. A branch that acts on the notification type alone applies stale changes, silently and out of
order. `docs/limitations.md` has the detail, and lists the dormant branches this applies to.

**`revoked_at` means "entitlement stopped here".** `payments.revoked_at` holds the store's refund instant,
and the entitlement granted up to that instant stands — the user really was subscribed until then. It must
never come to mean "this payment never existed": credit consumption depends on that reading, and
back-dating it would turn a consumed term into uncovered time and silently charge any credit that was alive
during it. (`generations.revoked_at` is a different thing — our own clock, stamped at the write site,
because the served revocation list turns it into `effective_ts`.)

**A credit is consumed only while nothing else covers the account.** A minted payment — a voucher, or dev
staging — carries `credit_remaining`, a *length* rather than a paid-through instant, and stacks on top of
whatever coverage exists instead of competing with it. Account expiry is `max(drain checkpoint, subscription
coverage) + Σ remaining`, and anchoring on the checkpoint rather than on `now` is what keeps that a fixed
instant: each drain pass advances the checkpoint by exactly what it charged. Reaching for the wall clock
there makes the expiry walk forward on every pass.

**The schema defines the data, never what the code wants from the data.** A column holds exactly one
domain fact; code adapts to the data, not the reverse. The grace-period column is this repo's
cautionary tale: it held our notification-latency allowance most of the time and the store's dunning
window during grace — two unrelated quantities sharing a column because both satisfied the consumer
("a number to add to expiry"), with nothing marking which was present — and it bit months later,
from a direction nobody predicted. The rules that fall out: our policy values (config, allowances)
are applied **on read** and never stored beside store facts, because a stored constant fossilises;
**NULL means the fact does not apply or was never stated** (a voucher has no grace concept; Google
expresses grace by moving `expiryTime`) — never encode absence as `0` or a sentinel, and never
introduce a NULL-vs-value distinction no domain input can produce; never store a marker derivable
from other columns (it drifts, and nothing enforces it). "Show me code that reads the distinction"
is not a valid argument for or against a schema shape in either direction — consumers legitimately
inform indexes and migration risk, never meaning.

## Documentation map

| File | What it is |
|---|---|
| `docs/pro-wire-protocol.md` | Authoritative client contract, shared with libsession-util. Describes the protocol as it is: no decision rationale, and no history of fields that were removed. |
| `docs/limitations.md` | Operator-facing: dormant provider branches that are safe only while a store feature is off, plus accepted trade-offs. Read before enabling anything in Play Console / App Store Connect. |
| `docs/deploy.md` | Deploy guide and disaster-recovery runbook. |
| `google.md` | Google Play lifecycle reference: what each notification means and how it is handled. |
| `readme.md` | Developer setup, architecture narrative and CLI reference. |

## Conventions

- Raise `base.FailError` / `base.ServerError`; the app error handler renders the wire envelope. `ErrorSink`
  is the older accumulate-then-check style, still used through the provider paths.
- The wire speaks integer seconds; the payment providers speak milliseconds. Convert only in `base`'s
  converters, at those two boundaries.
