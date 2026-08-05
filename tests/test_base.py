'''
Primitives: instants and durations across the DB boundary, the house rules a scan enforces, and
the standalone parsers/transports.
'''

import pathlib
import pendulum
from providers.google_play.types import GoogleDuration
from vendor import onion_req
import base
import db


def test_db_instants_are_pendulum_and_arithmetic_is_exact(pg_database):
    # Postgres hands back timestamptz in the session's TimeZone, which is not UTC in general, so a loaded
    # instant can carry a zone that has DST transitions. Adding a span to one must move real elapsed time.
    db.set_dsn(pg_database())
    with db.connection() as conn:
        conn.execute("CREATE TABLE t (ts timestamptz NOT NULL, iv interval NOT NULL)")
        conn.execute("SET TIME ZONE 'America/Halifax'")  # spring-forward at 2026-03-08 02:00 local
        conn.execute("INSERT INTO t VALUES ('2026-03-08 01:59:59-04', '1 hour')")
        row = conn.execute("SELECT ts, iv FROM t").fetchone()
        assert row is not None
        loaded_at, grace = row

        assert isinstance(loaded_at, pendulum.DateTime)
        assert isinstance(grace, pendulum.Duration)
        assert loaded_at.utcoffset() == -4 * base.HOUR  # the zone really is in effect, pre-transition

        for span in (1 * base.DAY, 26 * base.HOUR, base.REVOCATION_EFFECTIVE_DELAY):
            moved = loaded_at + span
            elapsed = moved.astimezone(pendulum.UTC) - loaded_at.astimezone(pendulum.UTC)
            assert elapsed.total_seconds() == span.total_seconds(), span

        # And the wire conversions still work on a loaded instant (they divide by a Duration, which a
        # stdlib timedelta divisor cannot do against pendulum's Interval). Same instant, written as UTC.
        assert base.unix_seconds_from_datetime(loaded_at) == base.unix_seconds_from_datetime(
            pendulum.datetime(2026, 3, 8, 5, 59, 59)
        )


def test_duration_constants_are_exact_spans():
    # A Duration built from days= or larger is a CALENDAR step, and it is indistinguishable from an exact
    # span by repr, by ==, or by .days/.seconds — only by adding it across a DST transition. So assert that
    # property directly for every duration the codebase exports, whatever it was spelled as.
    anchor = pendulum.datetime(2026, 3, 8, 1, 59, 59, tz='America/Halifax')  # 1s before spring-forward
    shape = base.PROOF_EXPIRY_SHAPE
    named: list[tuple[str, pendulum.Duration]] = [
        (name, value)
        for name, value in sorted(vars(base).items())
        if isinstance(value, pendulum.Duration) and not name.startswith('_')
    ]
    named += [(f'PROOF_EXPIRY_SHAPE.{field}', getattr(shape, field)) for field in ('clamp', 'renewal_lead', 'grid')]
    named += [('PROOF_EXPIRY_SHAPE.max_proof_lifetime', shape.max_proof_lifetime)]
    assert len(named) >= 10, named  # a rename must not silently empty this out

    for name, span in named:
        elapsed = (anchor + span).astimezone(pendulum.UTC) - anchor.astimezone(pendulum.UTC)
        assert elapsed.total_seconds() == span.total_seconds(), f'{name} is a calendar step, not a span'


def test_no_stdlib_datetime_arithmetic_in_source():
    # Enforce what review cannot see: a calendar-denominated Duration is identical to an exact span by
    # repr, by == and by .days/.seconds, so nothing but a scan catches one. The stdlib types are allowed
    # only where a value is a naive local wall clock (log lines, backup filenames) or at the psycopg
    # boundary that converts into pendulum.
    #
    # The needles are assembled from fragments so this scan does not match its own source.
    stdlib_allowed = {'base.py', 'db.py'}
    calendar_units = ('days', 'weeks', 'months', 'years')
    banned_anywhere = [('duration(' + unit + '=', 'denominate in hours or smaller') for unit in calendar_units]
    banned_outside_allowlist = [
        ('datetime.' + 'timedelta', 'use a pendulum Duration'),
        ('datetime.' + 'datetime', 'use pendulum.DateTime'),
    ]
    skip_dirs = {'vendor', '__pycache__', '.venv', '.git'}

    violations: list[str] = []
    for path in sorted(pathlib.Path('.').glob('**/*.py')):
        if skip_dirs & set(path.parts):
            continue
        allowed = str(path) in stdlib_allowed
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            code = line.split('#', 1)[0]
            checks = banned_anywhere if allowed else banned_anywhere + banned_outside_allowlist
            for needle, advice in checks:
                if needle in code:
                    violations.append(f'{path}:{lineno}: {needle} — {advice}')
    assert not violations, 'stdlib datetime / calendar-duration usage:\n' + '\n'.join(violations)


def test_google_duration_parser():
    err = base.ErrorSink()

    MINUTE_S = 60
    HOUR_S = 60 * MINUTE_S
    DAY_S = 24 * HOUR_S

    test_cases = [
        ("P1D", DAY_S),
        ("P7D", 7 * DAY_S),
        ("P14D", 14 * DAY_S),
        ("P30D", 30 * DAY_S),
        ("P1M", 30 * DAY_S),
        ("P3M", 90 * DAY_S),
        ("P12M", 12 * 30 * DAY_S),
        ("P1Y", 365 * DAY_S),
        ("P1DT1H", 25 * HOUR_S),
        ("P1DT1H12M", 25 * HOUR_S + (12 * MINUTE_S)),
        ("PT1S", 1),
        ("PT59S", 59),
        ("PT50M1S", 50 * MINUTE_S + 1),
    ]

    for string, seconds in test_cases:
        dur = GoogleDuration(string, err)
        assert dur.seconds == seconds, f' {seconds} != {dur.seconds} ({dur.iso8601})'
        assert dur.seconds * 1000 == dur.milliseconds
        assert not err.has()


def test_onion_request_response_lifecycle():
    # Also call into and test the vendored onion request (as we are currently
    # maintaining a bleeding edge version of it).
    onion_req.test_onion_request_response_lifecycle()
