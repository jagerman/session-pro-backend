# Session Pro Backend

A server powered by Python3 and Flask to manage the lifetime of a Session
Pro subscription for Session users such as:

- Registering payments for Session Pro subscriptions
- Producing cryptographic proofs to entitle cryptographic keys to use Session Pro
  features on the Session protocol
- Pruning expired and revoking cryptographic proofs
- Authorising new cryptographic keys for a pre-existing subscription

And so forth.

# Layout

- `vendor/`: 3rd party dependencies

- `base.py`: Basic primitives shared across all modules where necessary.

- `backend.py`: DB layer that validates incoming requests and stores/retrieves
information from the DB.

- `main.py`: Entry point of application that setups the basic environment for the
database and then hands over control flow to Flask to handle HTTP requests.

- `cli.py`: Command-line interface for database operations. Use this for user error
  management, Google notification handling, revocations, report generation, and DB
  inspection. Run `python cli.py --help` for detailed usage information.

- `providers/app_store.py`: iOS App Store layer that exposes a HTTP route to
receive subscription notifications and turns the purchases they describe into
payment records.

- `providers/google_play/`: Google Play Store layer that subscribes to Google's
real-time developer notifications to witness subscription purchases (`mule.py`
runs the subscriber, `notifications.py` handles what it pulls, `api.py` wraps the
Play Developer API).

- `server.py`: HTTP layer that parses client requests and forwards them to backend
layer and replies a response, if any.

- `db.py`: Connection pool, transaction helpers and the `@transactional` wrapper
every multi-statement backend function is written against.

- `config.py`: Parses the .INI file and environment overrides into the settings
the rest of the application reads.

- `maintenance.py`: The periodic-housekeeping mule — the DB prune and the Apple
notification catch-up, each on its own interval.

- `minting.py`: Creates payments no store ever witnessed, for vouchers and for
local testing.

- `migrations.py` / `schema/`: One-time DB migrations and the ledger that records
which have been applied. See `schema/README`.

- `dev_routes.py`: The `/dev/*` routes that mint Pro subscriptions with no payment
provider involved. Refuses to serve unless `provider_dry_run` is also set.

- `tests/`: The pytest suite, split by area (`test_google.py`, `test_apple.py`,
`test_credits.py`, `test_proofs.py`, `test_payments.py`, `test_server.py`,
`test_maintenance.py`, `test_cli_config.py`, `test_base.py`), with the shared
Flask/DB scaffolding in `tests/helpers.py`. `conftest.py` at the repo root
supplies the throwaway PostgreSQL each test runs against.

- `docs/`: Design and operational docs. **`docs/limitations.md` — payment-provider limitations and the
  store-config invariants they depend on; READ IT before enabling any new Google Play Console / App Store
  Connect feature (one-time products, prepaid plans, subscription pause, promotional offers, etc.).** Also
  the authoritative wire/proof spec, `docs/pro-wire-protocol.md`.

## Getting Started

```
[base]
# PostgreSQL connection URL. The DB layer is raw psycopg 3, so this must be a PostgreSQL DSN:
#   TCP:         postgresql://user:password@host:port/database
#   Unix socket: postgresql:///database?host=/var/run/postgresql&port=5432&user=<user>
db_url                       = postgresql://user:password@localhost:5432/session_pro

# Set the path where logs and rotated logs will be stored (omit this value/line to opt out of
# logging to a file completely)
log_path                     = <path/to/log>

# Stub ALL payment-provider egress (Apple/Google): outbound mutations become no-ops and gating reads
# return synthetic success. This lets you exercise the payment flow locally/in integration tests with
# no provider credentials and no calls off-box. For testing ONLY — never enable on a real instance.
provider_dry_run             = false

# Serve the /dev/* routes (see dev_routes.py), which mint Pro subscriptions for any unauthenticated
# caller so an end-to-end test can put an account into a Pro state with no payment provider involved.
# Requires provider_dry_run: startup FAILS if this is set without it, because an instance that can
# still reach Apple/Google is by definition not a throwaway one. For testing ONLY.
dev_endpoints                = false

# Enable pulling subscription purchases from the iOS App Store. The [apple] section must be
# configured if this is set
with_provider_app_store          = false

# Enable pulling subscription purchases from the Google Play Store. The [google] section must be
# configured if this is set
with_provider_google_play         = false

# Turn this on if you intend to pull test-notifications from Google/Apple and work with subscription
# payments that have a modified duration (e.g. Google modifies a 1-day subscription to 10 seconds). This
# will modify some functionality with event timestamps to ensure that these timespans are respected
#
# One example is rounding timestamps to Google/Apple's modified timespan to determine whether or not
# a revocation overlaps with the expiry of a payment. If there's an overlap the backend can skip
# issuing a revocation (which is an expensive operation).
provider_testing_env         = false

# By default the backend is configured to strip personal-identifying information (PII) from the
# logs. Enabling this preserves all information in logs. This should not be used in a
# production use-case.
unsafe_logging               = false

# Set the URL to the Session Webhook Manage URL to push warning and error logs to at runtime. Each
# subsequent webhook should be in a section with consecutive incrementing indexes. Omit this
# section to opt out

# [session_webhook.0]
# enabled = False
# url     = <url...>
# name    = <display name...>

# NOTE: The [apple] section and its fields are only required if `with_provider_app_store` is defined
[apple]

# Platform specific strings, see:
# https://github.com/apple/app-store-server-library-python?tab=readme-ov-file#api-usage
key_id                       = <string: key_id>    # e.g. ABCDEFGHIJ
issuer_id                    = <string: issuer_id> # e.g. aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
bundle_id                    = <string: bundle_id> # e.g. com.company.my_application

key_path                     = <string: path/to/keys.p8>
root_cert_path               = <string: path/to/AppleIncRootCertificate.cer>
root_cert_ca_g2_path         = <string: path/to/AppleRootCA-G2.cer>
root_cert_ca_g3_path         = <string: path/to/AppleRootCA-G3.cer>

# Run in Apple's Sandbox environment, otherwise production
sandbox_env                  = true

# This is required if running in production mode (i.e. `sandbox_env` is set to false), otherwise we are
# unable to start up Apple's library
app_id                       = <int: app_id>

# NOTE: The [google] section and its fields are only required if `with_provider_google_play` is defined
[google]
package_name                 = <string: package_name> # e.g. com.company.my_application

# Name of the product to handle Google Play notifications from
subscription_product_id      = session_pro

# Google cloud project that is authorised to receive billing notifications from the google play app
cloud_project_id             = <string: project_name> # e.g. company-ABCDE

# Name of the Google cloud subscription to query notifications from
cloud_subscription_name      = session-pro-sub

# Google cloud application credentials .JSON file
cloud_app_credentials_path   = <path/to/credentials>.json
```

A subset of the options specifiable by the .INI file can be overridden using
environment variables with the exception of `SESH_PRO_BACKEND_INI_PATH` which
can only be specified as an environment variable.

```
# Path to load the .INI file and hence the options to customise the runtime behaviour
SESH_PRO_BACKEND_INI_PATH=<path/to/ini/file.ini>

# For the following options, see the .INI section for more information
SESH_PRO_BACKEND_DB_URL                    = <...>
SESH_PRO_BACKEND_KEY_PATH                  = <...>
SESH_PRO_BACKEND_LOG_PATH                  = <...>
SESH_PRO_BACKEND_PROVIDER_DRY_RUN          = [0|1]
SESH_PRO_BACKEND_PROVIDER_TESTING_ENV      = [0|1]
SESH_PRO_BACKEND_DEV_ENDPOINTS             = [0|1]
SESH_PRO_BACKEND_WITH_PROVIDER_APP_STORE   = [0|1]
SESH_PRO_BACKEND_WITH_PROVIDER_GOOGLE_PLAY = [0|1]
```

## Build and run

```bash
# Get libsession C++ libraries by setting up the repository with the
# instructions at deb.oxen.io (or install from source
# at https://github.com/session-foundation/libsession-util)
sudo apt install libsession-util-dev

# Install the Python bindings to utilise libsession
git clone https://github.com/oxen-io/libsession-python
cd libsession-python && python -m pip install .

# Install Python dependencies for the Session Pro Backend (use requirements-dev.txt for a
# dev checkout — it adds pytest and a pip uWSGI on top of the runtime requirements.txt)
python -m pip install -r requirements-dev.txt

# Run backend w/ a local Flask server in debug mode
python -m flask --app main run --debug

# Another example: as above, but on port 8888 against a specific database
SESH_PRO_BACKEND_DB_URL=postgresql:///session_pro python -m flask --app main run --debug --port 8888

# Run the tests (with printing test names and test output to stdout enabled)
python -m pytest tests --verbose --capture=no

# For running in production we use UWSGI which run multiple instances of the
# Flask app with process lifecycle management, the following command is
# suitable.
#
# Note that the following runs it on a local UWSGI server. If you wish to run
# this from behind a reverse proxy, you want to use (--http-socket) instead of
# (--http) to defer the routing of requests to something like Nginx or Caddy.
# See this link for more details:
#
#   https://uwsgi-docs.readthedocs.io/en/latest/WSGIquickstart.html#putting-behind-a-full-webserver
#   https://uwsgi-docs.readthedocs.io/en/latest/HTTP.html
#
# Or alternatively see how oxen-observer in our ecosystem is configured for
# another reasonable real-world example:
#
#   https://github.com/oxen-io/oxen-observer
#
# Run the backend w/ local UWSGI on port 8000 with 4 processes (i.e. 4 HTTP request
# handlers) against the local `session_pro` database
#
# Threads must be enabled (--enable-threads) on UWSGI. By default UWSGI does not
# initialise Python's threading support, so threads the application creates never
# run. The Google Play subscriber runs its pull loop on a thread, so it needs this.
#
# Singleton background work runs in mules, not in the request workers: the
# maintenance loop (the periodic DB prune, the Apple notification catch-up) and,
# when Google is enabled, the Pub/Sub subscriber. Without the --mule flags below
# nothing prunes and no Google notification is ever consumed.
#
# Die on terminate (--die-on-term) restores
# UNIX convention in that a SIGTERM should kill the process. UWSGI hijacks this
# and reloads the process. This is the defined behaviour until UWSGI v2.1.
#
# Strict (--strict) and need app (--need-app) abort startup unless all
# configuration options are valid and there's a valid application for UWSGI to
# launch from the process. Any misconfiguration essentially aborts startup.
#
# Vacuum (--vacuum) cleans up any temporary files like sockets that UWSGI
# creates.
#
# Process name prefix (--procname-prefix) assigns a human readable name as the
# process name in the kernel.
SESH_PRO_BACKEND_DB_URL=postgresql:///session_pro \
  uwsgi \
  --http 127.0.0.1:8000 \
  --master \
  --wsgi-file main.py \
  --callable flask_app \
  --processes 4 \
  --mule=maintenance:run \
  --enable-threads \
  --die-on-term \
  --strict \
  --need-app \
  --vacuum \
  --worker-reload-mercy=5 \
  --procname-prefix \"SESH Pro Backend \"
```

## Docker (local dev and QA)

`docker/` builds a self-contained backend — one standalone uwsgi process serving HTTP, plus a
throwaway PostgreSQL — for local development and end-to-end testing. It is **not** the production
deployment; that is [scripts/deploy.sh](#deploy-guide).

```bash
cd docker && docker compose up --build
```

The backend comes up on **:8090**. It ships a **deterministic** signing key, so the pubkeys below are
stable across rebuilds (write your own to `key_ed25519` at the repo root before building to override):

```
Ed25519 signing pubkey : cf1079a5e0eb0ffc9397fbdf16d1eb96e91f06d35935d1d40d13f0a124a0cbe5
X25519 onion pubkey    : 62a5e20c04785c8d68cd1f85b782d467c84efc720753c36fa0b43c086dfa2022
```

Proofs are signed by the Ed25519 key; onion requests to `/oxen/v4/lsrpc` are encrypted to the X25519
key. Both derive from the same key file. The entrypoint prints them on every boot, and `/status`
returns the signing pubkey:

```bash
curl -s http://localhost:8090/status | jq
docker compose logs pro-backend | grep -A3 'signing pubkey'
```

### Granting Pro without a store

The stack runs with `provider_dry_run` and `dev_endpoints` on, so subscriptions can be staged for
**any of the three payment providers** with no credentials and no calls off-box. Mint one over HTTP:

```bash
curl -X POST http://localhost:8090/dev/add_payment -H 'Content-Type: application/json' \
     -d '{"master_pkey":"<64-hex>","provider":"google_play","plan":"12M"}'
```

That creates the payment and redeems it, so the account is entitled immediately; a client then asks
for its own proof through the normal `generate_pro_proof` route with its own rotating key. This is
the intended shape for a device test: park the device on the buy-Pro screen, POST the above, let the
device refresh.

Pass `"redeem": false` (Google/Apple only) to stop at an *unredeemed* payment. The payment carries the
master-derived account-id, so the account holder's next authenticated request (`generate_pro_proof` /
`get_pro_status`) reconciles it automatically — exercising the client's own reconcile-on-touch path,
the closest thing to a real store purchase. `"duration": <seconds>` overrides the plan length for expiry
tests.

To have accounts already entitled before anything starts, list them in `docker/vouchers.tsv`; the
entrypoint applies each row on boot and skips accounts that already have an active subscription.

Both payment providers are pinned **off** in this image and there is no way to supply Apple or Google
credentials to it — that is deliberate. It exists to mint payments locally; to exercise the live
integrations (Apple's signed webhook notifications, Google's RTDN subscriber) use a real deployment
via [scripts/deploy.sh](#deploy-guide).

## Command Line Interface

The `cli.py` tool provides a command-line to query and manipulate the database.

```bash
# Voucher management (requires --config)
python cli.py --config config.ini voucher --master-pkey 0xabcd... --plan 12M
# google_play/app_store mint a payment the store never saw, for exercising the per-provider paths;
# both need provider_dry_run. Omit --provider for the default, rangeproof.
python cli.py --config config.ini voucher --master-pkey 0xabcd... --plan 1M --provider google_play

# User error management (requires --config)
python cli.py --config config.ini user-error set "google_play:token123=true"
python cli.py --config config.ini user-error delete "google_play:token123"

# Google notification management (requires --config)
python cli.py --config config.ini google-notification handle "12345"
python cli.py --config config.ini google-notification delete "12345"
python cli.py --config config.ini google-notification list

# Revocation management (requires --config)
python cli.py --config config.ini revoke list 0xabcd...
python cli.py --config config.ini revoke user 0xabcd... --creation-unix-ts-s 1741170600
python cli.py --config config.ini revoke bump-ticket 1000

# Report generation (requires --config)
python cli.py --config config.ini report generate daily --count 7
python cli.py --config config.ini report generate weekly --format csv
```

Run `python cli.py --help` for full command documentation. Use `--help-full` for detailed
format specifications and examples.

# Deploy Guide

Deployment is handled by `scripts/deploy.sh` — an idempotent bash installer, run on the
target host, that provisions the backend under a dedicated non-root user in its own
PostgreSQL cluster (leaving other databases on the box untouched), behind nginx, with
off-host [pgBackRest](https://pgbackrest.org) backups and point-in-time recovery.

See **[docs/deploy.md](docs/deploy.md)** for the full guide, prerequisites, and the
disaster-recovery runbook. In brief:

```bash
git clone https://github.com/session-foundation/session-pro-backend
cd session-pro-backend
cp scripts/deploy.env.example deploy.env   # set PRO_DOMAIN, PGBACKREST_REPO_HOST, platforms, ...
./scripts/deploy.sh            # run as root
```

TLS is left to the operator (e.g. `certbot --nginx -d <domain>`), and Apple/Google
credentials can be added after the first deploy. Once DNS/TLS are up, smoke-test an
unauthenticated endpoint:

```
curl -X POST https://<your-domain>/get_pro_revocations -H "Content-Type: application/json" -d '{"version": 0, "ticket": 0}'
```
# Architecture

![Overview of Session Pro](docs/Session_Pro_Overview_200_zoom_10_border.png)

The deployment tooling (`scripts/deploy.sh` and [docs/deploy.md](docs/deploy.md)) doubles as
a concrete, technical description of the various components that the backend relies on. In
general, the backend is designed as a set of distinct layers that
feed data to each other, which is loosely described by the following diagram (in
reality the links between the layers are a bit more entangled but conceptually
stands).

![Code layers of Session Pro](docs/Session_Pro_Code_Layers_200_zoom_10_border.png)

Ultimately the code centralises in on the backend which manages the database and
lifetimes of payments. From here most payment data is processed and upper layers
can request it to produce cryptographic Pro proofs.

## High-level Design

**Session Pro Client Key Derivation**

A Session user’s account has a secret seed `s` from which their current `a/A`
key pair is derived. For Session Pro, derive a deterministic key (see
`src/ed25519.cpp` in libsession-util) we dub the Master Session Pro Key from
hashing `s` and generating a new key pair from that seed.

```
s2  = Blake2b32(s, key="SessionProRandom")
b/B = Ed25519FromSeed(s2)
```

In addition to the master key pair, a secondary transient key pair dubbed the
Rotating Session Pro Key `c/C` is generated that as its name suggests will be
rotated over time.

```
c = Rotating Session Pro Key
```

This key is loosely managed as it can be updated at any point, even during an
active subscription by registering a new rotating key (the
`/generate_pro_proof` request in `server.py`) with a signature from the master
key. This key pair (including the secret
component) will be synchronised across clients through
user config messages (see `include/session/config/pro.hpp` in libsession-util)
which are stored encrypted on the Session Network swarms.

> This means initially, the client should check if they have a user config
> stored in the swarm first, before generating their own Rotating Session Pro
> key.

The rate at which a Rotating Session Pro key is changed is at the discretion of
the client. Each rotation will require one request to the backend server to
authorise a new certificate to entitle the new Rotating Session Pro key to
Session Pro features.

**Session Pro Backend Server Overview**

The server signs the cryptographic proofs that entitle a device's rotating key to
Session Pro with an Ed25519 key loaded from disk at startup
(`backend.load_backend_signing_key`). Deployment creates that key and the backend
never generates one: a missing or unreadable key is a hard startup error, because
silently regenerating it would invalidate every proof already issued.

It subscribes to the payment hooks from Google Play, Apple App Store and in
future, third party payment vendors like PayPal, Stripe and BTCPay. These payment
systems in one form or another will notify the server upon purchase of a pro
subscription, as well as notifying the Session client that initiated the
purchase; the backend records each payment it witnesses with
`backend.add_unredeemed_payment`.

**Registering a new pro subscription**

The client does not submit the payment to the backend. The store's notification is
the only channel by which the backend learns that a payment exists: the
notification layer records it with `backend.add_unredeemed_payment`, carrying the
account identifier the store attests, which is itself derived from the Master
Session Pro key (Google's `obfuscatedAccountId` is the master public key verbatim;
Apple's `appAccountToken` is `app_store.uuid_from_master_pk` of it).

A payment recorded that way has no owner yet. The client's next authenticated
request — any of `/generate_pro_proof`, `/get_pro_status` or
`/get_payment_details` — binds it, because each of them reconciles first
(`backend.reconcile_pending_payments`) and claims every unowned payment whose
account identifier matches the master key the request is signed with. Holding the
key *is* the claim; there is no separate client-supplied token to match, and so
nothing for a client to get wrong or replay.

The payment record's main fields are:

- Plan and payment provider
- Purchase time, expiry time and grace period, as the provider reports them
- Redemption time and owning user, both null until the payment is claimed
- Revocation time, null unless the payment was refunded or charged back
- The provider's own identifiers, which live in a per-provider detail table
  (`google_play_payment_details`, `app_store_payment_details`, …) rather than as
  nullable columns on the payment row

The user table is updated (`backend._ensure_active_generation` and
`backend._update_user_expiry_grace_and_renew_flag_from_payment_list`) to track
the generation the user is currently on and the latest known subscription expiry
date at time of modification.

A generation is a per-user row carrying a random 32-byte token — the
`revocation_tag` that appears in the proof. It is an *epoch*, not a per-payment
value: the same generation is deliberately reused across renewals, stacked
purchases and auto-redemption, so the tag is stable for the lifetime of a
subscription. A fresh one is minted only when the current generation has been
revoked (`backend.revoke_master_pkey_proofs_and_allocate_new_gen_id`, reached from
`backend.revoke_payments_by_id_internal`), since reusing a revoked generation
would mint proofs that are born already-revoked.

Rolling the generation on every subscription event instead would add an entry to
the revocation list on every renewal, and the rate at which the tag changed would
leak how often the user renews.

This is necessary because clients are technically allowed to rotate their
Rotating Session Public key as many times as they wish. If not the backend is
forced to remember and revoke every key they have authorised through the
server. The generation serves as a way to group all the Rotating Session Public
keys we’ve generated a proof for, under a single identifier such that revocation
of the identifier will revoke all proofs that were generated using it.

> One alternative to the generation would be using the hash of the
> confidential token to group all the proofs generated for a payment. This works
> but imposes some issues for implementing clients that we can avoid.
>
> From a client’s perspective, the most reasonable approach is to cache a proof
> of their subscription until expiry or revocation. If a subscription is
> extended, clients will have to poll or subscribe to the Session Pro Backend
> server to witness this extension in addition to querying the revocation list.
>
> Another alternative is to limit the number of rotating keys that can be
> registered for a payment token/master key. When the key limit is met, we could
> consider removing keys in a FILO manner, all those keys however have to be
> revoked and so given a motivated enough adversary, the revocation list will
> continue to grow unbounded defeating the whole purpose of trying to bound the
> amount of space a user can occupy in the database.

A proof's expiry is the minimum of either 30 days or the remaining time in the
subscription (`backend._build_proof_clamped_expiry_time`), rounded up onto a
random per-account 24-hour grid (`users.proof_expiry_offset`, re-drawn whenever
the account's true expiry moves). The grid stops the proof from publishing the
exact purchase/renewal instant or a stable per-account time of day, and it
spreads renewal traffic that a shared midnight boundary would herd into a single
minute. It does not conceal the plan entirely — see the accepted limitation in
[docs/limitations.md](docs/limitations.md).

Note that subscription expiry is not the same as proof expiry due to this
clamping and it's very possible that a proof's expiry extends beyond the
subscription expiry. Subscription expiry precisely tracks the entitlement period
that the payment provider is enforcing in order to allow clients to accurately
show the subscription status from the perspective of their payment provider.

This means platform clients should take care to periodically on the ending 24
hours of the subscription to pre-emptively query for a new proof from the
Session Pro Backend to ensure seamless pro entitlement across the expiration
boundary if the user is intending to continue their billing cycle.

In absence of any record with an activation time, we assign the activation time
to the Session Pro Backend Server’s clock for the record with the earliest
creation time. This is important to allow the server to revoke active payment
records whilst continuing to correctly calculate the subsequent expiry dates.

The user table record will consist of:

- Master Session Pro Public Key
- Generation index
- Expiry time
- Proof of pro subscription

The `/generate_pro_proof` response carries the proof (`server.py`):

- Version
- Expiry time
- Revocation tag: the generation's random 32-byte token
- Rotating Session Pro Public Key
- Signature over revocation tag ‖ rotating key ‖ expiry time

The response also reports the account's current entitlement horizon alongside the
proof, as an advisory value that is deliberately *not* signed and not part of the
proof itself.

The revocation tag is a random token rather than a counter, so it leaks nothing
about how early in the protocol's lifetime the subscription was created or
modified.

**Updating rotating keys**

In the event that a new rotating key is procured by a client (e.g. a key is lost
and a new one is generated), it can be authorised for the subscription by
submitting the `/generate_pro_proof` request to the backend:

- Master Session Pro Public Key
- Rotating Session Pro Public Key
- Timestamp
- Signature of the payload with the Master Session Pro key
- Signature of the payload with the Rotating Session Pro key

Since the Master Session Pro public key is deterministically derived from the
user's seed, it’s always possible to sign a new request which authorizes a new
rotating key even if said key is lost.

This request will be accepted if the:

- Master Session Pro Public key has an entitlement that is currently live — a
  payment that has not expired and has not been revoked. An account with only
  expired or refunded payments is rejected, as is one with no payments at all.
- Timestamp is well within bounds (to prevent replay attacks)

In that case a proof will be replied to the client as per section Proof of pro
subscription.

The generation remains unchanged, which means every additional Rotating Session
Pro key authorised is grouped into the same bucket of proofs under the current
revocation tag. This is useful for when the user's subscription status is updated:
revoking that one tag blocks every proof in the same bucket.

Although the rotating keys can be updated at any point, the same key is reused
by syncing it to/from the swarm. Clients on start-up should prioritise keys
found in the user config before determining if they should generate a new
rotating key and/or request to generate a new proof. Clients not doing this
would leak the fact that they have multiple devices with different rotating keys
on the Pro proof.

**Lookup user’s proof of pro subscription**

Since clients will append the proof of their subscription to their message (see
`src/session_protocol.cpp` in libsession-util) there isn’t a need to allow users to lookup from the backend the pro
subscription status of other users. The only way then to ascertain their Pro
status is by messaging the user within a group or 1:1.

If a client itself no longer has possession of their Session Pro proof, it can
re-request it by submitting a request as per Updating rotating keys.

In the event the proof is lost but the Rotating Session Pro key is the same, it
can be resubmitted to get the server to sign a new proof. The server does not
hold onto any rotating keys so it does not care about re-use, just that the user
is in possession of a Master Session Pro public key that has an active
subscription.

**Revoking proofs for refunds**

Once proofs are signed by the Session Pro Backend, they are standalone
certificates, valid to use on the protocol until they expire. When
a subscription is updated/cancelled it is necessary to revoke a certificate
after it has been issued. Since the certificate is valid to use until expiry,
the backend must also maintain an additional list of proofs that have been
revoked, served by `/get_pro_revocations`. Clients will periodically synchronise
this list to override current valid proofs.

Upon notification of a refund from the backend’s subscription to the payment
providers, the refund will contain a reference to the confidential payment
token, then:

- The matching payment record has its revocation instant recorded
  (`backend.revoke_payments_by_id_internal`). Revoked and expired are distinct
  states: the payment keeps the store's own refund instant, because the
  entitlement it granted up to that point really did stand.
- The user's current generation is revoked
  (`backend.revoke_master_pkey_proofs_and_allocate_new_gen_id`), invalidating
  every proof issued under it. Each served entry is the revocation tag plus the
  instant it takes effect — a delay long enough that a client polling on its
  normal schedule learns its own tag was revoked before peers begin enforcing it.
  The list carries a monotonic ticket so clients fetch only what is new.

**Subscription expiry**

Every ten minutes the maintenance mule prunes the database, running one delete per
table and logging what each removed: `backend.delete_expired_revocations`,
`delete_expired_apple_notification_uuids` and `delete_expired_google_notifications`.
Each is attempted independently, so one failing does not hold back the rest.

Payments and users are never deleted. Payments are the history
`/get_payment_details` serves, and a user cannot be deleted while a payment
references them. Both tables therefore grow without bound.

**Using proofs on the Session protocol**

The client must be in possession of the specified Rotating Session Pro Public
key in the proof to use it. If the client does not have the key, then it can
restore or procure new keys respectively:

- If the user config message has expired, a new Rotating Session Pro key can be
  generated and authorised as per section Updating rotating keys

- If the user config message is available, then, the key can be restored from
  the user config message.

When submitting a message we append the proof (as per Proof of pro subscription)
as a part of the message payload. A user can be identified as having Session Pro
by verifying the:

- Proof is signed by the Session Pro Backend Server key
- Proof has not expired yet
- Underlying message was signed by the Rotating Session Pro Public key
  referenced in the proof (proving that they know the secret key and are the
  owner of said proof).
- Revocation tag in the proof is not on the revocation list

**Metadata**

The following is a summary of inbound and outbound requests for stake holders of
the system: Clients
- Communicate with the backend server using onion requests to mask the IP of the
  client from the server
- Communicate with other clients by appending the proof of pro subscription
  which consists of publicly available data and an opaque subscription
  identifier:
    - Version
    - Revocation tag (a random per-generation token)
    - Rotating Session Pro Public Key
    - Subscription expiry date
    - Signature for the payload consisting
- Other clients can link the Session user account to their current rotating key
- Retrieve the revocation list, which consists of revocation tags and the instant
  each takes effect, with no further information derivable from this data.
- Claim a payment the store has already reported, by making any authenticated
  request signed with the Master Session Pro key.

  The Session Pro backend server can link which payment is for which proof which
  is necessary to be able to revoke or authorise additional keys. It cannot
  reverse the Master Session Pro Public key to the Session user account without
  prior knowledge of the account.

- Communicates with payment providers which allows them to map IP address to
  a confidential payment token

**Server**

Can link a Master Session Pro and Rotation Session Pro key to their payment
token but not the Session user account due to the irreversibility of the Master
Session Pro key to the Session user key.

**Passive Observer**

All client to server communications are done via onion-requests, encrypted and unreadable.
They can collect proofs which consist of only public data and any private data is hashed

- Version
- Revocation tag (a random per-generation token)
- Rotating Session Pro Public Key
- Subscription expiry date
- Signature for the payload

Cannot observe the Master Session Pro public key because it is generated,
blinded with a quasi-random value unknown to an observer without a user’s
Session seed.

**Android Platform**

In-app purchases can be managed through the [REST
interface](https://developers.google.com/android-publisher/api-ref/rest/v3/inappproducts)
or through the [In-app products page in the Play
Console](https://support.google.com/googleplay/android-developer/answer/1153481#zippy=%2Ccreate-a-single-in-app-product)
(also see: [Create and configure your
products](https://developer.android.com/google/play/billing/getting-ready)). To
enable the payments and initiate a purchase through the app, developers will use
the Google Play Billing Library dependency as detailed
[here](https://developer.android.com/google/play/billing/integrate#connect).

After purchase, a confidential purchase token is emitted to both the Session Pro
Backend server and the client; the backend's handling of it lives in
`providers/google_play/notifications.py`. The client does not submit that token:
the purchase is attributed to the account by the `obfuscatedAccountId` set at
purchase time, and the client's next authenticated request claims it. When
a purchase is interrupted, for example, during network instability or crashes,
it’s recommended to call
[BillingClient.queryPurchasesAsync()](https://developer.android.com/google/play/billing/integrate#process)
on start-up to finish any pending processes. Google has a list of recommended
steps to [\*Verify purchases before granting
entitlements](https://developer.android.com/google/play/billing/security#verify).\*

Notifications of purchases are available by ensuring that [Real-time developer
notifications
(RTDN)](https://developer.android.com/google/play/billing/getting-ready#enable-rtdn)
is turned on. Session Pro is sold as an auto-renewing subscription product with
one base plan per term (monthly, three-monthly, yearly), so the notifications of
interest are the subscription ones; one-time products are not supported (see
[docs/limitations.md](docs/limitations.md)). Handling

**Backend support for Android**

Setup the backend to connect to [Google Play’s
publisher](https://developer.android.com/google/play/billing/lifecycle#rtdn-client)
to be notified of actions that change the entitlement of a certain purchase
token (such as purchase or refunds). When notifications are received, Google
Cloud will continue to deliver the notifications until it has been acknowledged.

If the purchase notification is not acknowledged within 3 days of the purchase,
the purchase is [automatically
refunded](https://developer.android.com/google/play/billing/integrate#notifying-google).
The notifications are encoded into the data structures described
[here](https://developer.android.com/google/play/billing/rtdn-reference#encoding).

Google cloud has some fault-tolerance with regards to when the RTDN fails to
publish to the backend, see their [Handling message
failures](https://cloud.google.com/pubsub/docs/handling-failures) section. In
summary

- You can configure the retry policy, immediate or exponential backoff

- Send the failed messages to a dead letter queue

**iOS Platform**

In-app purchases are managed through the [App Store
Connect](https://developer.apple.com/help/app-store-connect/configure-in-app-purchase-settings/overview-for-configuring-in-app-purchases)
which then uses StoreKit to implement the user flow on clients. Session Pro is
sold as an *auto-renewable subscription*, one product per term.
Apple coins their notification system the [\*App Store Server
Notifications](https://developer.apple.com/help/app-store-connect/configure-in-app-purchase-settings/enter-server-urls-for-app-store-server-notifications)\*
which we configure our backend server to be a recipient of, about events like
new purchases and refund status.

Enable notifications from the following
[guide](https://developer.apple.com/documentation/appstoreservernotifications/enabling-app-store-server-notifications).
The notifications are encoded in a JSON payload, the decoded payload has the
following
[structure](https://developer.apple.com/documentation/appstoreservernotifications/responding-to-app-store-server-notifications#Recover-from-server-outages).
After purchase a notification will be emitted to both the client and the Session
Pro backend server — handled in `providers/app_store.py` — and a similar flow to
the Android platform proceeds, the payment being claimed by the account holder's
next authenticated request.

**Backend support for iOS**

The backend will be configured as the recipient to the App Store Server
Notifications and handle responses as per their
[guide](https://developer.apple.com/documentation/appstoreservernotifications/responding-to-app-store-server-notifications).
Of note for fault-tolerance:

- For version 2 notifications, it retries five times, at 1, 12, 24, 48, and 72
  hours after the previous attempt.

- For version 1 notifications, it retries three times, at 6, 24, and 48 hours
  after the previous attempt.

- Additionally, unlike Google, Apple does have an API to retrieve previous
  purchases if the backend fails to witness them in the [Recover from server
  outages](https://developer.apple.com/documentation/appstoreservernotifications/responding-to-app-store-server-notifications#Recover-from-server-outages)
  section.
