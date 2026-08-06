# Session Pro Backend in a container, for local dev and QA.
#
# This is NOT the production deployment — that is scripts/deploy.sh (dedicated PostgreSQL cluster,
# uWSGI tyrant Emperor, nginx, pgBackRest). This image is a single self-contained uwsgi process
# serving HTTP directly, paired with a throwaway postgres in docker-compose.yml.
#
# It ships a deterministic signing key so the proof-signing pubkey (and therefore the onion pubkey
# derived from it) is stable across rebuilds, and runs with provider_dry_run + the /dev routes so
# subscriptions can be staged for any provider with no Apple/Google credentials involved anywhere.
#
# Build context is the repo ROOT, not this directory:
#   docker compose up --build        (from docker/)
#   docker build -f docker/Dockerfile .

FROM debian:bookworm-slim

ARG USER_NAME=pro-backend
ENV DEBIAN_FRONTEND=noninteractive
# Unbuffered so app logs appear in `docker compose logs` as they happen, not at flush time.
ENV PYTHONUNBUFFERED=1

# Base tooling needed to add the Oxen apt repo, plus psql for the entrypoint's readiness wait.
RUN apt-get update && apt-get install --no-install-recommends -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    postgresql-client \
    procps

# Install the Oxen apt repository public signing key and add the repository. This is where
# python3-session-util comes from — the onion-request binding that vendor/onion_req.py imports to
# serve /oxen/v4/lsrpc. (scripts/deploy.sh uses this same repo for the same package.)
RUN curl -so /etc/apt/trusted.gpg.d/oxen.gpg https://deb.oxen.io/pub.gpg && \
    echo "deb https://deb.oxen.io $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/oxen.list

# Prefer Debian-shipped libraries where they are adequate (leaner, security-updated, no compiler).
# uwsgi-core + the python3 and http plugins let one standalone process serve HTTP and run the mule.
RUN apt-get update && apt-get install --no-install-recommends -y \
    python3 \
    python3-pip \
    python3-flask \
    python3-nacl \
    python3-session-util \
    python3-uwsgidecorators \
    uwsgi-core \
    uwsgi-plugin-python3

# Non-root application user (do NOT run the backend as root).
RUN useradd -m $USER_NAME

COPY . /home/$USER_NAME/app
WORKDIR /home/$USER_NAME/app

# requirements.txt verbatim — no subsetting. pip reports the apt-installed flask/pynacl as already
# satisfied and installs the rest: psycopg + psycopg-pool (bookworm ships pool 3.1, the code wants
# ~=3.2) and the Apple/Google SDKs. Those SDKs are needed even with both providers disabled, because
# backend.py lazily imports them on the Apple and Google *redeem* paths — so a minted app_store or
# google_play payment touches them. Installed unconditionally rather than guessing which subset a
# given code path reaches.
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# Deterministic Ed25519 signing key, so the proof-signing pubkey — and the X25519 onion pubkey the
# backend derives from it (server.init -> to_curve25519_private_key) — are stable across rebuilds.
#
# The file holds 128 hex chars: the 32-byte seed followed by its 32-byte public key.
# load_backend_signing_key verifies the two match, so unlike the file server's key this cannot be an
# arbitrary hex string. The seed here is the ASCII "SessionProDevnetSessionProDevnet".
#
# This is a throwaway dev/QA key — do NOT reuse it for anything real.
#   ed25519 signing pubkey: cf1079a5e0eb0ffc9397fbdf16d1eb96e91f06d35935d1d40d13f0a124a0cbe5
#   x25519 onion pubkey   : 62a5e20c04785c8d68cd1f85b782d467c84efc720753c36fa0b43c086dfa2022
#
# To use your own key instead, write it to key_ed25519 at the repo root before building.
RUN install -d -m 0755 /etc/session-pro-backend && \
    if [ -f key_ed25519 ]; then cp key_ed25519 /etc/session-pro-backend/key_ed25519; else \
      printf '%s' '53657373696f6e50726f4465766e657453657373696f6e50726f4465766e6574cf1079a5e0eb0ffc9397fbdf16d1eb96e91f06d35935d1d40d13f0a124a0cbe5' \
        > /etc/session-pro-backend/key_ed25519; fi && \
    chown root:$USER_NAME /etc/session-pro-backend/key_ed25519 && \
    chmod 0440 /etc/session-pro-backend/key_ed25519

# uwsgi config: scripts/uwsgi/pro-backend.ini minus everything Emperor/socket/logfile-specific (no
# vassal, no venv, no unix socket, no log file — HTTP on :80 and logs to stdout for `docker logs`).
# The flags that are NOT incidental are commented; see the readme's uWSGI section for the rest.
RUN printf '%s\n' \
    '[uwsgi]' \
    "chdir = /home/$USER_NAME/app" \
    "uid = $USER_NAME" \
    "gid = $USER_NAME" \
    'plugins = python3,http' \
    'http = :80' \
    'module = main:flask_app' \
    '# Singleton background work runs in mules, not per-worker. Two of them, matching the paths in' \
    "# the backend's own scripts/uwsgi/pro-backend.ini — keep them in step: a mule whose module can't" \
    '# be imported is crippled and respawned forever, which uWSGI reports only in its own log while' \
    '# the HTTP side keeps serving, so it stays invisible until someone reads the container output.' \
    'mule = providers.google_play.mule:run' \
    'mule = maintenance:run' \
    'master = true' \
    'processes = 4' \
    '# MUST be enabled: the mule runs the subscriber pull loop on a thread, and without this uWSGI' \
    "# leaves the GIL disabled so the app's threads never run." \
    'enable-threads = true' \
    '# Restore the UNIX convention that SIGTERM kills the process (uWSGI otherwise reloads).' \
    'die-on-term = true' \
    '# Abort startup on any bad option or a missing app, rather than serving a half-configured process.' \
    'strict = true' \
    'need-app = true' \
    'vacuum = true' \
    'harakiri = 10' \
    'worker-reload-mercy = 5' \
    'log-4xx = true' \
    'log-5xx = true' \
    'env = SESH_PRO_BACKEND_INI_PATH=/etc/session-pro-backend/config.ini' \
    > /etc/session-pro-backend/uwsgi-pro.ini

COPY docker/entrypoint.sh /home/$USER_NAME/entrypoint.sh
RUN chmod +x /home/$USER_NAME/entrypoint.sh && chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/app

EXPOSE 80

ENTRYPOINT ["/home/pro-backend/entrypoint.sh"]
