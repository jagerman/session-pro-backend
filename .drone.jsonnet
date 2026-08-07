// Session Pro Backend CI. Three parallel pipelines — lint (black + flake8), typecheck (mypy), and
// test (the pytest suite against an ephemeral PostgreSQL). Structure/idioms follow the org's other
// .drone.jsonnet files (apt_get_quiet, docker_base, the eatmydata apt prelude, add_stf_repo).
//
// Everything Debian packages is installed from apt (the set to bake into a prebuilt CI image later);
// the few unpackaged deps — the Apple/Google SDKs — come from pip installed globally with
// --break-system-packages (no venv).

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';
local docker_base = 'registry.session.codes/';
local image = docker_base + 'debian-sid';

// The project's runtime deps that Debian packages. pip then adds only the unpackaged rest (the
// Apple/Google SDKs) on top. This is the set to bake into a prebuilt CI image.
local app_deb_deps = [
  'python3-coloredlogs',
  'python3-flask',
  'python3-nacl',
  'python3-pendulum',
  'python3-psycopg',
  'python3-psycopg-pool',
  'python3-googleapi',
];

// Install the pip-only deps (Apple/Google SDKs) globally; apt-satisfied deps are skipped, so no
// native wheels are built. Extra args (e.g. pytest-postgresql for the test job) are appended.
local pip_global = 'python3 -m pip install --break-system-packages -r requirements.txt';

// Add the Session apt repo (deb.session.foundation) — it provides python3-session-util, the
// onion-request binding vendor/onion_req.py needs. Key is vendored at utils/ (see the org's other
// .drone.jsonnet files for the same pattern); the sid image tracks the repo's `sid` suite.
local add_stf_repo = [
  'cp utils/deb.session.foundation.gpg /etc/apt/trusted.gpg.d/',
  'echo "deb http://deb.session.foundation sid main" > /etc/apt/sources.list.d/session.list',
  'eatmydata ' + apt_get_quiet + ' update',
];

// Quiet apt prelude + eatmydata, optionally add the Session repo, then install python3 + `deps`.
// Mirrors the debian_pipeline setup in libsession-util's .drone.jsonnet.
local apt_setup(deps, stf_repo=false) =
  [
    'echo "Running on ${DRONE_STAGE_MACHINE}"',
    'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
    apt_get_quiet + ' update',
    apt_get_quiet + ' install -y eatmydata',
  ]
  + (if stf_repo then add_stf_repo else [])
  + [
    'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y '
    + std.join(' ', ['python3', 'ca-certificates'] + deps),
  ];

// A single-step docker pipeline that apt-installs `deps` then runs `commands` on the sid image.
local py_pipeline(name, deps=[], commands=[], stf_repo=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: 'amd64' },
  trigger: { event: ['push', 'pull_request', 'tag'] },
  steps: [{
    name: name,
    image: image,
    pull: 'always',
    commands: apt_setup(deps, stf_repo) + commands,
  }],
};

[
  // black + flake8 straight from Debian — they import nothing from the project. (The CLI binaries
  // live in the `black` / `flake8` packages; `python3-black` doesn't exist and `python3-flake8` is
  // just the library.)
  py_pipeline('lint',
              deps=['black', 'flake8'],
              commands=['black --check .', 'flake8']),

  // mypy from Debian. It needs the real third-party types installed (e.g. appstoreserverlibrary, or
  // Apple fields degrade to `str` and false-positive), so install the full deps first; mypy then runs
  // under the system interpreter where pip put them. (session_util has no stubs, so it stays Any via
  // ignore_missing_imports — the Session repo isn't needed here.)
  py_pipeline('typecheck',
              deps=['mypy', 'python3-pip'] + app_deb_deps,
              commands=[pip_global, 'mypy .']),

  // Debian ships everything the suite needs except the Apple/Google SDKs (pip) — including
  // python3-session-util from the Session repo (vendor/onion_req.py imports it). postgresql provides
  // the initdb/pg_ctl binaries conftest.py boots its throwaway cluster with; initdb refuses to run as
  // root, so run the suite as an unprivileged user. The suite lives in `tests/`; naming it keeps the run
  // to the suite rather than whatever else default discovery might pick up.
  py_pipeline('test',
              stf_repo=true,
              deps=['python3-pytest', 'python3-pip', 'python3-session-util', 'postgresql'] + app_deb_deps,
              commands=[
                pip_global + ' pytest-postgresql',
                'useradd -m ci',
                'chown -R ci:ci .',
                "su ci -c 'python3 -m pytest -q tests'",
              ]),
]
