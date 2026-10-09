#!/bin/sh
# aibank quickstart — from clone to a running service with one command.
#
# Shape: self-hosted. You run this against YOUR OWN Flutterwave credentials;
# aibank never holds your money and no payment licence is involved.
#
#   ./deploy/quickstart.sh
#
# POSIX sh, no bashisms: this has to work on an Alpine host and a BSD box, not
# only on the author's machine.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"

say() { printf '\n== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

say "checking prerequisites"
have python3 || die "python3 is required (3.11+). Nothing else is."
python3 - <<'PY' || die "python 3.11 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
printf 'python3: %s\n' "$(python3 -V)"

# ---------------------------------------------------------------------------
# Secrets. Generated, never defaulted -- the service refuses to boot without
# them, and a prompt that offers a default is how published constants end up
# in production.
# ---------------------------------------------------------------------------
if [ -f .env ]; then
    say ".env already exists -- leaving it alone"
else
    say "generating .env with fresh secrets"
    gen() { python3 -c 'import secrets;print(secrets.token_urlsafe(32))'; }
    admin=$(gen)
    pepper=$(gen)
    # Written via a heredoc rather than `sed` over .env.example so a future
    # edit to the example cannot silently produce a file with an empty secret.
    cat > .env <<EOF
AIBANK_ADMIN_KEY=$admin
AIBANK_KEY_PEPPER=$pepper
FLW_SECRET_KEY=
FLW_SECRET_HASH=
AIBANK_TRUSTED_PROXY=0
EOF
    chmod 600 .env
    printf 'wrote .env (mode 600). See .env.example for every option.\n'
    printf 'FLW_SECRET_KEY is blank: no real payouts until you fill it in.\n'
fi

# shellcheck disable=SC2046
set -a; . ./.env; set +a

DB=${AIBANK_DB:-./aibank.db}
export AIBANK_DB="$DB"
# Say WHICH database. An inherited AIBANK_DB from the caller's environment is
# respected on purpose, but silently migrating a file somewhere else is how an
# operator ends up with two ledgers and no idea which one the service opens.
printf 'database: %s\n' "$DB"
case $DB in
    ./*|aibank.db) ;;
    *) printf 'note: that path came from AIBANK_DB in your environment, not from .env\n' ;;
esac

say "applying the schema (explicit, never at boot)"
python3 -m aibank.cli migrate

say "running the test suite before telling you it works"
# Production scrypt cost makes an auth-heavy suite crawl; the tests set their
# own cost internally. Dev secrets are scoped to this command only.
#
# The count is printed rather than swallowed: "tests passed" with no number is
# indistinguishable from "no tests ran".
if AIBANK_ALLOW_DEV_SECRETS=1 AIBANK_SCRYPT_N=1024 \
        python3 -m unittest discover -s tests -q > ./quickstart-tests.log 2>&1; then
    grep -E '^Ran [0-9]+ test' ./quickstart-tests.log || printf 'tests passed\n'
    rm -f ./quickstart-tests.log
else
    tail -30 ./quickstart-tests.log >&2
    die "tests failed -- do not deploy this (full log: ./quickstart-tests.log)"
fi

say "creating your account holder"
printf 'email: '
read -r email
[ -n "$email" ] || die "an email is required"
python3 -m aibank.cli create-user "$email"

say "taking a first verified backup"
python3 -m aibank.cli backup --dir ./backups

cat <<EOF

== ready

  start:    python3 -m aibank.cli serve --port 8000
  then:     http://127.0.0.1:8000/   (the dashboard)

  on a timer (both matter):
    python3 -m aibank.cli sweep-holds           # or a lost webhook freezes funds
    python3 -m aibank.cli needs-reconciliation  # exit 2 when something needs you
    python3 -m aibank.cli backup --dir ./backups  # verified snapshot

BEFORE this leaves localhost: it is plain HTTP and the dashboard carries a
session token. Put it behind TLS (deploy/nginx.conf, or compose.yaml which
wires that up) and set AIBANK_TRUSTED_PROXY=1 at the same time.
EOF
