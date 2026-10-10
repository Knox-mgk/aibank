# aibank

A double-entry banking backend where **humans hold the money and AI agents
spend it under limits they cannot reach.** An account holder signs in, funds a
wallet, allocates money to their agents, and sets each agent's ceilings from a
dashboard. The agent gets an API key that can do exactly one thing with money:
request a payout that the server either allows, holds for approval, or denies.

**You self-host it against your own payment credentials.** aibank never holds
your money and never touches a balance you do not own, so there is no custody
and no payment licence in the picture — the deployment is yours. One command
gets you a running service with TLS, a sweeper, and verified backups.

**Zero third-party dependencies.** Python standard library only, by design.

It ships both ends of that: a **dashboard** for the human and an **MCP server**
so the agent spends through typed tools instead of hand-rolled HTTP.

```
148 unit tests + 338 live assertions against real servers
 33 assertions against the built-and-installed wheel, 0 failures
```

---

## Why

An autonomous agent that can spend money is a liability unless four things are
true: its balance is always correct, its spending is bounded by policy it
cannot bypass, a retried request never moves money twice, and a **human** —
not the agent — decides what the bounds are. The first three are ledger
problems. The fourth is an authorisation problem, and it is the one that makes
this a banking service rather than a wallet library.

## The central invariant

> The human sets the limits. The agent operates under them and can never reach
> them.

This is enforced structurally, not by convention. There are three separate
trust domains, and the HTTP layer keeps them apart:

| domain | credential | may do |
|---|---|---|
| **Agent** | `Authorization: Bearer sk_agent_…` | request payouts, read own balance, add payees |
| **User** | `Authorization: Bearer sess_…` | set policy, fund wallets, approve/reject/refund, rotate keys |
| **Admin** | `X-Admin-Key` | pricing, settlement deposits, sweeper, cross-tenant reads |

An agent key presented to a user-domain route is rejected before any handler
runs. `POST /v1/agents/<id>/policy` is reachable only with a session token, so
**no sequence of agent API calls can raise an agent's own ceiling.** A test
asserts this against the router's source, and the HTTP smoke test proves it
against a live socket:

```
ok   agent key on policy POST -> 401
ok   limit unchanged by the agent's attempt
```

## The ledger

A general ledger with invariants enforced in code, not convention:

1. **Postings within an entry sum to exactly zero.** An unbalanced entry is
   rejected, not corrected.
2. **Postings are immutable.** Corrections are new reversing entries
   (`ledger.reverse_entry`), so history is append-only and auditable. A refund
   leaves both the original and its mirror on the books; reversing twice is
   refused.
3. **`balance = SUM(postings)`**, and **`available = balance − active holds`**.
   Balances are never stored, only derived — they cannot drift.
4. **An idempotency key produces at most one entry, ever**, enforced by a
   UNIQUE constraint rather than an application check.

Money is integer minor units throughout. No floats touch a balance. Fees use
floor division on basis points, so the same inputs always produce the same fee.

## Money flow

```
          admin deposit                user allocates            agent spends
settlement ──────────────► user wallet ──────────────► agent wallet ──────────► payee
                                ▲                            │
                                └──────── withdraw ──────────┘
```

A user cannot credit their own wallet (that is the admin/collection path), and
an agent cannot be funded from nothing — allocation debits a real user balance.
Money committed to an in-flight payout is held, so a user cannot withdraw funds
their agent has already promised.

## Spend policy

Evaluated server-side before funds are held, deny-by-default:

- per-transaction ceiling
- rolling daily and monthly caps (accumulate across transactions)
- **daily payout count ceiling** — catches a retry loop making a thousand
  individually-legal payments, which an amount cap cannot
- **timezone-correct daily reset** — a "daily" cap resetting at UTC midnight
  resets at 01:00 in Lagos, handing the agent a second allowance in that hour
- payee allowlist, and the payee's currency must match the payout's
- approval threshold above a configurable amount
- freeze: a frozen agent cannot spend at all
- **suspending the human immediately stops all of their agents**
- **no limits means no spending** — the default is deny, not allow. An agent
  needs at least one of the three amount ceilings or an approval threshold;
  with none set, every payout is refused rather than permitted. This was a real
  bug, not just a design note: `create_agent` always wrote a policy row, so the
  "no policy" deny branch was unreachable and an agent created without limits
  could move its entire wallet in one unapproved payout

## Payout lifecycle

```
request → policy check → HOLD → submit → webhook → capture
                           │                 │
                           │                 └─ FAILED → release hold
                           └─ over threshold → pending_approval → human approves/rejects
                           └─ no callback at all → sweeper releases the hold
```

Funds are held against available balance before the provider is called, so a
slow or failed provider response can never leave the ledger overdrawn. Webhook
delivery is treated as unreliable: duplicates are expected and settle exactly
once.

A failed submit is two different events, and conflating them is a money bug:

- The provider **replied and refused** (HTTP 4xx/5xx with a body — "invalid
  account", "insufficient merchant balance", "enable IP whitelisting"). Nothing
  was queued, so the payout fails and the hold is released immediately.
- The provider **did not reply** (connection error, socket timeout, an
  unreadable 200). The request may have arrived and the transfer may already be
  queued — the response is simply lost. The payout is left non-terminal, the
  **hold is kept**, and it goes into the reconciliation queue. Releasing it
  there would let the agent respend money that is on its way out, and the
  second spend would be backed by nothing.

`FlutterwaveError.indeterminate` carries that distinction and callers must
branch on it.

Holds carry an expiry. Without one, a webhook that never arrives freezes that
money permanently. `sweep-holds` releases expired holds and flags the payout for
reconciliation rather than declaring it failed — we do not know whether the
provider moved the money, and guessing "failed" could release funds that left.

Flutterwave integration supports both signature schemes:
- **v3** — `verif-hash` shared secret
- **v4** — HMAC-SHA256 over the raw body

Both compared in constant time (`hmac.compare_digest`).

## Authentication

- Passwords: **scrypt**, per-user salt, cost tunable but production-default
  n=2^14.
- Session tokens stored **hashed** — a stolen database yields no live sessions,
  exactly as it yields no live API keys.
- Unknown emails still pay for a dummy KDF run, so response time does not
  disclose which addresses are registered.
- Failed sign-ins are recorded **durably** and throttle brute force across
  restarts.
- Changing a password revokes every existing session, and requires the current
  password — a stolen session token cannot be upgraded into account ownership.
- API keys are per-agent, labelled, and revocable individually.

### Two-step verification (TOTP)

The human session is the one credential the central invariant rests on: whoever
holds it sets every agent's ceiling. A phished password is therefore not an
account problem but a *policy* problem, so the account holder can require a
second factor.

- **RFC 6238 TOTP**, implemented in `aibank/totp.py` from the spec — no
  dependency, and pinned against the RFC's own published test vectors for both
  TOTP and HOTP, so any authenticator app agrees with us.
- **A password alone yields no session once enrolled.** `POST /v1/auth/login`
  returns `{"mfa_required": true, "challenge_token": ...}` and the session is
  minted only by `POST /v1/auth/mfa/verify`. Sessions are created in exactly
  one function, reachable only after whatever the account requires — a second
  factor that one forgetful code path can skip is not a second factor.
- **Secrets are sealed at rest**, not stored in plaintext. A TOTP secret is
  symmetric, so a plaintext column would make it the easiest credential to
  steal from a database dump — easier than the scrypt-hashed password it is
  meant to reinforce. Sealing is encrypt-then-MAC under `AIBANK_KEY_PEPPER`
  (HMAC-SHA256 keystream, separate MAC key, random nonce), so a dump alone
  yields nothing and write access alone cannot substitute an attacker's secret.
  Stated plainly: a dump *plus* the environment does yield them — the same
  trust boundary the API key pepper already defines.
- **Codes are single-use.** The accepted counter is stored, so an observed code
  cannot be replayed within its 30–90 second validity, and that survives a
  restart.
- **Guesses are capped per challenge** (5), with the attempt committed in its
  own transaction — an increment inside a transaction that then raises is an
  increment that never happened, which is precisely how this project's login
  lockout was once silently dead.
- **Enrolment is two-phase.** The secret is stored but inactive until one
  working code is proven, so a mistyped key or a skewed clock cannot lock the
  owner out of a funded wallet.
- **Removing the factor requires the password *and* the factor.** If the
  password alone could disable it, a password thief would switch it off instead
  of defeating it. Disabling revokes every session, so an attacker doing it is
  visible to the owner on their next page load.
- **Ten single-use recovery codes**, peppered-hashed, shown once, rotatable.
  Without them a lost phone means a frozen wallet with live agents still
  spending under limits nobody can change — and users work around that by
  screenshotting the QR, which is worse than the problem.
- **A spent code is reported differently from a wrong one.** Confirming
  enrolment spends the code on screen, so signing in seconds later presents a
  correct-but-used code; calling that "invalid" tells a user whose setup works
  that it is broken. It says "wait for the next code" and does not burn the
  challenge.

## Concurrency

SQLite in WAL mode with `BEGIN IMMEDIATE` write transactions and thread-local
connections. Tests exist specifically to try to break it:

- **`test_parallel_payouts_cannot_overspend`** — 20 threads race to spend one
  wallet. Total settled never exceeds the balance.
- **`test_parallel_duplicate_webhooks_settle_once`** — 12 concurrent duplicate
  webhooks for one payout. It captures exactly once.
- **`test_same_key_from_two_threads_yields_one_payout_not_a_500`** — 6 threads
  send the same idempotency key simultaneously. One payout, one hold, no error.

## Bugs this found in itself

Each of these was reproduced by a test before being fixed, and the test remains:

- **Cross-tenant payout disclosure.** `get_payout` took only an id, so any
  valid agent key could read any agent's payout — amount, reference, and
  destination account. Reads are now scoped by SQL predicate.
- **Globally unique idempotency keys** let one agent replay another's key and
  retrieve that agent's payout. Keys are now scoped per agent.
- **Shared-connection race** let 20 concurrent threads overspend one wallet.
- **Lockout was dead code.** Failed logins were recorded inside the same
  transaction that then raised, so the rollback erased every record: the
  durable brute-force throttle counted rows that were never committed, and an
  attacker had unlimited guesses.
- **Migrations never ran in a transaction.** `executescript()` issues an
  implicit COMMIT, discarding the `BEGIN` opened before it — so a mid-migration
  failure left a half-built schema, and the explicit COMMIT raised *"cannot
  commit — no transaction is active"*.
- **The spender set our revenue.** The fee was whatever the caller put in the
  request body, and could be zero. Pricing now comes from a server-side
  schedule and the request field is ignored.
- **Secrets had working dev defaults.** `AIBANK_ADMIN_KEY` and
  `AIBANK_KEY_PEPPER` silently fell back to published constants, so a
  deployment that forgot them had a publicly known admin credential and no
  error. Both now fail closed.
- **Currency was never cross-checked** between payout and payee: a USD payout
  to an NGN account is a ~1,500x error, not a conversion.
- **A working authenticator reported as broken.** Confirming 2FA enrolment
  spends the code on screen, so signing in within that same 30-second step
  presented a correct-but-already-used code. It was reported as "invalid code"
  and charged an attempt against the brute-force cap — telling a user whose
  setup was fine that it was broken, which is how people conclude 2FA is flaky
  and turn it off. Spent and wrong are now distinct, and a spent code does not
  burn the challenge.
- **A mistyped one-time code signed the user out.** The dashboard treated every
  401 as "my session died", which is right for a dead token and wrong for
  "the code you just typed was incorrect" — one typo ejected the user to the
  sign-in screen mid-enrolment. The server now returns a distinct
  `session_invalid` code and the page only signs out on that.
- **A payout to a raw destination could never be approved.** Payments to a
  saved payee were fine, but one sent straight to a bank code and account
  number recorded no destination, so the approval path had nothing to submit:
  any such payment above the approval threshold parked and then froze the funds
  until the sweeper expired the hold. Schema v3 records the destination on the
  payout itself — which is the right shape regardless, since a payout record
  that cannot say where it was sending money is not an audit trail.
- **The limits form would have erased the limits.** `get_policy` returned only
  `*_minor` integer columns while the dashboard reads decimal fields, so every
  configured ceiling rendered as an empty input — which reads as "no limit" —
  and saving the form would have silently removed them. Found by asserting the
  inputs were pre-filled, not by asserting the endpoint returned 200.
- **Three tests hard-coded `schema_version == 2`.** Adding v3 failed them for
  no reason; they now assert against `db.SCHEMA_VERSION`. A test that must be
  edited by every migration is a test that will eventually be edited wrongly.
- **Per-account lockout did nothing against spraying.** The durable throttle
  counted failures per email, so one common password tried once each against a
  thousand accounts never tripped anything — while every attempt still cost us
  a full scrypt run. The attack was cheap for the attacker and expensive for
  us, which is backwards. There is now a per-source-address counter, checked
  *before* any key derivation so a flood costs the attacker an indexed `COUNT`
  instead of our CPU, with a higher threshold than the per-account one because
  a NAT'd office shares an address.
- **Backup created a file where a directory was meant.** `backup /var/backups/aibank`
  tested only `isdir`, so on a first run — when that directory does not exist
  yet — it silently wrote a *file* with that name, and the next run refused
  because "it exists". Both shipped timers pass exactly that path. Found by
  running the command, not by reading it.
- **Two backups in the same second collided.** The filename stamp is
  second-granularity, so a retry inside one second failed on "exists" — a
  false alarm from a timer that had actually succeeded. A name the tool chose
  itself now never needs `--force`.
- **A missing request field answered with a Python exception.** Omitting one
  returned `{"error": "KeyError", "reason": "'user_id'"}` — a class name and a
  quoted dict key, which tells an integrator nothing. Under a self-hosted
  shape the HTTP surface *is* the documentation, so a 400 now names the field.

---

## Try it in one command, with fake money

Before you connect a payment provider, see what you would be operating. This
starts the service against the **in-process test fake** instead of Flutterwave,
seeds a throwaway database, and prints a URL and a password:

```bash
git clone https://github.com/Knox-mgk/aibank
cd aibank
python3 scripts/demo/serve_demo.py
```

No credential, no account, no network call leaves the machine — the provider's
HTTP transport is replaced before the service is constructed, so nothing in the
demo can move real money. Python 3.11+ is the only prerequisite.

The seeded data is chosen to show every state the dashboard must render rather
than a flattering one: an agent with limits and settled history, one with a
payout parked above its approval threshold, one with **no policy at all** (which
means it can spend nothing — deny by default), and one frozen. Two payouts wait
for your approval, one of them to a raw account number with no saved payee, and
a refund sits on the books so the history shows a reversal. The seeder drives
settlement through the real webhook handler rather than writing `successful`
into a row, so the trial balance still nets to zero — a demo database the real
code could actually have produced.

`--reseed` rebuilds it, `--port` moves it, and `--host 0.0.0.0` lets another
device on a trusted network look (it warns, because the page posts a password
over plain HTTP).

---

## Run it

**Self-hosted, and that is the whole shape.** You run aibank against your
*own* Flutterwave credentials. It never holds your money, there is no custody
and no payment licence involved, and the operator of the deployment is you.

### Install the package

```bash
pip install aibank                   # not yet uploaded — see below
aibank migrate                       # explicit, never implicit
aibank create-user you@example.com
aibank serve --port 8000
```

**The PyPI name is not claimed yet**, so until the first upload install from
the repo instead — same two commands, same behaviour:

```bash
pip install git+https://github.com/Knox-mgk/aibank
```

Either way you get two commands: `aibank`, the operator CLI, and `aibank-mcp`,
the stdio server an agent runtime spawns. `pip install` pulls in **nothing
else** — there are no dependencies, which is the point.

It needs two secrets set or it refuses to boot, by design:

```bash
export AIBANK_ADMIN_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
export AIBANK_KEY_PEPPER="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
```

Keep the pepper with your backups. A restored ledger without its pepper has no
working agent keys **and no working second factors** — the sealed TOTP secrets
cannot be opened, so every enrolled account holder is left with recovery codes
as their only way in. Rotating the pepper on a live deployment is not a
supported operation for the same reason: it invalidates both at once. The
service names this explicitly (`mfa_unavailable`, pointing at
`AIBANK_KEY_PEPPER`) rather than telling users their codes are wrong.

### Or clone it — one command from git to a running service

```bash
git clone https://github.com/Knox-mgk/aibank
cd aibank
./deploy/quickstart.sh
```

It generates fresh secrets into `.env` (mode 600 — there are no working
defaults, by design), applies the schema explicitly, runs the full test suite
*before* telling you it works, creates your account holder, and takes a first
verified backup. Python 3.11+ is the only prerequisite; there is nothing to
install.

### Docker

```bash
cp .env.example .env && $EDITOR .env
docker compose run --rm aibank migrate
docker compose run --rm aibank create-user you@example.com
docker compose up -d
```

`compose.yaml` brings up four things, not one: the service, an nginx that
terminates TLS, a sweeper loop, and a backup loop that keeps 28 verified
snapshots. The service **publishes no port** — it is reachable only through the
proxy, because it speaks plain HTTP and the dashboard carries a session token.
Put your certificate pair in `deploy/certs/` as `fullchain.pem` and
`privkey.pem` (that directory is gitignored).

### systemd, without Docker

`deploy/systemd/` has the unit, a sweep timer (5 min) and a backup timer (6 h),
with the install steps in a comment at the top of the unit. The service runs as
a dedicated non-login user under `ProtectSystem=strict` with exactly one
writable path, a `@system-service` syscall filter, and `LimitCORE=0` so secrets
cannot land in a core dump.

Migration is deliberately **not** in any unit or entrypoint. A service that
migrates on start would apply an unreviewed `ALTER` to a live ledger during a
routine restart or a replica scale-up.

### Testing it yourself

```bash
export AIBANK_ALLOW_DEV_SECRETS=1 AIBANK_SCRYPT_N=1024

# 198 unit tests (fake provider — no network, no credentials)
python -m unittest discover -s tests

# 439 assertions against REAL servers on real sockets
python scripts/smoke_http.py        #  74  the core API
python scripts/smoke_mcp.py         #  82  the MCP tool surface
python scripts/smoke_dashboard.py   # 139  the dashboard's endpoints + markup
python scripts/smoke_mfa.py         #  65  the second factor, over HTTP
python scripts/smoke_dom.py         #  79  the dashboard's own JS, under node

# 33 assertions on the DISTRIBUTION: build a wheel, install it into a clean
# venv, and drive the installed copy. Needs network and ~300MB of scratch.
pip install build && python scripts/smoke_package.py
```

No install step, no requirements file — there are no dependencies.
`smoke_dom` skips itself cleanly when node is absent; the others are the
mandatory gate.

`smoke_package` exists because packaging fails in ways no source-tree test can
see. The dashboard is read off disk at request time, so a wheel missing
`aibank/static/dashboard.html` serves a 404 on `GET /` while all 148 unit
tests still pass; the console scripts are declared in `pyproject.toml` and
never executed by a repo run. It builds, installs, and then runs the CLI and
the server **from a different working directory**, so an accidental import of
the source tree cannot mask a gap in the wheel.

### Operating it

```bash
python -m aibank.cli migrate                      # explicit, auditable upgrade
python -m aibank.cli create-user you@example.com  # prompts for the password
python -m aibank.cli serve --port 8000
python -m aibank.cli sweep-holds                  # run on a timer
python -m aibank.cli needs-reconciliation         # the sweeper's open tickets
python -m aibank.cli reconcile PAYOUT_ID          # ask the provider the truth
python -m aibank.cli backup --dir ./backups       # verified snapshot
python -m aibank.cli trial-balance                # 0 = books balance
```

Two of those are not optional in a real deployment, which is why both compose
and the systemd units ship them on timers:

- **`sweep-holds`** — holds carry an expiry so a webhook that never arrives
  cannot freeze an agent's money forever. Nothing enforces that unless
  something runs the sweeper.
- **`needs-reconciliation`** — the sweeper deliberately refuses to declare an
  unanswered payout failed, because the money may well have left. That
  correctness choice creates an operator obligation, and this is the queue.
  It **exits 2** when there is work, so a cron or systemd wrapper alerts
  without parsing stdout.

**Backups use SQLite's online backup API, not `cp`.** In WAL mode the committed
truth is split between the database file and its `-wal` sidecar, so copying the
file captures a torn state and copying both races the writer. `backup` snapshots
under the source's own lock while the service is live, then **opens the copy**
and checks `integrity_check`, the schema version and the trial balance — a
backup nobody has read back is a hope, not a backup. Keep
`AIBANK_KEY_PEPPER` with it: a restored ledger without its pepper has no
working agent keys.

The service **refuses to boot** without `AIBANK_ADMIN_KEY` and
`AIBANK_KEY_PEPPER`. For local work only, `AIBANK_ALLOW_DEV_SECRETS=1` restores
the old insecure defaults.

Schema changes are never applied implicitly at boot. `serve` opens the database
with `migrate_on_open=False` and **refuses to start** against a schema it does
not expect, naming `migrate` as the fix — starting a new binary against an old
database is exactly when an unreviewed, unbacked-up `ALTER` is most dangerous.
`migrate` is the deliberate step, and every migration runs in one transaction
with a `PRAGMA foreign_key_check` afterwards. A test asserts this, because the
guarantee was documented here for a while before the code actually kept it.

### Running behind a reverse proxy

Set `AIBANK_TRUSTED_PROXY=1` **only** when the service is unreachable except
through a proxy that *overwrites* `X-Forwarded-For` (`deploy/nginx.conf` does).
Wrong in either direction hurts, and the two failures are opposites:

- Left off behind a proxy, every request appears to come from the proxy, so the
  per-address login throttle puts the whole internet in one bucket — the first
  sprayer locks out every legitimate user, and the defence becomes the outage.
- Switched on while the port is directly reachable, a client forges the header
  to mint unlimited fresh throttle buckets and to write any address it likes
  into the audit log.

`deploy/nginx.conf` also rate-limits `/v1/auth/login` and `/v1/auth/register` at
the edge (10/min, burst 5). That is the cheap outer layer; aibank's own
per-address throttle still applies underneath it, because an edge limit vanishes
the moment someone runs the container without the proxy.

## The MCP server — `pay()` as a typed tool

An LLM does not call this API with hand-rolled HTTP; it calls eight typed tools
over MCP stdio (`python -m aibank.mcp_server`):

```
whoami        get_balance    list_payees    add_payee
quote_fee     pay            get_payout     list_payouts
```

```bash
AIBANK_URL=http://127.0.0.1:8000 \
AIBANK_API_KEY=sk_agent_... \
  python -m aibank.mcp_server          # stdio JSON-RPC 2.0, protocol 2025-06-18
```

Three decisions worth stating, because they are what makes this safe to hand a
model:

- **The MCP process speaks HTTP; it never imports `Bank`.** An in-process bank
  would hand the model's host process a live SQLite handle, and therefore write
  access to the `policies` table — every limit the human set would be one stray
  tool implementation away from being raised by the thing it constrains. Over a
  socket, the agent credential is rejected on every policy and approval route
  before a handler runs. `tests/test_mcp.py` asserts that structurally against
  the module's own source, so a future tool cannot quietly reintroduce it.
- **The human gate is server-side, not client-side.** MCP says a client SHOULD
  let a human deny an invocation. On a bank that cannot be the only control: a
  client that chooses not to prompt would silently remove it. Here
  `require_approval_above` parks the payout in `pending_approval` and no
  sequence of tool calls can release it. A client prompt is a second line.
- **Refusals are returned as readable text, not just codes.** A denied payment
  explains the limit it hit and tells the model explicitly not to retry and not
  to split the amount — the machine-readable `code` is preserved alongside it.
  Without that, a model's natural next move after a 403 is to try again smaller,
  which is exactly how a daily cap gets walked around by salami-slicing.

`AIBANK_MCP_READONLY=1` drops every money-moving tool from `tools/list`
entirely rather than refusing it at call time: a tool the model cannot see is a
tool it cannot be talked into trying.

## The dashboard

`GET /` serves one file — `aibank/static/dashboard.html`, ~40KB of plain
HTML/CSS/JS. No build step, no bundler, no CDN, no framework. The whole UI is
one `GET /v1/dashboard` call: wallet, agents with their policies, pending
approvals, recent payments.

- Sign in, fund the wallet, allocate to an agent, set its limits, approve or
  reject what it parked, rotate its keys, read its statement.
- The session token lives in `sessionStorage`, not `localStorage` — it dies with
  the tab.
- A strict CSP is sent with the page and there are no external `script`/`link`
  tags, so there is nothing to exfiltrate a token to.
- Approval cards show the **masked** destination (`******0031`). The one moment
  a human can catch an agent paying the wrong account is at approval, so the
  destination is recorded on the payout itself rather than looked up from a
  saved payee.
- A **Security card** sits on the main dashboard, not in a buried settings
  page: turning on two-step verification, rotating recovery codes, and removing
  the factor. The card states what is at stake when the factor is off — "your
  password alone can sign in and change every agent's limits" — because the
  cost of leaving it off is not obvious from the toggle itself.
- The code prompt is a **separate view** from the sign-in card, since the
  password has already been accepted by then. The half-authenticated challenge
  token is held in memory only and never written to `sessionStorage`.

Testing a UI without a browser on the host is the awkward part, so it is done in
two layers. `smoke_dashboard.py` proves every endpoint the page calls is
reachable, returns the fields the page reads, and that all 17 call sites in the
page are exercised. `smoke_dom.py` goes further: it extracts the page's
`<script>`, runs it under node against a minimal DOM shim pointed at a real
server, and asserts the element tree that results — that the page's code
actually executes, renders real data, and that clicking Approve or Allocate
issues the right request with an idempotency key. Neither proves the page
*looks* right; they prove it is not blank.

`dom_check.mjs` takes a base URL, so the same harness runs against any seeded
server — including the demo above. Its expectations are read from
`/v1/dashboard` at startup rather than hard-coded, because a harness that
asserts its own fixture values reports failures for a page that is rendering
correctly, and that is worse than no test. It refuses to run against a server
with no agents or no pending approvals instead of letting those assertions
quietly become vacuous passes.

To see the page with content, run the demo server and open it:

```bash
python3 scripts/demo/serve_demo.py      # prints a URL and a password
```

## HTTP surface

```
POST   /v1/auth/register                 POST   /v1/auth/login
POST   /v1/auth/logout                   POST   /v1/auth/password

GET    /v1/auth/mfa                      POST   /v1/auth/mfa/enrol
POST   /v1/auth/mfa/confirm              POST   /v1/auth/mfa/verify
POST   /v1/auth/mfa/disable              POST   /v1/auth/mfa/recovery-codes

GET    /v1/dashboard                     GET    /v1/me
GET    /v1/wallet                        POST   /v1/wallet/deposit      (admin)
GET    /v1/agents                        POST   /v1/agents
GET    /v1/agents/<id>                   GET/POST /v1/agents/<id>/policy
POST   /v1/agents/<id>/allocate          POST   /v1/agents/<id>/withdraw
POST   /v1/agents/<id>/freeze            GET/POST /v1/agents/<id>/keys
GET    /v1/agents/<id>/statement         GET    /v1/approvals

GET    /v1/balance                       GET/POST /v1/payees
GET    /v1/quote                         POST   /v1/payouts
GET    /v1/payouts                       GET    /v1/payouts/<id>
POST   /v1/payouts/<id>/approve          POST   /v1/payouts/<id>/reject
POST   /v1/payouts/<id>/refund           POST   /v1/payouts/<id>/reconcile

GET/POST /v1/fees                 (admin)  POST /v1/admin/sweep-holds  (admin)
GET    /v1/admin/trial-balance    (admin)  POST /v1/webhooks/flutterwave
GET    /health                            GET    /  ·  /dashboard  (the UI)
```

## Layout

| path | purpose |
|---|---|
| `aibank/ledger.py` | double-entry core, holds, reversals, idempotency |
| `aibank/users.py` | account holders, scrypt, sessions, lockout, 2FA |
| `aibank/totp.py` | RFC 6238 TOTP, sealed secrets, recovery codes |
| `aibank/policy.py` | spend-policy evaluation, timezone-correct windows |
| `aibank/fees.py` | server-side pricing — never caller-supplied |
| `aibank/bank.py` | agents, keys, funding, payouts, approvals, sweeper |
| `aibank/db.py` | versioned schema + transactional migration runner |
| `aibank/flutterwave.py` | provider client, v3 + v4 signature verification |
| `aibank/money.py` | integer minor units, currency validation |
| `aibank/api.py` | HTTP surface, three trust domains |
| `aibank/cli.py` | migrate / serve / sweep / create-user |
| `aibank/mcp_server.py` | MCP stdio server — `pay()` as a typed LLM tool |
| `aibank/static/dashboard.html` | the whole dashboard: one file, no build step |
| `Dockerfile`, `compose.yaml` | the self-hosted stack: service, TLS, sweeper, backups |
| `deploy/quickstart.sh` | clone to running service in one command |
| `deploy/nginx.conf` | TLS termination, edge rate limit, unspoofable `X-Forwarded-For` |
| `deploy/systemd/` | unit plus sweep and backup timers, hardened |
| `scripts/smoke_*.py` | 439 assertions against live servers |
| `scripts/smoke_package.py` | 33 assertions against the built-and-installed wheel |
| `scripts/dom_check.mjs` | runs the page's real JS against a minimal DOM |
| `scripts/demo/` | one-command demo: fake provider, seeded data, no credential |
| `tests/` | 198 tests, including the concurrency, 2FA and packaging suites |

## Known limits

Stated plainly rather than discovered later:

- **Single process.** `db.write()` serialises on a process-global lock, so
  correctness assumes exactly one process owns the database file. Two workers
  against one SQLite file would reintroduce the policy-check/hold race. Multi-
  worker deployment needs Postgres behind `Database`, not a second process.
  `compose.yaml` pins `replicas: 1` for this reason — it is a correctness
  boundary, not a tuning choice.
- **Timezones are fixed offsets**, not tzdata zones, because the service must
  run on hosts with no tzdata (Termux/Android has none, and
  `ZoneInfo('Africa/Lagos')` raises there). Correct for zones without DST,
  which includes all of WAT.
- **A refund is a book entry, not a clawback.** Nothing can pull money back out
  of a beneficiary's account; the reversal records that it came back.
- **Inbound collections are not implemented.** `/v1/wallet/deposit` is
  admin-gated and stands in for a real virtual-account callback.
- **The dashboard has never been opened in a real browser.** There is none on
  the host it was written on. Its JS is executed under node against a DOM shim,
  which proves the code runs and renders — not that the layout is right in
  Safari. Treat the first real browser session as a test still owed.
- **The dashboard is served over plain HTTP by `http.server`.** Put it behind a
  TLS-terminating reverse proxy before it leaves localhost; a session token on
  the wire in clear is the whole account. `compose.yaml` and
  `deploy/nginx.conf` do this, and the compose service publishes no port of its
  own so it cannot be reached around the proxy.
- **The real Flutterwave API has been called for READS only.** Against a live
  sandbox key the adapter's auth, JSON handling and response shapes are
  confirmed on `GET /banks` (598 Nigerian banks), `GET /balances/NGN`
  (`available_balance` / `ledger_balance` / `currency`) and
  `POST /accounts/resolve` (`account_name` / `account_number`). Every test and
  smoke script still uses a fake, and the paths that MOVE money are still
  unproven end to end: `POST /transfers` is refused by the sandbox with
  `{"status":"error","message":"Please enable IP Whitelisting to access this
  service","data":null}` (HTTP 400) until the account whitelists the caller's
  address, and no real webhook has ever been delivered. So transfer field
  names, success-status strings and webhook payloads remain documentation-
  derived. Whitelist an address, run one real transfer and one real webhook
  before trusting it with money.
- **No email verification and no password reset.** An operator can create and
  reset accounts with the CLI; account holders cannot recover their own.
- **No metrics or structured logging.** `/health` reports the schema version,
  and `needs-reconciliation` exits 2 when a human is needed, which is enough to
  alert on but is not observability.
- **Not published to PyPI yet.** The package builds, installs into a clean
  venv and serves correctly (`scripts/smoke_package.py`, 33 assertions), and
  `pip install aibank` is the documented path — but the name is unclaimed, so
  that command does not work until the first upload. Until then, install from
  the repo.
- Not load-tested.

## Licence

MIT — see `LICENSE`.
