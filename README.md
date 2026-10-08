# aibank

A double-entry banking backend where **humans hold the money and AI agents
spend it under limits they cannot reach.** An account holder signs in, funds a
wallet, allocates money to their agents, and sets each agent's ceilings from a
dashboard. The agent gets an API key that can do exactly one thing with money:
request a payout that the server either allows, holds for approval, or denies.

**Zero third-party dependencies.** Python standard library only, by design.

```
92 unit tests + 74 live HTTP assertions, 0 failures
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
- **no policy means no spending** — the default is deny, not allow

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

---

## Run it

```bash
git clone https://github.com/Knox-mgk/aibank
cd aibank

# Unit tests (uses a fake provider — no network, no credentials)
AIBANK_ALLOW_DEV_SECRETS=1 AIBANK_SCRYPT_N=1024 \
  python -m unittest discover -s tests

# End-to-end HTTP test against a real server on a real socket
python scripts/smoke_http.py
```

No install step, no requirements file — there are no dependencies.

### Operating it

```bash
export AIBANK_ADMIN_KEY=$(python -c 'import secrets;print(secrets.token_urlsafe(32))')
export AIBANK_KEY_PEPPER=$(python -c 'import secrets;print(secrets.token_urlsafe(32))')
export FLW_SECRET_KEY=...        # real provider credential
export FLW_SECRET_HASH=...       # webhook signing secret
export AIBANK_DB=/var/lib/aibank/aibank.db

python -m aibank.cli migrate                      # explicit, auditable upgrade
python -m aibank.cli create-user you@example.com  # prompts for the password
python -m aibank.cli serve --port 8000
python -m aibank.cli sweep-holds                  # run on a timer
python -m aibank.cli trial-balance                # 0 = books balance
```

The service **refuses to boot** without `AIBANK_ADMIN_KEY` and
`AIBANK_KEY_PEPPER`. For local work only, `AIBANK_ALLOW_DEV_SECRETS=1` restores
the old insecure defaults.

Schema changes are never applied implicitly at boot: `migrate` is a deliberate
command, and every migration runs in one transaction with a
`PRAGMA foreign_key_check` afterwards.

## HTTP surface

```
POST   /v1/auth/register                 POST   /v1/auth/login
POST   /v1/auth/logout                   POST   /v1/auth/password

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
GET    /health
```

## Layout

| path | purpose |
|---|---|
| `aibank/ledger.py` | double-entry core, holds, reversals, idempotency |
| `aibank/users.py` | account holders, scrypt, sessions, lockout |
| `aibank/policy.py` | spend-policy evaluation, timezone-correct windows |
| `aibank/fees.py` | server-side pricing — never caller-supplied |
| `aibank/bank.py` | agents, keys, funding, payouts, approvals, sweeper |
| `aibank/db.py` | versioned schema + transactional migration runner |
| `aibank/flutterwave.py` | provider client, v3 + v4 signature verification |
| `aibank/money.py` | integer minor units, currency validation |
| `aibank/api.py` | HTTP surface, three trust domains |
| `aibank/cli.py` | migrate / serve / sweep / create-user |
| `scripts/smoke_http.py` | 74 assertions against a live server |
| `tests/` | 92 tests, including the concurrency suite |

## Known limits

Stated plainly rather than discovered later:

- **Single process.** `db.write()` serialises on a process-global lock, so
  correctness assumes exactly one process owns the database file. Two workers
  against one SQLite file would reintroduce the policy-check/hold race. Multi-
  worker deployment needs Postgres behind `Database`, not a second process.
- **Timezones are fixed offsets**, not tzdata zones, because the service must
  run on hosts with no tzdata (Termux/Android has none, and
  `ZoneInfo('Africa/Lagos')` raises there). Correct for zones without DST,
  which includes all of WAT.
- **A refund is a book entry, not a clawback.** Nothing can pull money back out
  of a beneficiary's account; the reversal records that it came back.
- **Inbound collections are not implemented.** `/v1/wallet/deposit` is
  admin-gated and stands in for a real virtual-account callback.
- Not load-tested.

## Licence

MIT — see `LICENSE`.
