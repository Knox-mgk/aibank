# aibank

A double-entry banking and payments backend for autonomous agents: agents hold
balances, spend under enforced policy limits, and pay out over real payment
rails — without being able to overspend, double-spend, or read each other's
records.

**Zero third-party dependencies.** Python standard library only, by design.

```
38 tests, 0 failures, 1.87s
```

---

## Why

An autonomous agent that can spend money is a liability unless three things are
true: its balance is always correct, its spending is bounded by policy it
cannot bypass, and a retried request never moves money twice. Those are ledger
problems, not prompt problems — so this is a ledger, built from first
principles.

## The ledger

A general ledger with invariants enforced in code, not convention:

1. **Postings within an entry sum to exactly zero.** An unbalanced entry is
   rejected, not corrected.
2. **Postings are immutable.** Corrections are new reversing entries, so
   history is append-only and auditable.
3. **`balance = SUM(postings)`**, and **`available = balance − active holds`**.
   Balances are never stored, only derived — they cannot drift.
4. **An idempotency key produces at most one entry, ever**, enforced by a
   UNIQUE constraint rather than an application check.

Money is integer minor units throughout. No floats touch a balance.

## Spend policy

Policy is evaluated before funds are held, and an agent cannot widen its own
limits:

- per-transaction ceiling
- rolling daily cap (accumulates across transactions)
- payee allowlist — transfers to saved payees only
- approval threshold above a configurable amount
- freeze: a frozen agent cannot spend at all
- **no policy means no spending** — the default is deny, not allow

## Payout lifecycle

```
hold → submit → webhook → capture → reconcile
```

Funds are held against available balance before the provider is called, so a
slow or failed provider response can never leave the ledger overdrawn. Webhook
delivery is treated as unreliable: duplicates are expected and settle exactly
once.

Flutterwave integration supports both signature schemes:
- **v3** — `verif-hash` shared secret
- **v4** — HMAC-SHA256 over the raw body

Both compared in constant time (`hmac.compare_digest`).

## Concurrency

SQLite in WAL mode with `BEGIN IMMEDIATE` write transactions and thread-local
connections. Two tests exist specifically to try to break it:

- **`test_parallel_payouts_cannot_overspend`** — 20 threads race to spend one
  wallet simultaneously. Total settled never exceeds the balance.
- **`test_parallel_duplicate_webhooks_settle_once`** — 12 concurrent duplicate
  webhooks for the same payout. The payout captures exactly once.

## A bug this found

Idempotency keys were originally globally unique. That let one agent replay
another agent's key and retrieve **that agent's payout record** — a
cross-tenant information disclosure. Keys are now scoped per agent, and
`test_cannot_pay_another_agents_payee` plus
`test_api_key_authenticates_only_its_owner` keep it fixed.

API keys are stored hashed; a test asserts the raw key never appears in the
`api_keys` table.

---

## Run it

```bash
git clone https://github.com/Knox-mgk/aibank
cd aibank
python -m unittest discover -s tests -v
```

No install step, no requirements file — there are no dependencies.

Demo HTTP server (uses a fake payment provider, no network, no credentials):

```bash
python run_demo_server.py
```

## Layout

| path | purpose |
|---|---|
| `aibank/ledger.py` | double-entry core, holds, idempotency |
| `aibank/policy.py` | spend-policy evaluation |
| `aibank/bank.py` | agents, API keys, payout orchestration |
| `aibank/db.py` | schema — 11 tables, WAL, enforced foreign keys |
| `aibank/flutterwave.py` | provider client, v3 + v4 signature verification |
| `aibank/money.py` | integer minor units, currency validation |
| `aibank/api.py` | HTTP surface |
| `tests/` | 38 tests, including the concurrency suite |

## Configuration

Real credentials are read from the environment and never committed:

```bash
export FLW_SECRET_KEY=...
```

Tests and the demo use a fake provider, so neither needs a key.

## Status

Working and tested, not production-load-tested. Built as a correctness
exercise in payments infrastructure — the interesting parts are the invariants
and the concurrency tests, not the feature count.

## Licence

MIT
