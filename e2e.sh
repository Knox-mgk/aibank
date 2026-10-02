#!/data/data/com.termux/files/usr/bin/bash
# End-to-end walk through the API with curl. Fake provider, real HTTP.
set -e
B=http://127.0.0.1:8077
ADMIN="X-Admin-Key: admin-dev-key"
j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get(sys.argv[1],''))" "$1"; }

echo "== 1. admin creates an agent with hard limits =="
AGENT=$(curl -s -X POST $B/v1/agents -H "$ADMIN" -H 'Content-Type: application/json' \
  -d '{"name":"research-bot","currency":"NGN","per_txn_max":"50000","daily_max":"150000","require_approval_above":"100000","allowlist_only":true}')
echo "$AGENT" | python3 -m json.tool
AID=$(echo "$AGENT" | j agent_id); KEY=$(echo "$AGENT" | j api_key)
AUTH="Authorization: Bearer $KEY"

echo; echo "== 2. fund the agent wallet with NGN 200,000 =="
curl -s -X POST $B/v1/fund -H "$ADMIN" -H 'Content-Type: application/json' \
  -d "{\"agent_id\":\"$AID\",\"amount\":\"200000\"}" | python3 -m json.tool

echo; echo "== 3. agent saves an allowlisted payee =="
PAYEE=$(curl -s -X POST $B/v1/payees -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"label":"gpu-vendor","bank_code":"044","account_number":"1234567890"}')
echo "$PAYEE"; PID=$(echo "$PAYEE" | j payee_id)

echo; echo "== 4. agent pays NGN 20,000 (within limits) =="
P1=$(curl -s -X POST $B/v1/payouts -H "$AUTH" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: job-001' \
  -d "{\"amount\":\"20000\",\"payee_id\":\"$PID\",\"narration\":\"gpu hours\"}")
echo "$P1" | python3 -m json.tool
REF=$(echo "$P1" | j reference)

echo; echo "== 5. balance shows HELD, not yet debited =="
curl -s "$B/v1/balance?currency=NGN" -H "$AUTH" | python3 -m json.tool

echo; echo "== 6. RETRY same Idempotency-Key -> no second transfer =="
curl -s -X POST $B/v1/payouts -H "$AUTH" -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: job-001' \
  -d "{\"amount\":\"20000\",\"payee_id\":\"$PID\"}" | python3 -c "import sys,json;d=json.load(sys.stdin);print('same payout id:',d['id'],'status:',d['status'])"

echo; echo "== 7. agent tries NGN 60,000 (over per-txn cap) -> DENIED =="
curl -s -o ./deny.json -w 'HTTP %{http_code}\n' -X POST $B/v1/payouts -H "$AUTH" \
  -H 'Content-Type: application/json' -d "{\"amount\":\"60000\",\"payee_id\":\"$PID\"}"
cat ./deny.json; echo

echo; echo "== 8. agent tries an UNSAVED account -> DENIED (allowlist) =="
curl -s -o ./deny2.json -w 'HTTP %{http_code}\n' -X POST $B/v1/payouts -H "$AUTH" \
  -H 'Content-Type: application/json' -d '{"amount":"1000","bank_code":"044","account_number":"9999999999"}'
cat ./deny2.json; echo

echo; echo "== 9. unsigned webhook -> 401 =="
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -X POST $B/v1/webhooks/flutterwave \
  -H 'Content-Type: application/json' -d '{"event":"transfer.completed","data":{"id":1}}'

echo; echo "== 10. SIGNED success webhook settles the payout =="
BODY="{\"event\":\"transfer.completed\",\"data\":{\"id\":90210,\"reference\":\"$REF\",\"status\":\"SUCCESSFUL\",\"amount\":20000,\"currency\":\"NGN\"}}"
curl -s -X POST $B/v1/webhooks/flutterwave -H 'Content-Type: application/json' \
  -H 'verif-hash: my-secret-hash' -d "$BODY"; echo

echo; echo "== 11. replay the SAME webhook -> duplicate, no double debit =="
curl -s -X POST $B/v1/webhooks/flutterwave -H 'Content-Type: application/json' \
  -H 'verif-hash: my-secret-hash' -d "$BODY"; echo

echo; echo "== 12. final balance: 200,000 - 20,000 = 180,000 =="
curl -s "$B/v1/balance?currency=NGN" -H "$AUTH" | python3 -m json.tool
