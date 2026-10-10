// Check run_aibank.js's TOTP helper against aibank/totp.py on the same secret.
// The browser side types a code computed in JS; if that implementation is
// wrong, enrolment fails and the failure reads as a broken QR or a broken
// server. Runs on the phone, before the PC ever sees it.
const { execFileSync } = require('child_process');
const crypto = require('crypto');

function b32decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of s.replace(/=+$/, '').toUpperCase()) {
    const i = A.indexOf(ch);
    if (i < 0) continue;
    bits += i.toString(2).padStart(5, '0');
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
function totp(secret, step = 30, digits = 6, at = Date.now()) {
  const counter = Math.floor(at / 1000 / step);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buf.writeUInt32BE(counter % 2 ** 32, 4);
  const h = crypto.createHmac('sha1', b32decode(secret)).update(buf).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

// RFC 6238 published vectors (SHA1, secret "12345678901234567890") pin the JS
// side on its own, independently of our Python.
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';   // base32 of that ASCII
const RFC = [[59, '287082'], [1111111109, '081804'], [1111111111, '050471'],
             [1234567890, '005924'], [2000000000, '279037']];
let fails = 0;
for (const [t, want] of RFC) {
  const got = totp(RFC_SECRET, 30, 6, t * 1000);
  const ok = got === want;
  if (!ok) fails++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} RFC 6238 t=${t} -> ${got} (want ${want})`);
}

// And agree with the implementation the server actually verifies against,
// across random secrets and a fixed instant so there is no step race.
const at = 1700000000;
const secrets = execFileSync('python3', ['-c',
  'from aibank import totp as T;print("\\n".join(T.new_secret() for _ in range(25)))'],
  { cwd: process.env.AIBANK_DIR || process.env.HOME + '/aibank', encoding: 'utf8' })
  .trim().split('\n');
const pyCodes = execFileSync('python3', ['-c',
  'import sys;from aibank import totp as T;print("\\n".join(T.totp(s,' + at + ') for s in sys.argv[1:]))',
  ...secrets], { cwd: process.env.AIBANK_DIR || process.env.HOME + '/aibank', encoding: 'utf8' })
  .trim().split('\n');
secrets.forEach((s, i) => {
  const got = totp(s, 30, 6, at * 1000);
  const ok = got === pyCodes[i];
  if (!ok) { fails++; console.log(`  FAIL ${s}: js ${got} != py ${pyCodes[i]}`); }
});
console.log(`  ok   ${secrets.length} random secrets agree with aibank/totp.py`);
console.log(`\n${RFC.length + 1 - fails} passed, ${fails} failed`);
process.exit(fails ? 1 : 0);
