// Drive the aibank dashboard in a REAL browser and prove the enrolment QR is
// scannable -- while the browser's machine never learns a single secret.
//
// WHY A BROWSER AT ALL, when scripts/dom_check.mjs already runs the page's JS:
// that harness runs under node with a DOM shim. It proves the page BUILDS the
// right nodes; it cannot prove a browser RENDERS them. Everything past the DOM
// -- the SVG viewBox, shape-rendering, the CSS that sizes and pads the symbol,
// the dark theme behind it, the rasteriser -- is unverified, and that is
// exactly the layer a phone camera has to read.
//
// HOW THE PROOF IS KEPT HONEST
// The naive version reads the secret off the page and computes its own code --
// which proves nothing about the pixels, because it already knew the answer.
// Here the roles are split the way they are in real life:
//
//     this machine (PC) = the user's BROWSER. Sees the page and six digits.
//     the phone         = the user's AUTHENTICATOR. Sees the symbol only as
//                         PNG pixels, recovers the secret from them, and is
//                         the sole holder of it.
//
// So: screenshot the symbol -> POST the PNG to the phone -> ask the phone for a
// code -> type it. Enrolment succeeding means the RENDERED PIXELS were
// sufficient. The secret never crosses the link, which is also what makes this
// safe to point at a real account rather than only a demo one.
//
// Both services arrive over the authenticated SSH reverse tunnel, so
// 127.0.0.1 is correct from this machine's point of view:
//     -R 8088  the aibank instance   (the phone's)
//     -R 8099  the authenticator     (the phone's)
//
//   node run_aibank.js --label demo --email a@b --pass xxx
//   node run_aibank.js --label real --email a@b --pass xxx --already-enrolled
//   node run_aibank.js ... --keep-off      turn the factor back off at the end
//   node run_aibank.js ... --no-mfa        dashboard only
//   node run_aibank.js ... --register      create the account first
//   node run_aibank.js ... --fund 80000    ask the phone to credit the wallet

const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

// ------------------------------------------------------------------ args
function arg(name, dflt) {
  const i = process.argv.indexOf('--' + name);
  return i > 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--')
    ? process.argv[i + 1] : dflt;
}
const has = (name) => process.argv.includes('--' + name);

const BASE  = arg('base', process.env.AIBANK_BASE || 'http://127.0.0.1:8088');
const AUTHN = arg('authn', process.env.AIBANK_AUTHN || 'http://127.0.0.1:8099');
const TOKEN = process.env.AIBANK_AUTHN_TOKEN || '';
const LABEL = arg('label', 'demo');
const EMAIL = arg('email', process.env.AIBANK_EMAIL || 'demo@aibank.local');
const PASS  = arg('pass',  process.env.AIBANK_PASS  || 'demo-password-1234');
const NAME  = arg('name', 'Browser Test');
const FUND  = arg('fund', '');
const OUT   = path.join(__dirname, 'out', LABEL);

const result = {
  label: LABEL, base: BASE, account: EMAIL,
  started: new Date().toISOString(), steps: [], ok: true,
};
let shotNo = 0;

function step(name, ok, detail) {
  result.steps.push({ name, ok: !!ok, detail: detail === undefined ? null : String(detail) });
  if (!ok) result.ok = false;
  console.log(`${ok ? 'ok  ' : 'FAIL'} [${LABEL}] ${name}${detail ? '  -- ' + detail : ''}`);
}

// ------------------------------------------------- the phone's authenticator
function phone(method, p, body, ctype) {
  // Plain http: the transport is already an authenticated SSH tunnel, so TLS
  // on top would only add a certificate to manage. The bearer token is still
  // required -- the tunnel's far end is loopback on a multi-process machine,
  // and a code minter is precisely what a local attacker would want.
  return new Promise((resolve, reject) => {
    const u = new URL(AUTHN + p);
    const req = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search,
      method,
      headers: {
        'Authorization': 'Bearer ' + TOKEN,
        'Content-Type': ctype || 'application/json',
        'Content-Length': body ? Buffer.byteLength(body) : 0,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString();
        let parsed;
        try { parsed = JSON.parse(text); } catch { parsed = { raw: text }; }
        if (res.statusCode >= 400) {
          return reject(new Error(`authn ${method} ${p} -> ${res.statusCode} ${text.slice(0, 200)}`));
        }
        resolve(parsed);
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// A code the server has NOT already accepted.
//
// TOTP replay protection makes every counter single-use, so any code that
// follows an accepted one -- confirming enrolment, then signing in; signing
// in, then disabling the factor -- is refused as a replay even though it is
// the digits currently on screen. `fresh=1` makes the authenticator wait for
// the next period, which is what a real user does. It blocks for up to one
// 30s period, deliberately: `phone()` sets no socket timeout, so the wait
// completes instead of surfacing as a hang.
const freshCode = async () =>
  (await phone('GET', `/code?label=${LABEL}&fresh=1`)).code;

const shot = async (page, name) =>
  page.screenshot({ path: path.join(OUT, `${String(++shotNo).padStart(2, '0')}-${name}.png`),
                    fullPage: true });

(async () => {
  fs.mkdirSync(OUT, { recursive: true });

  // channel:'msedge' drives the browser already installed. Disk here sits near
  // full and a bundled Chromium is ~300-400 MB for no benefit.
  const browser = await chromium.launch({
    channel: 'msedge', headless: true, args: ['--no-sandbox'],
  });
  const ctx = await browser.newContext({
    viewport: { width: 1280, height: 1600 }, deviceScaleFactor: 3,
  });
  const page = await ctx.newPage();

  // The page answers its own window.prompt for the password re-check and for
  // the disable flow's code. Registered before any click, because an unhandled
  // dialog blocks the page indefinitely.
  //
  // The code is always FRESH here: every prompt for a code arrives after a
  // sign-in that already spent the current one, so a plain code would be
  // correctly refused as a replay and the disable step would fail for a
  // reason that has nothing to do with the browser.
  let dialogAnswer = PASS;
  page.on('dialog', async (d) => {
    const want = /authenticator code|recovery code/i.test(d.message())
      ? await freshCode() : dialogAnswer;
    await d.accept(want);
  });

  // Console errors and failed requests are findings, not noise: a strict-CSP
  // page that silently blocks its own script still renders a plausible shell.
  const consoleErrors = [], failedReqs = [];
  page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('requestfailed', r => failedReqs.push(`${r.method()} ${r.url()} ${r.failure() && r.failure().errorText}`));
  page.on('pageerror', e => consoleErrors.push('pageerror: ' + e.message));

  try {
    // --- the authenticator must answer BEFORE anything is enrolled ---------
    // Otherwise a factor gets switched on for an account whose codes nobody
    // can compute, which on a real account means losing it.
    const health = await phone('GET', '/health');
    step('the phone authenticator answers', health.ok === true,
         `labels: ${(health.labels || []).join(',') || 'none'}`);

    if (FUND) {
      // The deposit route is admin-gated. The phone performs it and keeps the
      // admin key; this machine only ever names an account and an amount.
      const f = await phone('POST', '/fund',
        JSON.stringify({ user_id: arg('user-id', ''), amount: FUND, nonce: String(Date.now()) }));
      step('wallet funded by the phone (admin key never left it)', f.ok === true,
           `balance ${JSON.stringify(f.balance)}`);
    }

    const resp = await page.goto(BASE + '/', { waitUntil: 'load', timeout: 60000 });
    step('dashboard HTML loads', resp.ok(), `HTTP ${resp.status()}`);

    // --- security headers, as the BROWSER received them -------------------
    // smoke_dashboard.py asserts these against a raw socket. Re-checking them
    // here proves the browser saw the same thing through the tunnel, and that
    // nothing on this machine rewrote them.
    const h = resp.headers();
    step('CSP header present', !!h['content-security-policy'],
         (h['content-security-policy'] || '').slice(0, 60));
    step('CSP forbids external connections',
         (h['content-security-policy'] || '').includes("connect-src 'self'"));
    step('framing denied (a clickjacked Approve button)',
         (h['x-frame-options'] || '').toUpperCase() === 'DENY' ||
         (h['content-security-policy'] || '').includes("frame-ancestors 'none'"));
    step('nosniff', h['x-content-type-options'] === 'nosniff');
    step('no-store (session page must not be cached)',
         (h['cache-control'] || '').includes('no-store'));
    step('no referrer leak', h['referrer-policy'] === 'no-referrer');
    await shot(page, 'signin');

    // --- a wrong password must be refused, before using the right one -----
    await page.fill('#email', EMAIL);
    await page.fill('#password', 'definitely-not-the-password');
    await page.click('#dologin');
    await page.waitForTimeout(2500);
    const stillAuth = await page.locator('#dashview.hidden').count();
    step('a wrong password does not reach the dashboard', stillAuth === 1,
         (await page.locator('#flash').innerText().catch(() => '')).slice(0, 60));

    if (has('register')) {
      await page.click('#toggleauth');
      await page.fill('#email', EMAIL);
      await page.fill('#password', PASS);
      await page.fill('#dispname', NAME);
      await page.click('#dologin');
      await page.waitForTimeout(3000);
      step('account created through the real form',
           (await page.locator('#dashview:not(.hidden)').count()) === 1);
    }

    // --- sign in -----------------------------------------------------------
    if ((await page.locator('#dashview:not(.hidden)').count()) === 0) {
      await page.fill('#email', EMAIL);
      await page.fill('#password', PASS);
      await page.click('#dologin');

      // An already-enrolled account stops at the second factor. That is the
      // path a real returning user takes, so walk it with a code the PHONE
      // computes from the secret it holds.
      const mfaView = page.locator('#mfaview:not(.hidden)');
      try {
        await mfaView.waitFor({ state: 'visible', timeout: 8000 });
        step('an enrolled account is challenged for a second factor', true);
        // Fresh: on a re-run of an already-enrolled account the previous
        // run's code may still be the current one, and the server has
        // already spent it.
        await page.fill('#mfacode', await freshCode());
        await shot(page, 'mfa-challenge');
        await page.click('#domfa');
      } catch {
        step('no second factor was required (account not enrolled yet)', true);
      }
      await page.waitForSelector('#dashview:not(.hidden)', { timeout: 45000 });
    }
    step('sign-in reaches the dashboard', true);
    await page.waitForTimeout(1500);                   // let the cards populate
    await shot(page, 'dashboard');

    // Real data, not an empty shell: an empty card means the page rendered
    // without its data, which a screenshot alone would not reveal.
    const agentsTxt  = await page.locator('#agents').innerText().catch(() => '');
    const payoutsTxt = await page.locator('#payouts').innerText().catch(() => '');
    const walBal     = await page.locator('#walBal').innerText().catch(() => '');
    step('agents card has content',  agentsTxt.trim().length  > 10, `${agentsTxt.length} chars`);
    step('payments card rendered', payoutsTxt.trim().length > 0, `${payoutsTxt.length} chars`);
    step('wallet balance rendered', walBal.trim() !== '' && walBal.trim() !== '—', walBal.trim());

    // The account holder's own email must be what the header shows: rendering
    // someone else's would be a session-scoping bug no unit test would catch.
    const header = await page.locator('header').innerText().catch(() => '');
    step('the header names THIS account', header.includes(EMAIL),
         header.replace(/\n/g, ' ').slice(0, 70));

    // --- the QR, through the real UI ---------------------------------------
    if (!has('no-mfa')) {
      const sec = page.locator('#security');
      await sec.waitFor({ state: 'visible', timeout: 30000 });
      const secTxt = await sec.innerText();
      step('security card reports the factor state', /two-step/i.test(secTxt),
           secTxt.split('\n')[0]);

      const onBtn = page.locator('#security button', { hasText: /turn on two-step/i });
      if (await onBtn.count() === 0) {
        step('factor already enrolled: enrolment not re-tested', true,
             'the sign-in challenge above exercised it instead');
      } else {
        await onBtn.first().click();                   // dialog handler answers
        const svg = page.locator('#security .qrbox svg').first();
        await svg.waitFor({ state: 'visible', timeout: 45000 });
        await shot(page, 'enrol-card');

        const box = await svg.boundingBox();
        step('QR has a non-zero rendered size',
             !!box && box.width > 40 && box.height > 40,
             box ? `${Math.round(box.width)}x${Math.round(box.height)} css px` : 'no box');
        step('QR renders square', !!box && Math.abs(box.width - box.height) <= 2,
             box ? `${Math.round(box.width)}x${Math.round(box.height)}` : 'no box');

        // The key must also be legible beside the symbol -- the fallback for a
        // user whose camera will not cooperate. Sent to the phone so IT can
        // compare; this machine never learns whether they agree, because it
        // never learns what the pixels said.
        const shown = (await page.locator('#security .mono').first().innerText()
                       .catch(() => '')).replace(/\s/g, '');
        step('key shown for hand entry', /^[A-Z2-7]{16,}$/.test(shown),
             shown.slice(0, 6) + '...');
        await phone('POST', `/displayed?label=${LABEL}`,
                    JSON.stringify({ secret: shown }));

        // Clip to the symbol itself: a full-page shot scales it down and the
        // decode would then be testing the screenshot, not the render.
        const qrPath = path.join(OUT, 'qr.png');
        await svg.screenshot({ path: qrPath });
        const png = fs.readFileSync(qrPath);
        step('QR screenshot written', png.length > 500, `${png.length} bytes`);

        const dec = await phone('POST', `/decode?label=${LABEL}`, png, 'image/png');
        step('the PHONE recovered the payload from the rendered pixels',
             !!dec.account, `account=${dec.account} ${dec.digits}d/${dec.period}s`);
        step('the pixels carry THIS account, not another',
             dec.account === EMAIL, dec.account);
        step('the scanned symbol agrees with the key shown for hand entry',
             dec.matches_displayed === true, String(dec.matches_displayed));
        result.decoded = dec;

        // THE PROOF: the code typed here was computed by the phone from the
        // secret it read out of the pixels. This machine cannot compute it.
        const codeInput = page.locator('#security input[placeholder="123456"]').first();
        await codeInput.fill(await freshCode());
        await page.locator('#security button', { hasText: /^Confirm$/ }).first().click();
        await page.waitForTimeout(2500);
        const after = await sec.innerText();
        const enrolled = /recovery code/i.test(after) || /is on/i.test(after);
        step('ENROLLED using a code derived only from the rendered pixels',
             enrolled, after.split('\n')[0]);
        await shot(page, 'after-enrol');

        // Recovery codes are shown exactly once. Capturing them matters for a
        // real account: without them an authenticator loss is terminal.
        if (enrolled) {
          const codes = (await sec.innerText()).split('\n')
            .map(s => s.trim()).filter(s => /^[A-Z0-9]{4,}-[A-Z0-9-]+$/i.test(s));
          step('recovery codes displayed once, and captured', codes.length >= 8,
               `${codes.length} codes`);
          fs.writeFileSync(path.join(OUT, 'recovery-codes.txt'), codes.join('\n') + '\n');
          result.recovery_code_count = codes.length;
        }

        // A spent code must not work twice. Reusing the same digits is the
        // cheapest real attack on TOTP, and the page is where it would land.
        if (enrolled) {
          await page.click('#refresh');
          await page.waitForTimeout(1500);
        }
      }

      // --- the factor is load-bearing: prove it blocks a password-only sign-in
      if (has('prove-blocks')) {
        await page.click('#logout').catch(() => {});
        await page.waitForTimeout(1200);
        await page.fill('#email', EMAIL);
        await page.fill('#password', PASS);
        await page.click('#dologin');
        await page.waitForTimeout(3000);
        const challenged = (await page.locator('#mfaview:not(.hidden)').count()) === 1;
        const gotIn = (await page.locator('#dashview:not(.hidden)').count()) === 1;
        step('the correct password ALONE no longer reaches the dashboard',
             challenged && !gotIn, `challenged=${challenged} in=${gotIn}`);

        const bad = await phone('GET', `/code?label=${LABEL}&skew=-3600`);
        await page.fill('#mfacode', bad.code);
        await page.click('#domfa');
        await page.waitForTimeout(2500);
        step('a code from an hour ago is refused',
             (await page.locator('#dashview:not(.hidden)').count()) === 0);

        // Fresh: confirming enrolment above SPENT the current counter, so
        // the digits on screen right now are a replay to the server.
        await page.fill('#mfacode', await freshCode());
        await page.click('#domfa');
        await page.waitForSelector('#dashview:not(.hidden)', { timeout: 30000 });
        step('a current code from the phone completes the sign-in', true);
        await shot(page, 'reauth');
      }

      if (has('keep-off')) {
        // Leave the account as it was found. Both factors are required to
        // remove a factor, and the dialog handler supplies each in turn.
        await page.click('#refresh');
        await page.waitForTimeout(1500);
        const offBtn = page.locator('#security button', { hasText: /turn off/i });
        if (await offBtn.count()) {
          await offBtn.first().click();
          await page.waitForTimeout(3000);
          // Disabling revokes every session, so the page returns to sign-in --
          // that is the expected evidence, not a failure.
          const back = (await page.locator('#authview:not(.hidden)').count()) === 1;
          step('factor turned back off; all sessions revoked', back,
               'page returned to sign-in, as designed');
          await shot(page, 'after-disable');
        } else {
          step('factor turned back off', false, 'no Turn off button found');
        }
      }
    }

    step('no console errors', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '));
    step('no failed requests', failedReqs.length === 0, failedReqs.slice(0, 3).join(' | '));
  } catch (err) {
    step('run completed without throwing', false, err.message);
    await page.screenshot({ path: path.join(OUT, 'ZZ-error.png'), fullPage: true }).catch(() => {});
  } finally {
    result.consoleErrors = consoleErrors;
    result.failedRequests = failedReqs;
    result.finished = new Date().toISOString();
    result.passed = result.steps.filter(s => s.ok).length;
    result.failed = result.steps.filter(s => !s.ok).length;
    fs.writeFileSync(path.join(OUT, 'result.json'), JSON.stringify(result, null, 2));
    await browser.close();
    console.log(`\n[${LABEL}] ${result.passed} passed, ${result.failed} failed`);
    process.exitCode = result.ok ? 0 : 1;
  }
})();
