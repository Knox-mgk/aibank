// Drive the aibank dashboard in a REAL browser and prove the QR is scannable.
//
// WHY A BROWSER AT ALL, when scripts/dom_check.mjs already runs the page's JS:
// that harness runs under node with a DOM shim. It proves the page BUILDS the
// right nodes; it cannot prove a browser RENDERS them. Everything past the DOM
// -- the SVG viewBox, shape-rendering, the CSS that sizes and pads the symbol,
// the dark theme behind it, the rasteriser -- is unverified, and that is exactly
// the layer a phone camera has to read.
//
// So this walks the REAL user path (sign in, open the Security card, click
// "Turn on two-step verification", answer the password prompt), screenshots the
// symbol, and then the phone side decodes those PIXELS back to an otpauth URI
// (scripts/dev/decode_png_qr.py). The code typed into the Confirm box is
// computed from the DECODED secret, not from the API response -- so enrolment
// succeeding proves the rendered symbol alone is sufficient, which is precisely
// what a scanning user does.
//
// It also answers the one question no automated check can: LAYOUT. The
// screenshots in ./out are for a human to look at.
//
// Served from the phone over `ssh -R 8088:127.0.0.1:8088`, so 127.0.0.1 is
// correct from the browser's point of view.
//
//   node run_aibank.js              full run, leaves 2FA ON
//   node run_aibank.js --keep-off   turn the factor back off at the end
//   node run_aibank.js --no-mfa     dashboard only

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const BASE  = process.env.AIBANK_BASE  || 'http://127.0.0.1:8088';
const EMAIL = process.env.AIBANK_EMAIL || 'demo@aibank.local';
const PASS  = process.env.AIBANK_PASS  || 'demo-password-1234';
const OUT   = path.join(__dirname, 'out');

const result = { base: BASE, started: new Date().toISOString(), steps: [], ok: true };
function step(name, ok, detail) {
  result.steps.push({ name, ok, detail: detail === undefined ? null : detail });
  if (!ok) result.ok = false;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  -- ' + detail : ''}`);
}

// --- TOTP, so the code we type comes from the DECODED secret ---------------
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

  // The page answers its own window.prompt for the password re-check. Registered
  // before any click, because an unhandled dialog blocks the page indefinitely.
  page.on('dialog', async (d) => { await d.accept(PASS); });

  // Console errors and failed requests are findings, not noise: a strict-CSP
  // page that silently blocks its own script still renders a plausible shell.
  const consoleErrors = [], failedReqs = [];
  page.on('console', m => { if (m.type() === 'error') consoleErrors.push(m.text()); });
  page.on('requestfailed', r => failedReqs.push(`${r.method()} ${r.url()} ${r.failure() && r.failure().errorText}`));
  page.on('pageerror', e => consoleErrors.push('pageerror: ' + e.message));

  try {
    const resp = await page.goto(BASE + '/', { waitUntil: 'load', timeout: 60000 });
    step('dashboard HTML loads', resp.ok(), `HTTP ${resp.status()}`);
    await page.screenshot({ path: path.join(OUT, '01-signin.png'), fullPage: true });

    // --- sign in -----------------------------------------------------------
    await page.fill('#email', EMAIL);
    await page.fill('#password', PASS);
    await page.click('#dologin');
    await page.waitForSelector('#dashview:not(.hidden)', { timeout: 45000 });
    step('sign-in reaches the dashboard', true);
    await page.waitForTimeout(1500);                   // let the cards populate
    await page.screenshot({ path: path.join(OUT, '02-dashboard.png'), fullPage: true });

    // Real data, not an empty shell: the demo db is seeded with agents and
    // payouts, so an empty card means the page rendered without its data.
    const agentsTxt  = await page.locator('#agents').innerText().catch(() => '');
    const payoutsTxt = await page.locator('#payouts').innerText().catch(() => '');
    const walBal     = await page.locator('#walBal').innerText().catch(() => '');
    step('agents card has content',  agentsTxt.trim().length  > 20, `${agentsTxt.length} chars`);
    step('payouts card has content', payoutsTxt.trim().length > 20, `${payoutsTxt.length} chars`);
    step('wallet balance rendered', walBal.trim() !== '' && walBal.trim() !== '—', walBal.trim());

    // --- the QR, through the real UI ---------------------------------------
    if (!process.argv.includes('--no-mfa')) {
      const sec = page.locator('#security');
      await sec.waitFor({ state: 'visible', timeout: 30000 });
      const secTxt = await sec.innerText();
      step('security card reports the factor state', /two-step/i.test(secTxt),
           secTxt.split('\n')[0]);

      const onBtn = page.locator('#security button', { hasText: /turn on two-step/i });
      if (await onBtn.count() === 0) {
        step('factor is currently OFF so enrolment can be tested', false,
             'already enrolled — turn it off first');
      } else {
        await onBtn.first().click();                   // dialog handler answers
        const svg = page.locator('#security .qrbox svg').first();
        await svg.waitFor({ state: 'visible', timeout: 45000 });
        await page.screenshot({ path: path.join(OUT, '03-enrol-card.png'), fullPage: true });

        const box = await svg.boundingBox();
        step('QR has a non-zero rendered size',
             !!box && box.width > 40 && box.height > 40,
             box ? `${Math.round(box.width)}x${Math.round(box.height)} css px` : 'no box');
        step('QR renders square', !!box && Math.abs(box.width - box.height) <= 2,
             box ? `${Math.round(box.width)}x${Math.round(box.height)}` : 'no box');

        // Clip to the symbol itself: a full-page shot scales it down and the
        // decode would then be testing the screenshot, not the render.
        await svg.screenshot({ path: path.join(OUT, '04-qr.png') });
        const qrBytes = fs.statSync(path.join(OUT, '04-qr.png')).size;
        step('QR screenshot written', qrBytes > 500, `${qrBytes} bytes`);

        // The key must also be legible beside the symbol -- the fallback for a
        // user whose camera will not cooperate.
        const shown = (await page.locator('#security .mono').first().innerText()
                       .catch(() => '')).replace(/\s/g, '');
        step('key shown for hand entry', /^[A-Z2-7]{16,}$/.test(shown),
             shown.slice(0, 10) + '...');
        fs.writeFileSync(path.join(OUT, 'secret.txt'), shown + '\n');
        result.shown_secret = shown;

        // The phone decodes 04-qr.png and writes the secret it recovered here.
        // If that file exists, type a code derived from the DECODED secret, so
        // confirmation proves the rendered pixels alone are sufficient.
        const decodedPath = path.join(OUT, 'decoded_secret.txt');
        const useSecret = fs.existsSync(decodedPath)
          ? fs.readFileSync(decodedPath, 'utf8').trim() : shown;
        result.confirmed_from = fs.existsSync(decodedPath) ? 'decoded-pixels' : 'rendered-key';

        const codeInput = page.locator('#security input[placeholder="123456"]').first();
        await codeInput.fill(totp(useSecret));
        await page.locator('#security button', { hasText: /^Confirm$/ }).first().click();
        await page.waitForTimeout(2500);
        const after = await sec.innerText();
        step(`enrolment confirmed with a code from the ${result.confirmed_from}`,
             /recovery code/i.test(after) || /is on/i.test(after),
             after.split('\n')[0]);
        await page.screenshot({ path: path.join(OUT, '05-after-enrol.png'), fullPage: true });

        if (process.argv.includes('--keep-off')) {
          const offBtn = page.locator('#security button', { hasText: /turn off/i });
          if (await offBtn.count()) {
            // Reloading the card first; the recovery-code panel replaces it.
            await page.click('#refresh');
            await page.waitForTimeout(1500);
            const off2 = page.locator('#security button', { hasText: /turn off/i });
            if (await off2.count()) {
              await off2.first().click();              // password prompt, then code
              await page.waitForTimeout(500);
              const ci = page.locator('#security input').first();
              if (await ci.count()) {
                await ci.fill(totp(useSecret, 30, 6, Date.now() + 30000));
                const ok = page.locator('#security button', { hasText: /confirm|turn off/i });
                await ok.first().click();
                await page.waitForTimeout(2000);
              }
            }
          }
          step('factor turned back off', !/is on/i.test(await sec.innerText()), 'demo left as found');
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
    fs.writeFileSync(path.join(OUT, 'result.json'), JSON.stringify(result, null, 2));
    await browser.close();
    console.log(result.ok ? '\nALL CHECKS PASSED' : '\nSOME CHECKS FAILED');
  }
})();
