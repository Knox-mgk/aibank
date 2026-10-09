#!/usr/bin/env node
/*
 * Run the dashboard's real JavaScript against a minimal DOM, talking to a REAL
 * aibank server over HTTP.
 *
 * Why this exists: smoke_dashboard.py proves every endpoint the page calls is
 * reachable and returns the fields the page reads. It does NOT prove the page's
 * own code runs -- a typo in a render function, a null dereference on an empty
 * list, or a function that throws on first paint would pass that test and still
 * leave a blank screen.
 *
 * There is no browser on this host and a headless Chromium is not a dependency
 * this project will take (the disk budget rules it out). So: extract the
 * <script> from the page, give it just enough DOM to run, and assert on the
 * resulting element tree. A fake DOM cannot prove the page LOOKS right, and
 * this does not claim to -- it proves the code executes, renders the data, and
 * that clicking the money buttons issues the right requests.
 *
 * Usage: node scripts/dom_check.mjs <base-url> <email> <password>
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [BASE, EMAIL, PASSWORD] = process.argv.slice(2);
if (!BASE) {
  console.error("usage: dom_check.mjs <base-url> <email> <password>");
  process.exit(2);
}

const HERE = dirname(fileURLToPath(import.meta.url));
const HTML = readFileSync(join(HERE, "..", "aibank", "static", "dashboard.html"),
                          "utf8");

let pass = 0, fail = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) { pass++; console.log(`  ok   ${label}`); }
  else { fail++; console.log(`  FAIL ${label}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`); }
};

/* ------------------------------------------------------------- DOM shim */
class Node {
  constructor(tag) {
    this.tagName = (tag || "").toUpperCase();
    this.childNodes = [];
    this.attributes = {};
    this.classList = new ClassList(this);
    this.style = {};
    this._text = "";
    this._listeners = {};
    this.parentNode = null;
    this.disabled = false;
    this.value = "";
  }
  get className() { return this.attributes.class || ""; }
  set className(v) { this.attributes.class = v; }
  get children() { return this.childNodes.filter((n) => n instanceof Node); }
  // Real elements expose these; omitting them makes the page throw a
  // TypeError that its own try/catch swallows into a flash message, so the
  // panel silently renders empty and the failure looks like missing data.
  get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
  get firstChild() { return this.childNodes[0] || null; }
  // `placeholder` and `title` are reflected properties in a real DOM: setting
  // the property sets the attribute. The page sets them as properties and the
  // assertions read them as attributes.
  get placeholder() { return this.attributes.placeholder || ""; }
  set placeholder(v) { this.attributes.placeholder = String(v); }
  get title() { return this.attributes.title || ""; }
  set title(v) { this.attributes.title = String(v); }
  get textContent() {
    if (this.childNodes.length === 0) return this._text;
    return this._text + this.childNodes.map((c) => c.textContent).join("");
  }
  set textContent(v) { this._text = String(v); this.childNodes = []; }
  appendChild(n) { n.parentNode = this; this.childNodes.push(n); return n; }
  replaceChildren(...ns) {
    this.childNodes = [];
    ns.forEach((n) => this.appendChild(n));
  }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k] ?? null; }
  addEventListener(ev, fn) { (this._listeners[ev] ||= []).push(fn); }
  async click() {
    for (const fn of this._listeners.click || []) await fn({ key: "click" });
  }
  querySelector(sel) {
    // Only ".class" is used by the page.
    const want = sel.replace(/^\./, "");
    const walk = (n) => {
      for (const c of n.children) {
        if (c.classList.contains(want)) return c;
        const hit = walk(c);
        if (hit) return hit;
      }
      return null;
    };
    return walk(this);
  }
  // Helpers for the assertions below (not part of the DOM API).
  find(pred) {
    const out = [];
    const walk = (n) => {
      for (const c of n.children) { if (pred(c)) out.push(c); walk(c); }
    };
    walk(this);
    return out;
  }
  buttons(label) {
    return this.find((n) => n.tagName === "BUTTON" &&
                            n.textContent.includes(label));
  }
}

class ClassList {
  constructor(node) { this.node = node; }
  _set() {
    return new Set((this.node.attributes.class || "").split(/\s+/).filter(Boolean));
  }
  _write(s) { this.node.attributes.class = [...s].join(" "); }
  add(...c) { const s = this._set(); c.forEach((x) => s.add(x)); this._write(s); }
  remove(...c) { const s = this._set(); c.forEach((x) => s.delete(x)); this._write(s); }
  contains(c) { return this._set().has(c); }
  toggle(c, force) {
    const s = this._set();
    const on = force === undefined ? !s.has(c) : !!force;
    if (on) s.add(c); else s.delete(c);
    this._write(s);
    return on;
  }
}

const byId = new Map();
// Elements the page looks up by id. Parsed from the HTML so this list cannot
// drift from the markup.
for (const m of HTML.matchAll(/<(\w+)[^>]*\bid="([^"]+)"/g)) {
  const n = new Node(m[1]);
  n.attributes.id = m[2];
  const cls = /class="([^"]*)"/.exec(m[0]);
  if (cls) n.attributes.class = cls[1];
  byId.set(m[2], n);
}

const document = {
  getElementById: (id) => byId.get(id) || null,
  createElement: (tag) => new Node(tag),
  createTextNode: (t) => { const n = new Node("#text"); n._text = t; return n; },
};

const storage = () => {
  const m = new Map();
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
  };
};

const CONFIRMS = { answer: true, count: 0 };
const FETCHES = [];

const window = {
  scrollTo() {},
  confirm(msg) { CONFIRMS.count++; CONFIRMS.last = msg; return CONFIRMS.answer; },
};

globalThis.document = document;
globalThis.window = window;
globalThis.sessionStorage = storage();
// The flash banner clears itself on a timer. Record the callback but do NOT
// fire it: firing immediately would wipe the message before it is asserted on.
//
// This is deliberately NOT installed on globalThis. Node's own fetch (undici)
// uses the global timers internally, so clobbering globalThis.setTimeout makes
// every request throw from inside undici -- which the page catches and renders
// as "service unreachable", pointing the blame at the server instead of the
// harness. The page receives this via the Function parameter below.
const TIMEOUTS = [];
const pageSetTimeout = (fn, ms) => { TIMEOUTS.push({ fn, ms }); return 0; };

// MUST be captured BEFORE the shim is installed. Reading `fetch` after the
// assignment below resolves to the shim itself, and the shim then awaits
// itself -- "Maximum call stack size exceeded" on the first request, with the
// real error swallowed by an unhandled promise rejection.
const realFetch = globalThis.fetch.bind(globalThis);
let INFLIGHT = 0;
globalThis.fetch = async (path, opts) => {
  const url = path.startsWith("http") ? path : BASE + path;
  FETCHES.push({ method: (opts?.method || "GET"), path, body: opts?.body });
  INFLIGHT++;
  try {
    const r = await realFetch(url, opts);
    const text = await r.text();
    return { ok: r.ok, status: r.status, text: async () => text };
  } catch (e) {
    // Never let a harness-level transport failure masquerade as the page's
    // own error handling.
    console.log(`  !! transport error on ${path}: ${e.message}`);
    throw e;
  } finally {
    INFLIGHT--;
  }
};

/* ------------------------------------------- expectations from the server */
// The assertions below used to hard-code this harness's own fixture values
// ("Dom", "dash-agent", exactly one pending approval). That made the harness
// unrunnable against any other seeded database: pointed at a demo server it
// reported three FAILs for a page that was rendering correctly, which is the
// worst failure mode a test can have. Ask the API what the truth is, then
// assert the page renders THAT. The expectation still comes from outside the
// page, so the assertion keeps its meaning.
const preflight = async () => {
  const login = await realFetch(BASE + "/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  if (!login.ok) {
    throw new Error(`preflight login failed: ${login.status} ` +
                    `${await login.text()}`);
  }
  const body = await login.json();
  const token = body.token || body.session_token;
  if (!token) throw new Error(`preflight login returned no token`);
  const dash = await realFetch(BASE + "/v1/dashboard",
                               { headers: { Authorization: "Bearer " + token } });
  if (!dash.ok) {
    throw new Error(`preflight dashboard failed: ${dash.status}`);
  }
  const d = await dash.json();
  const u = d.user || {};
  const agents = d.agents || [];
  if (!agents.length) {
    throw new Error("preflight: server has no agents; the agent-card " +
                    "assertions cannot be meaningful. Seed one first.");
  }
  const approvals = d.pending_approvals || [];
  if (!approvals.length) {
    throw new Error("preflight: server has no pending approvals; the " +
                    "approval-flow assertions cannot be meaningful.");
  }
  // Release the preflight session so it does not sit in the sessions table.
  await realFetch(BASE + "/v1/auth/logout",
                  { method: "POST",
                    headers: { Authorization: "Bearer " + token } });
  return {
    whoami: (u.display_name || u.email || "") +
            (u.role === "admin" ? " \u00b7 admin" : ""),
    agentName: agents[0].name,
    agentStatus: agents[0].status,
    approvalCount: approvals.length,
  };
};
const EXPECT = await preflight();
console.log(`  expectations from the API: whoami=${JSON.stringify(EXPECT.whoami)} ` +
            `agent[0]=${JSON.stringify(EXPECT.agentName)} ` +
            `(${EXPECT.agentStatus}) pending=${EXPECT.approvalCount}\n`);

/* --------------------------------------------------- run the page's code */
const script = [...HTML.matchAll(/<script>([\s\S]*?)<\/script>/g)]
  .map((m) => m[1]).join("\n");
check("page has a script block", script.length > 1000, true);

// The page's top-level code runs here. `use strict` plus the real source --
// a syntax error or a missing global throws now.
const run = new Function("document", "window", "sessionStorage", "fetch",
                         "setTimeout", script);
try {
  run(document, window, globalThis.sessionStorage, globalThis.fetch,
      pageSetTimeout);
  check("page script executes without throwing", true, true);
} catch (e) {
  check("page script executes without throwing", String(e), true);
  console.log("\n" + "=".repeat(52));
  console.log(`${pass} passed, ${fail} failed`);
  process.exit(1);
}

// Real HTTP is a macrotask away, not a microtask: spinning setImmediate does
// NOT wait for a socket. Settle = drain microtasks, then keep yielding to the
// event loop until no fetch is in flight (with a ceiling so a hung request
// fails the run instead of hanging it).
const tick = () => new Promise((r) => setImmediate(r));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const settle = async (ms = 4000) => {
  const deadline = Date.now() + ms;
  do {
    for (let i = 0; i < 5; i++) await tick();
    if (INFLIGHT === 0) { await sleep(5); for (let i = 0; i < 5; i++) await tick(); }
    if (INFLIGHT === 0) return;
    await sleep(10);
  } while (Date.now() < deadline);
  throw new Error(`settle timed out with ${INFLIGHT} request(s) in flight`);
};

await settle();

check("health probe ran", FETCHES.some((f) => f.path === "/health"), true);
// Assert on the TEXT, not on a boolean: when this fails the message itself
// ("service unreachable") names the cause, while `got: false` names nothing.
const healthText = byId.get("health").textContent;
check("schema shown in the header",
      /^schema v\d+$/.test(healthText) ? "schema vN" : healthText, "schema vN");
check("starts on the sign-in view",
      byId.get("authview").classList.contains("hidden"), false);
check("dashboard hidden before sign-in",
      byId.get("dashview").classList.contains("hidden"), true);

/* ------------------------------------------------------------- sign in */
byId.get("email").value = EMAIL;
byId.get("password").value = PASSWORD;
await byId.get("dologin").click();
await settle();

check("login POSTed", FETCHES.some((f) => f.method === "POST" &&
      f.path === "/v1/auth/login"), true);
check("dashboard loaded", FETCHES.some((f) => f.path === "/v1/dashboard"), true);
check("dashboard view is visible",
      byId.get("dashview").classList.contains("hidden"), false);
check("auth view hidden", byId.get("authview").classList.contains("hidden"), true);
check("password field cleared after sign-in", byId.get("password").value, "");
// The header shows the DISPLAY NAME, not the email local part -- matching
// case-sensitively on the email was the harness's original bug. The expected
// string now comes from /v1/dashboard (see preflight), so this runs against
// any seeded database instead of only the CI fixture.
check("identity in the header", byId.get("whoami").textContent, EXPECT.whoami);
// A page error is caught by the page and rendered into #flash. Assert it is
// clean, or every later "rendered nothing" failure hides the real reason.
check("no error flash after sign-in", byId.get("flash")?.textContent || "", "");

/* ------------------------------------------------------- wallet panel */
const walBal = byId.get("walBal").textContent;
check("wallet balance rendered, not a dash", walBal !== "—", true);
check("wallet balance formatted with the currency",
      /^NGN [\d,]+\.\d\d$/.test(walBal), true);
check("allocated-to-agents tile rendered",
      /^NGN [\d,]+\.\d\d$/.test(byId.get("walAlloc").textContent), true);
check("pending count rendered",
      /\d+ payments?$/.test(byId.get("walPending").textContent), true);

/* -------------------------------------------------------- agents panel */
const agents = byId.get("agents");
check("an agent card rendered", agents.children.length >= 1, true);
const card = agents.children[0];
check("agent name shown", card.textContent.includes(EXPECT.agentName), true);
check("agent marked active", card.textContent.includes(EXPECT.agentStatus), true);
check("available balance shown on the card",
      card.textContent.includes("available"), true);

/* --------------------------------------------- limits tab is populated */
// THE regression this catches: policy came back as *_minor only, so every
// limit input rendered EMPTY -- which reads as "no limit" and would erase the
// ceiling on save. An empty-input dashboard passes an endpoint-coverage test.
const inputs = card.find((n) => n.tagName === "INPUT");
check("limits form has inputs", inputs.length >= 5, true);
const filled = inputs.filter((i) => String(i.value).trim() !== "");
check("configured limits are PRE-FILLED, not blank",
      filled.length >= 3, true);
check("per-payment max shows a real number",
      inputs.some((i) => /^\d+\.\d\d$/.test(String(i.value))), true);

/* ---------------------------------------- approvals card and its action */
const approvals = byId.get("approvals");
check("a pending approval is rendered", approvals.children.length >= 1, true);
const appr = approvals.children[0];
check("approval shows the amount",
      /NGN [\d,]+\.\d\d/.test(appr.textContent), true);
check("approval shows the masked destination",
      /\*+\d{4}/.test(appr.textContent), true);
check("approval does NOT show a full account number",
      /\d{10}/.test(appr.textContent), false);

const before = FETCHES.length;
CONFIRMS.answer = false;
await appr.buttons("Approve")[0].click();
await settle();
check("declining the confirm issues NO request", FETCHES.length, before);

CONFIRMS.answer = true;
await appr.buttons("Approve")[0].click();
await settle();
const approveCall = FETCHES.slice(before).find((f) => /\/approve$/.test(f.path));
check("confirming approves via POST", !!approveCall, true);
check("approve used POST", approveCall?.method, "POST");
// After approving one, the card hides only if that was the LAST pending
// approval. Hard-coding "hidden" assumed a one-approval fixture and failed
// against any realistic database; assert the actual rule instead.
if (EXPECT.approvalCount === 1) {
  check("approvals card hidden once empty",
        byId.get("approvalsCard").classList.contains("hidden"), true);
} else {
  check("approvals card still shown while others pend",
        byId.get("approvalsCard").classList.contains("hidden"), false);
  check("one fewer approval rendered after approving",
        byId.get("approvals").children.length, EXPECT.approvalCount - 1);
}

/* ------------------------------------------------------- payments table */
const payouts = byId.get("payouts");
check("payments table rendered", payouts.children.length >= 1, true);
const rows = payouts.find((n) => n.tagName === "TR");
check("has a header row plus data rows", rows.length >= 2, true);
check("a status pill rendered",
      payouts.find((n) => n.classList.contains("pill")).length >= 1, true);
check("payments table shows the masked destination",
      /\*+\d{4}/.test(payouts.textContent), true);

/* ----------------------------------------------------- allocate flow */
const fundsTab = card.buttons("Move funds")[0];
check("Move funds tab exists", !!fundsTab, true);
await fundsTab.click();
await settle();
const amt = card.find((n) => n.tagName === "INPUT" &&
                             String(n.attributes.placeholder || "")
                               .includes("10000.00"))[0];
check("amount input present on the funds tab", !!amt, true);
amt.value = "123.00";
const n0 = FETCHES.length;
await card.buttons("Allocate")[0].click();
await settle();
const alloc = FETCHES.slice(n0).find((f) => /\/allocate$/.test(f.path));
check("allocate POSTed", !!alloc, true);
const allocBody = JSON.parse(alloc?.body || "{}");
check("allocate sent the typed amount", allocBody.amount, "123.00");
check("allocate carried an idempotency key",
      typeof allocBody.idempotency_key === "string" &&
      allocBody.idempotency_key.length > 5, true);

/* ---------------------------------------------------------- sign out */
await byId.get("logout").click();
await settle();
check("logout POSTed",
      FETCHES.some((f) => f.path === "/v1/auth/logout"), true);
check("back on the sign-in view",
      byId.get("authview").classList.contains("hidden"), false);
check("token cleared from storage",
      globalThis.sessionStorage.getItem("aibank_token"), null);

console.log("\n" + "=".repeat(52));
console.log(`${pass} passed, ${fail} failed`);
console.log("=".repeat(52));
process.exit(fail ? 1 : 0);
