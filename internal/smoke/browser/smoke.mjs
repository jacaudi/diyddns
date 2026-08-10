// Browser smoke check: drives the REAL pages and the REAL passkey.js through
// Chromium with a virtual authenticator, then the REAL diyddns-client binary
// through the enrollment and check-in flow.
//
// Why this exists, when internal/smoke already covers the same flow: the Go
// harness speaks to the API directly, so it never executes passkey.js or
// ui.js. A bug in passkey.js — sending the grant token on a bootstrap-claim
// finish — made first-run admin setup impossible in a browser while every Go
// test stayed green. Nothing else in this repo runs the browser client, and
// nothing else in this repo can see rendered CSS geometry: a stylesheet-text
// assertion can prove a rule exists, only a browser can prove two elements
// line up (see the topbar brand/nav centre-line check below, added after two
// real geometry defects reached a browser against a fully green suite).
//
// Deliberately NOT a repo dependency: no package.json, no node_modules. It is
// run on demand via `npx playwright`, so `go build` and `go test ./...` are
// unaffected and the project stays buildable with the Go toolchain alone.
//
// The device enrolled below cannot be pre-seeded: the bootstrap admin row is
// created inside FinishClaim when THIS SCRIPT claims the token, so there is
// no user to own a device until the claim step below runs. The device is
// created the way a real one is — by the real client binary, spawned from
// here — mirroring the sequence internal/smoke/smoke_test.go already uses
// (mint a code -> enroll --code -> run --once).
//
// Invoked by browser_test.go, which starts the server and passes:
//   argv[2] = base URL (must be http://localhost:PORT — see the RP ID note
//             in config.example.yaml; an IP is not a valid RP ID)
//   argv[3] = bootstrap token scraped from the server log
//   argv[4] = path to the built diyddns-client binary
//   argv[5] = path to write the enrolled device's credentials.json
//   argv[6] = "discover" to also run a real check-in (network required), or
//             "skip-discovery" to stop after enrollment (the default)
//
// Exits 0 on success, non-zero with a message naming the failing step.

import { chromium } from "playwright";
import { execFileSync } from "node:child_process";

const [, , BASE_URL, TOKEN, CLIENT_BIN, CREDS_PATH, DISCOVERY] = process.argv;
const EMAIL = "browser-admin@example.com";
const PASSKEY_NAME = "Browser Test Key";

if (!BASE_URL || !TOKEN || !CLIENT_BIN || !CREDS_PATH || !DISCOVERY) {
  console.error("usage: smoke.mjs <base-url> <bootstrap-token> <client-bin> <creds-path> <discover|skip-discovery>");
  process.exit(2);
}

const step = (m) => console.log(`==> ${m}`);
const fail = (m) => {
  console.error(`BROWSER SMOKE FAIL: ${m}`);
  process.exit(1);
};

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();

// Surface page-side errors: a broken passkey.js otherwise shows up only as a
// timeout on the navigation assertion, which says nothing about the cause.
const pageErrors = [];
page.on("pageerror", (e) => pageErrors.push(String(e)));
page.on("console", (m) => {
  if (m.type() === "error") pageErrors.push(m.text());
});

try {
  // A virtual authenticator via CDP. Without this navigator.credentials.create()
  // would wait forever for hardware that isn't there.
  step("attach a virtual authenticator");
  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  await client.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true, // discoverable credentials — login has no username field
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  step("GET /register");
  await page.goto(`${BASE_URL}/register`, { waitUntil: "domcontentloaded" });

  step("fill the first-run claim form and submit");
  await page.fill("#register-token", TOKEN);
  await page.fill("#register-email", EMAIL);
  await page.fill("#register-name", PASSKEY_NAME);

  // Regression guard for a real defect (Task 5 review round 3): the passkey
  // name field is immediately followed by the submit button, and .field's own
  // margin used to SUM with the button's margin instead of collapsing (.btn is
  // display: inline-block, and inline-block boxes never collapse margins with
  // siblings), landing the button 40px below the field instead of the
  // intended 24px, then 16px once the scale settled. app.css now zeroes the
  // field's side with `.field:has(+ .btn)` so the button's own margin-top is
  // the whole gap. A stylesheet-text assertion can prove that rule exists;
  // only a browser can prove the button actually landed 16px away.
  const registerGap = await page.evaluate(() => {
    const input = document.querySelector("#register-name");
    const btn = document.querySelector("#register-form button[type=submit]");
    return btn.getBoundingClientRect().top - input.getBoundingClientRect().bottom;
  });
  if (Math.abs(registerGap - 16) > 1) {
    fail(`register form field-to-button gap = ${registerGap}px, want ~16px (see app.css .field:has(+ .btn))`);
  }

  await page.click("#register-form button[type=submit]");

  // The real assertion: a successful claim lands on /account WITH a session.
  // Before the session fix this bounced to /login, and before the passkey.js
  // fix it never left /register at all.
  step("land on /account, signed in");
  try {
    await page.waitForURL(`${BASE_URL}/account`, { timeout: 15000 });
  } catch {
    const status = (await page.textContent("#register-status").catch(() => null)) ?? "(no status)";
    fail(`did not reach /account. status="${status.trim()}" url=${page.url()}` +
      (pageErrors.length ? ` pageErrors=${JSON.stringify(pageErrors)}` : ""));
  }

  step("the account page lists the new passkey");
  await page.waitForSelector("#passkey-list li", { timeout: 10000 }).catch(() =>
    fail("passkey list never rendered on /account"));
  const listed = await page.textContent("#passkey-list");
  if (!listed.includes(PASSKEY_NAME)) {
    fail(`passkey list does not mention ${JSON.stringify(PASSKEY_NAME)}; got ${JSON.stringify(listed)}`);
  }

  // Log out and back in, exercising discoverable login: no username is typed
  // anywhere, the authenticator alone identifies the user.
  step("log out");
  await page.click("#logout-form button[type=submit]").catch(() => {});
  await page.waitForURL(`${BASE_URL}/login`, { timeout: 10000 }).catch(() =>
    fail("logout did not return to /login"));

  step("discoverable passkey login (no username typed)");
  await page.click("#passkey-login");
  try {
    await page.waitForURL(`${BASE_URL}/account`, { timeout: 15000 });
  } catch {
    const status = (await page.textContent("#passkey-login-status").catch(() => null)) ?? "(no status)";
    fail(`passkey login did not reach /account. status="${status.trim()}" url=${page.url()}` +
      (pageErrors.length ? ` pageErrors=${JSON.stringify(pageErrors)}` : ""));
  }

  step("GET / lands on the devices list");
  await page.goto(`${BASE_URL}/`, { waitUntil: "domcontentloaded" });
  if (!page.url().endsWith("/devices")) {
    fail(`GET / did not land on /devices; got ${page.url()}`);
  }

  step("the devices list shows its teaching empty state");
  if (!(await page.textContent("main")).includes("No devices yet")) {
    fail("the empty devices list does not teach the next step");
  }

  // Regression guard for a real defect (Task 5 review round 2): the shared
  // .brand rule used to carry a margin-bottom needed only by the auth shell's
  // stacked layout, and the topbar never overrode it. In a flex row with
  // align-items: center, the MARGIN box is what gets centered, so the brand
  // mark rendered 12px above the nav links' centre line. app.css now scopes
  // that margin to the auth shell only. A stylesheet-text assertion can prove
  // the margin rule moved; only a browser can prove the two elements actually
  // line up now.
  step("the topbar brand and nav links share a vertical centre line");
  const centres = await page.evaluate(() => {
    const centreOf = (el) => {
      const r = el.getBoundingClientRect();
      return r.top + r.height / 2;
    };
    const brand = document.querySelector(".topbar .brand");
    const navLink = document.querySelector(".nav a");
    if (!brand || !navLink) return null;
    return { brand: centreOf(brand), nav: centreOf(navLink) };
  });
  if (!centres) fail("could not find .topbar .brand or .nav a to measure");
  const centreDelta = Math.abs(centres.brand - centres.nav);
  console.log(`    brand centre=${centres.brand.toFixed(2)}px nav centre=${centres.nav.toFixed(2)}px delta=${centreDelta.toFixed(2)}px`);
  if (centreDelta > 1) {
    fail(`topbar brand and nav links do not share a centre line: brand=${centres.brand}, nav=${centres.nav}, delta=${centreDelta}px`);
  }

  step("create an enrollment code");
  // The empty devices list renders TWO links to /devices/new (the page-head
  // button and the empty-state button), so target the first explicitly rather
  // than relying on a bare selector's strictness behaviour.
  await page.locator('a[href="/devices/new"]').first().click();
  await page.fill("#label", "browser-test-device");
  await page.click('form[action="/devices/new"] button[type=submit]');

  // The reveal must carry BOTH the raw code and a ready-to-paste command. This
  // doubles as how the harness learns the code.
  const reveal = await page.textContent("main");
  if (!reveal.includes("diyddns-client enroll")) {
    fail("the reveal is missing the ready-to-paste enroll command");
  }
  if (!reveal.includes("Shown once")) {
    fail("the reveal is missing its shown-once warning");
  }
  const codeEl = await page.locator("main code").first().textContent();
  const code = codeEl.trim();
  if (!code) fail("could not read the enrollment code out of the reveal");

  // Enroll with the REAL client binary. Faking this in Node would reimplement
  // the agent's HMAC signing, and a harness that works around the real client is
  // evidence about the client, not a substitute for it.
  step("enroll the device with the real diyddns-client");
  execFileSync(CLIENT_BIN, [
    "enroll", "--server", BASE_URL, "--code", code, "--credentials-file", CREDS_PATH,
  ], { stdio: "inherit" });

  if (DISCOVERY === "discover") {
    step("check in once with the real client");
    execFileSync(CLIENT_BIN, [
      "run", "--once", "--credentials-file", CREDS_PATH,
    ], { stdio: "inherit" });
  }

  step("the device now appears in the list");
  await page.goto(`${BASE_URL}/devices`, { waitUntil: "domcontentloaded" });
  const list = await page.textContent("main");
  if (!list.includes("browser-test-device")) {
    fail("the enrolled device is missing from the devices list");
  }
  // Read the status OUT OF THE ROW, not off the page. `main` also contains the
  // filter <select>, whose <option> labels include every status name — so a
  // textContent check for "Online" or "Never seen" matches either way and proves
  // nothing. Same failure class as asserting against a <datalist>.
  const statusCell = await page
    .locator('tr:has(a:text("browser-test-device")) td[data-label="Status"]')
    .textContent();
  const expectedStatus = DISCOVERY === "discover" ? "Online" : "Never seen";
  if (!statusCell.includes(expectedStatus)) {
    fail(`device status cell = ${JSON.stringify(statusCell.trim())}, want ${JSON.stringify(expectedStatus)}`);
  }

  step("open the device detail screen");
  await page.click(`a:has-text("browser-test-device")`);
  const detail = await page.textContent("main");
  for (const want of ["Danger zone", "Rotate client secret", "Delete device"]) {
    if (!detail.includes(want)) fail(`device detail missing ${JSON.stringify(want)}`);
  }

  step("the copy button actually copies");
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.locator("[data-copy]").first().click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  if (!copied) fail("clicking a copy button put nothing on the clipboard");

  step("open the device history screen");
  await page.click('a:has-text("View full history")');
  if (!(await page.textContent("main")).includes("IP history")) {
    fail("the history screen did not render");
  }

  step("walk the three admin screens");
  for (const [path, marker] of [
    ["/admin/users", "Users"],
    ["/admin/audit", "Audit log"],
    ["/admin/server", "Server info"],
  ]) {
    await page.goto(`${BASE_URL}${path}`, { waitUntil: "domcontentloaded" });
    const body = await page.textContent("main");
    if (!body.includes(marker)) fail(`${path} did not render (looked for ${JSON.stringify(marker)})`);
    if (!(await page.textContent("nav")).includes("Server")) {
      fail(`${path} is missing the admin navigation`);
    }
  }

  step("the audit log recorded the enrollment");
  await page.goto(`${BASE_URL}/admin/audit?event_type=device.enroll.code`, { waitUntil: "domcontentloaded" });
  if (!(await page.textContent("main")).includes("device.enroll.code")) {
    fail("the audit filter did not find the enrollment event");
  }

  if (pageErrors.length) {
    fail(`page reported errors during an otherwise passing run: ${JSON.stringify(pageErrors)}`);
  }
  console.log("BROWSER SMOKE OK");
} finally {
  await browser.close();
}
