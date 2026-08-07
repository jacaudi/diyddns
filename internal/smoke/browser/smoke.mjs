// Browser smoke check: drives the REAL pages and the REAL passkey.js through
// Chromium with a virtual authenticator.
//
// Why this exists, when internal/smoke already covers the same flow: the Go
// harness speaks to the API directly, so it never executes passkey.js. A bug
// in that file — sending the grant token on a bootstrap-claim finish — made
// first-run admin setup impossible in a browser while every Go test stayed
// green. Nothing else in this repo runs the browser client.
//
// Deliberately NOT a repo dependency: no package.json, no node_modules. It is
// run on demand via `npx playwright`, so `go build` and `go test ./...` are
// unaffected and the project stays buildable with the Go toolchain alone.
//
// Invoked by browser_test.go, which starts the server and passes:
//   argv[2] = base URL (must be http://localhost:PORT — see the RP ID note
//             in config.example.yaml; an IP is not a valid RP ID)
//   argv[3] = bootstrap token scraped from the server log
//
// Exits 0 on success, non-zero with a message naming the failing step.

import { chromium } from "playwright";

const [, , BASE_URL, TOKEN] = process.argv;
const EMAIL = "browser-admin@example.com";
const PASSKEY_NAME = "Browser Test Key";

if (!BASE_URL || !TOKEN) {
  console.error("usage: smoke.mjs <base-url> <bootstrap-token>");
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

  step("GET / redirects rather than 404ing");
  const rootResp = await page.goto(`${BASE_URL}/`, { waitUntil: "domcontentloaded" });
  if (rootResp && rootResp.status() === 404) fail("GET / returned 404");

  if (pageErrors.length) {
    fail(`page reported errors during an otherwise passing run: ${JSON.stringify(pageErrors)}`);
  }
  console.log("BROWSER SMOKE OK");
} finally {
  await browser.close();
}
