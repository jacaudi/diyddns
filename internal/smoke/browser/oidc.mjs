// Browser OIDC check: drives a REAL browser through the REAL /login page and
// the REAL authorization-code + PKCE flow against a mock OpenID Provider, and
// proves the session cookie it lands with actually authenticates the next
// request.
//
// Why this exists, when internal/server/api/oidc_test.go already covers the
// flow: that test drives an in-process handler with a Go cookie jar, so it
// never renders /login (the provider button is a template branch on
// .ShowOIDC), never crosses the IdP origin in a browser, and never asks a
// browser whether it would keep the cookie the server set. Every one of those
// is a place the flow can be correct in Go and broken in a browser — the
// cookie's Secure attribute over plain HTTP being the one issue #39 is about.
//
// Invoked by oidc_browser_test.go, which starts the mock IdP and the server:
//   argv[2] = base URL (http://localhost:PORT)
//   argv[3] = the email the mock IdP mints in its ID token
//
// Exits 0 on success, non-zero with a message naming the failing step.

import { chromium } from "playwright";

const [, , BASE_URL, EMAIL] = process.argv;

if (!BASE_URL || !EMAIL) {
  console.error("usage: oidc.mjs <base-url> <expected-email>");
  process.exit(2);
}

const step = (m) => console.log(`==> ${m}`);
const fail = (m) => {
  console.error(`OIDC BROWSER FAIL: ${m}`);
  process.exit(1);
};

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();

const pageErrors = [];
page.on("pageerror", (e) => pageErrors.push(String(e)));
page.on("console", (m) => {
  if (m.type() === "error") pageErrors.push(m.text());
});

try {
  step("GET /login");
  await page.goto(`${BASE_URL}/login`, { waitUntil: "domcontentloaded" });

  // The button is rendered only under .ShowOIDC (auth.oidc.enabled). Its
  // absence means the server booted with OIDC off, which no amount of
  // flow-level correctness downstream would make up for.
  step("/login offers the provider button");
  const btn = page.locator('a[href="/api/v1/auth/oidc/start"]');
  if ((await btn.count()) === 0) {
    fail(`/login has no provider button; page text was ${JSON.stringify(await page.textContent("main"))}`);
  }

  step("click through the IdP and back");
  await btn.first().click();

  // Landing on /devices is the whole assertion: the callback set a session
  // cookie, the browser KEPT it, and the very next navigation was served as an
  // authenticated user rather than bounced to /login. A cookie the browser
  // discards fails here and nowhere earlier.
  try {
    await page.waitForURL(`${BASE_URL}/devices`, { timeout: 20000 });
  } catch {
    fail(
      `did not land authenticated on /devices; url=${page.url()}` +
        (pageErrors.length ? ` pageErrors=${JSON.stringify(pageErrors)}` : ""),
    );
  }

  step("the session cookie is present, HttpOnly, and reported");
  const cookies = await context.cookies();
  const session = cookies.find((c) => c.name === "diyddns_session");
  if (!session) {
    fail(`no diyddns_session cookie after login; got ${JSON.stringify(cookies.map((c) => c.name))}`);
  }
  // Printed rather than asserted: the Secure attribute over plain HTTP is
  // exactly the configuration issue #39 describes, and this run is the
  // evidence for the ruling on it. localhost is a potentially-trustworthy
  // origin, so the browser keeps a Secure cookie here; a LAN address would
  // not. Asserting a value would bake one deployment shape into the harness.
  console.log(
    `    diyddns_session: secure=${session.secure} httpOnly=${session.httpOnly} sameSite=${session.sameSite}`,
  );
  if (!session.httpOnly) fail("the session cookie is not HttpOnly");

  // A second, independent request. waitForURL above proves the redirect chain
  // ended somewhere authenticated; this proves the session is durable and
  // resolves to the identity the IdP asserted, not just to *some* user.
  step("GET /account shows the OIDC identity");
  await page.goto(`${BASE_URL}/account`, { waitUntil: "domcontentloaded" });
  if (!page.url().endsWith("/account")) {
    fail(`GET /account bounced to ${page.url()} — the session did not survive`);
  }
  const account = await page.textContent("main");
  if (!account.includes(EMAIL)) {
    fail(`/account does not mention ${JSON.stringify(EMAIL)}; got ${JSON.stringify(account)}`);
  }

  step("log out and confirm the session is gone");
  await page.click("#logout-form button[type=submit]");
  await page.waitForURL(`${BASE_URL}/login`, { timeout: 10000 }).catch(() =>
    fail(`logout did not return to /login; url=${page.url()}`),
  );

  console.log("OIDC BROWSER OK");
} finally {
  await browser.close();
}
