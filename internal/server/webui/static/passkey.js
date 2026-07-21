// static/passkey.js — vanilla JS WebAuthn ceremony driver for the diyddns
// web UI. No framework, no build step. Drives the Task 7 JSON endpoints
// directly and converts between the wire's base64url strings and the
// ArrayBuffers navigator.credentials.create()/get() require.
(function () {
  "use strict";

  // ---- base64url <-> ArrayBuffer -------------------------------------
  // go-webauthn's protocol.URLEncodedBase64 marshals as unpadded
  // base64url (base64.RawURLEncoding); atob/btoa only understand standard
  // base64, so padding and the -/_  <-> +// swap are handled here.

  function b64urlToBuf(b64url) {
    const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
    const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // decodeCreationOptions/decodeRequestOptions mutate a go-webauthn
  // CredentialCreation/CredentialAssertion's ".publicKey" object in place,
  // turning every base64url id field into the ArrayBuffer
  // navigator.credentials.create()/get() require.

  function decodeCreationOptions(publicKey) {
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    if (publicKey.user) publicKey.user.id = b64urlToBuf(publicKey.user.id);
    if (publicKey.excludeCredentials) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64urlToBuf(c.id) });
      });
    }
    return publicKey;
  }

  function decodeRequestOptions(publicKey) {
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    if (publicKey.allowCredentials) {
      publicKey.allowCredentials = publicKey.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: b64urlToBuf(c.id) });
      });
    }
    return publicKey;
  }

  // encodeCredential converts the PublicKeyCredential returned by
  // navigator.credentials.create()/get() into the base64url JSON shape
  // go-webauthn's protocol.Parse*ResponseBody expects on the wire.
  function encodeCredential(cred) {
    const out = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      },
    };
    if (cred.response.attestationObject) {
      // navigator.credentials.create() response.
      out.response.attestationObject = bufToB64url(cred.response.attestationObject);
      if (cred.response.getTransports) out.response.transports = cred.response.getTransports();
    } else {
      // navigator.credentials.get() response.
      out.response.authenticatorData = bufToB64url(cred.response.authenticatorData);
      out.response.signature = bufToB64url(cred.response.signature);
      if (cred.response.userHandle) out.response.userHandle = bufToB64url(cred.response.userHandle);
    }
    if (cred.getClientExtensionResults) {
      out.clientExtensionResults = cred.getClientExtensionResults();
    }
    return out;
  }

  // ---- fetch + status helpers -----------------------------------------

  async function api(method, url, body, csrf) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const resp = await fetch(url, {
      method: method,
      headers: headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: "same-origin",
    });
    if (!resp.ok) {
      let msg = "request failed (" + resp.status + ")";
      try {
        const err = await resp.json();
        if (err && err.detail) msg = err.detail;
      } catch (e) {
        // response had no JSON body — keep the generic message.
      }
      throw new Error(msg);
    }
    const ct = resp.headers.get("Content-Type") || "";
    return ct.indexOf("application/json") === 0 ? resp.json() : null;
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf"]');
    return meta ? meta.content : "";
  }

  function setStatus(el, msg, isError) {
    if (!el) return;
    el.textContent = msg;
    el.classList.toggle("status-error", !!isError);
  }

  // ---- ceremonies -------------------------------------------------------

  // Login: discoverable (usernameless) passkey sign-in.
  async function loginWithPasskey() {
    const status = document.getElementById("passkey-login-status");
    try {
      setStatus(status, "Waiting for your passkey...");
      const opts = await api("POST", "/api/v1/auth/passkey/login/begin");
      const publicKey = decodeRequestOptions(opts.publicKey);
      const cred = await navigator.credentials.get({ publicKey: publicKey });
      await api("POST", "/api/v1/auth/passkey/login/finish", encodeCredential(cred));
      window.location.href = "/account";
    } catch (err) {
      setStatus(status, err.message || "Sign-in failed", true);
    }
  }

  // Add passkey: session-authenticated registration ceremony, CSRF-guarded.
  async function addPasskey(name) {
    const status = document.getElementById("passkey-status");
    const csrf = csrfToken();
    setStatus(status, "Waiting for your passkey...");
    const opts = await api("POST", "/api/v1/account/passkeys/register/begin", undefined, csrf);
    const publicKey = decodeCreationOptions(opts.publicKey);
    const cred = await navigator.credentials.create({ publicKey: publicKey });
    const body = Object.assign(encodeCredential(cred), { name: name });
    await api("POST", "/api/v1/account/passkeys/register/finish", body, csrf);
    setStatus(status, "Passkey added.");
  }

  // Token register: shared by the bootstrap, invite, and recovery flows —
  // token (+ email, bootstrap only) identifies which of the three the
  // service layer routes to; this page never has to know which one it is.
  async function registerWithToken(token, email, name) {
    const status = document.getElementById("register-status");
    setStatus(status, "Waiting for your passkey...");
    const beginBody = email ? { token: token, email: email } : { token: token };
    const opts = await api("POST", "/api/v1/register/begin", beginBody);
    const publicKey = decodeCreationOptions(opts.publicKey);
    const cred = await navigator.credentials.create({ publicKey: publicKey });
    const finishBody = Object.assign(encodeCredential(cred), { token: token, name: name });
    await api("POST", "/api/v1/register/finish", finishBody);
    setStatus(status, "Passkey created. Signing you in...");
    window.location.href = "/account";
  }

  // ---- account passkey management ---------------------------------------

  function renderPasskeyList(passkeys) {
    const list = document.getElementById("passkey-list");
    if (!list) return;
    list.innerHTML = "";
    passkeys.forEach(function (pk) {
      const li = document.createElement("li");

      const label = document.createElement("span");
      label.textContent = pk.name || "(unnamed passkey)";
      li.appendChild(label);

      const actions = document.createElement("span");
      actions.className = "actions";

      const renameBtn = document.createElement("button");
      renameBtn.type = "button";
      renameBtn.className = "btn";
      renameBtn.textContent = "Rename";
      renameBtn.addEventListener("click", function () { renamePasskey(pk.id, pk.name); });
      actions.appendChild(renameBtn);

      const removeBtn = document.createElement("button");
      removeBtn.type = "button";
      removeBtn.className = "btn";
      removeBtn.textContent = "Remove";
      removeBtn.addEventListener("click", function () { removePasskey(pk.id); });
      actions.appendChild(removeBtn);

      li.appendChild(actions);
      list.appendChild(li);
    });
  }

  async function loadPasskeys() {
    const status = document.getElementById("passkey-status");
    try {
      const passkeys = await api("GET", "/api/v1/account/passkeys");
      renderPasskeyList(passkeys || []);
    } catch (err) {
      setStatus(status, err.message || "Failed to load passkeys", true);
    }
  }

  async function renamePasskey(id, currentName) {
    const status = document.getElementById("passkey-status");
    const name = window.prompt("Rename passkey", currentName || "");
    if (name === null || name === currentName) return;
    try {
      await api("PATCH", "/api/v1/account/passkeys/" + encodeURIComponent(id), { name: name }, csrfToken());
      await loadPasskeys();
    } catch (err) {
      setStatus(status, err.message || "Rename failed", true);
    }
  }

  async function removePasskey(id) {
    const status = document.getElementById("passkey-status");
    if (!window.confirm("Remove this passkey? This cannot be undone.")) return;
    try {
      await api("DELETE", "/api/v1/account/passkeys/" + encodeURIComponent(id), undefined, csrfToken());
      await loadPasskeys();
    } catch (err) {
      setStatus(status, err.message || "Remove failed", true);
    }
  }

  // ---- plain-form progressive enhancement --------------------------------
  // Logout and the recovery request are real <form> elements with a hidden
  // csrf field (design §9/N2) so they degrade to a normal POST; both target
  // JSON-only API endpoints, so a submit handler here converts the form into
  // the equivalent fetch() call and handles the redirect/status client-side.

  function wireFormPost(formID, statusID, build, onSuccess) {
    const form = document.getElementById(formID);
    if (!form) return;
    form.addEventListener("submit", async function (evt) {
      evt.preventDefault();
      const status = document.getElementById(statusID);
      try {
        await build(form);
        onSuccess();
      } catch (err) {
        setStatus(status, err.message || "request failed", true);
      }
    });
  }

  // ---- wire-up ------------------------------------------------------------

  document.addEventListener("DOMContentLoaded", function () {
    const loginBtn = document.getElementById("passkey-login");
    if (loginBtn) loginBtn.addEventListener("click", loginWithPasskey);

    const recoverToggle = document.getElementById("recover-toggle");
    const recoverForm = document.getElementById("recover-form");
    if (recoverToggle && recoverForm) {
      recoverToggle.addEventListener("click", function (evt) {
        evt.preventDefault();
        recoverForm.hidden = !recoverForm.hidden;
      });
    }
    wireFormPost(
      "recover-form",
      "recover-status",
      function (form) {
        return api("POST", "/api/v1/auth/recovery/request", { email: form.elements.email.value });
      },
      function () {
        setStatus(document.getElementById("recover-status"), "If that address has an account, a recovery link is on its way.");
      }
    );

    wireFormPost(
      "logout-form",
      null,
      function () { return api("POST", "/api/v1/auth/logout"); },
      function () { window.location.href = "/login"; }
    );

    const registerForm = document.getElementById("register-form");
    if (registerForm) {
      registerForm.addEventListener("submit", function (evt) {
        evt.preventDefault();
        registerWithToken(
          registerForm.elements.token.value,
          registerForm.elements.email.value,
          registerForm.elements.name.value
        ).catch(function (err) {
          setStatus(document.getElementById("register-status"), err.message || "Registration failed", true);
        });
      });
    }

    const addForm = document.getElementById("add-passkey-form");
    if (addForm) {
      addForm.addEventListener("submit", function (evt) {
        evt.preventDefault();
        const name = addForm.elements.name.value;
        addPasskey(name)
          .then(function () {
            addForm.reset();
            return loadPasskeys();
          })
          .catch(function (err) {
            setStatus(document.getElementById("passkey-status"), err.message || "Failed to add passkey", true);
          });
      });
    }

    if (document.getElementById("passkey-list")) loadPasskeys();
  });
})();
