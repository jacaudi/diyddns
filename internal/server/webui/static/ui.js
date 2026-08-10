// Progressive enhancement only. Every page renders and every action works with
// this file blocked: copy buttons fall back to selectable text, the nav is
// visible at desktop widths, and destructive confirmations are enforced
// server-side by a typed-confirmation field, never by confirm().
//
// No inline handlers anywhere in the templates, so a future
// Content-Security-Policy without 'unsafe-inline' needs no template rewrite.

(function () {
  "use strict";

  // Copy-to-clipboard. navigator.clipboard requires a secure context, so it is
  // absent over plain HTTP — the button then does nothing and the value stays
  // selectable, which is the documented fallback.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    if (!navigator.clipboard) {
      btn.hidden = true;
      return;
    }
    btn.addEventListener("click", function () {
      var value = btn.getAttribute("data-copy");
      var original = btn.textContent;
      var done = function () {
        btn.textContent = "Copied ✓";
        setTimeout(function () { btn.textContent = original; }, 1200);
      };
      navigator.clipboard.writeText(value).then(done, done);
    });
  });

  // Mobile nav toggle.
  var toggle = document.querySelector("[data-toggle-nav]");
  var nav = document.getElementById("nav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
  }

  // Confirmation sugar. The server independently requires a typed confirmation
  // field on every destructive form, so declining here only saves a round trip.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });
})();
