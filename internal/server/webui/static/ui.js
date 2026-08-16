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

  // Modal dismissal. The modal is a <details>, so with this file blocked it
  // still opens and its form still submits — only these shortcuts are lost, and
  // the summary itself remains the way to close it again.
  var modals = document.querySelectorAll("details.modal");

  var close = function (modal) {
    modal.removeAttribute("open");
  };

  modals.forEach(function (modal) {
    var panel = modal.querySelector(".modal-panel");
    if (panel) {
      // Only a click on the backdrop itself, never one that bubbled up out of
      // the card — otherwise typing in the confirm field could dismiss it.
      panel.addEventListener("click", function (event) {
        if (event.target === panel) {
          close(modal);
        }
      });
    }
    modal.querySelectorAll("[data-modal-close]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        close(modal);
      });
    });
    // Focus the confirm field on open: the operator has to type into it, and
    // without this the focus stays on the summary behind the backdrop.
    modal.addEventListener("toggle", function () {
      if (modal.open) {
        var input = modal.querySelector("input:not([type=hidden])");
        if (input) {
          input.focus();
        }
      }
    });
  });

  if (modals.length) {
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        modals.forEach(function (modal) {
          if (modal.open) {
            close(modal);
          }
        });
      }
    });
  }
})();
