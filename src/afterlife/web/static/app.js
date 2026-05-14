// Afterlife dashboard: keyboard shortcuts, copy-to-clipboard, help modal.
// Vanilla JS, no dependencies. Self-hosted, no analytics, no network.
//
// Shortcuts:
//   /        focus the search box on the current page
//   Esc      blur active input / close the help modal
//   ?        toggle the keyboard help modal
//   g h      go to overview
//   g f      go to findings
//   g c      go to credentials
//   g i      go to identities

(function () {
  "use strict";

  // ---------- copy-to-clipboard ----------
  function attachCopyButtons() {
    document.querySelectorAll("pre:not(.copy-attached)").forEach((pre) => {
      pre.classList.add("copy-attached");
      const wrap = document.createElement("div");
      wrap.className = "copy-wrap";
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-btn";
      btn.textContent = "copy";
      btn.setAttribute("aria-label", "Copy to clipboard");
      btn.addEventListener("click", async () => {
        const text = pre.textContent || "";
        try {
          await navigator.clipboard.writeText(text);
          btn.textContent = "copied";
          btn.classList.add("copied");
          setTimeout(() => {
            btn.textContent = "copy";
            btn.classList.remove("copied");
          }, 1200);
        } catch (e) {
          btn.textContent = "failed";
          setTimeout(() => (btn.textContent = "copy"), 1200);
        }
      });
      wrap.appendChild(btn);
    });
  }

  // ---------- keyboard shortcuts ----------
  let gPending = false;
  let gTimer = null;

  function isTyping() {
    const el = document.activeElement;
    if (!el) return false;
    const tag = (el.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return true;
    if (el.isContentEditable) return true;
    return false;
  }

  function focusSearch() {
    const target =
      document.querySelector('input[type="search"]') ||
      document.querySelector(".search-input");
    if (target) {
      target.focus();
      target.select();
    }
  }

  function closeHelp() {
    const dlg = document.getElementById("kbd-help");
    if (dlg && typeof dlg.close === "function") dlg.close();
  }

  function toggleHelp() {
    const dlg = document.getElementById("kbd-help");
    if (!dlg) return;
    if (dlg.open) {
      dlg.close();
    } else if (typeof dlg.showModal === "function") {
      dlg.showModal();
    }
  }

  document.addEventListener("keydown", (e) => {
    // Always-on: Esc handling
    if (e.key === "Escape") {
      if (document.getElementById("kbd-help")?.open) {
        e.preventDefault();
        closeHelp();
        return;
      }
      if (isTyping()) {
        document.activeElement.blur();
      }
      return;
    }

    // Don't intercept shortcuts while the user is typing
    if (isTyping()) return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;

    if (e.key === "/") {
      e.preventDefault();
      focusSearch();
      return;
    }
    if (e.key === "?") {
      e.preventDefault();
      toggleHelp();
      return;
    }

    if (gPending) {
      gPending = false;
      clearTimeout(gTimer);
      const dest = {
        h: "/",
        f: "/findings",
        c: "/credentials",
        i: "/identities",
      }[e.key];
      if (dest) {
        e.preventDefault();
        window.location.href = dest;
      }
      return;
    }
    if (e.key === "g") {
      gPending = true;
      gTimer = setTimeout(() => {
        gPending = false;
      }, 800);
      return;
    }
  });

  // ---------- bootstrap ----------
  function init() {
    attachCopyButtons();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // Re-attach copy buttons after HTMX swaps content into the page.
  document.body.addEventListener("htmx:afterSwap", attachCopyButtons);
})();
