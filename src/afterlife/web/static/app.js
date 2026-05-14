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

  // ---------- per-finding acknowledge (localStorage) ----------
  const ACK_KEY = "afterlife.acked";

  function loadAcked() {
    try {
      return new Set(JSON.parse(localStorage.getItem(ACK_KEY) || "[]"));
    } catch (e) {
      return new Set();
    }
  }

  function saveAcked(set) {
    try {
      localStorage.setItem(ACK_KEY, JSON.stringify([...set]));
    } catch (e) {
      // localStorage may be disabled / full; degrade silently.
    }
  }

  function findingIdFromCard(card) {
    const link = card.querySelector('a[href^="/findings/"]');
    if (!link) return null;
    const match = link.getAttribute("href").match(/\/findings\/(\d+)/);
    return match ? match[1] : null;
  }

  function attachAckButtons() {
    const acked = loadAcked();
    document.querySelectorAll("details.finding:not(.ack-attached)").forEach((card) => {
      card.classList.add("ack-attached");
      const id = findingIdFromCard(card);
      if (!id) return;
      if (acked.has(id)) card.classList.add("acked");

      const summary = card.querySelector("summary");
      if (!summary) return;

      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "ack-btn" + (acked.has(id) ? " acked" : "");
      btn.textContent = acked.has(id) ? "✓ acked" : "ack";
      btn.title = "Acknowledge (visual only, stored in your browser)";
      btn.setAttribute("aria-pressed", acked.has(id) ? "true" : "false");
      btn.addEventListener("click", (e) => {
        // Don't toggle the <details> when the button is clicked.
        e.preventDefault();
        e.stopPropagation();
        const set = loadAcked();
        if (set.has(id)) {
          set.delete(id);
          card.classList.remove("acked");
          btn.classList.remove("acked");
          btn.textContent = "ack";
          btn.setAttribute("aria-pressed", "false");
        } else {
          set.add(id);
          card.classList.add("acked");
          btn.classList.add("acked");
          btn.textContent = "✓ acked";
          btn.setAttribute("aria-pressed", "true");
        }
        saveAcked(set);
        document.body.dispatchEvent(new CustomEvent("afterlife:ack-changed"));
      });
      summary.appendChild(btn);
    });
  }

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
    attachAckButtons();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  // Re-attach controls after HTMX swaps content into the page.
  document.body.addEventListener("htmx:afterSwap", () => {
    attachCopyButtons();
    attachAckButtons();
  });
})();
