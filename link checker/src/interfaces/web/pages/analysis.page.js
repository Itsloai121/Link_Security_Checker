import { ApiError, api } from "/static/api_client/client.js";
import { initPage, initReveal } from "/static/components/boot.js";
import { createCard, fillCard } from "/static/components/check-card.js";
import { h } from "/static/components/dom.js";
import { renderJourney } from "/static/components/journey.js";
import { createVerdictRenderer } from "/static/components/verdict-panel.js";
import { forgetScan, lastScan } from "/static/state/session.js";
import { watchScan } from "/static/state/scan-store.js";

initPage();
const main = document.getElementById("main");
const id = new URLSearchParams(location.search).get("id") || lastScan();

function showEmpty(title, text) {
  document.title = `${title} · Unmask`;
  main.setAttribute("aria-busy", "false");
  main.replaceChildren(h("section", { class: "report__empty glass glass--frost" },
    h("h1", { class: "verdict__headline", text: title }), h("p", { class: "lede", text }),
    h("a", { class: "btn btn--primary float", href: "/process", text: "Check a link" })));
}

async function run() {
  if (!id) return showEmpty("No report here", "Open a report from the link we gave you right after a check, or start a new check.");
  const verdict = createVerdictRenderer(document.getElementById("verdict"));
  const grid = document.getElementById("checks");
  const filters = document.querySelectorAll(".filter");
  const cards = new Map(), filled = new Map();
  let filter = "all", lastScanData = null;

  let catalog;
  try { catalog = await api.checks(); } catch { return showEmpty("We could not load the report", "Please refresh the page in a moment."); }
  for (const spec of catalog.checks) { const card = createCard(spec); cards.set(spec.id, card); grid.append(card); }
  initReveal();

  const group = (s) => (s === "notice" || s === "warning" || s === "danger" ? "flagged" : s);
  function applyFilter() {
    const tally = { all: cards.size, flagged: 0, clear: 0, unavailable: 0 };
    for (const [cid, card] of cards) {
      const s = card.dataset.status;
      if (s !== "pending") tally[group(s)] += 1;
      card.hidden = !(filter === "all" || group(s) === filter);
    }
    for (const key of Object.keys(tally)) document.getElementById(`f-${key}`).textContent = tally[key];
    filters.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.filter === filter)));
  }
  filters.forEach((b) => b.addEventListener("click", () => { filter = b.dataset.filter; applyFilter(); }));

  function update(scan) {
    lastScanData = scan;
    verdict(scan);
    for (const result of scan.checks) {
      if (filled.get(result.id) === result.status + result.summary) continue;
      filled.set(result.id, result.status + result.summary);
      const card = cards.get(result.id);
      if (card) fillCard(card, result);
    }
    renderJourney(document.getElementById("journey"), document.getElementById("journey-list"), scan);
    applyFilter();
    if (scan.status === "completed" || scan.status === "failed") {
      main.setAttribute("aria-busy", "false");
      const when = new Date(scan.expires_at);
      document.getElementById("expiry-note").textContent = `This report is kept until ${when.toLocaleString()} and then deleted automatically.`;
    }
  }

  const stop = watchScan(id, {
    onUpdate: update,
    onError: (err) => {
      if (err instanceof ApiError && err.status === 404) { forgetScan(); showEmpty("This report is gone", "Reports are deleted after 24 hours, or when their owner deletes them."); }
      else document.getElementById("page-error").textContent = "We lost contact with the server while checking this link. Reload the page to keep watching.";
    },
  });
  window.addEventListener("pagehide", stop);

  const del = document.getElementById("delete-btn");
  let armed = 0;
  del.addEventListener("click", async () => {
    if (!armed) { del.textContent = "Click again to confirm"; armed = setTimeout(() => { armed = 0; del.textContent = "Delete this report now"; }, 4000); return; }
    clearTimeout(armed); del.disabled = true; del.textContent = "Deleting…"; stop();
    try { await api.deleteScan(id); forgetScan(); showEmpty("Report deleted", "Nothing about this check is stored any more."); }
    catch { del.disabled = false; del.textContent = "Delete this report now"; document.getElementById("page-error").textContent = "The report could not be deleted. Please try again."; }
  });
}
run();
