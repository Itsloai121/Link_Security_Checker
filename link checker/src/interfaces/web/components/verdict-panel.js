import { h } from "./dom.js";
import { safeText } from "./safe-text.js";
import { typeNow } from "./typing.js";

const KICKER = { pending: "Checking this link", completed: "Verdict", failed: "Something went wrong" };

function hostOf(url) {
  try { return new URL(url).host; } catch { return url; }
}

export function createVerdictRenderer(root) {
  const $ = (id) => root.querySelector(id);
  const el = { kicker: $("#verdict-kicker"), headline: $("#verdict-headline"), url: $("#verdict-url"), lands: $("#verdict-lands"), reasons: $("#verdict-reasons"),
    score: $("#meter-score"), fill: $("#meter-fill"), progress: $("#progress"), pfill: $("#progress-fill"), ptext: $("#progress-text"), counts: $("#counts"),
    flagged: $("#count-flagged"), clear: $("#count-clear"), unverified: $("#count-unverified") };
  let lastHeadline = "";

  return function render(scan) {
    const done = scan.status === "completed", failed = scan.status === "failed";
    root.dataset.verdict = failed ? "inconclusive" : scan.verdict || "pending";
    const headline = failed ? "We could not finish this check" : done ? scan.headline : "Checking…";
    if (headline !== lastHeadline) { typeNow(el.headline, headline, 30); lastHeadline = headline; }
    el.kicker.textContent = KICKER[failed ? "failed" : done ? "completed" : "pending"];
    el.url.textContent = safeText(scan.submitted_input);
    if (scan.final_url && scan.final_url !== scan.normalized_url) {
      el.lands.replaceChildren("It lands on ", h("strong", { text: hostOf(scan.final_url) }));
      el.lands.hidden = false;
    } else el.lands.hidden = true;
    el.reasons.replaceChildren(...(scan.reasons || []).map((r) => h("li", { text: r, dir: "auto" })));
    el.score.textContent = done ? String(scan.risk_score) : "–";
    el.fill.style.setProperty("--score", done ? scan.risk_score : 0);
    el.progress.hidden = done || failed;
    el.pfill.style.setProperty("--done", scan.progress.done);
    el.ptext.textContent = scan.progress.done === 0 ? "Starting the tests…" : `${scan.progress.done} of ${scan.progress.total} tests done`;
    el.counts.hidden = !done;
    if (done) {
      el.flagged.textContent = scan.counts.flagged; el.clear.textContent = scan.counts.clear; el.unverified.textContent = scan.counts.unverified;
    }
    if (failed) { el.reasons.replaceChildren(h("li", { text: "Something went wrong on our side while analysing this link. Please try again in a moment." })); }
    document.title = `${headline} · Unmask`;
  };
}
