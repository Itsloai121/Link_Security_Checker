import { h } from "./dom.js";
import { typeNow } from "./typing.js";

export const STATUS_LABEL = { clear: "Clear", notice: "Notice", warning: "Warning", danger: "Danger", unavailable: "Not verified", pending: "Checking…" };
const SEVERITY_LABEL = { info: "Info", low: "Low", medium: "Medium", high: "High", critical: "Critical" };
const HOP_KEY = /^Hop \d+$/;

/** A card in its "pending" state: title and explanation are known up front, the result arrives later. */
export function createCard(spec) {
  return h("article", { class: "check float", "data-reveal": "", dataset: { status: "pending", category: spec.category, id: spec.id } },
    h("div", { class: "check__head" },
      h("span", { class: "chip", dataset: { status: "pending" }, text: STATUS_LABEL.pending }),
      h("span", { class: "check__cat", text: spec.category_label })),
    h("h3", { class: "check__title", text: spec.title }),
    h("p", { class: "check__summary", text: "Running this test…" }),
    h("p", { class: "check__explain" }, h("strong", { text: "What this test does. " }), spec.explanation),
    h("div", { class: "check__more" }));
}

const pairs = (cls, items) => h("dl", { class: cls }, items.flatMap((kv) => [h("dt", { text: kv.key }), h("dd", { text: kv.value, dir: "auto" })]));

/** Fill a card with a finished result. Every string goes in through textContent (see dom.js). */
export function fillCard(card, result) {
  card.dataset.status = result.status;
  const chip = card.querySelector(".chip");
  chip.dataset.status = result.status;
  chip.textContent = STATUS_LABEL[result.status] ?? result.status;
  const summary = card.querySelector(".check__summary");
  summary.setAttribute("dir", "auto");
  typeNow(summary, result.summary, 14);

  const facts = (result.facts || []).filter((f) => !HOP_KEY.test(f.key));
  const findings = result.findings || [];
  const more = card.querySelector(".check__more");
  if (!findings.length && !facts.length && !result.limitation) { more.replaceChildren(); return; }
  const shown = findings.filter((f) => f.severity !== "info").length || findings.length;
  more.replaceChildren(h("details", { class: "check__details", open: result.status === "danger" },
    h("summary", { text: shown ? `Evidence (${shown})` : "Details" }),
    findings.length ? h("ul", { class: "findings" }, findings.map((f) =>
      h("li", { class: "finding", dataset: { severity: f.severity } },
        h("span", { class: "finding__sev", text: SEVERITY_LABEL[f.severity] || f.severity }),
        h("p", { text: f.message, dir: "auto" }),
        f.evidence?.length ? pairs("evidence", f.evidence) : null))) : null,
    facts.length ? pairs("facts", facts) : null,
    result.limitation ? h("p", { class: "limit", text: result.limitation }) : null));
}
