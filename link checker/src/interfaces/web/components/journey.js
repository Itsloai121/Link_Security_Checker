import { h } from "./dom.js";

const HOP_KEY = /^Hop \d+$/;

/** Draws the redirect chain from the redirect_chain test's facts. Hidden when the link does not redirect. */
export function renderJourney(section, list, scan) {
  const chain = scan.checks.find((c) => c.id === "redirect_chain");
  const hops = (chain?.facts || []).filter((f) => HOP_KEY.test(f.key));
  if (hops.length < 2) { section.hidden = true; return; }
  section.hidden = false;
  list.replaceChildren(...hops.map((hop, i) => {
    const m = hop.value.match(/^(\S+)\s+(?:\(([^)]+)\)\s+)?([\s\S]*)$/) || [null, "—", "", hop.value];
    const last = i === hops.length - 1;
    const meta = [`Hop ${i + 1}`, m[1] !== "—" ? `status ${m[1]}` : "no answer", m[2] || null, i === 0 ? "the link you submitted" : null, last ? "where it lands" : null].filter(Boolean).join(" · ");
    return h("li", { class: `hop${last ? " hop--final" : ""}` }, h("span", { class: "hop__meta", text: meta }), h("span", { class: "hop__url", text: m[3], dir: "ltr" }));
  }));
}
