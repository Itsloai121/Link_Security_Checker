import { h } from "./dom.js";

const ORDER = ["address", "journey", "reputation", "behavior"];

/** The 20 tests grouped by where they look; the list comes from the API so there is one source of truth. */
export function renderTestsOverview(container, catalog) {
  container.replaceChildren(...ORDER.map((cat) => h("article", { class: "tests__group glass float", "data-reveal": "" },
    h("h3", { text: catalog.categories[cat] }),
    h("ul", {}, catalog.checks.filter((c) => c.category === cat).map((c) => h("li", { text: c.title }))))));
}
