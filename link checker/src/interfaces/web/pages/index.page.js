import { api } from "/static/api_client/client.js";
import { initPage, initReveal } from "/static/components/boot.js";
import { renderTestsOverview } from "/static/components/tests-overview.js";

initPage();
api.checks()
  .then((catalog) => { renderTestsOverview(document.getElementById("tests-grid"), catalog); initReveal(); })
  .catch(() => { document.getElementById("tests-error").hidden = false; });
