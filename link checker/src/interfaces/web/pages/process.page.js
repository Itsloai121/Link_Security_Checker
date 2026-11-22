import { ApiError, api } from "/static/api_client/client.js";
import { initPage } from "/static/components/boot.js";
import { rememberScan } from "/static/state/session.js";

initPage();
const form = document.getElementById("check-form");
const input = document.getElementById("url");
const label = document.getElementById("label");
const button = document.getElementById("submit");
const error = document.getElementById("url-error");

function message(err) {
  if (!(err instanceof ApiError) || err.status === 0) return "We could not reach the server. Check your connection and try again.";
  if (err.status === 422 && err.details[0]) return err.details[0].issue;
  if (err.status === 429) return `You are checking links very quickly. Please try again in ${err.retryAfter || 30} seconds.`;
  if (err.status === 503) return "The service is busy right now. Please try again in a moment.";
  return `${err.message}${err.requestId ? ` (reference ${err.requestId})` : ""}`;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  error.textContent = "";
  input.removeAttribute("aria-invalid");
  const url = input.value.trim();
  if (!url) { error.textContent = "Enter the link you want to check."; input.setAttribute("aria-invalid", "true"); input.focus(); return; }
  button.disabled = true;
  button.textContent = "Starting…";
  try {
    const scan = await api.submit(url, label.value.trim());
    rememberScan(scan.id);
    location.assign(`/analysis?id=${encodeURIComponent(scan.id)}`);
  } catch (err) {
    error.textContent = message(err);
    input.setAttribute("aria-invalid", "true");
    button.disabled = false;
    button.textContent = "Check link";
  }
});

for (const chip of document.querySelectorAll(".example")) {
  chip.addEventListener("click", () => { input.value = chip.dataset.url; input.focus(); error.textContent = ""; input.removeAttribute("aria-invalid"); });
}
