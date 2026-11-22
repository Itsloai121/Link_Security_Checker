import { ApiError, api } from "../api_client/client.js";

/** Poll a scan until it finishes, delivering every partial result as soon as it exists. Returns a stop() function. */
export function watchScan(id, { onUpdate, onError, intervalMs = 900, timeoutMs = 150_000 }) {
  let stopped = false, timer = 0, failures = 0;
  const started = Date.now();
  async function poll() {
    if (stopped) return;
    let wait = intervalMs;
    try {
      const scan = await api.getScan(id);
      failures = 0;
      onUpdate(scan);
      if (scan.status === "completed" || scan.status === "failed") return;
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) return onError(err);
      if (err instanceof ApiError && err.status === 429) wait = (err.retryAfter || 5) * 1000;
      else if (++failures >= 5) return onError(err);
      else wait = intervalMs * (1 + failures);
    }
    if (Date.now() - started > timeoutMs) return onError(new Error("timeout"));
    timer = setTimeout(poll, wait);
  }
  poll();
  return () => { stopped = true; clearTimeout(timer); };
}
