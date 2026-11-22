// Thin client for the Unmask API. Every failure becomes an ApiError that carries the server's error contract.
export class ApiError extends Error {
  constructor(status, body, retryAfter) {
    const e = body?.error;
    super(e?.message || "The request failed.");
    this.status = status;
    this.code = e?.code || "NETWORK_ERROR";
    this.details = e?.details || [];
    this.requestId = e?.request_id || null;
    this.retryAfter = retryAfter ? Number(retryAfter) : null;
  }
}

async function request(path, { method = "GET", body } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method, cache: "no-store", credentials: "same-origin",
      headers: { Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, null, null);
  }
  if (res.status === 204) return null;
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON error page */ }
  if (!res.ok) throw new ApiError(res.status, data, res.headers.get("Retry-After"));
  return data;
}

export const api = {
  submit: (url, displayText) => request("/api/v1/scans", { method: "POST", body: { url, display_text: displayText || null } }),
  getScan: (id) => request(`/api/v1/scans/${encodeURIComponent(id)}`),
  deleteScan: (id) => request(`/api/v1/scans/${encodeURIComponent(id)}`, { method: "DELETE" }),
  checks: () => request("/api/v1/checks"),
};
