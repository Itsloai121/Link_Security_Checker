const { AppError } = require('../../shared/app_error');
class FixedWindowRateLimiter {
  constructor({ windowMs, maxRequests }) { this.windowMs = windowMs; this.maxRequests = maxRequests; this.entries = new Map(); }
  consume(key) {
    const now = Date.now();
    let entry = this.entries.get(key);
    if (!entry || now - entry.start >= this.windowMs) { entry = { start: now, count: 0 }; this.entries.set(key, entry); }
    entry.count += 1;
    if (this.entries.size > 5000) for (const [candidate, value] of this.entries) if (now - value.start >= this.windowMs) this.entries.delete(candidate);
    if (entry.count > this.maxRequests) throw AppError.rateLimited();
  }
}
function applySecurityHeaders(res, { environment }) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('X-DNS-Prefetch-Control', 'off');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  res.setHeader('Cache-Control', 'no-store');
  if (environment === 'production') res.setHeader('Strict-Transport-Security', 'max-age=31536000');
}
function clientRateKey(req) {
  // Deliberately ignore X-Forwarded-For; configure a trusted edge limiter before proxy deployments.
  return req.socket.remoteAddress || 'unknown';
}
module.exports = { FixedWindowRateLimiter, applySecurityHeaders, clientRateKey };

