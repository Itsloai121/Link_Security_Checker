const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { AppError } = require('../../shared/app_error');
const { validateCreateScanBody } = require('./schemas/scan_request');
const { FixedWindowRateLimiter, applySecurityHeaders, clientRateKey } = require('./security');
const STATIC_FILES = Object.freeze({ '/': 'index.html', '/index.html': 'index.html', '/styles.css': 'styles.css', '/app.js': 'app.js' });

function createHttpServer({ config, logger, scanRepository, createScan, getScan }) {
  const limiter = new FixedWindowRateLimiter({ windowMs: config.rateLimitWindowMs, maxRequests: config.rateLimitMaxRequests });
  return require('node:http').createServer(async (req, res) => {
    const requestId = randomUUID();
    const started = process.hrtime.bigint();
    applySecurityHeaders(res, config);
    res.setHeader('X-Request-Id', requestId);
    let route = 'other';
    try {
      const pathname = new URL(req.url, 'http://local.invalid').pathname;
      route = routeLabel(req.method, pathname);
      if ((pathname.startsWith('/api/') || pathname.startsWith('/health/')) && (req.method === 'POST' || req.method === 'GET')) limiter.consume(clientRateKey(req));
      if (req.method === 'GET' && pathname === '/health/live') return json(res, 200, { status: 'ok', request_id: requestId });
      if (req.method === 'GET' && pathname === '/health/ready') {
        await scanRepository.ping();
        return json(res, 200, { status: 'ready', request_id: requestId });
      }
      if (req.method === 'POST' && (pathname === '/api/analyze' || pathname === '/api/v1/scans')) {
        const legacy = pathname === '/api/analyze';
        requireJson(req);
        const body = await readJson(req, config.maxBodyBytes);
        const url = validateCreateScanBody(body, config.maxUrlLength);
        const report = await createScan(url);
        const { input, ...safeResponse } = report;
        return json(res, legacy ? 200 : 201, { ...safeResponse, request_id: requestId });
      }
      const reportMatch = pathname.match(/^\/api\/v1\/scans\/([0-9a-f-]{36})$/i);
      if (req.method === 'GET' && reportMatch) {
        const match = (req.headers.authorization || '').match(/^Bearer ([a-f0-9]{64})$/i);
        const report = await getScan(reportMatch[1], match && match[1]);
        return json(res, 200, { ...report, request_id: requestId });
      }
      if (req.method === 'GET' && STATIC_FILES[pathname]) return serveStatic(res, config.publicDirectory, STATIC_FILES[pathname]);
      if (req.method !== 'GET' && req.method !== 'POST' && req.method !== 'HEAD') throw new AppError('METHOD_NOT_ALLOWED', 'Method not allowed.', 405);
      throw AppError.notFound();
    } catch (error) {
      const appError = error instanceof AppError ? error : new AppError('INTERNAL_ERROR', 'An unexpected server error occurred.', 500);
      if (!(error instanceof AppError)) logger.error('request_failed', { request_id: requestId, route, error_name: error && error.name });
      const message = appError.status >= 500 ? 'An unexpected server error occurred.' : appError.message;
      const legacy = route === 'analyze_legacy';
      if (res.headersSent) { res.destroy(); return; }
      if (appError.status === 413) res.setHeader('Connection', 'close');
      json(res, appError.status, legacy ? { error: message, request_id: requestId } : { error: { code: appError.code, message, request_id: requestId, details: appError.details || [] } });
    } finally {
      const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
      logger.info('http_request', { request_id: requestId, route, method: req.method, duration_ms: Math.round(durationMs), status: res.statusCode });
    }
  });
}
function routeLabel(method, pathname) {
  if (pathname === '/api/analyze') return 'analyze_legacy';
  if (pathname === '/api/v1/scans') return 'create_scan';
  if (/^\/api\/v1\/scans\//.test(pathname)) return 'get_scan';
  if (pathname.startsWith('/health/')) return 'health';
  if (STATIC_FILES[pathname]) return 'web_asset';
  return 'other';
}
function requireJson(req) {
  const type = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  if (type !== 'application/json') throw new AppError('UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json.', 415);
}
async function readJson(req, maxBytes) {
  const declared = Number(req.headers['content-length'] || 0);
  if (declared > maxBytes) throw AppError.tooLarge();
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) { req.pause(); throw AppError.tooLarge(); }
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw AppError.invalid('Request body must contain valid JSON.'); }
}
function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function serveStatic(res, directory, filename) {
  const target = path.join(directory, filename);
  const contentTypes = { 'index.html': 'text/html; charset=utf-8', 'styles.css': 'text/css; charset=utf-8', 'app.js': 'text/javascript; charset=utf-8' };
  const data = fs.readFileSync(target);
  res.writeHead(200, { 'Content-Type': contentTypes[filename], 'Content-Length': data.length });
  res.end(data);
}
module.exports = { createHttpServer };
