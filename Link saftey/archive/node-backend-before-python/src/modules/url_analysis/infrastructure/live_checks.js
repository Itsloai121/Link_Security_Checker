'use strict';

const dns = require('node:dns').promises;
const net = require('node:net');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const { createHash } = require('node:crypto');

const CHECK_META = Object.freeze({
  blocklist: ['Threat & phishing blocklist', 'Checks the submitted URL against PhishTank’s phishing database.'],
  age: ['Domain age & freshness', 'A recent registration can be a useful risk signal, but is not proof of abuse.'],
  hosting: ['Hosting IP, ASN & registry risk', 'Public routing and registry records add infrastructure context; country codes are not precise geolocation.'],
  forms: ['Login & credential forms', 'Credential prompts can be risky on unfamiliar sites.'],
  formaction: ['Form action destination', 'A form may submit credentials to a different host.'],
  brand: ['Brand impersonation & urgency', 'Brand clues and pressure language can indicate social engineering.'],
  hidden: ['Hidden elements & clickjacking', 'Hidden controls and framing policy can affect visitor safety.'],
  cloaking: ['Cloaking & bot evasion', 'Different responses to browser and crawler user agents can conceal behavior.'],
  tls: ['TLS certificate validity', 'Certificates should be valid and match the requested host.'],
  redirect: ['Open redirect & cross-domain jump', 'Redirects can move a visitor to a different destination.'],
  shortener: ['Shortener & redirect unwrapping', 'Short links hide their final destination until expanded.']
});
const SHORTENERS = new Set(['bit.ly', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'tiny.cc', 'shorturl.at', 'rb.gy', 'lnkd.in']);
const BRAND_NAMES = ['PayPal', 'Microsoft', 'Google', 'Amazon', 'Apple', 'Netflix', 'Facebook', 'Instagram', 'WhatsApp', 'Discord', 'Steam', 'Bank of America', 'Chase', 'DHL', 'FedEx'];
const MULTI_LABEL_SUFFIXES = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'co.nz', 'org.nz', 'govt.nz', 'co.jp', 'ne.jp', 'or.jp', 'co.in', 'firm.in', 'net.in', 'org.in', 'gen.in', 'com.br', 'com.cn', 'net.cn', 'org.cn', 'com.sg', 'com.my', 'com.tr', 'co.za', 'org.za', 'com.mx', 'com.tw', 'com.hk', 'com.ar', 'com.pl', 'com.ua', 'com.eg']);
const URGENCY = /\b(urgent|immediately|act now|account (?:locked|suspended|restricted)|verify (?:your )?(?:account|identity)|password expires|payment failed|unusual activity|within \d+ hours|limited time|avoid suspension)\b/i;
const MAX_PAGE_BYTES = 384 * 1024;
const HTTP_TIMEOUT_MS = 3500;
const BOOTSTRAP_URLS = Object.freeze({
  dns: 'https://data.iana.org/rdap/dns.json',
  ipv4: 'https://data.iana.org/rdap/ipv4.json',
  ipv6: 'https://data.iana.org/rdap/ipv6.json'
});
const bootstrapCache = new Map();

function updateCheck(analysis, id, status, detail) {
  const check = analysis.checks.find(item => item.id === id);
  if (check) { check.status = status; check.detail = String(detail).slice(0, 900); }
}
function markFailure(analysis, ids, reason, status = 'pending') {
  for (const id of ids) {
    const existing = analysis.checks.find(item => item.id === id);
    if (existing && existing.status === 'warning') continue;
    updateCheck(analysis, id, status, reason);
  }
}
function normalizeHost(host) { return String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, ''); }
function normalizedUrl(url) {
  const parsed = url instanceof URL ? new URL(url.href) : new URL(url);
  if (parsed.hostname.endsWith('.')) parsed.hostname = parsed.hostname.slice(0, -1);
  return parsed;
}
function policyBlocked(error) {
  return /not a public internet hostname|did not resolve exclusively to public|Only public HTTP and HTTPS|Non-standard destination ports are blocked|redirect attempted to leave HTTP\/HTTPS/i.test(String(error && error.message || ''));
}
function failureStatus(error) { return policyBlocked(error) ? 'blocked' : 'error'; }
function timeoutSignal(ms) { return AbortSignal.timeout(ms); }
function stripHtml(value) {
  return String(value || '').replace(/<!--[\s\S]*?-->/g, ' ').replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, ' ').replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;|&#160;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&quot;|&#34;/gi, '"').replace(/&#39;|&apos;/gi, "'").replace(/\s+/g, ' ').trim();
}
function attr(tag, name) {
  const found = String(tag || '').match(new RegExp('(?:^|\\s)' + name + '\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i'));
  return found ? (found[1] ?? found[2] ?? found[3] ?? '').replace(/&amp;/gi, '&').trim() : '';
}
function ipv4Number(value) { return value.split('.').reduce((n, part) => (n * 256) + Number(part), 0); }
function ipv6Number(value) {
  let input = value.toLowerCase().split('%')[0];
  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    const ipv4 = input.slice(lastColon + 1);
    if (net.isIP(ipv4) !== 4) return null;
    const n = ipv4Number(ipv4);
    input = input.slice(0, lastColon) + ':' + ((n >>> 16).toString(16)) + ':' + ((n & 0xffff).toString(16));
  }
  const halves = input.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const words = [...left, ...Array(missing).fill('0'), ...right];
  if (words.length !== 8 || words.some(part => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  return words.reduce((n, part) => (n << 16n) | BigInt(parseInt(part, 16)), 0n);
}
function isPublicIp(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const n = ipv4Number(address);
    const blocked = [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
      ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
      ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
    ];
    return !blocked.some(([base, bits]) => {
      const shift = 32 - bits;
      return Math.floor(n / (2 ** shift)) === Math.floor(ipv4Number(base) / (2 ** shift));
    });
  }
  if (family === 6) {
    const n = ipv6Number(address);
    if (n === null) return false;
    const mappedPrefix = BigInt('0xffff');
    if ((n >> 32n) === mappedPrefix) return isPublicIp(`${Number((n >> 24n) & 255n)}.${Number((n >> 16n) & 255n)}.${Number((n >> 8n) & 255n)}.${Number(n & 255n)}`);
    // Public IPv6 unicast is limited to 2000::/3 here; exceptions include documentation and special-use blocks.
    if ((n >> 125n) !== 1n) return false;
    const exclusions = [
      ['2001:db8::', 32], ['2001::', 23], ['2001:2::', 48], ['2001:10::', 28],
      ['2002::', 16], ['3fff::', 20]
    ];
    return !exclusions.some(([base, bits]) => {
      const prefix = ipv6Number(base);
      return prefix !== null && (n >> BigInt(128 - bits)) === (prefix >> BigInt(128 - bits));
    });
  }
  return false;
}
function isValidHostname(host) {
  host = normalizeHost(host);
  if (!host || host.length > 253 || host.includes('%')) return false;
  if (net.isIP(host)) return isPublicIp(host);
  if (!host.includes('.') || host === 'localhost' || host.endsWith('.localhost')) return false;
  return host.split('.').every(label => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
}
async function resolvePublic(host) {
  host = normalizeHost(host);
  if (!isValidHostname(host)) throw new Error('The destination is not a public internet hostname.');
  if (net.isIP(host)) return [{ address: host, family: net.isIP(host) }];
  const records = await Promise.race([
    dns.lookup(host, { all: true, verbatim: true }),
    new Promise((_, reject) => setTimeout(() => reject(new Error('DNS lookup timed out.')), 1800).unref())
  ]);
  if (!records.length || records.some(record => !isPublicIp(record.address))) throw new Error('The host did not resolve exclusively to public internet addresses.');
  return records;
}
function pinnedLookup(records) {
  return (_hostname, options, callback) => {
    const selected = records.find(record => !options || !options.family || record.family === options.family) || records[0];
    if (options && options.all) callback(null, records.map(record => ({ address: record.address, family: record.family })));
    else callback(null, selected.address, selected.family);
  };
}
async function requestPinned(url, { userAgent = 'LinkSafety/0.3 security-screening', maxBytes = MAX_PAGE_BYTES, timeoutMs = HTTP_TIMEOUT_MS } = {}) {
  const parsed = normalizedUrl(url);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error('Only public HTTP and HTTPS destinations are inspected.');
  if ((parsed.protocol === 'https:' && parsed.port && parsed.port !== '443') || (parsed.protocol === 'http:' && parsed.port && parsed.port !== '80')) throw new Error('Non-standard destination ports are blocked for live inspection.');
  const targetHost = normalizeHost(parsed.hostname);
  const records = await resolvePublic(targetHost);
  return new Promise((resolve, reject) => {
    const client = parsed.protocol === 'https:' ? https : http;
    let settled = false;
    const finish = (fn, value) => { if (settled) return; settled = true; clearTimeout(timer); fn(value); };
    const timer = setTimeout(() => { request.destroy(new Error('Destination request timed out.')); finish(reject, new Error('Destination request timed out.')); }, timeoutMs);
    timer.unref();
    const request = client.request({
      protocol: parsed.protocol, hostname: targetHost, port: parsed.port || undefined,
      path: parsed.pathname + parsed.search, method: 'GET', lookup: pinnedLookup(records), agent: false,
      rejectUnauthorized: true, servername: net.isIP(targetHost) ? undefined : targetHost,
      maxHeaderSize: 16 * 1024,
      headers: { 'User-Agent': userAgent, Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1', 'Accept-Encoding': 'identity', Connection: 'close' }
    }, response => {
      const chunks = []; let size = 0;
      response.on('data', chunk => {
        if (settled) return;
        const remaining = maxBytes - size;
        if (chunk.length >= remaining) {
          if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
          size = maxBytes;
          response.destroy();
          finish(resolve, { status: response.statusCode || 0, headers: response.headers, body: Buffer.concat(chunks).toString('utf8'), truncated: true, url: parsed.href });
          return;
        }
        chunks.push(chunk); size += chunk.length;
      });
      response.on('end', () => finish(resolve, { status: response.statusCode || 0, headers: response.headers, body: Buffer.concat(chunks).toString('utf8'), truncated: false, url: parsed.href }));
      response.on('error', error => { if (!settled) finish(reject, error); });
    });
    request.on('error', error => finish(reject, error));
    request.end();
  });
}
async function requestJson(url, { method = 'GET', headers = {}, body, maxBytes = 1024 * 1024, timeoutMs = 3000, fetchImpl = fetch } = {}) {
  const response = await fetchImpl(url, { method, headers: { Accept: 'application/json', 'User-Agent': 'LinkSafety/0.3', ...headers }, body, redirect: 'error', signal: timeoutSignal(timeoutMs) });
  if (!response.ok) {
    const error = new Error('Lookup service returned HTTP ' + response.status + '.');
    error.status = response.status;
    error.providerChallenge = response.headers.get('cf-mitigated') === 'challenge';
    throw error;
  }
  const reader = response.body && response.body.getReader();
  if (!reader) return {};
  const chunks = []; let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) { await reader.cancel(); throw new Error('Lookup response exceeded its size limit.'); }
    chunks.push(Buffer.from(value));
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
function providerFlag(value) { return value === true || value === 1 || /^(?:y|yes|true|1)$/i.test(String(value || '')); }
function createPhishTankLookup({ appKey = '', fetchImpl = fetch } = {}) {
  const cache = new Map();
  const inflight = new Map();
  return async function lookupPhishTank(url) {
    const digest = createHash('sha256').update(url).digest('hex');
    const cached = cache.get(digest);
    if (cached && cached.expiresAt > Date.now()) return cached.result;
    if (cached) cache.delete(digest);
    if (inflight.has(digest)) return inflight.get(digest);
    const task = (async () => {
      const parameters = new URLSearchParams({ url, format: 'json' });
      if (appKey) parameters.set('app_key', appKey);
      const data = await requestJson('https://checkurl.phishtank.com/checkurl/', {
        method: 'POST', body: parameters.toString(), maxBytes: 64 * 1024, timeoutMs: 3000, fetchImpl,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'PhishTank/LinkSafety-URL-Check/0.3'
        }
      });
      const result = data && data.results;
      if (!result || typeof result.in_database === 'undefined') throw new Error('PhishTank returned an unrecognized response.');
      let finding;
      if (providerFlag(result.in_database)) {
        const verified = providerFlag(result.verified);
        const valid = providerFlag(result.valid);
        const phishId = /^\d{1,12}$/.test(String(result.phish_id || '')) ? ' (entry ' + result.phish_id + ')' : '';
        finding = {
          status: 'warning',
          detail: verified && valid
            ? 'PhishTank has a verified, currently valid phishing match' + phishId + '. Treat this URL as unsafe.'
            : 'PhishTank has a reported match' + phishId + ', but it is not confirmed as both verified and currently valid. Review before proceeding.'
        };
      } else {
        finding = { status: 'clear', detail: 'No match was found in PhishTank at lookup time. This is not a safety guarantee.' };
      }
      cache.set(digest, { result: finding, expiresAt: Date.now() + 5 * 60 * 1000 });
      while (cache.size > 500) cache.delete(cache.keys().next().value);
      return finding;
    })();
    inflight.set(digest, task);
    try { return await task; }
    finally { inflight.delete(digest); }
  };
}
async function getBootstrap(kind) {
  if (!bootstrapCache.has(kind)) bootstrapCache.set(kind, requestJson(BOOTSTRAP_URLS[kind], { maxBytes: 1024 * 1024, timeoutMs: 3000 }));
  try { return await bootstrapCache.get(kind); }
  catch (error) { bootstrapCache.delete(kind); throw error; }
}
function prefixMatches(ip, cidr) {
  const [base, bitsText] = cidr.split('/'); const bits = Number(bitsText);
  const family = net.isIP(ip);
  if (family !== net.isIP(base)) return false;
  if (family === 4) return Math.floor(ipv4Number(ip) / (2 ** (32 - bits))) === Math.floor(ipv4Number(base) / (2 ** (32 - bits)));
  const left = ipv6Number(ip), right = ipv6Number(base);
  return left !== null && right !== null && (left >> BigInt(128 - bits)) === (right >> BigInt(128 - bits));
}
async function rdapBaseForDomain(host) {
  const bootstrap = await getBootstrap('dns');
  const labels = host.toLowerCase().split('.');
  for (let length = 1; length <= labels.length; length++) {
    const suffix = labels.slice(-length).join('.');
    const service = (bootstrap.services || []).find(entry => entry[0].some(item => item.toLowerCase() === suffix));
    if (service && service[1].length) return service[1][0];
  }
  throw new Error('No RDAP registry is published for this domain suffix.');
}
async function rdapBaseForIp(ip) {
  const kind = net.isIP(ip) === 4 ? 'ipv4' : 'ipv6';
  const bootstrap = await getBootstrap(kind);
  for (const entry of bootstrap.services || []) {
    if (entry[0].some(cidr => prefixMatches(ip, cidr))) return entry[1][0];
  }
  throw new Error('No RDAP registry is published for this address.');
}
function rdapResource(base, type, value) {
  const root = new URL(base);
  if (root.protocol !== 'https:' || root.username || root.password) throw new Error('The RDAP registry endpoint is not secure.');
  if (!root.pathname.endsWith('/')) root.pathname += '/';
  return new URL(type + '/' + encodeURIComponent(value), root).href;
}
async function lookupDomainAge(host) {
  host = normalizeHost(host);
  if (net.isIP(host)) throw new Error('Registration age is unavailable for an IP address.');
  const labels = host.toLowerCase().split('.');
  const suffixLength = MULTI_LABEL_SUFFIXES.has(labels.slice(-2).join('.')) ? 2 : 1;
  if (labels.length <= suffixLength) throw new Error('A registrable domain could not be determined.');
  const candidate = labels.slice(-(suffixLength + 1)).join('.');
  const base = await rdapBaseForDomain(candidate);
  const data = await requestJson(rdapResource(base, 'domain', candidate), { maxBytes: 256 * 1024, timeoutMs: 3000 });
  if (data.ldhName && data.ldhName.toLowerCase() !== candidate.toLowerCase()) throw new Error('The registry response did not match the queried domain.');
  const created = (data.events || []).find(event => /registration|registered/i.test(event.eventAction || ''));
  if (!created || !created.eventDate || Number.isNaN(Date.parse(created.eventDate))) throw new Error('The registry did not publish a registration date.');
  const days = Math.max(0, Math.floor((Date.now() - Date.parse(created.eventDate)) / 86400000));
  const date = new Date(created.eventDate).toISOString().slice(0, 10);
  return { days, date };
}
async function lookupOrigin(ip) {
  let reverse;
  if (net.isIP(ip) === 4) reverse = ip.split('.').reverse().join('.');
  else reverse = ipv6Number(ip).toString(16).padStart(32, '0').split('').reverse().join('.');
  const zone = net.isIP(ip) === 4 ? 'origin.asn.cymru.com' : 'origin6.asn.cymru.com';
  const answers = await Promise.race([
    dns.resolveTxt(reverse + '.' + zone),
    new Promise((_, reject) => setTimeout(() => reject(new Error('ASN lookup timed out.')), 1700).unref())
  ]);
  const row = (answers || []).flat().join('').split('|').map(value => value.trim());
  if (row.length < 5 || !/^\d+$/.test(row[0])) throw new Error('No public BGP origin record was returned.');
  return { asn: row[0], prefix: row[1], country: row[2], registry: row[3] };
}
function tlsCheck(host, records) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => { if (settled) return; settled = true; clearTimeout(timer); if (socket) socket.destroy(); fn(value); };
    let socket;
    const timer = setTimeout(() => finish(reject, Object.assign(new Error('TLS handshake timed out.'), { code: 'ETIMEDOUT' })), 3500);
    timer.unref();
    socket = tls.connect({ host, port: 443, servername: net.isIP(host) ? undefined : host, lookup: pinnedLookup(records), rejectUnauthorized: true, timeout: 3500 });
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      finish(resolve, { subject: cert.subject && (cert.subject.CN || cert.subject.O) || host, validTo: cert.valid_to || '', authorized: socket.authorized });
    });
    socket.once('timeout', () => finish(reject, Object.assign(new Error('TLS handshake timed out.'), { code: 'ETIMEDOUT' })));
    socket.once('error', error => finish(reject, error));
  });
}
function tlsErrorIsCertificate(error) {
  return /CERT|TLS_CERT|SELF_SIGNED|ALTNAME|UNABLE_TO_VERIFY|ISSUER/i.test(String(error && error.code || ''));
}
async function inspectRedirects(startUrl, budgetMs = 3000, userAgent = 'Mozilla/5.0 (compatible; LinkSafetyCheck/0.3)') {
  let current = normalizedUrl(startUrl);
  const redirects = [];
  const deadline = Date.now() + budgetMs;
  for (let hop = 0; hop <= 5; hop++) {
    const remaining = deadline - Date.now();
    if (remaining < 150) throw new Error('Destination inspection time limit reached.');
    const response = await requestPinned(current, { userAgent, maxBytes: MAX_PAGE_BYTES, timeoutMs: Math.min(HTTP_TIMEOUT_MS, remaining) });
    const location = response.headers.location;
    if (response.status >= 300 && response.status < 400 && location) {
      if (hop === 5) return { response, redirects, finalUrl: current, tooMany: true };
      const next = normalizedUrl(new URL(location, current));
      if (!['http:', 'https:'].includes(next.protocol) || next.username || next.password) throw new Error('A redirect attempted to leave HTTP/HTTPS or included credentials; it was blocked.');
      redirects.push({ from: current.hostname, to: next.hostname, crossHost: current.hostname.toLowerCase() !== next.hostname.toLowerCase() });
      current = next;
      continue;
    }
    return { response, redirects, finalUrl: current, tooMany: false };
  }
  throw new Error('Redirect limit reached.');
}
async function inspectPage(rawUrl, analysis) {
  const original = normalizedUrl(rawUrl);
  const started = Date.now();
  const result = await inspectRedirects(original, 2800);
  const { response, redirects, finalUrl } = result;
  const contentType = String(response.headers['content-type'] || '').toLowerCase();
  const attachment = /attachment/i.test(String(response.headers['content-disposition'] || '')) || /application\/(?:octet-stream|x-msdownload)/i.test(contentType);
  const isHtml = /text\/html|application\/xhtml\+xml/.test(contentType);
  const finalHost = finalUrl.hostname.toLowerCase();
  if (original.protocol === 'https:' && finalUrl.protocol === 'http:') analysis.tlsDowngrade = finalUrl.hostname;
  const shortenerHop = SHORTENERS.has(original.hostname.toLowerCase()) || redirects.some(item => SHORTENERS.has(item.from.toLowerCase()));
  if (redirects.length) {
    const crossHost = redirects.filter(item => item.crossHost);
    const existingRedirectCheck = analysis.checks.find(item => item.id === 'redirect');
    if (crossHost.length || !existingRedirectCheck || existingRedirectCheck.status !== 'warning') updateCheck(analysis, 'redirect', crossHost.length ? 'warning' : 'clear', crossHost.length
      ? 'The destination crossed to ' + [...new Set(crossHost.map(item => item.to))].slice(0, 3).join(', ') + ' during ' + redirects.length + ' redirect(s).'
      : 'The destination redirected ' + redirects.length + ' time(s) without changing host.');
    if (shortenerHop) updateCheck(analysis, 'shortener', 'clear', 'Expanded through ' + redirects.length + ' redirect(s) to ' + finalHost + '. Confirm the final host before continuing.');
  } else if (SHORTENERS.has(original.hostname.toLowerCase())) {
    updateCheck(analysis, 'shortener', 'clear', 'The short link resolved without a redirect to ' + finalHost + '.');
  } else {
    const existingRedirectCheck = analysis.checks.find(item => item.id === 'redirect');
    if (!existingRedirectCheck || existingRedirectCheck.status !== 'warning') updateCheck(analysis, 'redirect', 'clear', 'No HTTP redirect was returned for this request. Client-side JavaScript redirects are not executed.');
    updateCheck(analysis, 'shortener', 'clear', 'The host is not in the known shortener list and no redirect was returned.');
  }
  if (attachment) updateCheck(analysis, 'download', 'warning', 'The server responded with attachment or executable-style content headers. The response body was not executed or downloaded.');
  if (!isHtml || response.status < 200 || response.status >= 400 || result.tooMany) {
    const reason = result.tooMany ? 'The site exceeded the five-redirect inspection limit.' : !isHtml ? 'The destination did not return an HTML page; page-content checks were skipped.' : 'The destination returned HTTP ' + response.status + '.';
    markFailure(analysis, ['forms', 'formaction', 'brand', 'hidden', 'cloaking'], reason, 'error');
    return;
  }
  const html = response.body;
  const text = stripHtml(html);
  const forms = [...html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)];
  const credentialForms = forms.filter(form => /<input\b[^>]*\btype\s*=\s*(?:["']password["']|password\b)/i.test(form[2]));
  if (credentialForms.length) updateCheck(analysis, 'forms', 'warning', 'Found ' + credentialForms.length + ' form(s) containing password fields. This check cannot determine whether the site is legitimate.');
  else updateCheck(analysis, 'forms', 'clear', 'No password input was found in the inspected HTML. JavaScript-rendered forms are not inspected.');
  const actionIssues = [];
  for (const form of credentialForms) {
    const action = attr(form[1], 'action');
    if (!action || action.startsWith('#')) continue;
    try {
      const target = new URL(action, finalUrl);
      if (target.origin !== finalUrl.origin) actionIssues.push(target.hostname + ' (different host)');
      else if (finalUrl.protocol === 'https:' && target.protocol !== 'https:') actionIssues.push(target.hostname + ' (unencrypted submission)');
    } catch { actionIssues.push('an invalid action URL'); }
  }
  if (actionIssues.length) updateCheck(analysis, 'formaction', 'warning', 'A password form submits to ' + [...new Set(actionIssues)].slice(0, 3).join(', ') + '.');
  else updateCheck(analysis, 'formaction', 'clear', credentialForms.length ? 'Password-form actions stayed on the inspected host or used the browser default.' : 'No password form action was present in the inspected HTML.');
  const brandMentions = BRAND_NAMES.filter(name => new RegExp('\\b' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i').test(text));
  const urgency = URGENCY.test(text);
  const knownDomain = { paypal: 'paypal.com', microsoft: 'microsoft.com', google: 'google.com', amazon: 'amazon.com', apple: 'apple.com', netflix: 'netflix.com', facebook: 'facebook.com', instagram: 'instagram.com', whatsapp: 'whatsapp.com', discord: 'discord.com', steam: 'steampowered.com', 'bank of america': 'bankofamerica.com', chase: 'chase.com', dhl: 'dhl.com', fedex: 'fedex.com' };
  const mismatched = brandMentions.filter(name => {
    const domain = knownDomain[name.toLowerCase()];
    return finalHost !== domain && !finalHost.endsWith('.' + domain);
  });
  if (mismatched.length || urgency) updateCheck(analysis, 'brand', 'warning', 'Found ' + [mismatched.length ? 'brand references that do not match this host (' + mismatched.slice(0, 4).join(', ') + ')' : '', urgency ? 'urgent pressure wording' : ''].filter(Boolean).join(' and ') + '. This text-based heuristic needs human review.');
  else updateCheck(analysis, 'brand', 'clear', brandMentions.length ? 'Brand text found (' + brandMentions.join(', ') + ') without an obvious host mismatch or urgent phrase.' : urgency ? 'Urgent wording found without a recognized brand name; treat the page with care.' : 'No recognized brand mismatch or urgent pressure phrase was found in the visible HTML text.');
  const hiddenTags = [...html.matchAll(/<(?:a|button|input|iframe|div|section)\b([^>]*)>/gi)];
  let hiddenInteractive = 0, overlayLike = 0;
  for (const match of hiddenTags) {
    const attributes = match[1]; const style = attr(attributes, 'style').toLowerCase();
    const hidden = /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\D|$)/.test(style) || /\baria-hidden\s*=\s*["']true/i.test(attributes);
    const interactive = /^(?:a|button|input|iframe)/i.test(match[0]);
    if (hidden && interactive && !/^input\b/i.test(match[0]) && !/\btype\s*=\s*["']?hidden\b/i.test(attributes)) hiddenInteractive++;
    if (/position\s*:\s*(?:fixed|absolute)/.test(style) && /z-index\s*:\s*(?:[1-9]\d{2,}|\d{4,})/.test(style) && /(?:100vw|100vh|inset\s*:\s*0|top\s*:\s*0)/.test(style)) overlayLike++;
  }
  const csp = String(response.headers['content-security-policy'] || '');
  const frameProtected = /frame-ancestors\s+(?!\s*\*|\s*http:|\s*https:)[^;]+/i.test(csp) || /\bX-Frame-Options\b/i.test(String(response.headers['x-frame-options'] || ''));
  if (hiddenInteractive || overlayLike) updateCheck(analysis, 'hidden', 'warning', 'Found ' + hiddenInteractive + ' hidden interactive element(s) and ' + overlayLike + ' overlay-like element(s) in HTML/CSS. Browser rendering was not performed.');
  else if (!frameProtected) updateCheck(analysis, 'hidden', 'warning', 'No restrictive frame-ancestors or X-Frame-Options header was found. This is a framing weakness, not proof of malicious behavior.');
  else updateCheck(analysis, 'hidden', 'clear', 'No suspicious hidden controls were found and the response limits framing. This check does not render the page.');
  const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i);
  const browserTitle = stripHtml(titleMatch && titleMatch[1] || '').toLowerCase();
  try {
    const remaining = Math.max(150, 6000 - (Date.now() - started));
    const alternate = await inspectRedirects(new URL(rawUrl), Math.min(2600, remaining), 'Googlebot/2.1 (+https://www.google.com/bot.html)');
    const botTitleMatch = alternate.response.body.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i);
    const botTitle = stripHtml(botTitleMatch && botTitleMatch[1] || '').toLowerCase();
    const browserTextLength = text.length, botTextLength = stripHtml(alternate.response.body).length;
    const lengthRatio = Math.max(browserTextLength, botTextLength) / Math.max(1, Math.min(browserTextLength, botTextLength));
    if (response.status !== alternate.response.status || (browserTitle && botTitle && browserTitle !== botTitle) || lengthRatio >= 3.5) {
      updateCheck(analysis, 'cloaking', 'warning', 'Responses differed by user agent (HTTP ' + response.status + ' vs ' + alternate.response.status + (browserTitle !== botTitle ? ', page title changed' : '') + '). This may be normal personalization; scripts were not run.');
    } else updateCheck(analysis, 'cloaking', 'clear', 'Browser and crawler requests returned similar status, title, and text size. JavaScript behavior was not compared.');
  } catch {
    updateCheck(analysis, 'cloaking', 'error', 'The alternate user-agent comparison could not be completed within the safe request limits.');
  }
  if (response.truncated) {
    for (const id of ['forms', 'formaction', 'brand', 'hidden']) {
      const check = analysis.checks.find(item => item.id === id);
      if (check) check.detail += ' Only the first 384 KB of HTML was inspected.';
    }
  }
}
function deriveAssessment(analysis) {
  const warnings = analysis.checks.filter(check => check.status === 'warning').length;
  const unavailable = analysis.checks.filter(check => ['pending', 'error', 'blocked'].includes(check.status)).length;
  analysis.score = Math.max(0, 100 - warnings * 12);
  analysis.verdict = warnings >= 3 ? 'high' : warnings ? 'caution' : unavailable ? 'incomplete' : 'clear';
  analysis.summary = warnings
    ? warnings + ' potential concern(s) found.' + (unavailable ? ' ' + unavailable + ' check(s) could not be completed.' : '')
    : unavailable ? 'No obvious risk signals found in completed checks; ' + unavailable + ' check(s) could not be completed.'
      : 'No obvious risk signals found in the checks that ran. This screening is not a safety guarantee.';
  return analysis;
}
function withDeadline(promise, ms, message) {
  return Promise.race([promise, new Promise((_, reject) => setTimeout(() => reject(new Error(message)), ms).unref())]);
}
function phishTankFailureDetail(error) {
  if (error && error.providerChallenge) return 'PhishTank returned a Cloudflare security challenge (HTTP 403), so this server could not complete the phishing lookup.';
  if (error && error.status === 509) return 'PhishTank rate-limited this lookup (HTTP 509). Retry later or set the optional PHISHTANK_APP_KEY.';
  return 'PhishTank lookup could not complete (' + safeErrorCode(error) + '). Check provider access or set the optional PHISHTANK_APP_KEY.';
}

function createLiveChecks({ phishtankAppKey = '', fetchImpl = fetch } = {}) {
  const lookupPhishTank = createPhishTankLookup({ appKey: phishtankAppKey, fetchImpl });
  return async function runLiveChecks(rawUrl, analysis) {
    const original = normalizedUrl(rawUrl);
    if (!['http:', 'https:'].includes(original.protocol) || original.username || original.password) {
      markFailure(analysis, ['age', 'hosting', 'forms', 'formaction', 'brand', 'hidden', 'cloaking', 'tls', 'redirect', 'shortener'], 'Live checks only run for credential-free HTTP or HTTPS links.');
      updateCheck(analysis, 'blocklist', 'error', 'PhishTank checks only support HTTP/HTTPS links. No lookup was made.');
      return deriveAssessment(analysis);
    }

    const jobs = [];
    jobs.push(withDeadline(lookupPhishTank(original.href), 3500, 'Threat reputation lookup timed out.')
      .then(result => updateCheck(analysis, 'blocklist', result.status, result.detail))
      .catch(error => updateCheck(analysis, 'blocklist', 'error', phishTankFailureDetail(error))));

    const host = original.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    let publicRecordsPromise;
    const getPublicRecords = () => {
      if (!publicRecordsPromise) publicRecordsPromise = withDeadline(resolvePublic(host), 2200, 'DNS lookup timed out.');
      return publicRecordsPromise;
    };

    jobs.push((async () => {
      const host = original.hostname.toLowerCase().replace(/^\[|\]$/g, '');
      try {
        const age = await withDeadline(lookupDomainAge(host), 4500, 'Domain registration lookup timed out.');
        const fresh = age.days < 30;
        updateCheck(analysis, 'age', fresh ? 'warning' : 'clear', 'RDAP reports registration on ' + age.date + ' (' + age.days + ' day(s) ago).' + (fresh ? ' Very recent registration merits extra care.' : ''));
      } catch (error) { updateCheck(analysis, 'age', failureStatus(error), 'RDAP registration lookup unavailable: ' + safeErrorCode(error) + '.'); }
    })());

    jobs.push((async () => {
      try {
        const records = await getPublicRecords();
        const addresses = [...new Set(records.map(record => record.address))].slice(0, 4);
        const originResults = await Promise.allSettled(addresses.slice(0, 2).map(ip => withDeadline(lookupOrigin(ip), 1900, 'ASN lookup timed out.')));
        const origins = originResults.filter(item => item.status === 'fulfilled').map(item => ({ ip: addresses[originResults.indexOf(item)], ...item.value }));
        const rdap = await Promise.allSettled(addresses.slice(0, 2).map(async ip => {
          const base = await rdapBaseForIp(ip);
          const record = await requestJson(rdapResource(base, 'ip', ip), { maxBytes: 128 * 1024, timeoutMs: 2200 });
          return { ip, name: String(record.name || record.handle || 'network registry record').slice(0, 100), country: String(record.country || '').slice(0, 2) };
        }));
        const networks = rdap.filter(item => item.status === 'fulfilled').map(item => item.value);
        const info = addresses.map(ip => {
          const origin = origins.find(item => item.ip === ip);
          const network = networks.find(item => item.ip === ip);
          return ip + (origin ? ' (AS' + origin.asn + ', prefix ' + origin.prefix + ', registry country ' + origin.country + ')' : network ? ' (' + network.name + (network.country ? ', registry country ' + network.country : '') + ')' : '');
        });
        if (!origins.length && !networks.length) updateCheck(analysis, 'hosting', 'error', 'Resolved to public IP address(es): ' + info.join('; ') + '. ASN and registry enrichment was unavailable.');
        else updateCheck(analysis, 'hosting', 'clear', 'Resolved to public IP address(es): ' + info.join('; ') + '. Registry country is not physical geolocation; no abuse reputation was inferred.');
      } catch (error) {
        const reason = 'Live network checks were blocked or unavailable: ' + safeErrorCode(error) + '. No connection was made to the destination.';
        markFailure(analysis, ['hosting', 'forms', 'formaction', 'brand', 'hidden', 'cloaking', 'redirect', 'shortener'], reason, failureStatus(error));
      }
    })());

    if (original.protocol === 'https:') {
      jobs.push((async () => {
        try {
          const records = await getPublicRecords();
          const certificate = await withDeadline(tlsCheck(host, records), 3900, 'TLS handshake timed out.');
          updateCheck(analysis, 'tls', 'clear', 'TLS chain and hostname verified by Node. Certificate is valid through ' + new Date(certificate.validTo).toISOString().slice(0, 10) + '.');
        } catch (error) {
          updateCheck(analysis, 'tls', tlsErrorIsCertificate(error) ? 'warning' : failureStatus(error), tlsErrorIsCertificate(error) ? 'TLS certificate validation failed (' + safeErrorCode(error) + ').' : 'TLS certificate check could not complete (' + safeErrorCode(error) + ').');
        }
      })());
    } else updateCheck(analysis, 'tls', 'warning', 'The submitted URL uses HTTP and has no TLS encryption.');

    jobs.push(inspectPage(rawUrl, analysis)
      .catch(error => markFailure(analysis, ['forms', 'formaction', 'brand', 'hidden', 'cloaking', 'redirect', 'shortener'], 'Remote page inspection stopped safely: ' + safeErrorCode(error) + '.', failureStatus(error))));

    await Promise.allSettled(jobs);
    if (analysis.tlsDowngrade) {
      updateCheck(analysis, 'tls', 'warning', 'TLS was valid for the submitted host, but the page redirected to unencrypted HTTP at ' + analysis.tlsDowngrade + '.');
      delete analysis.tlsDowngrade;
    }
    return deriveAssessment(analysis);
  };
}
function safeErrorCode(error) {
  const code = error && (error.code || error.name);
  if (/^[A-Z0-9_]{2,40}$/.test(String(code || '')) && code !== 'Error') return String(code);
  const message = String(error && error.message || 'lookup unavailable').replace(/[\r\n\t]/g, ' ').trim().replace(/[.]+$/, '');
  return /^[A-Za-z0-9 .,:;()/_-]{3,100}$/.test(message) ? message : 'lookup unavailable';
}

module.exports = { createLiveChecks, createPhishTankLookup, isPublicIp, resolvePublic, deriveAssessment };
