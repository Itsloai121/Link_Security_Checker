const { domainToUnicode } = require('node:url');

const analyzeUrl = (urlText) => {
  let parsed;
  try { parsed = new URL(urlText); } catch { return { error: 'Enter a complete URL such as https://example.com/path.' }; }
  if (parsed.hostname.endsWith('.')) parsed.hostname = parsed.hostname.slice(0, -1);
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const unicodeHost = domainToUnicode(host);
  const labels = host.split('.');
  const decoded = (() => { try { return decodeURIComponent(urlText); } catch { return urlText; } })();
  const risk = [];
  const result = [];
  const add = (id, title, description, status, detail) => result.push({ id, title, description, status, detail });
  const flag = (id, title, description, detail) => { risk.push(id); add(id, title, description, 'warning', detail); };
  const clear = (id, title, description, detail) => add(id, title, description, 'clear', detail);
  const pending = (id, title, description, detail) => add(id, title, description, 'pending', detail);

  if (parsed.username || parsed.password || urlText.includes('@')) flag('userinfo', 'User-info (@) masking', 'The @ separator can make decoy text look like the destination host.', 'This URL contains user-info or an @ sign. The actual host is shown as ' + host + '.');
  else clear('userinfo', 'User-info (@) masking', 'The @ separator can make decoy text look like the destination host.', 'No user-info section or @ sign was found.');
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') flag('scheme', 'Dangerous scheme & protocol', 'Only ordinary web links use HTTP or HTTPS.', 'This link uses ' + parsed.protocol + '.');
  else clear('scheme', 'Dangerous scheme & protocol', 'Only ordinary web links use HTTP or HTTPS.', 'The protocol is ' + parsed.protocol.slice(0, -1) + '.');
  if (parsed.protocol === 'https:') clear('https', 'HTTPS scheme', 'HTTPS encrypts traffic in transit, but does not prove a site is trustworthy.', 'The URL uses HTTPS. Certificate chain and hostname are checked separately below.');
  else flag('https', 'HTTPS scheme', 'HTTPS encrypts traffic in transit, but does not prove a site is trustworthy.', 'The URL does not use HTTPS.');
  if (/^xn--/i.test(host) || unicodeHost !== host) flag('homograph', 'Homograph & punycode', 'Internationalized domains can use lookalike characters.', 'This host has an internationalized/punycode representation: ' + unicodeHost + '.');
  else clear('homograph', 'Homograph & punycode', 'Internationalized domains can use lookalike characters.', 'No punycode label was detected. Mixed-script lookalikes need deeper analysis.');
  const brand = /(paypa[il1]|micros[o0]ft|g[o0]{2}gle|amaz[o0]n|apple|netflix|faceb[o0]{2}k)/i;
  const suspiciousBrand = labels.slice(0, -1).join('.').match(brand) || parsed.pathname.match(/(paypa[il1]|micros[o0]ft|g[o0]{2}gle|amaz[o0]n)/i);
  if (suspiciousBrand && !/(paypal\.com|microsoft\.com|google\.com|amazon\.com|apple\.com|netflix\.com|facebook\.com)$/i.test(host)) flag('lookalike', 'Lookalike & typosquatting', 'Brand-like spellings on unrelated domains may impersonate a trusted service.', 'A common brand-like string appears in this host or path. Confirm the registrable domain independently.');
  else clear('lookalike', 'Lookalike & typosquatting', 'Brand-like spellings on unrelated domains may impersonate a trusted service.', 'No obvious match to the small built-in brand heuristic was found.');
  if (labels.length >= 5 || labels.slice(0, -2).some(x => /^(secure|login|account|verify|signin|bank)$/i.test(x))) flag('subdomain', 'Subdomain spoofing', 'A trusted-looking word in a subdomain does not make the root domain trusted.', 'The host has ' + labels.length + ' labels or a security-themed subdomain. Root-domain reputation is not available.');
  else clear('subdomain', 'Subdomain spoofing', 'A trusted-looking word in a subdomain does not make the root domain trusted.', 'No unusually deep or obvious security-themed subdomain was found.');
  if (parsed.port && !(['80', '443'].includes(parsed.port))) flag('portpath', 'Port & path anomaly', 'Unusual ports and misleading paths can hide a service or download.', 'The URL specifies non-standard port ' + parsed.port + '.');
  else if (/\.(pdf|docx?|xlsx?|txt)(\/|$)/i.test(parsed.pathname) && !/\.(pdf|docx?|xlsx?|txt)$/i.test(parsed.pathname)) flag('portpath', 'Port & path anomaly', 'Unusual ports and misleading paths can hide a service or download.', 'A document-like extension appears before more path segments.');
  else clear('portpath', 'Port & path anomaly', 'Unusual ports and misleading paths can hide a service or download.', 'No non-standard port or obvious misleading document path was found.');
  const escapes = (urlText.match(/%[0-9a-f]{2}/gi) || []).length;
  if (escapes >= 4 || /(?:0x[0-9a-f]{2,}|\\u[0-9a-f]{4}|[a-z0-9+/]{28,}={0,2})/i.test(urlText)) flag('obfuscation', 'URL obfuscation & encoding', 'Heavy encoding can conceal characters or destinations.', 'Found ' + escapes + ' percent-encoded bytes or a string matching a common encoded payload pattern.');
  else clear('obfuscation', 'URL obfuscation & encoding', 'Heavy encoding can conceal characters or destinations.', 'No heavy percent-encoding or obvious encoded blob was found.');
  if (/\.(exe|msi|apk|iso|zip|js|vbs|scr|bat|dll)(?:$|[?#])/i.test(parsed.pathname)) flag('download', 'Auto-download & file trigger', 'Executable and script downloads carry elevated risk.', 'The path ends with a potentially executable or archive file extension.');
  else clear('download', 'Auto-download & file trigger', 'Executable and script downloads carry elevated risk.', 'No risky file extension is visible in the URL path.');
  if (/(https?:\/\/|%2f%2f).*(?:url|redirect|return|next|continue)=/i.test(urlText)) flag('redirect', 'Open redirect & cross-domain jump', 'Redirect parameters can send users to a different host.', 'A redirect-like parameter and destination pattern is present; it has not been followed.');
  else clear('redirect', 'Open redirect & cross-domain jump', 'Redirect parameters can send users to a different host.', 'No obvious redirect parameter was found. Redirect behavior was not followed.');

  const p = parsed.searchParams;
  const shortHosts = /^(bit\.ly|t\.co|tinyurl\.com|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rebrand\.ly)$/i;
  if (shortHosts.test(host)) flag('shortener', 'Shortener & redirect unwrapping', 'Short links hide their final destination until expanded.', 'This is a known shortener domain. Destination expansion is not enabled.');
  else clear('shortener', 'Shortener & redirect unwrapping', 'Short links hide their final destination until expanded.', 'The host is not in the built-in shortener list; no redirect requests were made.');
  if (parsed.search || parsed.hash) clear('display', 'Display text vs destination', 'A link label can differ from the real URL destination.', 'The destination can be inspected as ' + parsed.origin + '. A displayed label was not supplied.');
  else clear('display', 'Display text vs destination', 'A link label can differ from the real URL destination.', 'No display label was supplied for comparison.');
  for (const [id, title, description, detail] of [
    ['blocklist','Threat & phishing blocklist','Checks the submitted URL against PhishTank’s phishing database.','Checking the exact submitted URL against PhishTank.'],
    ['age','Domain age & freshness','A recent registration can be a useful risk signal, but is not proof of abuse.','Checking domain registration data with RDAP.'],
    ['hosting','Hosting IP, ASN & registry risk','Public routing and registry records add infrastructure context; country codes are not precise geolocation.','Checking public DNS, BGP origin, and registry records.'],
    ['forms','Login & credential forms','Credential prompts can be risky on unfamiliar sites.','Inspecting the returned HTML for password fields.'],
    ['formaction','Form action destination','A form may submit credentials to a different host.','Comparing password-form actions with the inspected page origin.'],
    ['brand','Brand impersonation & urgency','Brand clues and pressure language can indicate social engineering.','Checking visible page text for brand mismatch and urgency signals.'],
    ['hidden','Hidden elements & clickjacking','Hidden controls and framing policy can affect visitor safety.','Checking HTML/CSS signals and framing response headers.'],
    ['cloaking','Cloaking & bot evasion','Different responses to browser and crawler user agents can conceal behavior.','Comparing bounded responses from two user agents.'],
    ['tls','TLS certificate validity','Certificates should be valid and match the requested host.','Verifying the TLS chain and requested hostname.']
  ]) pending(id, title, description, detail);
  return { input: urlText, normalized: parsed.href, host, score: Math.max(0, 100 - risk.length * 12), verdict: risk.length ? (risk.length >= 3 ? 'high' : 'caution') : 'incomplete', checks: result, summary: risk.length ? risk.length + ' potential concern(s) found.' : 'No obvious URL-structure concerns found. Several live checks are unavailable.' };
};

module.exports = { analyzeUrl };

