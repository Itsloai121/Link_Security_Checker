const ALLOWED_VERDICTS = new Set(['high', 'caution', 'incomplete', 'clear']);
const ALLOWED_CHECK_STATES = new Set(['clear', 'warning', 'pending', 'error', 'blocked']);
function assertScanRecord(scan) {
  if (!scan || typeof scan.id !== 'string' || !scan.id || typeof scan.host !== 'string' || typeof scan.scheme !== 'string') throw new TypeError('Scan identity, host, and scheme are required.');
  if (!Number.isInteger(scan.score) || scan.score < 0 || scan.score > 100) throw new TypeError('Scan score must be an integer from 0 to 100.');
  if (!ALLOWED_VERDICTS.has(scan.verdict) || !Array.isArray(scan.checks)) throw new TypeError('Scan verdict or check list is invalid.');
  const seen = new Set();
  for (const check of scan.checks) {
    if (!check || typeof check.id !== 'string' || !check.id || seen.has(check.id) || !ALLOWED_CHECK_STATES.has(check.status)) throw new TypeError('Scan checks must have unique IDs and an allowed status.');
    if (['title', 'description', 'detail'].some(field => typeof check[field] !== 'string')) throw new TypeError('Scan check text fields must be strings.');
    seen.add(check.id);
  }
  return scan;
}
module.exports = { assertScanRecord };
