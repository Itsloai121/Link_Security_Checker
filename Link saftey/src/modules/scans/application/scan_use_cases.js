const { randomUUID, randomBytes, createHash } = require('node:crypto');
const { AppError } = require('../../../shared/app_error');
const { assertScanRecord } = require('../domain/scan_record');
const { assertScanRepository } = require('../ports/scan_repository');
const { assertLiveCheckPort } = require('../../url_analysis/ports/external_check_ports');
const ANALYZER_VERSION = 'url-live-v2';

function sha256(value) { return createHash('sha256').update(value, 'utf8').digest('hex'); }
function createScanUseCase({ analyzeUrl, liveCheckPort, scanRepository }) {
  assertScanRepository(scanRepository);
  if (liveCheckPort) assertLiveCheckPort(liveCheckPort);
  return async function createScan(rawUrl) {
    const analysis = analyzeUrl(rawUrl);
    if (analysis.error) throw AppError.invalid(analysis.error);
    if (liveCheckPort) await liveCheckPort.run(rawUrl, analysis);
    let parsed;
    try { parsed = new URL(rawUrl); } catch { throw AppError.invalid('Enter a complete URL to analyze.'); }
    const id = randomUUID();
    const accessToken = randomBytes(32).toString('hex');
    const accessTokenHash = sha256(accessToken);
    const createdAt = new Date().toISOString();
    const scan = {
      id, host: analysis.host || '', scheme: parsed.protocol, score: analysis.score,
      verdict: analysis.verdict, summary: analysis.summary, analyzerVersion: ANALYZER_VERSION,
      createdAt, checks: analysis.checks
    };
    assertScanRecord(scan);
    await scanRepository.create(scan, accessTokenHash);
    return { ...analysis, scan_id: id, access_token: accessToken, created_at: createdAt };
  };
}
function getScanUseCase({ scanRepository }) {
  assertScanRepository(scanRepository);
  return async function getScan(id, bearerToken) {
    const scan = await scanRepository.findById(id);
    if (!scan) throw AppError.notFound();
    if (typeof bearerToken !== 'string' || !/^[a-f0-9]{64}$/i.test(bearerToken)) throw AppError.unauthorized();
    const expected = Buffer.from(scan.access_token_hash, 'hex');
    const actual = Buffer.from(sha256(bearerToken), 'hex');
    const { timingSafeEqual } = require('node:crypto');
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw AppError.unauthorized();
    const { access_token_hash, ...publicScan } = scan;
    return publicScan;
  };
}
module.exports = { createScanUseCase, getScanUseCase };


