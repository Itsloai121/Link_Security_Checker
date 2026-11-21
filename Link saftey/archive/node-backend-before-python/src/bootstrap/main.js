const { createHttpServer } = require('../interfaces/api/http_server');
const { createScanUseCase, getScanUseCase } = require('../modules/scans/application/scan_use_cases');
const { SqliteScanRepository } = require('../modules/scans/infrastructure/sqlite_scan_repository');
const { analyzeUrl } = require('../modules/url_analysis/domain/analyze_url');
const { createLiveChecks } = require('../modules/url_analysis/infrastructure/live_checks');
const { openDatabase, applyMigrations } = require('../infrastructure/persistence/sqlite_database');
const { createLogger } = require('../infrastructure/observability/logger');
const { loadConfig } = require('../../config/load_config');

function start() {
  const config = loadConfig();
  const logger = createLogger(config);
  const db = openDatabase(config);
  applyMigrations(db, config.migrationDirectory);
  const scanRepository = new SqliteScanRepository(db);
  const liveCheckPort = Object.freeze({ run: createLiveChecks({ phishtankAppKey: config.phishtankAppKey }) });
  const createScan = createScanUseCase({ analyzeUrl, liveCheckPort, scanRepository });
  const getScan = getScanUseCase({ scanRepository });
  const server = createHttpServer({ config, logger, scanRepository, createScan, getScan });
  server.requestTimeout = 10000;
  server.headersTimeout = 12000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 80;
  server.maxRequestsPerSocket = 1000;
  const retentionTimer = setInterval(() => {
    scanRepository.deleteExpired(config.dataRetentionDays).catch(error => logger.error('retention_cleanup_failed', { error_name: error.name }));
  }, 6 * 60 * 60 * 1000);
  retentionTimer.unref();
  scanRepository.deleteExpired(config.dataRetentionDays).catch(error => logger.error('retention_cleanup_failed', { error_name: error.name }));
  server.on('error', error => { logger.error('server_error', { error_name: error.name, error_code: error.code }); db.close(); process.exitCode = 1; });
  server.listen(config.port, config.bindAddress, () => logger.info('server_started', { bind_address: config.bindAddress, port: config.port, environment: config.environment }));
  const shutdown = signal => {
    logger.info('server_shutdown_started', { signal });
    clearInterval(retentionTimer);
    server.close(() => { db.close(); logger.info('server_stopped'); process.exit(0); });
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  return { server, db };
}
module.exports = { start };

