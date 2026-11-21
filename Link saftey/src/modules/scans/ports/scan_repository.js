// Application-facing persistence contract; adapters implement these operations.
function assertScanRepository(repository) {
  for (const operation of ['create', 'findById', 'deleteExpired', 'ping']) {
    if (!repository || typeof repository[operation] !== 'function') throw new TypeError(`ScanRepository must implement ${operation}().`);
  }
  return repository;
}
module.exports = { assertScanRepository };
