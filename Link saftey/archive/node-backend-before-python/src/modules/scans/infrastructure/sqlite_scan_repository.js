class SqliteScanRepository {
  constructor(db) {
    this.db = db;
    this.insertScan = db.prepare(`INSERT INTO scans (id, access_token_hash, host, scheme, score, verdict, summary, analyzer_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    this.insertCheck = db.prepare(`INSERT INTO scan_checks (scan_id, check_id, ordinal, title, description, status, detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    this.findScan = db.prepare(`SELECT id, access_token_hash, host, scheme, score, verdict, summary, analyzer_version, created_at FROM scans WHERE id = ?`);
    this.findChecks = db.prepare(`SELECT check_id, title, description, status, detail FROM scan_checks WHERE scan_id = ? ORDER BY ordinal`);
    this.deleteExpiredStatement = db.prepare(`DELETE FROM scans WHERE julianday(created_at) < julianday('now', ?)`);
  }
  async create(scan, accessTokenHash) {
    this.db.exec('BEGIN IMMEDIATE;');
    try {
      this.insertScan.run(scan.id, accessTokenHash, scan.host, scan.scheme, scan.score, scan.verdict, scan.summary, scan.analyzerVersion, scan.createdAt);
      scan.checks.forEach((check, ordinal) => this.insertCheck.run(scan.id, check.id, ordinal, check.title, check.description, check.status, check.detail, scan.createdAt));
      this.db.exec('COMMIT;');
    } catch (error) {
      try { this.db.exec('ROLLBACK;'); } catch {}
      throw error;
    }
  }
  async findById(id) {
    const scan = this.findScan.get(id);
    if (!scan) return null;
    return { ...scan, checks: this.findChecks.all(id).map(row => ({ id: row.check_id, title: row.title, description: row.description, status: row.status, detail: row.detail })) };
  }
  async deleteExpired(retentionDays) { return this.deleteExpiredStatement.run(`-${retentionDays} days`).changes; }
  async ping() { this.db.prepare('SELECT 1 AS ok').get(); return true; }
}
module.exports = { SqliteScanRepository };

