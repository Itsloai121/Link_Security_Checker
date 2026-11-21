const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

function openDatabase(config) {
  if (config.databasePath !== ':memory:') fs.mkdirSync(path.dirname(config.databasePath), { recursive: true });
  const db = new DatabaseSync(config.databasePath, { timeout: 5000 });
  db.enableDefensive(true);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA trusted_schema = OFF;');
  return db;
}
function applyMigrations(db, directory) {
  db.exec('CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL) STRICT;');
  const applied = new Set(db.prepare('SELECT name FROM schema_migrations').all().map(row => row.name));
  const files = fs.readdirSync(directory).filter(name => /^\d{4}_[a-z0-9_-]+\.sql$/i.test(name)).sort();
  for (const name of files) {
    if (applied.has(name)) continue;
    const sql = fs.readFileSync(path.join(directory, name), 'utf8').replace(/^\uFEFF/, '');
    db.exec('BEGIN IMMEDIATE;');
    try {
      db.exec(sql);
      db.prepare('INSERT INTO schema_migrations(name, applied_at) VALUES (?, ?)').run(name, new Date().toISOString());
      db.exec('COMMIT;');
    } catch (error) {
      try { db.exec('ROLLBACK;'); } catch {}
      throw new Error(`Database migration ${name} failed: ${error.message}`, { cause: error });
    }
  }
}
module.exports = { openDatabase, applyMigrations };
