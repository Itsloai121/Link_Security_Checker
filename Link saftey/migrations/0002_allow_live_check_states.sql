CREATE TABLE scans_v2 (
  id TEXT PRIMARY KEY,
  access_token_hash TEXT NOT NULL CHECK (length(access_token_hash) = 64),
  host TEXT NOT NULL,
  scheme TEXT NOT NULL,
  score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  verdict TEXT NOT NULL CHECK (verdict IN ('high', 'caution', 'incomplete', 'clear')),
  summary TEXT NOT NULL,
  analyzer_version TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;

INSERT INTO scans_v2 SELECT id, access_token_hash, host, scheme, score, verdict, summary, analyzer_version, created_at FROM scans;

CREATE TABLE scan_checks_v2 (
  scan_id TEXT NOT NULL REFERENCES scans_v2(id) ON DELETE CASCADE,
  check_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('clear', 'warning', 'pending', 'error', 'blocked')),
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (scan_id, check_id),
  UNIQUE (scan_id, ordinal)
) STRICT;

INSERT INTO scan_checks_v2 SELECT scan_id, check_id, ordinal, title, description, status, detail, created_at FROM scan_checks;

DROP TABLE scan_checks;
DROP TABLE scans;
ALTER TABLE scans_v2 RENAME TO scans;
ALTER TABLE scan_checks_v2 RENAME TO scan_checks;

CREATE INDEX scans_created_at_idx ON scans(created_at);
CREATE INDEX scans_host_created_at_idx ON scans(host, created_at);
