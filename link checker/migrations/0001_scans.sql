-- Scans and their per-check results (owner: link_analysis). USDA: constraints live in the database, not only in code.
CREATE TABLE scans (
  id                TEXT PRIMARY KEY CHECK (length(id) = 22),            -- 128-bit random, doubles as the access capability
  status            TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
  submitted_input   TEXT NOT NULL CHECK (length(submitted_input) BETWEEN 1 AND 4096),
  display_text      TEXT CHECK (display_text IS NULL OR length(display_text) <= 1000),
  normalized_url    TEXT,
  final_url         TEXT,
  verdict           TEXT CHECK (verdict IS NULL OR verdict IN ('safe','caution','suspicious','dangerous','inconclusive')),
  risk_score        INTEGER CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 100),
  coverage_percent  INTEGER CHECK (coverage_percent IS NULL OR coverage_percent BETWEEN 0 AND 100),
  headline          TEXT,
  reasons_json      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(reasons_json)),
  error_code        TEXT,
  engine_version    TEXT NOT NULL,
  created_at        TEXT NOT NULL,                                         -- ISO-8601 UTC ('Z')
  started_at        TEXT,
  completed_at      TEXT,
  expires_at        TEXT NOT NULL,
  CHECK ((status = 'completed') = (verdict IS NOT NULL)),                  -- a verdict exists exactly when completed
  CHECK (status <> 'failed' OR error_code IS NOT NULL)
) STRICT;
CREATE INDEX idx_scans_expires_at ON scans (expires_at);                   -- retention purge
CREATE INDEX idx_scans_status_created ON scans (status, created_at);       -- startup recovery

CREATE TABLE scan_checks (
  scan_id       TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
  check_id      TEXT NOT NULL,
  position      INTEGER NOT NULL CHECK (position BETWEEN 1 AND 20),
  status        TEXT NOT NULL CHECK (status IN ('clear','notice','warning','danger','unavailable')),
  risk_points   INTEGER NOT NULL CHECK (risk_points BETWEEN 0 AND 100),
  summary       TEXT NOT NULL,
  detail_json   TEXT NOT NULL CHECK (json_valid(detail_json)),            -- findings, facts, limitation (variable shape, versioned by scans.engine_version)
  duration_ms   INTEGER NOT NULL CHECK (duration_ms >= 0),
  PRIMARY KEY (scan_id, check_id),
  UNIQUE (scan_id, position)
) STRICT;
