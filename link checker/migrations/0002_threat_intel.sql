-- Threat indicators downloaded from public feeds (owner: threat_intel). Derived data: rebuilt by `update-feeds`, never edited by hand.
CREATE TABLE threat_indicators (
  source      TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('url','host','cidr','asn')),
  value       TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
  category    TEXT NOT NULL DEFAULT 'unknown' CHECK (category IN ('phishing','malware','scam','abuse','unknown')),
  loaded_at   TEXT NOT NULL,
  PRIMARY KEY (source, kind, value)
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_threat_indicators_lookup ON threat_indicators (kind, value);

-- One row per refresh attempt: the audit trail and the basis for reconciliation (a feed that suddenly shrinks is rejected).
CREATE TABLE feed_updates (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  source             TEXT NOT NULL,
  started_at         TEXT NOT NULL,
  finished_at        TEXT,
  status             TEXT NOT NULL CHECK (status IN ('running','succeeded','rejected','failed')),
  indicators_loaded  INTEGER CHECK (indicators_loaded IS NULL OR indicators_loaded >= 0),
  previous_count     INTEGER CHECK (previous_count IS NULL OR previous_count >= 0),
  note               TEXT
) STRICT;
CREATE INDEX idx_feed_updates_source_started ON feed_updates (source, started_at);
