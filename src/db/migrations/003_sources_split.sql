-- v3: per-source ownership columns for the Phase 1b sources.
-- cves.fixed_versions stays the displayed list (union of the two below) so the
-- cvelist and NVD writers can each replace only their own contribution.
ALTER TABLE cves ADD COLUMN fixed_cna TEXT NOT NULL DEFAULT '[]';
ALTER TABLE cves ADD COLUMN fixed_nvd TEXT NOT NULL DEFAULT '[]';
-- CISA-ADP KEV marker (dateAdded) and the SSVC decision timestamp.
ALTER TABLE cves ADD COLUMN adp_kev_date TEXT;
ALTER TABLE cves ADD COLUMN ssvc_timestamp TEXT;
