-- v1: core CVE monitor schema. Timestamps are RFC 3339 UTC text.
-- JSON columns hold small lists that are only ever read/written whole.

CREATE TABLE tracked_products (
    id               TEXT PRIMARY KEY,              -- slug of the display name
    name             TEXT NOT NULL,
    cpes             TEXT NOT NULL DEFAULT '[]',    -- [{part,vendor,product,note}]
    cna_names        TEXT NOT NULL DEFAULT '[]',    -- [{vendor,product,source_cna}]
    kev_names        TEXT NOT NULL DEFAULT '[]',    -- [{vendor_project,product}]
    aliases          TEXT NOT NULL DEFAULT '[]',
    keywords         TEXT NOT NULL DEFAULT '[]',
    exclude_keywords TEXT NOT NULL DEFAULT '[]',
    match_mode       TEXT NOT NULL DEFAULT 'cpe+names' CHECK (match_mode IN ('cpe+names', 'keyword')),
    confirmed_by     TEXT NOT NULL DEFAULT 'agent',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
) STRICT;

-- One row per CVE id seen (tracked or not: untracked rows stay thin so a later
-- product addition can be backfilled). CVSS is stored per source; the displayed
-- score is chosen by precedence in code (nvd primary > cna > adp > nvd secondary).
CREATE TABLE cves (
    cve_id            TEXT PRIMARY KEY,
    state             TEXT NOT NULL DEFAULT 'PUBLISHED',   -- PUBLISHED | REJECTED
    assigner          TEXT,
    description       TEXT NOT NULL DEFAULT '',
    published         TEXT,
    last_modified     TEXT NOT NULL,                       -- max(cvelist dateUpdated, nvd lastModified)
    cvelist_updated   TEXT,
    nvd_updated       TEXT,
    nvd_status        TEXT,
    first_seen_at     TEXT NOT NULL,
    cna_cvss_score    REAL,
    cna_cvss_vector   TEXT,
    cna_cvss_version  TEXT,
    adp_cvss_score    REAL,
    adp_cvss_vector   TEXT,
    adp_cvss_version  TEXT,
    nvd_cvss_score    REAL,
    nvd_cvss_vector   TEXT,
    nvd_cvss_version  TEXT,
    nvd_cvss_primary  INTEGER NOT NULL DEFAULT 0,          -- 1 if the NVD score is nvd@nist.gov Primary
    cvss_all          TEXT NOT NULL DEFAULT '[]',          -- every metric seen, with source
    ssvc_exploitation TEXT,
    ssvc_automatable  TEXT,
    ssvc_tech_impact  TEXT,
    fixed_versions    TEXT NOT NULL DEFAULT '[]',
    refs              TEXT NOT NULL DEFAULT '[]',
    raw               TEXT                                  -- optional raw cvelist record JSON
) STRICT;
CREATE INDEX idx_cves_last_modified ON cves (last_modified);
CREATE INDEX idx_cves_published ON cves (published);

-- Flattened affected-product entries used for matching.
CREATE TABLE cve_affected (
    id              INTEGER PRIMARY KEY,
    cve_id          TEXT NOT NULL REFERENCES cves (cve_id) ON DELETE CASCADE,
    source          TEXT NOT NULL CHECK (source IN ('cna', 'adp', 'nvd')),
    vendor_raw      TEXT,
    product_raw     TEXT,
    vendor_norm     TEXT,
    product_norm    TEXT,
    product_squash  TEXT,
    cpe             TEXT,
    cpe_vendor      TEXT,
    cpe_product     TEXT,
    versions        TEXT NOT NULL DEFAULT '[]'
) STRICT;
CREATE INDEX idx_affected_cve ON cve_affected (cve_id);
CREATE INDEX idx_affected_names ON cve_affected (vendor_norm, product_squash);
CREATE INDEX idx_affected_product ON cve_affected (product_squash);
CREATE INDEX idx_affected_cpe ON cve_affected (cpe_vendor, cpe_product) WHERE cpe_vendor IS NOT NULL;

CREATE TABLE cve_product_matches (
    cve_id     TEXT NOT NULL REFERENCES cves (cve_id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES tracked_products (id) ON DELETE CASCADE,
    matched_by TEXT NOT NULL,                              -- cpe | cna_name | kev_name | keyword
    matched_at TEXT NOT NULL,
    PRIMARY KEY (cve_id, product_id)
) STRICT;
CREATE INDEX idx_matches_product ON cve_product_matches (product_id);

CREATE TABLE kev (
    cve_id         TEXT PRIMARY KEY,
    vendor_project TEXT,
    product        TEXT,
    name           TEXT,
    date_added     TEXT,
    due_date       TEXT,
    ransomware     INTEGER NOT NULL DEFAULT 0,
    first_seen_at  TEXT NOT NULL
) STRICT;
CREATE INDEX idx_kev_first_seen ON kev (first_seen_at);

CREATE TABLE epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    percentile REAL NOT NULL,
    score_date TEXT NOT NULL
) STRICT;

-- What each consumer has acknowledged, with the state at that moment so that
-- later kev_added / cvss_changed changes can be detected.
CREATE TABLE delivered (
    consumer      TEXT NOT NULL,
    cve_id        TEXT NOT NULL,
    product_id    TEXT NOT NULL,
    delivered_at  TEXT NOT NULL,
    acked_at      TEXT,
    snapshot_cvss REAL,
    snapshot_kev  INTEGER NOT NULL DEFAULT 0,
    snapshot_state TEXT,
    PRIMARY KEY (consumer, cve_id, product_id)
) STRICT;
CREATE INDEX idx_delivered_cve ON delivered (cve_id);

CREATE TABLE source_status (
    source       TEXT PRIMARY KEY,                         -- cvelist | nvd_feed | nvd_api | kev | epss
    cursor       TEXT,                                     -- source-specific JSON
    etag         TEXT,
    last_attempt TEXT,
    last_success TEXT,
    last_error   TEXT
) STRICT;
