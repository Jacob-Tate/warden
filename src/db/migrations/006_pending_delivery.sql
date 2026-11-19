-- v6: what was actually handed to a consumer. `get_new_cves` records, per returned
-- (cve, product), the CVSS/KEV/state it showed; `ack` promotes that snapshot to the acked
-- snapshot (instead of snapshotting whatever the state is at ack time), so a change that
-- lands between get and ack is not swallowed. A pending row has acked_at NULL (or keeps
-- its older acked_at/snapshot) and never hides an item: fetching still does not consume.
ALTER TABLE delivered ADD COLUMN pending_at TEXT;
ALTER TABLE delivered ADD COLUMN pending_cvss REAL;
ALTER TABLE delivered ADD COLUMN pending_kev INTEGER;
ALTER TABLE delivered ADD COLUMN pending_state TEXT;
