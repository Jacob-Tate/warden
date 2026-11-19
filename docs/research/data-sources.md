# Warden Phase 0: CVE data source research

Verified live on 2026-11-19 (UTC ~21:25) with curl. Raw downloads are in
`C:\Users\jacob\AppData\Local\Temp\claude\3bb8977541efb7ef\db4e442c-6b91-464c-8de5-87430ee70eeb\scratchpad\research-sources\` (untrusted data).
Items marked (unverified) came from secondary sources or memory, not a live probe.

## 1. Summary and recommendation

| Source | Role | Verdict |
|---|---|---|
| cvelistV5 hourly delta zips + raw records | Primary spine: new/changed CVE + CNA data + CISA-ADP (Vulnrichment) | Use. Unauthenticated, hourly, long retention. |
| NVD 2.0 `modified` feed (.json.gz + .meta) | Enrichment: CPE configurations (version ranges), NVD CVSS, vulnStatus, Patch-tagged refs | Use, but expect many CVEs to never get NVD analysis. |
| NVD API 2.0 | Single-CVE lookup, outage catch-up only | Use sparingly (5 req / 30 s without key). |
| CISA KEV JSON | Exploited-in-wild flag, ransomware flag | Use. Single 1.9 MB file, poll hourly with ETag. |
| EPSS | Exploit probability | Use the daily bulk CSV (2.9 MB gz), not per-CVE API calls. |
| CISA Vulnrichment (ADP) | SSVC (exploitation/automatable/tech impact), CVSS, KEV mirror | Free: already inside the cvelistV5 records, no separate fetch. |

Key findings that change the plan:
1. **cvelistV5 deltas are cumulative per UTC day, not per hour.** `..._delta_CVEs_at_2100Z.zip` holds every record changed since 00:00Z that day (2919 records, 5.5 MB at 21Z; the 0000Z one had 22). Sizes grow monotonically through the day (5.7 KB at 01Z ... 5.5 MB at 21Z), which is how this was inferred; the zip holds no metadata saying so. Dedupe by CVE id and compare `cveMetadata.dateUpdated` to your cursor. The final per-day delta is tagged `..._at_end_of_day`.
2. **NVD no longer enriches most CVEs.** Since 2026-04-15 NIST uses risk-based triage (secondary reporting). In today's modified feed only 2797/10785 (26%) are `Analyzed`; 2443 `Deferred`, 2361 `Received`, 2137 `Awaiting Analysis`. NVD CPE `configurations` exist only for Analyzed/Modified records (3500/10785). Affected-product data must come primarily from CNA `affected` (NVD now mirrors it in an `affected` array), with NVD CPEs as a bonus.
3. **NVD 2.0 JSON now also carries `affected` (CNA data), `ssvcV203` metrics (CISA-ADP) and KEV fields (`cisaExploitAdd` etc.)**, so the NVD feed is close to a superset, but it lags the CVE List.
4. **EPSS batch API silently returns empty data when the URL exceeds ~2000 chars** (about 100-130 CVE ids). Use the bulk CSV.
5. cvelistV5 does not need the GitHub API (60 req/h unauthenticated); release assets and raw.githubusercontent.com suffice. Derive tag names from the clock instead of listing releases.

### Recommended pipeline (hourly, run at about :35 past, after the :2x release)
1. **KEV**: GET with `If-None-Match`. If changed, diff the `cveID` set against the stored set (also look at `dateAdded`). Small and fast, drives priority.
2. **cvelistV5**: compute today's tag(s), download the latest delta zip (see catch-up), parse records whose `dateUpdated` > cursor. Upsert CNA + ADP fields.
3. **Filter** to tracked products (CNA `affected` vendor/product, plus CPE when present). Keep a thin row (id, KEV flag) for untracked CVEs so a later product-list change can backfill.
4. **NVD modified feed**: fetch `.meta`, compare `sha256` with stored; if changed, download the gz (5.4 MB) and apply only to tracked CVEs. Gives CPE ranges, NVD status/CVSS.
5. **EPSS**: once daily after ~12:30Z (score_date 12:00Z), download the bulk gz, upsert for tracked CVEs; skip if the header `score_date` is unchanged.
6. **NVD API**: only for (a) tracked CVE absent from every feed, (b) outage catch-up window.
7. Compute the "what's new" view from changes in the normalized record since the agent's last read.

### Cursors to persist
| Source | Cursor |
|---|---|
| cvelistV5 | `last_delta_tag` (e.g. `cve_2026-11-19_2100Z`) plus `max_date_updated` (ISO ms) of records applied; optional ETag of `deltaLog.json` |
| NVD feed | `.meta` `sha256` + `lastModifiedDate` of last applied file; `max(lastModified)` seen |
| NVD API | `lastModEndDate` of last successful catch-up window |
| KEV | HTTP ETag, `catalogVersion`, `dateReleased`, full set of cveIDs |
| EPSS | `score_date` from CSV header line 1 |

### Catch-up after being offline (e.g. 3 days)
- Preferred: for each missed UTC day D download that day's end-of-day delta (`D_delta_CVEs_at_end_of_day.zip`, ~4.6 MB at today's volume), plus today's latest hourly delta. Because each is cumulative per day, 3 days costs about 4 files / ~20 MB. Filter by `dateUpdated` > cursor. If the end_of_day tag is missing use the `_2300Z` tag (11-18: 4.55 MB vs end_of_day 4.62 MB, so end_of_day may include a few more records; prefer it).
- Alternative: `cves/deltaLog.json` (31 MB, 3414 entries, ~30 days back to 2026-10-20, newest first) gives IDs + `dateUpdated`; then fetch each record by raw path. Good for tiny gaps only.
- Gap > ~30 days or empty state DB: download the latest `*_all_CVEs_at_midnight.zip.zip` (667 MB; note double `.zip`), then apply deltas.
- NVD: modified feed covers ~8 days. Longer gaps: NVD API lastMod windows of <=120 days (404 beyond), paged.
- KEV and EPSS are snapshots, so no catch-up (EPSS history via `date=` or `scope=time-series`).

## 2. Normalized internal record schema and source precedence

| Field | Winner (then fallbacks) | Notes |
|---|---|---|
| `cve_id`, `state` (PUBLISHED/REJECTED) | cvelistV5 `cveMetadata` | REJECTED appears in deltas (5 today); exclude from lists. |
| `description` | CNA `descriptions[lang=en]` | NVD copy is identical in practice; fall back if empty. |
| `published` | cvelistV5 `datePublished` | NVD `published` is NVD ingest time (later). Also store `first_seen_at` for "what's new" ordering. |
| `last_modified` | max(CVE `dateUpdated`, NVD `lastModified`) | Change detection. |
| `cvss` (score, vector, version, source) | 1. NVD Primary (nvd@nist.gov) 2. CNA metrics (cvssV4_0 / V3_1 / V3_0 / V2_0) 3. CISA-ADP cvss 4. NVD Secondary | Store all with `source`; display one. NVD Primary is rare now (1815 of 9091 V3.1 metrics; the rest Secondary = CNA copies), so CNA is usually the real source. Keep v3.1 and v4.0 both. |
| `severity` | derived from displayed CVSS `baseSeverity` | KEV/EPSS flags shown separately, not folded in. |
| `vendor`/`product` | CNA `affected[].vendor/product` (lowercase, trim; "n/a" = unknown) | NVD CPE vendor/product as join key when present. |
| `cpes` | NVD `cpeMatch.criteria` where `vulnerable=true`; else CNA/ADP `affected[].cpes` if present | Only Analyzed/Modified NVD records have them. |
| `affected_ranges` | CNA `affected[].versions[]` (`version`, `lessThan`, `lessThanOrEqual`, `status`, `versionType`, `changes[]`), else NVD cpeMatch ranges | |
| `fixed_versions` | CNA: `changes[].at` with `status=unaffected`, `versions[].lessThan` on `status=affected` rows, rows with `status=unaffected`; NVD: `versionEndExcluding` | Heuristic ("likely fixed in"). `versionEndIncluding` implies no fix info. Also keep NVD refs tagged `Patch`/`Vendor Advisory` as links. |
| `kev` (bool, dateAdded, dueDate, ransomware) | CISA KEV JSON | NVD `cisaExploitAdd` and ADP `kev` metric are fallbacks. |
| `epss`, `epss_percentile`, `epss_date` | FIRST EPSS | Strings in the API; parse as floats. |
| `ssvc_exploitation` (none/poc/active), `automatable`, `technical_impact` | CISA-ADP `metrics[].other(type=ssvc)`; NVD `ssvcV203[].ssvcData.options` | Store the timestamp; exploitation is point-in-time. |
| `nvd_status` | NVD `vulnStatus` | |
| `references` | union; keep NVD tags | |
| `provenance` | per-field source + fetched_at | |

## 3. Evidence: cvelistV5

### 3.1 Releases and assets
- Listing: `GET https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=100` (listing capped at 1000 results; page 10 reached 2026-10-10; page 20 returned 422 "Only the first 1000 results are available").
- Tags: `cve_YYYY-MM-DD_HH00Z`, 23-25 per day (hourly; 11-16 to 11-18: 24-25), plus `cve_YYYY-MM-DD_at_end_of_day` published ~00:40Z next day. Hourly releases appear ~20-30 min past the hour (2100Z tag published 21:21Z; 2000Z at 20:28Z; 1900Z at 19:29Z).
- Assets of `cve_2026-11-19_2100Z`:
  - `2026-11-19_delta_CVEs_at_2100Z.zip` 5,567,329 B
  - `2026-11-19_all_CVEs_at_midnight.zip.zip` 667,344,285 B (daily baseline attached to every release that day; double `.zip`)
  - `release_notes.md` 48 KB (starts `2919 changes (970 new | 1949 updated):` then id lists)
- Download: `https://github.com/CVEProject/cvelistV5/releases/download/<tag>/<asset>` (302 to CDN). Delta zip contents: flat `deltaCves/CVE-YYYY-NNNN.json` (2919 files); no `delta.json`/`deltaLog.json` inside. Each file is a full CVE Record v5.
- Baseline growth: 647 MB (10-30), 650 (11-03), 654 (11-07), 660 (11-11), 663 (11-15), 667 (11-19).
- **Retention: effectively indefinite.** HEAD of `cve_2025-06-01_2300Z/2025-06-01_delta_CVEs_at_2300Z.zip` returned 302 then 200 (17 months old); tag pages for 2025-06, 2026-06 and 2026-09 return 200.
- Repo cadence: `cves/delta.json` fetchTime 21:19Z, `deltaLog.json` newest 21:24Z, so the repo itself updates every ~5-10 min; releases are hourly snapshots.

### 3.2 `cves/deltaLog.json` / `cves/delta.json` (in repo, not release assets)
- `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json`: latest run only (`fetchTime`, `numberOfChanges` 20, `new[]`, `updated[]`).
- `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json`: 31 MB, newest first; entries `{fetchTime, numberOfChanges, new[], updated[], error}`; items `{cveId, cveOrgLink, githubLink, dateUpdated}`. raw CDN `Cache-Control: max-age=300`.

### 3.3 Single records
- Raw path: `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<year>/<floor(n/1000)>xxx/CVE-<year>-<n>.json`, e.g. `cves/2021/44xxx/CVE-2021-44228.json` (200, 36.7 KB, ETag, max-age=300). Ids under 1000 use `0xxx` (repo convention, unverified).
- CVE Services: `https://cveawg.mitre.org/api/cve/CVE-2021-44228` -> 200, 18 KB, `Cache-Control: no-store`, `RateLimit-Limit: 25000` with `w=60`. It returned a smaller document (18 KB vs 36.7 KB) than the repo file; the repo file contains the ADP containers. Prefer raw GitHub for single lookups; use cveawg as fallback. Neither needs auth.

### 3.4 Where scores live
- CNA: `containers.cna.metrics[]`, each item keyed `cvssV3_1`, `cvssV4_0`, `cvssV3_0`, `cvssV2_0` or `other`. Today's delta (2919 records): cvssV3_1 2171, cvssV4_0 637, cvssV3_0 34, cvssV2_0 25, `other` 70. Some CNAs give only `{"other":{"type":"unknown","content":{"other":"critical"}}}` (log4j).
- CVSS item: `{"cvssV4_0":{"version":"4.0","vectorString":"CVSS:4.0/AV:N/...","baseScore":8.7,"baseSeverity":"HIGH"}}`.
- ADP containers in today's delta: CISA-ADP 2409, CVE (program) 18, redhat-SADP 4, siemens-SADP 1. Identify by `providerMetadata.shortName`; CISA-ADP orgId `134c704f-9b21-4f2e-91b3-4a467353bcc0`. 2409/2919 records have CISA-ADP, mostly SSVC only.

### 3.5 Trimmed real record (CVE-2021-44228, cvelistV5 main)
```json
{"dataVersion":"5.1","cveMetadata":{"state":"PUBLISHED","cveId":"CVE-2021-44228","assignerShortName":"apache","dateUpdated":"2025-10-21T23:25:23.121Z","datePublished":"2021-12-10T00:00:00.000Z"},
 "containers":{
  "cna":{"descriptions":[{"lang":"en","value":"Apache Log4j2 2.0-beta9 through 2.15.0 ..."}],
    "affected":[{"vendor":"Apache Software Foundation","product":"Apache Log4j2",
      "versions":[{"version":"2.0-beta9","status":"affected","lessThan":"log4j-core*","versionType":"custom",
        "changes":[{"at":"2.3.1","status":"unaffected"},{"at":"2.4","status":"affected"},{"at":"2.12.2","status":"unaffected"},{"at":"2.13.0","status":"affected"},{"at":"2.15.0","status":"unaffected"}]}]}],
    "metrics":[{"other":{"type":"unknown","content":{"other":"critical"}}}]},
  "adp":[{"title":"CISA ADP Vulnrichment","providerMetadata":{"orgId":"134c704f-9b21-4f2e-91b3-4a467353bcc0","shortName":"CISA-ADP","dateUpdated":"2025-10-21T23:25:23.121Z"},
    "metrics":[
     {"cvssV3_1":{"version":"3.1","baseScore":10,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
     {"other":{"type":"ssvc","content":{"id":"CVE-2021-44228","role":"CISA Coordinator","version":"2.0.3","timestamp":"2025-02-04T14:25:34.416117Z",
        "options":[{"Exploitation":"active"},{"Automatable":"yes"},{"Technical Impact":"total"}]}}},
     {"other":{"type":"kev","content":{"dateAdded":"2021-12-10","reference":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-44228"}}}]}]}}
```
(The real ADP cvssV3_1 object also carries the per-component fields; trimmed.) A fresh record in today's delta with CNA CVSS 4.0 and ADP SSVC: CVE-2012-20008 (VulnCheck CNA, `cvssV4_0` 8.7, affected `openSIS` `5.1` lessThan `9.0`, ADP `Exploitation: poc`, `Automatable: no`, `Technical Impact: total`).

### 3.6 Gotchas
- `lessThan` can hold a non-version string (`log4j-core*`, `versionType: custom`); parse ranges defensively. `versionType: git` means commit hashes.
- `defaultStatus` may be `unknown`/`affected`/`unaffected`; vendor/product can be `n/a`.
- ADP SSVC option keys are Title Case in CVE JSON, camelCase in NVD (`exploitation`).
- REJECTED records appear in deltas (5 today) with state `REJECTED`.
- A record can reappear in many hourly zips; deltas also include records where only the ADP container changed.
- Sequence numbers can exceed 5 digits (e.g. CVE-2026-133217 in today's data); compute buckets by `floor(n/1000)`.

## 4. Evidence: NVD JSON 2.0 feeds
- Feeds (verified 200):
  - `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz` (5,384,911 B gz; `.meta` `size:63901251` uncompressed)
  - `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz` (1,775,514 B gz; 22.6 MB uncompressed)
  - `.../nvdcve-2.0-modified.meta` and `.../nvdcve-2.0-recent.meta`: lines `lastModifiedDate:2026-11-19T16:00:08-05:00`, `size`, `zipSize`, `gzSize`, `sha256` (of the JSON).
  - Yearly `nvdcve-2.0-YYYY.json.gz` exist per NVD docs (unverified).
- Fetching a `.meta` body hung once past 120 s while the headers returned quickly; use `-m 40` timeouts and retries.
- Window: modified feed held 10,785 CVEs with `lastModified` 2026-11-11T05:19Z to 2026-11-19T20:59Z, so a **~8-day rolling window**. Page timestamp 21:00Z; HTTP last-modified 21:15Z (modified) and 21:00Z (recent). Regenerated about hourly (NVD says every 2 hours; observed hourly). Poll `.meta` and compare `sha256`.
- Legacy 1.1: `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz` returns **403 Forbidden**; treat as retired (NVD announced the 1.1 feed retirement in 2023; not re-verified).
- Top level: `{"resultsPerPage":10785,"startIndex":0,"totalResults":10785,"format":"NVD_CVE","version":"2.0","timestamp":"...","vulnerabilities":[{"cve":{...}}]}`.
- `cve` keys: `id, sourceIdentifier, published, lastModified, vulnStatus, cveTags, descriptions, affected, metrics, weaknesses, configurations, references`, plus `cisaExploitAdd, cisaActionDue, cisaRequiredAction, cisaVulnerabilityName` for KEV entries (18 in this feed). Timestamps carry no timezone (UTC).
- `vulnStatus` today: Analyzed 2797, Deferred 2443, Received 2361, Awaiting Analysis 2137, Modified 699, Undergoing Analysis 289, Rejected 59. `configurations` present on all Analyzed and Modified, only 4 Undergoing, none of the others.
- `metrics` keys: `cvssMetricV31` 9091 (Secondary 7769 / Primary 1815), `cvssMetricV40` 3608 (all Secondary), `cvssMetricV2` 214, `cvssMetricV30` 112, `ssvcV203` 9252 (CISA-ADP; `source` is the ADP orgId; `ssvcData.options` e.g. `[{"exploitation":"none"},{"automatable":"no"},{"technicalImpact":"partial"}]`). Primary = nvd@nist.gov, Secondary = CNA/other.
- `affected`: `[{"source":"<cna uuid>","affectedData":[{"vendor","product","defaultStatus","versions":[{"version","status"}]}]}]`, present on 10,726/10,785 (often `n/a` or free text like "EdgeLink versions prior to 2.8.5.0").
- Trimmed analyzed record (CVE-2021-32662): `configurations[0].nodes[0].cpeMatch[0]` = `{"vulnerable":true,"criteria":"cpe:2.3:a:linuxfoundation:backstage\\/techdocs-common:*:*:*:*:*:node.js:*:*","versionEndExcluding":"0.6.3","matchCriteriaId":"..."}`; `references[]` = `{"url","source","tags":["Patch","Third Party Advisory"]}`; `metrics.cvssMetricV31` has a Secondary entry (GitHub) and a Primary (nvd@nist.gov), each `{source,type,cvssData{version,vectorString,baseScore,baseSeverity,...},exploitabilityScore,impactScore}`.
- Fixed versions: `versionEndExcluding` is the first non-affected version; `versionStartIncluding/Excluding` is the lower bound; `versionEndIncluding` gives no fix. `Patch` tag on 1711/10785 records' references (commit/advisory links, not version numbers).
- Gotchas: CPE strings contain escapes; nodes can be AND/OR with `negate` and non-vulnerable "running on" matches (filter `vulnerable=true`); verify `sha256` against `.meta` to detect truncated download.

### NVD enrichment backlog status (2025-2026)
- From secondary reporting (SecurityWeek, The Record, CSA Labs research note, Tamnoon; the nist.gov page is JS-rendered and could not be fetched): effective **2026-04-15** NIST moved to risk-based triage after a ~263% rise in submissions. Priority: CISA KEV (target one business day), federal-use and critical software. Unenriched CVEs published before 2026-03-01 move to **"Not Scheduled"**. NVD will not add its own severity when the CNA gave one, and will not re-analyze modified entries unless material. Researchers can email nvd@nist.gov to request enrichment. Confirm against the NIST announcement.
- Live corroboration: only 26% of today's modified feed is Analyzed; the visible status label for the parked ones is `Deferred`.
- Consequence: do not wait for NVD analysis; use CNA + CISA-ADP immediately, treat NVD CPEs as optional.

## 5. Evidence: NVD API 2.0
- Base: `https://services.nvd.nist.gov/rest/json/cves/2.0`. Verified:
  - `?cveId=CVE-2021-44228` -> 200, 87 KB, `totalResults:1`.
  - `?lastModStartDate=2026-11-19T20:00:00.000Z&lastModEndDate=2026-11-19T21:00:00.000Z&resultsPerPage=1` -> 200, `totalResults:261`.
  - lastMod range of ~171 days -> **404** with empty body (limit 120 days; start and end must both be given).
- Other params (NVD docs, unverified live): `startIndex`, `resultsPerPage` (default and max 2000), `pubStartDate/pubEndDate` (also 120 days), `noRejected`, `hasKev`, `cvssV3Severity`, `cpeName`, `keywordSearch`.
- Auth: header `apiKey: <key>` (listed in CORS allow-headers). Limits: 5 requests per rolling 30 s without key, 50 with a free key; NIST suggests ~6 s sleep between calls (apis.io, unverified).
- Paging: `startIndex += resultsPerPage` until `>= totalResults`, same window each page. A 2000-item page is tens of MB.
- Reliability: community reports of 503s/timeouts (offseq summary dated 2026-06-20; DependencyCheck issue #8469, June 2026, retries without backoff), and 429s without a key (project issue, Oct 2026). No official NIST status notice found. Use exponential backoff with jitter, single-flight, 6 s spacing, and treat 404 as an invalid range, not a missing CVE. `totalResults:0` for a brand-new CVE is normal (NVD ingest lag).

## 6. Evidence: CISA KEV
- URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (200, 1,863,915 B, ETag `"1c70eb-66091dd613278"`, Last-Modified 2026-11-18 19:17:40 GMT, `Cache-Control: max-age=2462`). A CSV twin exists (unverified).
- Top level: `title`, `catalogVersion` ("2026.11.18"), `dateReleased` ("2026-11-18T19:17:41.0354Z"), `count` 1786, `vulnerabilities[]`.
- Item fields: `cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse ("Known"/"Unknown"), notes, cwes`. Example latest: CVE-2024-10441 (Synology DSM), `dateAdded` 2026-11-18.
- Cadence: irregular, several updates a week, usually weekday afternoons US time.
- New-entry detection: persist the set of `cveID`s and diff (robust to backdated `dateAdded` and removals); `dateAdded >= last_seen_max` is only a quick filter. Use ETag/If-Modified-Since.
- Gotchas: `knownRansomwareCampaignUse` can flip Unknown -> Known later, so refresh it for all entries; text has Unicode curly quotes (decode UTF-8); send a descriptive User-Agent in case of bot filtering.

## 7. Evidence: EPSS
- Bulk: `https://epss.cyentia.com/epss_scores-current.csv.gz` -> 301 to `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` -> 302 to `epss_scores-2026-11-19.csv.gz`. Follow redirects (the host moved). 2,866,725 B gz, 409,087 data rows.
- CSV: line 1 `#model_version:v2026.06.15,score_date:2026-11-19T12:00:23Z`; line 2 `cve,epss,percentile`; rows like `CVE-1999-0001,0.04753,0.92065`. Daily; scores dated 12:00Z. Dated historical files exist.
- API: `https://api.first.org/data/v1/epss?cve=A,B` returns `{"status":"OK","total":N,"offset":0,"limit":100,"data":[{"cve":"CVE-2024-3094","epss":"0.909000000","percentile":"0.998100000","date":"2026-11-19"}]}` (strings). Verified params: `date=YYYY-MM-DD`, `scope=time-series`, `order=!epss`, `epss-gt`, `limit`, `offset`.
- **Batch limit**: GET with 100 ids and 130 ids (1949 chars) worked; 160 ids (2399 chars), 200 and 400 returned HTTP 200 with `total:0,data:[]` (silent failure from URL length ~2000). POST with 400 ids also returned empty. Safe: <=100 ids per GET and check `total` vs requested (unknown CVEs are simply omitted; 100 requested gave 73).
- No auth; no published rate limit found; be polite. Brand-new CVEs have no score until the next daily run (null EPSS is normal).

## 8. Failure modes summary
| Source | Failure | Handling |
|---|---|---|
| GitHub releases | Hour missing/late; asset 404 | Try previous tag/end_of_day; fall back to `deltaLog.json`; never rely on listing API |
| GitHub raw | 5-min CDN cache | ETag, backoff |
| NVD feed | Slow/hung `.meta`, truncated gz | Timeouts, verify sha256 |
| NVD API | 503/timeouts/429; 404 for >120-day range | Backoff, 6 s spacing, chunk windows |
| KEV | Site blocking/stale | ETag; fall back to NVD `cisaExploitAdd` or ADP `kev` |
| EPSS | Host redirect; silent empty batch | Follow redirects; verify `total`; prefer bulk |
