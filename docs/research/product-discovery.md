# Product discovery for `add_tracked(name)` (Phase 0 research)

Date of live calls: 2026-11-19. All API calls unauthenticated, UA `warden-research`, ~7s between NVD calls. Raw downloads kept in the scratchpad (not in repo).

## 1. Summary

- **No single source gives a clean identity.** Four sources name the same product four different ways:

  | Product | NVD CPE (vendor:product) | CNA `affected` (vendor / product) | KEV (vendorProject / product) |
  |---|---|---|---|
  | FortiClient EMS | `fortinet:forticlientems` | `Fortinet` / `FortiClientEMS` | `Fortinet` / `FortiClient EMS` |
  | Apache HTTP Server | `apache:http_server` | `Apache Software Foundation` / `Apache HTTP Server` | `Apache` / `HTTP Server` |
  | Arista EOS | `arista:eos` | `Arista Networks` / `EOS` | `Arista` / `Extensible Operating System` |
  | Grafana | `grafana:grafana` | `grafana` / `grafana` (GitHub_M CNA) | `Grafana Labs` / `Grafana` |
  | NGINX | `f5:nginx`, `f5:nginx_open_source` (+ deprecated `nginx:nginx`, `igor_sysoev:nginx`) | `F5` / `NGINX Open Source` | none |
  | Moodle | `moodle:moodle` | `vendor` absent, `packageName: "moodle"` (Fedora CNA) | none |
- **Three of the 14 test products have no usable CPE at all** (XCP-ng, Ellucian Colleague, and FortiClient EMS under the *natural* spelling, because the CPE is `forticlientems`). Helix Core has a CPE but only 1 product with 2 dictionary entries.
- **There is no free-text search API for CVE records.** `cveawg.mitre.org` only does `GET /api/cve/{id}` unauthenticated; the list/search endpoints require a `CVE-API-ORG` auth header. Discovery of CNA strings must therefore be done *indirectly* (see 5).
- **Recommended approach:** a *proposal pipeline*. Query NVD CPE dictionary by keyword, aggregate rows to distinct `part:vendor:product`, rank, then for the top candidates sample real CVEs (NVD CVE API by `virtualMatchString`, then `cveawg` record) to learn the CNA vendor/product strings; look up KEV locally by fuzzy match. Show the agent a ranked list with evidence; the agent confirms; store all four name-sets plus keyword fallback. Matching at feed time uses **normalized** comparison against all stored name-sets.

## 2. Recommended algorithm for `add_tracked(name)`

### 2.1 Inputs
`name` (free text, e.g. "Perforce Helix Core"), optional `hints` (vendor, aliases), optional `confirm` (selected candidate ids, for the 2-step flow). Make the tool two-phase: `add_tracked(name)` returns `{status:"needs_confirmation", candidates:[...]}`; `add_tracked(name, select:[...], keywords?:[...], exclude_keywords?:[...])` commits. (Or the first call stores a draft and the agent calls `confirm_tracked`.)

### 2.2 Steps
1. **Normalize query**: lowercase, NFKD-strip, collapse `[-_\s.]+` to a single space for the "token form", also build the "squashed form" (no separators: `forticlientems`, `xcpng`) and the "underscore form" (`helix_core`, as NVD uses). Drop only corporate noise tokens (`inc`, `corp`, `ltd`, `the`); keep `server`, `software`, etc.
2. **NVD CPE dictionary** (1 call per variant, `resultsPerPage=10000`, filter `deprecated=false` for ranking but remember deprecated ones):
   - Variant A: full token form, e.g. `keywordSearch=perforce helix core`.
   - Variant B: squashed form (`forticlientems`) if the name has >1 token. This is what rescues FortiClient EMS (`forticlient ems` = 0 hits; `forticlientems` = 82).
   - Variant C: if A returns 0, each token alone (`ellucian` = 22 rows; `colleague` = 0; `xcp` = 77 rows, all noise).
   - Variant D (when the user supplied a vendor, or the best A hit gives a vendor): `cpeMatchString=cpe:2.3:*:{vendor}:*` is NOT useful for listing (returns 3620 rows for `fortinet:forti*`); prefer keyword + vendor filter.
3. **Aggregate** rows to distinct `(part, vendor, product)` from `cpeName.split(':')[2..4]`. Keep per candidate: `total_rows`, `live_rows`, `deprecated_rows`, one `title` (strip the trailing version), a `refs` URL (Vendor/Product ref).
4. **Score** each candidate (all case-folded, separators folded):
   - +10 if `product` (underscores to spaces) equals the query token form; +8 if the query contains vendor AND product; +5 if product is a prefix/word-subset of the query; +3 if the title contains all query tokens.
   - +log2(live_rows) as a popularity/maturity tiebreak (caps noise like `hardware per-model` entries at 1 row each).
   - Penalties: -5 `part:h` (per-model hardware, e.g. 93 `fortigate-*` rows each its own "product"); -4 product names that are a superset only via a suffix (`fortios-6k7k`, `fortios_ips_engine`, `forticlientems_cloud`) unless the user asked for them; -8 if `live_rows == 0` (fully deprecated, e.g. `nginx:nginx`, `igor_sysoev:nginx`); -6 if vendor/product is a *third-party plugin for* the query (title ends "for Docker", "for Moodle", "for Grafana", "for Apache").
   - Group family variants (`ios_xe`, `ios_xe_sd-wan`, `ios_xe_3.2sg`...) under one "family" so the agent isn't shown 21 rows; show top-N=5 plus "N more".
5. **Probe CVE linkage** for the top ~3 candidates (cheap, validates the CPE is actually used): `GET /rest/json/cves/2.0?virtualMatchString=cpe:2.3:{part}:{vendor}:{product}&resultsPerPage=1` and read `totalResults` (note: a pub-date window is limited to 120 days; without dates it is fine). Optionally `cpematch/2.0?matchStringSearch=cpe:2.3:a:grafana:loki` (3 match strings returned for Loki) as a second check. Drop candidates with 0.
6. **Learn CNA strings**: from the probe, take the 3-5 most recent CVEs (`lastModStartDate` window <= 120 days, or just newest by sorting client-side) and `GET https://cveawg.mitre.org/api/cve/{id}` (or `raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{yyyy}/{nnn}xxx/{id}.json`). Collect distinct `(vendor, product, packageName)` from `containers.cna.affected[]` where the record also matches the candidate (by CPE in `cpes` or ADP `cpes`, or by the NVD configuration that linked it). Count occurrences; store the top ones as `cna_names`. Skip entries with `vendor`/`product` in {`n/a`, `unspecified`, `multiple products`, ``}.
7. **KEV lookup** (local, free; the catalog is 1.8 MB, cache it): normalized contains/equal match of query tokens and the CPE vendor/product against `vendorProject` and `product`. Return distinct `(vendorProject, product)` with counts. Expect plural variants (`FortiOS`, `FortiOS and FortiProxy`), so match with token containment, not equality. Present them as `kev_names` candidates.
8. **Keyword-only fallback** (no candidate with CVE linkage, i.e. XCP-ng, Ellucian Colleague): propose `keywords:[...]` from the name (token form + squashed form + known aliases the agent supplies), propose `exclude_keywords` from noise found in a trial search (see 2.5), and say clearly "no CPE; matching by text".
9. **Return** to the agent, per candidate: `{id, cpe:"o:fortinet:fortios", title, live_rows, cve_count, recent_cna_names:[...], kev_names:[...], noise_flags:[...], score}` plus a `recommendation` (the top candidate if score gap is large, else "ambiguous: ask the user").
10. **Commit** on confirmation. Allow multiple candidates per product (FortiOS = `fortinet:fortios` only; NGINX = `f5:nginx` + `f5:nginx_open_source` + maybe `f5:nginx_plus`).

### 2.3 Normalization rules for matching (used at ingest time)
- `norm(s)`: NFKD, lowercase, replace `&` with `and`, strip punctuation to spaces except keep alphanumerics, collapse whitespace, strip trailing "inc"/"ltd"/"corp"/"llc" (`Grafana Labs` vs `grafana` must match, so treat `labs`, `networks`, `software foundation`, `project` as strippable vendor suffixes; `apache software foundation` -> `apache`).
- Compare both `norm(s)` and `squash(norm(s))` (all spaces removed) so `FortiClient EMS` == `FortiClientEMS` == `forticlientems`.
- Vendor aliases table, learned at discovery time and persisted per product (not global): `{apache, apache software foundation, the apache software foundation}`, `{arista, arista networks}`, `{grafana, grafana labs}`, `{f5, f5 networks, nginx, igor sysoev}`.
- Product match = exact on squashed form, or one side is a *word-boundary* prefix of the other when the other adds only version/edition tokens (`Cisco IOS XE Software` ~ `ios xe`). NOT substring (`IOS` is inside `IOS XR`, `Radios`, etc.).
- Version-less: never compare versions at discovery.
- Strip CPE escapes (`\:`, `\\`), and treat `_` and `-` as spaces.
- Prefer CPE match on structured CVE data over name match when both exist. A CVE matches a tracked product if ANY of: (a) NVD `configurations` / ADP `cpes` contains `{vendor}:{product}`; (b) a CNA `cpes[]` entry does; (c) a CNA `(vendor,product)` normalizes into the stored `cna_names`; (d) a KEV row normalizes into `kev_names`; (e) keyword rule hits (only for keyword-only products, and subject to `exclude_keywords`).

### 2.4 Stored shape per product
```json
{
  "id": "fortios",
  "name": "FortiOS",
  "created": "2026-11-19T00:00:00Z",
  "cpes": [
    {"part":"o","vendor":"fortinet","product":"fortios","note":"NVD, 271 entries"}
  ],
  "cna_names": [
    {"vendor":"Fortinet","product":"FortiOS","source_cna":"fortinet"}
  ],
  "kev_names": [
    {"vendorProject":"Fortinet","product":"FortiOS"},
    {"vendorProject":"Fortinet","product":"FortiOS and FortiProxy"}
  ],
  "aliases": ["fortigate os", "forti os"],
  "keywords": [],
  "exclude_keywords": [],
  "match_mode": "cpe+names",
  "confirmed_by": "agent|user",
  "discovery_evidence": {"nvd_queries":["fortios"],"sample_cves":["CVE-2025-68686"]}
}
```
Keyword-only example (XCP-ng):
```json
{"id":"xcp-ng","name":"XCP-ng","cpes":[],
 "cna_names":[{"vendor":"Xen","product":"Xen","note":"upstream hypervisor CVEs; XCP-ng is a downstream distro"}],
 "kev_names":[],
 "keywords":["xcp-ng","xcp ng","xcpng","vates"],
 "exclude_keywords":["first4internet","fujitsu","m10","m12","xcp2","documentum"],
 "match_mode":"keywords"}
```
Store the discovery timestamp and re-validate periodically (CPEs get added: e.g. a vendor may later add `vates:xcp-ng`); expose `refresh_tracked(id)`.

### 2.5 Keyword false-positive pitfalls (all observed or verified)
- **NVD `keywordSearch` is token-AND over CPE title/refs (CPE API) or over description (CVE API); it is substring-ish, not word-boundary.** `xcp` matched Fujitsu "XCP" firmware (25 distinct products), EMC Documentum xCP, Sony First4Internet XCP DRM; `docker` matched 87 products incl. 552 rows of "Dozzle for Docker", "Heimdall docker image"; `nginx` matched 36 incl. `nginx_ui`, `nginx_proxy_manager`, Kubernetes ingress.
- **Ceph**: CVE keyword `ceph` over 2026-07-25..2026-11-18 gives 37 CVEs, the first two being Linux kernel `libceph` fixes (vendor `Linux`, product `Linux`). The kernel CNA text mentions every subsystem. Exclude CNA product `Linux` unless the user tracks the kernel.
- **Loki** is also a Grafana product (`grafana:loki`) but "loki" matches unrelated words/products; require vendor + product (cpe) rather than keyword. The Grafana product keyword `grafana` also hits Loki, Tempo, OnCall, Agent, Alloy, Pyroscope, operator and ~30 plugin CPEs.
- **Apache HTTP Server**: `apache http server` also yields `apache:traffic_server` (209 rows), `james_server`, `mod_perl`, `oracle:weblogic_server` ("...for Apache" titles), `e-guardian:siteguard` (48 rows) and `rsa:authentication_agent_for_web`. Titles ending "for Apache"/"for Apache HTTP Server" are third-party modules/plugins.
- **FortiGate**: only 93 per-model hardware CPEs (`h:fortinet:fortigate-60f`, ...); the software is `o:fortinet:fortios`. Product name != CPE. Provide a curated alias hint list (FortiGate -> fortios) or surface candidates found via vendor siblings.
- **Cisco IOS XE**: 21 CPE products: `ios_xe` (o), deprecated `a:ios_xe`, per-train `ios_xe_3.2sg`, ..., `ios_xe_sd-wan`, `ios_xe_rom_monitor`. KEV spells it 8+ ways ("IOS and IOS XE Software", "IOS XE Software", "Cisco IOS XE Web UI", "IOS, IOS XR, and IOS XE"). Substring "IOS" would also hit `IOS XR`, and Apple iOS (case-folded `ios`!) - never match bare `ios`.
- **"Multiple Products"** (KEV: 7 Fortinet rows; 1 Cisco) and CNA `vendor: "n/a"` give no product signal; the CVE must be matched by CPE/description.
- **Moodle**: keyword matches 3rd-party plugins ("for Moodle") and the `moodle-block_sitenews_project` junk vendor. Fedora/RedHat CNAs write "Moodle: moodle: ..." with `packageName:"moodle"` and *no* vendor/product.
- **Case/ambiguity**: `edge`, `core`, `desktop`, `colleague`, `loki` (Norse god, many hobby projects) are common words. For Helix Core, `helix core` hits only 2 rows, but `helix` alone would hit `helix_alm`, `helix_sync`, Red Hat Helix, etc. Perforce is also parent of Puppet (`puppet:puppet`, `perforce:puppet_bolt`), Perfecto, Klocwork, Gliffy, so vendor-only keyword `perforce` returns 809 rows/12 products.
- For keyword-only products: always require the **whole phrase** match with word boundaries (`\bxcp-ng\b`), match against `title` and `description` only (not references/URLs), and keep an `exclude_keywords` list.

## 3. Evidence: NVD CPE Products API 2.0

Base: `https://services.nvd.nist.gov/rest/json/cpes/2.0`

### 3.1 Parameters (observed to work)
| Param | Notes |
|---|---|
| `keywordSearch` | free text, multi-word = AND of terms; matches CPE title / ref text, not just vendor:product. `keywordSearch=forticlient%20ems` -> 0, `forticlientems` -> 82. |
| `keywordExactMatch` | flag; with `keywordSearch=helix core` returns the exact phrase matches (2). |
| `cpeMatchString` | partial CPE name, e.g. `cpe:2.3:o:fortinet:fortios` -> 271 rows (that product only); `cpe:2.3:*:fortinet:forti*` -> 3620 rows (wildcard works on the product slot). |
| `cpeNameId` | UUID lookup. |
| `matchCriteriaId` | UUID of match string. |
| `lastModStartDate`/`lastModEndDate` | for incremental updates (<=120 days window). |
| `resultsPerPage` | max 10000 (we used 10000: docker = 4504 rows, 2.1 MB single response, ~1 s). `startIndex` for paging. |

### 3.2 Response shape (trimmed)
`GET .../cpes/2.0?keywordSearch=grafana&resultsPerPage=3`
```json
{"resultsPerPage":3,"startIndex":0,"totalResults":2432,"format":"NVD_CPE","version":"2.0",
 "timestamp":"2026-11-19T21:23:36.420",
 "products":[{"cpe":{"deprecated":true,
   "cpeName":"cpe:2.3:a:grafana:grafana:4.6.0:*:*:*:*:*:*:*",
   "cpeNameId":"DFB171DA-F8C7-45A3-A0A1-1A451F70C929",
   "lastModified":"2019-06-06T15:58:37.723","created":"2019-04-26T18:58:00.200",
   "titles":[{"title":"Grafana 4.6.0","lang":"en"}],
   "refs":[{"ref":"https://github.com/grafana/grafana/","type":"Version"}],
   "deprecatedBy":[{"cpeName":"cpe:2.3:a:grafana:grafana:4.6.0:-:*:*:*:*:*:*","cpeNameId":"..."}]}}]}
```
Each row is a **versioned CPE**, so there is no "distinct product" endpoint: you must aggregate client-side (split `cpeName` on `:`, fields 2/3/4 = part/vendor/product; beware escaped colons `\:` e.g. `mailcow\:` appeared as a product). Pagination: `startIndex += resultsPerPage` until `startIndex >= totalResults`; for a discovery call a single page of 10000 suffices for every test name (largest: docker 4504). Rate limit without key: 5 requests per rolling 30 s.
Empty result for an invalid combo returns HTTP 200 with `totalResults:0`; some invalid params return HTTP 404 with an empty body and the reason in the `message` response header (e.g. `message: Date range cannot exceed 120 days.` on the CVE API).

### 3.3 Other NVD endpoints
- **CPE Match Criteria API** `https://services.nvd.nist.gov/rest/json/cpematch/2.0` (params `matchStringSearch`, `cveId`, `matchCriteriaId`, `lastModStartDate`...; `keywordSearch` is NOT supported, returns empty). Example: `?matchStringSearch=cpe:2.3:a:grafana:loki&resultsPerPage=2` -> `totalResults:3`, each `matchString` has `criteria:"cpe:2.3:a:grafana:loki:*:*:*:*:*:*:*:*"`, `versionEndIncluding:"2.2.1"`, `status:"Active"`, `matches:[{cpeName,cpeNameId}...]`. Use: validation that a vendor:product is referenced by CVE configurations (i.e. at least one CVE applicability statement), and for expanding version ranges; NOT for free-text discovery.
- **CVE API 2.0** `.../cves/2.0`: `virtualMatchString=cpe:2.3:a:perforce:helix_core` -> 4 CVEs; `keywordSearch` searches descriptions (`ellucian colleague` -> 1 hit, WebAdvisor, not Colleague; `"xcp-ng"` -> 0); **date windows max 120 days**.
- **Bulk feeds** (HEAD checked 2026-11-19):
  - `https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz` -> 200, **85 MB** (gzip tar of paged JSON; full dictionary, rebuilt daily ~05:00 UTC).
  - `https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.tar.gz` -> 200, **892 MB**.
  - Old XML `official-cpe-dictionary_v2.3.xml.zip` -> **403** (retired).
  - Verdict: a local mirror of the dictionary is feasible (85 MB download; aggregated to distinct part/vendor/product it should be far smaller - size not measured) and removes rate-limit and the "squash" fuzzy cases (can do trigram/FTS locally). But for an MCP server that adds a product occasionally, **live API is simpler; use the feed as an optional offline index later**. Do not use the cpematch bulk file (892 MB).

## 4. Evidence: live discovery for each test name

Calls: `https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch={q}&resultsPerPage=10000`. Counts are CPE rows (versions), `dep` = deprecated rows.

| Query | rows | distinct products | Right answer(s) found | Noise |
|---|---|---|---|---|
| `apache http server` | 625 | 9 | `a:apache:http_server` (272, 3 dep) | `apache:traffic_server` 209, `e-guardian:siteguard` 48, `apache:james_server` 34, `oracle:weblogic_server` 33, `apache:mod_perl` 24, `rsa:authentication_agent_for_web`, `doris_mcp_server` |
| `fortios` | 333 | 3 | `o:fortinet:fortios` (271) | `a:fortinet:fortios-6k7k` 45, `fortios_ips_engine` 17 |
| `forticlient ems` | 0 | 0 | (nothing) | multi-word AND fails: CPE is squashed |
| `forticlientems` | 82 | 2 | `a:fortinet:forticlientems` (46) | `forticlientems_cloud` 36 (legit sibling) |
| `fortigate` | 93 | 93 | none: only `h:fortinet:fortigate-60f`-style per-model hardware | every row is its own "product". Software is `fortios` |
| `moodle` | 590 | 6 | `a:moodle:moodle` (578, 35 dep) | `moodle:virtual_programming_lab`, `saml_authentication` (first-party plugins), `lmsdoctor:2_factor_authentication`, `youracclaim:acclaim`, `moodle-block_sitenews_project:*` |
| `grafana` | 2432 | 17 | `a:grafana:grafana` (1289, 66 dep) | siblings: `oncall` 281, `pyroscope`, `agent`, `loki` 110, `grafana_operator`, `tempo`, `alloy`, `json_api_data_source`, `snowflake`, `worldmap_panel`, `grafana-image-renderer` |
| `loki` | 110 | 1 | `a:grafana:loki` | none (good) |
| `xcp-ng` | 0 | 0 | **no CPE** | n/a |
| `xcp` / `vates` | 77 / 0 | 25 / 0 | none | Fujitsu M10/M12 firmware XCP, EMC Documentum xCP, Carahsoft Jabber Xcp |
| `ceph` | 707 | 15 | `a:redhat:ceph` 334 (dep 0), `a:redhat:ceph_storage`, `a:linuxfoundation:ceph` 52, `a:ibm:storage_ceph` | `a:ceph:ceph-ansible` 293, `ceph-deploy`, `redhat:ceph_storage_osd/mon`, `o:mi:cepheus_firmware` (Xiaomi "Cepheus" substring match!). No `ceph:ceph` vendor product. |
| `docker` | 4504 | 87 | `a:docker:docker` 355 (1 dep), `docker:engine` 333, `docker:desktop` 190, `docker:docker_desktop` 143, `docker:command_line_interface` 226, `mobyproject:moby` 188 | `amirraminfar:dozzle` 552, `linuxserver:docker-heimdall` 308, `snyk:snyk_docker_cli` 274, `futo:immich` 238, ~70 more ("for Docker") |
| `nginx` | 3404 | 36 | `f5:nginx` 582, `f5:nginx_open_source` 504, `f5:nginx_plus` 129, `f5:nginx_ingress_controller` 221 | deprecated-only `nginx:nginx` 543 (all dep), `igor_sysoev:nginx` 383 (all dep), `nginx:njs` 51 (all dep); `nginxui:nginx_ui`, `jc21:nginx_proxy_manager`, `kubernetes:nginx_ingress_controller`, `cym1102:nginxwebui` |
| `ellucian colleague` | 0 | 0 | **no CPE** | `ellucian` alone: 22 rows, 5 products: `banner`, `banner_student`, `banner_web_tailor`, `banner_enterprise_identity_services`, `ethos_identity` (Colleague absent) |
| `perforce helix core` | 2 | 1 | `a:perforce:helix_core` (2 rows: `2023.2` and `-`) | none; `perforce` alone: 809 rows / 12 products |
| `arista eos` | 177 | 4 | `o:arista:eos` (174) | 3 `dcs-70xx_eos_software` per-model |
| `cisco ios xe` | 1229 | 21 | `o:cisco:ios_xe` (1094) | `ios_xe_sd-wan` 50 (legit sibling), 11 per-train deprecated `ios_xe_3.2sg`..., `a:ios_xe` all deprecated, `ios_xe_rom_monitor` |

**Keyword-only (no CPE) products:** XCP-ng, Ellucian Colleague. (Perforce Helix Core and Loki have CPEs but are small/niche.) Even where a CPE exists, NVD enrichment can lag (NVD CPE dictionary is manually curated; many CNA-scored CVEs have no NVD configurations yet), so a name-based fallback is needed for all products.

XCP-ng specifics: Vates publishes advisories ("VSA-2026-0xx") that cite upstream Xen XSAs (e.g. `CVE-2026-62428 / XSA-500`). The CVE record (assigner `XEN`) is `vendor:"Xen", product:"Xen", versions:[{"version":"consult Xen advisory XSA-500","status":"unknown"}]` - nothing in it says XCP-ng. NVD `keywordSearch=xcp-ng` -> 0 in CVE descriptions (also 0 for `xcp-ng xen` for the last 120 days). So XCP-ng CVEs come in as **Xen** CVEs plus Vates-authored ones (if Vates is a CNA; not verified). The tracked product needs a "related upstream" notion (`xen:xen`) with the agent making the call whether a Xen CVE applies. (Vates advisories: https://docs.vates.tech/security-advisories/advisories/ - could be a Phase 2 source.)

## 5. Evidence: CVE Program records (cvelistV5)

### 5.1 Access methods
- Single record, no auth: `https://cveawg.mitre.org/api/cve/CVE-2024-38475` (200, JSON 5.x). Also `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/38xxx/CVE-2024-38475.json` (path = year / floor(num/1000) + "xxx").
- **List/search**: `https://cveawg.mitre.org/api/cve?search=grafana` and `?cveState=PUBLISHED&count_only=1` -> `{"error":"BAD_REQUEST","message":"CVE-API-ORG header field required."}` i.e. authenticated CVE Services only (for CNAs). Public search is only via the cve.org website (not an API). So there is **no public free-text search by vendor/product**.
- **Change feed** (good for ingest): `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json` (~every few minutes: `{"fetchTime","numberOfChanges":28,"new":[{cveId,githubLink,dateUpdated}],"updated":[...]}`); `cves/deltaLog.json` is **31 MB** (do not poll it); release zips at `github.com/CVEProject/cvelistV5/releases/latest` -> `cve_2026-11-19_2100Z` (hourly/daily full snapshots; large).
- Consequence: matching CNA strings must be done by **sampling records** (found through NVD `virtualMatchString`, KEV IDs, or the delta feed) and learning the strings, or by normalized fuzzy match at ingest time against `affected[].vendor/product/packageName`.

### 5.2 Real strings used by CNAs (from `GET /api/cve/{id}`)
| CVE | Assigner (CNA) | `vendor` | `product` / `packageName` | `cpes` |
|---|---|---|---|---|
| CVE-2025-68686 (FortiOS, KEV) | fortinet | `Fortinet` | `FortiOS` | **yes**: `cpe:2.3:o:fortinet:fortios:7.6.1:*:*:*:*:*:*:*` ... (66 per-version) |
| CVE-2026-21643 (FortiClient EMS, KEV) | fortinet | `Fortinet` | `FortiClientEMS` | yes `cpe:2.3:a:fortinet:forticlientems:7.4.4:...` |
| CVE-2021-43798 (Grafana, KEV) | GitHub_M | `grafana` | `grafana` | none |
| CVE-2022-31107 (Grafana) | GitHub_M | `grafana` | `grafana` | none |
| CVE-2024-38475 (Apache httpd, KEV) | apache | `Apache Software Foundation` | `Apache HTTP Server` | none in CNA; **ADP (CISA-ADP)** adds `vendor:"apache" product:"http_server" cpes:["cpe:2.3:a:apache:http_server:2.4.0:*..."]` plus an unrelated `netapp:ontap_9` |
| CVE-2025-24813 (Tomcat) | apache | `Apache Software Foundation` | `Apache Tomcat` | none |
| CVE-2018-0174 (Cisco IOS XE, KEV) | cisco | `n/a` | `Cisco IOS and IOS XE` | none |
| CVE-2026-7473 (Arista EOS, KEV) | Arista | `Arista Networks` | `EOS` | none |
| CVE-2019-15752 (Docker Desktop, KEV) | mitre | `n/a` | `n/a` | none (no info at all) |
| CVE-2024-7347 (NGINX) | f5 | `F5` | `NGINX Open Source`, `NGINX Plus` (separate entries) | none |
| CVE-2025-67847 (Moodle) | fedora | *(absent)* | `packageName: "moodle"` (no `product`) | none; title "Moodle: moodle: remote code execution..." |
| CVE-2023-45849 (Helix Core) | Perforce | `Helix` (!) | `Helix Core` | none |
| CVE-2026-109430 (Ellucian WebAdvisor) | VulnCheck | `Ellucian` | `WebAdvisor` | none (Colleague CVEs not found) |
| CVE-2026-62428 (Xen, XSA-500) | XEN | `Xen` | `Xen` (versions: "consult Xen advisory XSA-500", status unknown) | none |
| CVE-2026-68082 (libceph) | Linux | `Linux` | `Linux` (only commit hashes as versions) | none |

Observations:
- The `affected[]` keys present: `vendor`, `product`, `defaultStatus`, `versions` (+ optionally `packageName`, `collectionURL`, `repo`, `modules`, `platforms`, `programFiles`, `cpes`). **`cpes` is rare**: present for Fortinet (and a few others), otherwise absent. CISA-ADP containers (`containers.adp[]`) frequently add proper `cpes` after the fact; those are the best structured cross-reference in the record. NVD also enriches via its own ADP.
- Vendor strings: legal/long forms (`Apache Software Foundation`, `Arista Networks`), lower-case (`grafana`), `n/a`, even `Helix` instead of Perforce. Product strings may include vendor prefix (`Apache HTTP Server`, `Cisco IOS and IOS XE`), omit it (`EOS`), have no space (`FortiClientEMS`), or be a combined list.
- The CNA identity (`cveMetadata.assignerShortName`: fortinet, apache, GitHub_M, Perforce...) is a useful extra signal: store `source_cna` per name and prefer a vendor's own CNA.
- Cisco/Fortinet CVEs are often *multi-product* in one record; per-record matching must iterate **all** `affected[]` entries.

## 6. Evidence: CISA KEV

URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` -> 1.86 MB (downloaded once; catalogVersion `2026.11.18`, count 1786).

Top-level keys: `title`, `catalogVersion`, `dateReleased`, `count`, `vulnerabilities[]`. Entry keys: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse` (`Known`/`Unknown`), `forensicTriage`?, `notes`, `cwes[]`. (No CPE, no ID beyond free-text vendor/product.)

Exact spellings (vendorProject | product, count of entries) for the test products, via local grep:
- Apache | **HTTP Server** (4); also Apache | Apache (1, junk), Tomcat 6, Struts 6 (+`Struts 1`,`Struts 2`), Solr 2, ActiveMQ 3, ...
- Fortinet | **FortiOS** (9), **FortiOS and FortiProxy** (4), **FortiOS and FortiADC** (1), **FortiOS and FortiProxy SSL-VPN** (1), **FortiClient EMS** (3), FortiMail, FortiManager, FortiSandbox, FortiWeb, **Multiple Products** (7)
- **Grafana Labs | Grafana** (2)
- Arista | **Extensible Operating System** (1) (the EOS product!); Arista | VeloCloud Orchestrator (3)
- Docker | **Desktop Community Edition** (1)
- Perforce | Puppet Enterprise (1) (not Helix Core)
- Cisco IOS XE family (all vendorProject `Cisco`): `IOS and IOS XE Software` 14, `IOS XE Software` 2, `IOS XE Web UI` 1, `Cisco IOS XE Web UI` 1, `IOS and IOS XE` 4, `IOS Software and Cisco IOS XE Software` 3, `IOS, IOS XR, and IOS XE` 1, `IOS, XR, and XE Software` 2, plus `IOS` 2, `IOS Software` 4, `IOS software` 6, `IOS XR` 6 - spelling inconsistent *within* Cisco (including `Catalyst SD-WAN Manger` typo).
- **None in KEV** (zero rows): Moodle, Loki, XCP-ng, Ceph, nginx, Ellucian Colleague, Helix Core.
- Matching rule consequence: KEV `product` is frequently a *list* ("A and B", "A, B, and C") so split on ` and `, `,` and normalize each; and the entry name may include the vendor (`Cisco IOS XE Web UI`).

## 7. Open questions / follow-ups
- Does a CPE for the product's *newest* CVEs arrive in time? NVD enrichment lag means the CPE route alone misses fresh CVEs (check `vulnStatus: Awaiting Analysis`); the CNA-name route covers them, hence storing both.
- Whether Vates is a CNA (not verified); XCP-ng's CVEs ride on Xen XSAs.
- Ellucian Colleague: no CVEs found at all via NVD description search; probably keyword on vendor `Ellucian` (VulnCheck CNA uses vendor `Ellucian`, product `WebAdvisor`/`Banner`...). Propose vendor-level tracking (`vendor_keywords:["ellucian"]`) with an agent-side relevance filter on product.
- Rate limits: NVD 5 req/30 s unkeyed (50 w/ key). One add_tracked uses ~2-4 keyword queries + 1-3 probe queries + 3-5 `cveawg` GETs. Budget for 429/503 with backoff and cache results by query (24 h).
- Consider shipping a small curated alias seed file (FortiGate->fortios, EOS->arista:eos, "FortiClient EMS"->forticlientems, Helix Core->perforce:helix_core, XCP-ng->xen) to bootstrap; the discovery pipeline should still work without it.
