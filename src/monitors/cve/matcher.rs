//! Links CVEs to tracked products. Pure and allocation-light: build
//! [`CompiledProduct`]s once per sync ([`compile_all`]) and run
//! [`match_cve`] over each CVE's [`CveFacts`].
//!
//! # Rules (first hit wins, in this priority order)
//!
//! 1. `cpe`: any affected row (cna/adp/nvd) has `cpe_vendor:cpe_product` equal to one
//!    of the product's `cpes` (case-insensitive, exact).
//! 2. `cna_name`: an affected row's `(vendor, product)` matches a stored `cna_names`
//!    entry, alias or the display name. Products are compared in squashed form
//!    (`FortiClient EMS` == `FortiClientEMS`) after splitting list-like strings
//!    (`"IOS and IOS XE"`), stripping a leading vendor from the product
//!    (`Apache HTTP Server` ~ `HTTP Server`), trailing edition words (`software`,
//!    `edition`, ...) and, for 3+ word row names, the initialism
//!    (`Extensible Operating System` ~ `EOS`). Never substring matches.
//!    Vendors are compared via `normalize_vendor` (`Arista Networks, Inc.` == `arista`)
//!    against every vendor the product knows (cna names, cpe vendors, KEV vendors).
//!    A known row vendor that is NOT one of those rejects the match when the stored
//!    name has a vendor. When the row vendor is unknown (`n/a`, empty, ...) or the stored
//!    name has no vendor (aliases), the match is product-only and only allowed if the
//!    matched form is *distinctive*: at least 5 squashed characters and not a generic
//!    word (`core`, `server`, `linux`, ...). So `n/a` + `Cisco IOS and IOS XE` matches
//!    `IOS XE` (`iosxe`), but a bare `EOS` with unknown vendor does not.
//! 3. `kev_name`: the KEV row (vendorProject, product) matches `kev_names` (same
//!    comparison as 2) or any cna name/alias. `Multiple Products` is ignored.
//! 4. `keyword`: a keyword/phrase occurs in the description with word boundaries
//!    (case-insensitive; `-`, `_`, spaces inside a phrase are interchangeable), no
//!    `exclude_keywords` occurs, and the occurrence is not third-party noise: followed by
//!    `plugin|module|extension|...`, preceded by `<plugin noun> for [the]`, or the CVE's
//!    own affected product is named `... for <keyword>` (`Dozzle for Docker`).
//!
//! `match_mode = keyword` products skip rules 1-2 (only 3 and 4 apply).
//!
//! Version filtering is intentionally absent: we track products, not versions. If it is
//! ever needed, port vigil's CPE range check (`versionStartIncluding` ..
//! `versionEndExcluding` on the `cve_affected.versions` JSON) as an extra predicate on
//! rule 1 only.

use std::collections::HashSet;

use regex::Regex;

use super::normalize::{
    is_unknown, is_unknown_product, norm, normalize_vendor, split_product_list, strip_vendor_prefix,
};
use crate::model::{MatchMode, TrackedProduct};

/// Why a CVE matched a product; stored in `cve_product_matches.matched_by`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedBy {
    Cpe,
    CnaName,
    KevName,
    Keyword,
}

impl MatchedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpe => "cpe",
            Self::CnaName => "cna_name",
            Self::KevName => "kev_name",
            Self::Keyword => "keyword",
        }
    }
}

/// A (vendor, product) pair as written by some source, pre-processed for matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRow {
    /// `normalize_vendor` token form; `None` for unknown vendors (`n/a`...).
    vendor: Option<String>,
    /// Normalized whole product followed by its list segments. Empty if unknown.
    segs: Vec<String>,
}

impl NameRow {
    pub fn new(vendor: Option<&str>, product: Option<&str>) -> Self {
        let vendor = vendor
            .filter(|v| !is_unknown(v))
            .map(normalize_vendor)
            .filter(|v| !v.is_empty());
        let mut segs = Vec::new();
        if let Some(p) = product.filter(|p| !is_unknown_product(p)) {
            let whole = norm(p);
            if !whole.is_empty() {
                for part in split_product_list(p) {
                    let n = norm(&part);
                    if !n.is_empty() && n != whole {
                        segs.push(n);
                    }
                }
                segs.insert(0, whole);
            }
        }
        Self { vendor, segs }
    }
}

/// One `cve_affected` row, reduced to what matching needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedFacts {
    name: NameRow,
    /// Lowercased `(cpe_vendor, cpe_product)`.
    cpe: Option<(String, String)>,
}

impl AffectedFacts {
    pub fn new(
        vendor_raw: Option<&str>,
        product_raw: Option<&str>,
        cpe_vendor: Option<&str>,
        cpe_product: Option<&str>,
    ) -> Self {
        let cpe = match (cpe_vendor, cpe_product) {
            (Some(v), Some(p)) if !v.is_empty() && !p.is_empty() => {
                Some((v.to_lowercase(), p.to_lowercase()))
            }
            _ => None,
        };
        Self {
            name: NameRow::new(vendor_raw, product_raw),
            cpe,
        }
    }
}

/// Everything the matcher needs to know about one CVE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveFacts {
    pub cve_id: String,
    pub description: String,
    pub affected: Vec<AffectedFacts>,
    /// KEV `(vendorProject, product)` if the CVE is in the KEV catalog.
    pub kev: Option<(String, String)>,
}

/// Stored name (cna name, alias or KEV name) in comparable form.
#[derive(Debug, Clone)]
struct NameKey {
    /// Squashed `normalize_vendor`; `None` if the stored name has no vendor.
    vendor: Option<String>,
    forms: HashSet<String>,
}

struct KeywordSet {
    re: Regex,
    norms: Vec<String>,
}

/// Per-product matcher, built once per sync.
pub struct CompiledProduct {
    pub id: String,
    mode: MatchMode,
    cpe_keys: HashSet<(String, String)>,
    /// All vendors the product is known under (token form, deduped).
    vendors: Vec<String>,
    vendor_squash: HashSet<String>,
    names: Vec<NameKey>,
    kev: Vec<NameKey>,
    keywords: Option<KeywordSet>,
    exclude: Option<Regex>,
}

const EDITION_NOISE: &[&str] = &[
    "software",
    "edition",
    "version",
    "series",
    "appliance",
    "firmware",
];

/// Squashed names too generic to match on without a vendor.
const GENERIC: &[&str] = &[
    "core",
    "desktop",
    "edge",
    "server",
    "client",
    "agent",
    "linux",
    "windows",
    "web",
    "cloud",
    "platform",
    "manager",
    "studio",
    "portal",
    "admin",
    "enterprise",
    "community",
    "kernel",
    "software",
    "plugin",
    "plugins",
    "module",
    "extension",
    "theme",
    "application",
    "system",
    "android",
    "macos",
    "network",
    "service",
    "services",
    "framework",
    "library",
    "tools",
    "toolkit",
    "console",
    "gateway",
    "router",
    "switch",
    "firewall",
    "controller",
];

const PLUGIN_NOUNS: &[&str] = &[
    "plugin",
    "plugins",
    "module",
    "modules",
    "extension",
    "extensions",
    "add-on",
    "addon",
    "theme",
    "block",
    "connector",
    "integration",
    "widget",
    "exporter",
];

fn is_distinctive(form: &str) -> bool {
    form.chars().count() >= 5 && !GENERIC.contains(&form)
}

fn squash_n(n: &str) -> String {
    n.replace(' ', "")
}

fn trim_edition_noise(n: &str) -> &str {
    let mut cur = n;
    while let Some((head, last)) = cur.rsplit_once(' ') {
        if EDITION_NOISE.contains(&last) {
            cur = head;
        } else {
            break;
        }
    }
    cur
}

fn initialism(n: &str) -> Option<String> {
    let toks: Vec<&str> = n.split(' ').collect();
    (toks.len() >= 3).then(|| toks.iter().filter_map(|t| t.chars().next()).collect())
}

/// Comparable squashed forms of a normalized segment list.
fn forms(segs: &[String], vendors: &[&str], with_initialism: bool) -> HashSet<String> {
    let mut out = HashSet::new();
    for seg in segs {
        let mut variants: Vec<String> = vec![seg.clone()];
        for v in vendors {
            let st = strip_vendor_prefix(v, seg);
            if st != *seg {
                variants.push(st);
            }
        }
        for v in variants {
            let t = trim_edition_noise(&v);
            for s in [v.as_str(), t] {
                let sq = squash_n(s);
                if !sq.is_empty() {
                    out.insert(sq);
                }
            }
            if with_initialism && let Some(i) = initialism(trim_edition_noise(&v)) {
                out.insert(i);
            }
        }
    }
    out
}

/// Space-delimited comparable forms of one affected row (` form1 form2 `, empty if
/// the product is unknown), stored in `cve_affected.product_keys` so the DB
/// prefilter can find rows whose matcher forms differ from `squash(product_raw)`
/// (list-like products, vendor prefixes, edition words, initialisms).
pub fn row_keys(vendor: Option<&str>, product: &str) -> String {
    let row = NameRow::new(vendor, Some(product));
    if row.segs.is_empty() {
        return String::new();
    }
    let vs: Vec<&str> = row.vendor.iter().map(String::as_str).collect();
    let mut f: Vec<String> = forms(&row.segs, &vs, true).into_iter().collect();
    f.sort();
    format!(" {} ", f.join(" "))
}

/// Boundary-delimited alternation of phrases; `Ok(None)` if no usable phrase, `Err` if the
/// resulting pattern does not compile (e.g. exceeds the regex size limit).
fn phrase_regex_checked(phrases: &[String]) -> Result<Option<(Regex, Vec<String>)>, regex::Error> {
    let mut parts = Vec::new();
    let mut norms = Vec::new();
    for p in phrases {
        let toks: Vec<String> = norm(p)
            .split(' ')
            .filter(|t| !t.is_empty())
            .map(regex::escape)
            .collect();
        if toks.is_empty() {
            continue;
        }
        norms.push(norm(p));
        parts.push(toks.join(r"[\s_\-]+"));
    }
    if parts.is_empty() {
        return Ok(None);
    }
    let pat = format!(
        r"(?i)(?:^|[^\p{{L}}\p{{N}}])({})(?:[^\p{{L}}\p{{N}}]|$)",
        parts.join("|")
    );
    Regex::new(&pat).map(|re| Some((re, norms)))
}

/// Like [`phrase_regex_checked`], but a failure is logged (matching by that list is then
/// disabled) instead of silently ignored. Products are validated when saved
/// ([`check_patterns`]), so this only fires for rows that predate the check.
fn phrase_regex(phrases: &[String]) -> Option<(Regex, Vec<String>)> {
    match phrase_regex_checked(phrases) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "keyword pattern does not compile; matching by it is disabled");
            None
        }
    }
}

/// Verify that a product's keyword lists compile; the message names the offending list.
pub fn check_patterns(p: &TrackedProduct) -> Result<(), String> {
    for (label, list) in [
        ("keywords", &p.keywords),
        ("exclude_keywords", &p.exclude_keywords),
    ] {
        phrase_regex_checked(list).map_err(|e| {
            format!("{label} cannot be compiled into a matcher ({e}); use fewer or shorter phrases")
        })?;
    }
    Ok(())
}

impl CompiledProduct {
    pub fn new(p: &TrackedProduct) -> Self {
        let mut vendors: Vec<String> = Vec::new();
        let mut push_vendor = |v: &str| {
            if !is_unknown(v) {
                let n = normalize_vendor(v);
                if !n.is_empty() && !vendors.contains(&n) {
                    vendors.push(n);
                }
            }
        };
        for c in &p.cna_names {
            push_vendor(&c.vendor);
        }
        for c in &p.cpes {
            push_vendor(&c.vendor);
        }
        for k in &p.kev_names {
            push_vendor(&k.vendor_project);
        }
        let vendor_squash: HashSet<String> = vendors.iter().map(|v| squash_n(v)).collect();
        let vrefs: Vec<&str> = vendors.iter().map(String::as_str).collect();

        let key = |vendor: Option<&str>, product: &str| -> Option<NameKey> {
            let row = NameRow::new(vendor, Some(product));
            if row.segs.is_empty() {
                return None;
            }
            // Stored side never uses initialisms (they would be too loose).
            Some(NameKey {
                vendor: row.vendor.as_deref().map(squash_n),
                forms: forms(&row.segs, &vrefs, false),
            })
        };
        let mut names: Vec<NameKey> = p
            .cna_names
            .iter()
            .filter_map(|c| key(Some(&c.vendor), &c.product))
            .collect();
        names.extend(p.aliases.iter().filter_map(|a| key(None, a)));
        // The product's own display name is an implicit alias.
        names.extend(key(None, &p.name));
        let kev = p
            .kev_names
            .iter()
            .filter_map(|k| key(Some(&k.vendor_project), &k.product))
            .collect();

        let kw = phrase_regex(&p.keywords).map(|(re, norms)| KeywordSet { re, norms });
        let cpe_keys = p
            .cpes
            .iter()
            .map(|c| (c.vendor.to_lowercase(), c.product.to_lowercase()))
            .collect();
        Self {
            id: p.id.clone(),
            mode: p.match_mode,
            cpe_keys,
            vendors,
            vendor_squash,
            names,
            kev,
            keywords: kw,
            exclude: phrase_regex(&p.exclude_keywords).map(|(r, _)| r),
        }
    }

    /// Squashed name forms and squashed vendors, used by the DB candidate prefilter.
    pub fn name_forms(&self) -> (HashSet<String>, Vec<String>) {
        let mut f = HashSet::new();
        for k in self.names.iter().chain(&self.kev) {
            f.extend(k.forms.iter().cloned());
        }
        (f, self.vendor_squash.iter().cloned().collect())
    }

    pub fn cpe_keys(&self) -> impl Iterator<Item = &(String, String)> {
        self.cpe_keys.iter()
    }

    /// Whether rules 1-2 (cpe, cna names) apply to this product.
    pub fn uses_names(&self) -> bool {
        self.mode == MatchMode::CpeNames
    }

    pub fn keyword_regex(&self) -> Option<&Regex> {
        self.keywords.as_ref().map(|k| &k.re)
    }

    /// Does the KEV `(vendorProject, product)` match this product's KEV/name keys?
    pub fn matches_kev(&self, vendor_project: &str, product: &str) -> bool {
        let row = NameRow::new(Some(vendor_project), Some(product));
        self.keys_match(&self.kev, &row)
            || (self.uses_names() && self.keys_match(&self.names, &row))
    }

    fn keys_match(&self, keys: &[NameKey], row: &NameRow) -> bool {
        if row.segs.is_empty() {
            return false;
        }
        let mut vrefs: Vec<&str> = self.vendors.iter().map(String::as_str).collect();
        if let Some(v) = &row.vendor {
            vrefs.push(v);
        }
        let row_forms = forms(&row.segs, &vrefs, true);
        let row_vendor = row.vendor.as_deref().map(squash_n);
        let vendor_known = row.vendor.as_deref().is_some_and(|rv| {
            // "Moodle Pty" still starts with the known vendor "moodle".
            self.vendors
                .iter()
                .any(|v| rv == v || rv.starts_with(&format!("{v} ")))
        });
        for key in keys {
            for f in key.forms.iter().filter(|f| row_forms.contains(*f)) {
                let ok = match &row_vendor {
                    Some(rv) if self.vendor_squash.contains(rv) || vendor_known => true,
                    Some(rv) if key.vendor.as_ref() == Some(rv) => true,
                    Some(_) if key.vendor.is_some() || !self.vendors.is_empty() => false,
                    _ => is_distinctive(f),
                };
                if ok {
                    return true;
                }
            }
        }
        false
    }

    /// Best reason `cve` matches this product, if any.
    pub fn matches(&self, cve: &CveFacts) -> Option<MatchedBy> {
        if self.uses_names() {
            if cve
                .affected
                .iter()
                .any(|a| a.cpe.as_ref().is_some_and(|k| self.cpe_keys.contains(k)))
            {
                return Some(MatchedBy::Cpe);
            }
            if cve
                .affected
                .iter()
                .any(|a| self.keys_match(&self.names, &a.name))
            {
                return Some(MatchedBy::CnaName);
            }
        }
        if let Some((v, p)) = &cve.kev
            && self.matches_kev(v, p)
        {
            return Some(MatchedBy::KevName);
        }
        if self.keyword_hit(cve) {
            return Some(MatchedBy::Keyword);
        }
        None
    }

    fn keyword_hit(&self, cve: &CveFacts) -> bool {
        let Some(kw) = &self.keywords else {
            return false;
        };
        let desc = &cve.description;
        if self.exclude.as_ref().is_some_and(|e| e.is_match(desc)) {
            return false;
        }
        if !kw.re.is_match(desc) || third_party_structured(&cve.affected, &kw.norms) {
            return false;
        }
        kw.re
            .captures_iter(desc)
            .filter_map(|c| c.get(1))
            .any(|m| !third_party_context(desc, m.start(), m.end()))
    }
}

/// True if an affected product is literally named `... for <keyword>`.
fn third_party_structured(rows: &[AffectedFacts], kw_norms: &[String]) -> bool {
    rows.iter().any(|a| {
        a.name.segs.first().is_some_and(|p| {
            kw_norms.iter().any(|k| {
                [format!(" for {k}"), format!(" for the {k}")]
                    .iter()
                    .any(|n| p.ends_with(n.as_str()) || p.contains(&format!("{n} ")))
            })
        })
    })
}

/// True if the keyword occurrence at `[s, e)` reads as "<plugin> for X" / "X plugin".
fn third_party_context(desc: &str, s: usize, e: usize) -> bool {
    let after: String = desc[e..]
        .chars()
        .take(40)
        .collect::<String>()
        .to_lowercase();
    if let Some(w) = after.split_whitespace().next()
        && PLUGIN_NOUNS.contains(
            &w.split('_')
                .next()
                .unwrap_or(w)
                .trim_matches(|c: char| !c.is_alphanumeric() && c != '-'),
        )
    {
        return true;
    }
    let tail: Vec<char> = desc[..s].chars().rev().take(60).collect();
    let before: String = tail.into_iter().rev().collect::<String>().to_lowercase();
    let mut it = before.split_whitespace().rev();
    let mut w = it.next();
    if w == Some("the") {
        w = it.next();
    }
    if w == Some("for") {
        return it
            .next()
            .is_some_and(|n| PLUGIN_NOUNS.contains(&n.trim_matches(',')));
    }
    false
}

/// Compile every product once (per sync / per rematch).
pub fn compile_all(products: &[TrackedProduct]) -> Vec<CompiledProduct> {
    products.iter().map(CompiledProduct::new).collect()
}

/// All products `cve` matches, with the reason.
pub fn match_cve(products: &[CompiledProduct], cve: &CveFacts) -> Vec<(String, MatchedBy)> {
    products
        .iter()
        .filter_map(|p| p.matches(cve).map(|m| (p.id.clone(), m)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CnaName, CpeRef, KevName};

    fn product(id: &str, name: &str) -> TrackedProduct {
        TrackedProduct {
            id: id.into(),
            name: name.into(),
            cpes: vec![],
            cna_names: vec![],
            kev_names: vec![],
            aliases: vec![],
            keywords: vec![],
            exclude_keywords: vec![],
            match_mode: MatchMode::CpeNames,
            confirmed_by: "test".into(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }
    fn cpe(v: &str, p: &str) -> CpeRef {
        CpeRef {
            part: "a".into(),
            vendor: v.into(),
            product: p.into(),
            note: None,
        }
    }
    fn cna(v: &str, p: &str) -> CnaName {
        CnaName {
            vendor: v.into(),
            product: p.into(),
            source_cna: None,
        }
    }
    fn kev(v: &str, p: &str) -> KevName {
        KevName {
            vendor_project: v.into(),
            product: p.into(),
        }
    }
    fn row(v: Option<&str>, p: Option<&str>) -> AffectedFacts {
        AffectedFacts::new(v, p, None, None)
    }
    fn cpe_row(v: &str, p: &str) -> AffectedFacts {
        AffectedFacts::new(None, None, Some(v), Some(p))
    }
    fn cve(desc: &str, affected: Vec<AffectedFacts>, kev: Option<(&str, &str)>) -> CveFacts {
        CveFacts {
            cve_id: "CVE-2026-0001".into(),
            description: desc.into(),
            affected,
            kev: kev.map(|(v, p)| (v.to_owned(), p.to_owned())),
        }
    }
    fn m(p: &TrackedProduct, c: &CveFacts) -> Option<MatchedBy> {
        CompiledProduct::new(p).matches(c)
    }

    fn forticlient() -> TrackedProduct {
        let mut p = product("forticlient-ems", "FortiClient EMS");
        p.cpes = vec![cpe("fortinet", "forticlientems")];
        p.cna_names = vec![cna("Fortinet", "FortiClientEMS")];
        p.kev_names = vec![kev("Fortinet", "FortiClient EMS")];
        p
    }

    #[test]
    fn forticlient_ems_all_sources() {
        let p = forticlient();
        let by_cpe = cve("x", vec![cpe_row("fortinet", "forticlientems")], None);
        assert_eq!(m(&p, &by_cpe), Some(MatchedBy::Cpe));
        let by_cna = cve(
            "x",
            vec![row(Some("Fortinet"), Some("FortiClientEMS"))],
            None,
        );
        assert_eq!(m(&p, &by_cna), Some(MatchedBy::CnaName));
        // CNA spelled with a space squashes to the same form
        let by_cna2 = cve(
            "x",
            vec![row(Some("fortinet"), Some("FortiClient EMS"))],
            None,
        );
        assert_eq!(m(&p, &by_cna2), Some(MatchedBy::CnaName));
        let by_kev = cve("x", vec![], Some(("Fortinet", "FortiClient EMS")));
        assert_eq!(m(&p, &by_kev), Some(MatchedBy::KevName));
        // sibling products of the same vendor do not match
        let other = cve(
            "x",
            vec![
                row(Some("Fortinet"), Some("FortiOS")),
                cpe_row("fortinet", "fortios"),
            ],
            Some(("Fortinet", "FortiOS and FortiProxy")),
        );
        assert_eq!(m(&p, &other), None);
        let multi = cve("x", vec![], Some(("Fortinet", "Multiple Products")));
        assert_eq!(m(&p, &multi), None);
    }

    #[test]
    fn fortios_matches_kev_list() {
        let mut p = product("fortios", "FortiOS");
        p.kev_names = vec![kev("Fortinet", "FortiOS")];
        let c = cve("x", vec![], Some(("Fortinet", "FortiOS and FortiProxy")));
        assert_eq!(m(&p, &c), Some(MatchedBy::KevName));
    }

    #[test]
    fn arista_eos() {
        let mut p = product("arista-eos", "Arista EOS");
        p.cpes = vec![cpe("arista", "eos")];
        p.cna_names = vec![cna("Arista Networks", "EOS")];
        p.kev_names = vec![kev("Arista", "Extensible Operating System")];
        let by_cna = cve("x", vec![row(Some("Arista Networks"), Some("EOS"))], None);
        assert_eq!(m(&p, &by_cna), Some(MatchedBy::CnaName));
        let by_kev = cve("x", vec![], Some(("Arista", "Extensible Operating System")));
        assert_eq!(m(&p, &by_kev), Some(MatchedBy::KevName));
        // unknown vendor + 3-letter product is not distinctive
        assert_eq!(m(&p, &cve("x", vec![row(None, Some("EOS"))], None)), None);
        // a different vendor's EOS must not match
        let acme = cve("x", vec![row(Some("Acme"), Some("EOS"))], None);
        assert_eq!(m(&p, &acme), None);
        // KEV initialism matches even if kev_names was left empty
        let mut q = p.clone();
        q.kev_names.clear();
        assert_eq!(m(&q, &by_kev), Some(MatchedBy::KevName));
        let other = cve("x", vec![], Some(("Other", "Extensible Operating System")));
        assert_eq!(m(&q, &other), None);
    }

    #[test]
    fn ceph_does_not_match_kernel_libceph() {
        let mut p = product("ceph", "Ceph");
        p.cpes = vec![cpe("redhat", "ceph")];
        p.cna_names = vec![cna("Red Hat", "Ceph")];
        p.keywords = vec!["ceph".into()];
        p.exclude_keywords = vec!["linux kernel".into()];
        let linux = row(Some("Linux"), Some("Linux"));
        let libceph = cve(
            "In the Linux kernel, the following vulnerability has been resolved: libceph: fix \
             crash in osd client",
            vec![linux.clone()],
            None,
        );
        assert_eq!(m(&p, &libceph), None);
        // "ceph:" subsystem prefix hits the keyword but the exclusion suppresses it
        let ceph_sub = cve(
            "In the Linux kernel, the following vulnerability has been resolved: ceph: fix a \
             race",
            vec![linux],
            None,
        );
        assert_eq!(m(&p, &ceph_sub), None);
        let real = cve("Ceph RGW allows an attacker to read objects", vec![], None);
        assert_eq!(m(&p, &real), Some(MatchedBy::Keyword));
        let by_cpe = cve("x", vec![cpe_row("redhat", "ceph")], None);
        assert_eq!(m(&p, &by_cpe), Some(MatchedBy::Cpe));
    }

    #[test]
    fn third_party_plugin_noise() {
        let mut moodle = product("moodle", "Moodle");
        moodle.cpes = vec![cpe("moodle", "moodle")];
        moodle.keywords = vec!["moodle".into()];
        let core = cve(
            "Moodle 4.1 allows remote attackers to run code",
            vec![],
            None,
        );
        assert_eq!(m(&moodle, &core), Some(MatchedBy::Keyword));
        for d in [
            "XSS in the Foo Bar plugin for Moodle before 1.2",
            "SQL injection in a theme for the Moodle platform",
            "The Moodle plugin foo_bar allows XSS",
            "Moodle block_sitenews module allows XSS",
        ] {
            assert_eq!(m(&moodle, &cve(d, vec![], None)), None, "{d}");
        }

        let mut docker = product("docker", "Docker");
        docker.cpes = vec![cpe("docker", "docker")];
        docker.keywords = vec!["docker".into()];
        let dozzle = cve(
            "Dozzle for Docker before 8.0 has an XSS in the log viewer; run it with docker run",
            vec![row(Some("amir20"), Some("Dozzle for Docker"))],
            None,
        );
        assert_eq!(m(&docker, &dozzle), None);
        let engine = cve("Docker Engine before 25 mishandles volumes", vec![], None);
        assert_eq!(m(&docker, &engine), Some(MatchedBy::Keyword));
        // word boundary: "Dockerfile" is not "docker"
        assert_eq!(
            m(&docker, &cve("A Dockerfile parser bug", vec![], None)),
            None
        );
    }

    #[test]
    fn cisco_vendor_na() {
        let mut p = product("cisco-ios-xe", "Cisco IOS XE");
        p.cpes = vec![cpe("cisco", "ios_xe")];
        p.cna_names = vec![cna("Cisco", "IOS XE")];
        p.kev_names = vec![kev("Cisco", "IOS XE Software")];
        // CNA vendor "n/a", product carries the vendor and a list
        let c = cve(
            "x",
            vec![row(Some("n/a"), Some("Cisco IOS and IOS XE"))],
            None,
        );
        assert_eq!(m(&p, &c), Some(MatchedBy::CnaName));
        // IOS XR is a different product
        let xr = cve(
            "x",
            vec![row(Some("n/a"), Some("Cisco IOS XR Software"))],
            None,
        );
        assert_eq!(m(&p, &xr), None);
        let kev_row = cve("x", vec![], Some(("Cisco", "IOS and IOS XE Software")));
        assert_eq!(m(&p, &kev_row), Some(MatchedBy::KevName));
        let kev_xr = cve("x", vec![], Some(("Cisco", "IOS XR")));
        assert_eq!(m(&p, &kev_xr), None);
        // fully unknown rows never match
        let na = cve("x", vec![row(Some("n/a"), Some("n/a"))], None);
        assert_eq!(m(&p, &na), None);
    }

    #[test]
    fn xcp_ng_via_xen_and_keywords() {
        let mut p = product("xcp-ng", "XCP-ng");
        p.cna_names = vec![cna("Xen", "Xen")];
        p.keywords = vec!["xcp-ng".into(), "xcpng".into(), "vates".into()];
        p.exclude_keywords = vec!["fujitsu".into(), "documentum".into()];
        let xen = cve("x", vec![row(Some("Xen"), Some("Xen"))], None);
        assert_eq!(m(&p, &xen), Some(MatchedBy::CnaName));
        let vates = cve(
            "Vates XCP-ng 8.3 ships a vulnerable toolstack",
            vec![],
            None,
        );
        assert_eq!(m(&p, &vates), Some(MatchedBy::Keyword));
        let spaced = cve("The XCP ng hypervisor ...", vec![], None);
        assert_eq!(m(&p, &spaced), Some(MatchedBy::Keyword));
        let fujitsu = cve("Fujitsu SPARC M10 XCP firmware vulnerability", vec![], None);
        assert_eq!(m(&p, &fujitsu), None);
        let documentum = cve("EMC Documentum xCP Designer flaw", vec![], None);
        assert_eq!(m(&p, &documentum), None);

        // keyword mode ignores cna names / cpes
        let mut k = p.clone();
        k.match_mode = MatchMode::Keyword;
        assert_eq!(m(&k, &xen), None);
        assert_eq!(m(&k, &vates), Some(MatchedBy::Keyword));
    }

    #[test]
    fn keyword_mode_still_uses_kev_names() {
        let mut k = product("thing", "Thing");
        k.match_mode = MatchMode::Keyword;
        k.kev_names = vec![kev("Acme", "Thing Server")];
        let c = cve("x", vec![], Some(("Acme", "Thing Server")));
        assert_eq!(m(&k, &c), Some(MatchedBy::KevName));
    }

    #[test]
    fn grafana_vendor_suffix_and_siblings() {
        let mut p = product("grafana", "Grafana");
        p.cpes = vec![cpe("grafana", "grafana")];
        p.cna_names = vec![cna("grafana", "grafana")];
        p.kev_names = vec![kev("Grafana Labs", "Grafana")];
        let kev_row = cve("x", vec![], Some(("Grafana Labs", "Grafana")));
        assert_eq!(m(&p, &kev_row), Some(MatchedBy::KevName));
        let loki = cve(
            "x",
            vec![row(Some("Grafana Labs"), Some("Grafana Loki"))],
            None,
        );
        assert_eq!(m(&p, &loki), None);
        let cna_row = cve("x", vec![row(Some("Grafana Labs"), Some("Grafana"))], None);
        assert_eq!(m(&p, &cna_row), Some(MatchedBy::CnaName));
    }

    #[test]
    fn priority_cpe_over_names() {
        let p = forticlient();
        let c = cve(
            "x",
            vec![
                row(Some("Fortinet"), Some("FortiClientEMS")),
                cpe_row("fortinet", "forticlientems"),
            ],
            Some(("Fortinet", "FortiClient EMS")),
        );
        assert_eq!(m(&p, &c), Some(MatchedBy::Cpe));
    }

    #[test]
    fn match_cve_over_many() {
        let mut moodle = product("moodle", "Moodle");
        moodle.cpes = vec![cpe("moodle", "moodle")];
        let ps = compile_all(&[forticlient(), moodle]);
        let c = cve("x", vec![cpe_row("moodle", "moodle")], None);
        assert_eq!(
            match_cve(&ps, &c),
            vec![("moodle".to_string(), MatchedBy::Cpe)]
        );
    }

    #[test]
    fn vendor_name_variants_are_not_rejected() {
        // Product knows only its CPE vendor ("grafana"); CNAs write corporate names.
        let mut g = product("grafana", "Grafana");
        g.cpes = vec![cpe("grafana", "grafana")];
        g.cna_names = vec![cna("Grafana", "Grafana")];
        for v in ["Grafana Labs", "Grafana", "GRAFANA LABS, INC.", "grafana"] {
            let c = cve("x", vec![row(Some(v), Some("Grafana"))], None);
            assert_eq!(m(&g, &c), Some(MatchedBy::CnaName), "vendor {v}");
        }

        let mut a = product("apache-http-server", "Apache HTTP Server");
        a.cpes = vec![cpe("apache", "http_server")];
        a.cna_names = vec![cna("Apache", "HTTP Server")];
        for v in [
            "Apache Software Foundation",
            "The Apache Software Foundation",
            "apache",
            "Apache",
        ] {
            for p in ["Apache HTTP Server", "HTTP Server"] {
                let c = cve("x", vec![row(Some(v), Some(p))], None);
                assert_eq!(m(&a, &c), Some(MatchedBy::CnaName), "{v} / {p}");
            }
        }
        // Different vendor with the same product name is still rejected.
        let other = cve("x", vec![row(Some("Acme Corp"), Some("HTTP Server"))], None);
        assert_eq!(m(&a, &other), None);

        let mut f = product("fortios", "FortiOS");
        f.cpes = vec![cpe("fortinet", "fortios")];
        f.cna_names = vec![cna("Fortinet", "FortiOS")];
        for v in ["Fortinet, Inc.", "Fortinet Inc", "fortinet", "Fortinet"] {
            for p in ["FortiOS", "Fortinet FortiOS"] {
                let c = cve("x", vec![row(Some(v), Some(p))], None);
                assert_eq!(m(&f, &c), Some(MatchedBy::CnaName), "{v} / {p}");
            }
        }
        let mut mo = product("moodle", "Moodle");
        mo.cpes = vec![cpe("moodle", "moodle")];
        mo.cna_names = vec![cna("Moodle", "Moodle")];
        let c = cve("x", vec![row(Some("Moodle Pty Ltd"), Some("Moodle"))], None);
        assert_eq!(m(&mo, &c), Some(MatchedBy::CnaName));
    }

    #[test]
    fn row_keys_cover_stripped_and_listed_forms() {
        let k = row_keys(Some("Apache Software Foundation"), "Apache HTTP Server");
        assert!(
            k.contains(" httpserver ") && k.contains(" apachehttpserver "),
            "{k}"
        );
        let k = row_keys(Some("Cisco"), "Cisco IOS and IOS XE");
        assert!(k.contains(" ios ") && k.contains(" iosxe "), "{k}");
        let k = row_keys(Some("Arista"), "Extensible Operating System");
        assert!(k.contains(" eos "), "{k}");
        assert_eq!(row_keys(None, "n/a"), "");
    }
}
