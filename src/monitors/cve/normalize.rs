//! Pure normalization helpers shared by the matcher and product discovery.
//!
//! Rules follow docs/research/product-discovery.md section 2.3: NFKD +
//! lowercase, `&` -> "and", punctuation -> spaces, collapse whitespace; compare
//! both the token form and the squashed form so `FortiClient EMS` ==
//! `FortiClientEMS`.

use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

/// Token form: lowercase, accents stripped, separators collapsed to single spaces.
pub fn norm(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.nfkd().filter(|c| !is_combining_mark(*c)) {
        if c == '&' {
            // "R&D" style joins are rare; treat as the word "and".
            if !out.is_empty() {
                out.push_str(" and");
            }
            pending_space = true;
        } else if c.is_alphanumeric() {
            if pending_space && !out.is_empty() {
                out.push(' ');
            }
            pending_space = false;
            out.extend(c.to_lowercase());
        } else {
            pending_space = true;
        }
    }
    out
}

/// Squashed form: token form with all spaces removed (`forticlientems`).
pub fn squash(s: &str) -> String {
    norm(s).replace(' ', "")
}

/// Tokens of the normalized form.
pub fn tokens(s: &str) -> Vec<String> {
    norm(s)
        .split(' ')
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Single-token vendor suffixes that carry no identity ("Grafana Labs" ~ "grafana").
const VENDOR_SUFFIXES: &[&str] = &[
    "inc",
    "incorporated",
    "ltd",
    "limited",
    "corp",
    "corporation",
    "co",
    "company",
    "llc",
    "gmbh",
    "plc",
    "ag",
    "sa",
    "labs",
    "networks",
    "technologies",
    "foundation",
    "project",
];

/// Vendor placeholders used by CNAs when the vendor is unknown.
pub fn is_unknown(s: &str) -> bool {
    matches!(
        norm(s).as_str(),
        "" | "n a" | "na" | "none" | "unknown" | "unspecified"
    )
}

/// Normalized vendor: token form minus a leading "the" and trailing corporate
/// suffixes. `"The Apache Software Foundation"` -> `"apache"`,
/// `"Arista Networks, Inc."` -> `"arista"`. Never strips the last remaining token.
pub fn normalize_vendor(s: &str) -> String {
    let mut t = tokens(s);
    if t.len() > 1 && t[0] == "the" {
        t.remove(0);
    }
    while t.len() > 1 {
        let last = t.last().map(String::as_str).unwrap_or_default();
        if last == "foundation" && t.len() > 2 && t[t.len() - 2] == "software" {
            t.truncate(t.len() - 2);
        } else if VENDOR_SUFFIXES.contains(&last) {
            t.pop();
        } else {
            break;
        }
    }
    t.join(" ")
}

/// Normalized product: token form (vendor prefixes are handled by the matcher,
/// which knows the vendor).
pub fn normalize_product(s: &str) -> String {
    norm(s)
}

/// Remove a leading vendor from a product name when it is a whole-word prefix
/// (`"Apache HTTP Server"` with vendor `apache` -> `"http server"`).
pub fn strip_vendor_prefix(vendor_norm: &str, product_norm: &str) -> String {
    match product_norm.strip_prefix(vendor_norm) {
        Some(rest) if rest.starts_with(' ') => rest.trim().to_owned(),
        _ => product_norm.to_owned(),
    }
}

/// Split a list-like product string into its parts: KEV and CNAs write
/// `"FortiOS and FortiProxy"`, `"IOS, IOS XR, and IOS XE"`, `"A / B"`.
/// The whole (unsplit) string is NOT included; callers add it themselves.
pub fn split_product_list(s: &str) -> Vec<String> {
    let lower = s.to_lowercase();
    let mut buf = String::with_capacity(lower.len());
    for part in lower.split(" and ") {
        if !buf.is_empty() {
            buf.push('|');
        }
        buf.push_str(part);
    }
    buf.split([',', '/', '&', ';', '|', '+'])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Product placeholders that carry no identity (superset of [`is_unknown`]).
pub fn is_unknown_product(s: &str) -> bool {
    is_unknown(s)
        || matches!(
            norm(s).as_str(),
            "multiple products" | "multiple" | "various" | "all products" | "multiple versions"
        )
}

/// Lowercase ASCII slug (`"FortiClient EMS"` -> `"forticlient-ems"`).
pub fn slugify(s: &str) -> String {
    norm(s).replace(' ', "-")
}

/// A parsed CPE 2.3 formatted string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCpe {
    /// `a` (application), `o` (OS) or `h` (hardware).
    pub part: String,
    pub vendor: String,
    pub product: String,
    /// `None` for `*` / `-` (any / not applicable).
    pub version: Option<String>,
}

impl ParsedCpe {
    /// `vendor:product` join key used for CPE matching.
    pub fn key(&self) -> String {
        format!("{}:{}", self.vendor, self.product)
    }
}

/// Split on unescaped `:` and resolve `\x` escapes.
fn split_cpe(s: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    parts.last_mut().expect("non-empty").push(n);
                }
            }
            ':' => parts.push(String::new()),
            _ => parts.last_mut().expect("non-empty").push(c),
        }
    }
    parts
}

/// Parse `cpe:2.3:<part>:<vendor>:<product>:<version>:...`. Vendor, product and
/// version are lowercased and unescaped. Returns `None` for anything else.
pub fn parse_cpe(s: &str) -> Option<ParsedCpe> {
    let f = split_cpe(s.trim());
    if f.len() < 5 || f[0] != "cpe" || f[1] != "2.3" {
        return None;
    }
    let part = f[2].to_lowercase();
    if !matches!(part.as_str(), "a" | "o" | "h") || f[3].is_empty() || f[4].is_empty() {
        return None;
    }
    let version = f
        .get(5)
        .map(|v| v.to_lowercase())
        .filter(|v| !v.is_empty() && v != "*" && v != "-");
    Some(ParsedCpe {
        part,
        vendor: f[3].to_lowercase(),
        product: f[4].to_lowercase(),
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_basics() {
        assert_eq!(norm("  FortiClient-EMS_v2.0 "), "forticlient ems v2 0");
        assert_eq!(norm("Café Naïve"), "cafe naive");
        assert_eq!(norm("AT&T"), "at and t");
        assert_eq!(norm("---"), "");
    }

    #[test]
    fn squash_equates_spacing_variants() {
        assert_eq!(squash("FortiClient EMS"), "forticlientems");
        assert_eq!(squash("FortiClientEMS"), "forticlientems");
        assert_eq!(squash("helix_core"), squash("Helix Core"));
        assert_eq!(squash("XCP-ng"), "xcpng");
    }

    #[test]
    fn vendor_suffixes() {
        assert_eq!(normalize_vendor("Apache Software Foundation"), "apache");
        assert_eq!(normalize_vendor("The Apache Software Foundation"), "apache");
        assert_eq!(normalize_vendor("Arista Networks, Inc."), "arista");
        assert_eq!(normalize_vendor("Grafana Labs"), "grafana");
        assert_eq!(normalize_vendor("grafana"), "grafana");
        assert_eq!(normalize_vendor("F5 Networks"), "f5");
        assert_eq!(normalize_vendor("Foo Bar Ltd"), "foo bar");
        // never reduce to nothing
        assert_eq!(normalize_vendor("Networks"), "networks");
        assert_eq!(normalize_vendor("Software Foundation"), "software");
    }

    #[test]
    fn unknown_placeholders() {
        for s in ["n/a", "N/A", "", " unknown ", "Unspecified"] {
            assert!(is_unknown(s), "{s:?}");
        }
        assert!(!is_unknown("Fortinet"));
    }

    #[test]
    fn vendor_prefix_stripping() {
        assert_eq!(
            strip_vendor_prefix("apache", "apache http server"),
            "http server"
        );
        assert_eq!(strip_vendor_prefix("apache", "apachex"), "apachex");
        assert_eq!(strip_vendor_prefix("eos", "eos"), "eos");
    }

    #[test]
    fn parses_cpe() {
        let c = parse_cpe("cpe:2.3:o:fortinet:fortios:7.6.1:*:*:*:*:*:*:*").unwrap();
        assert_eq!(c.part, "o");
        assert_eq!(c.vendor, "fortinet");
        assert_eq!(c.product, "fortios");
        assert_eq!(c.version.as_deref(), Some("7.6.1"));
        assert_eq!(c.key(), "fortinet:fortios");
    }

    #[test]
    fn parses_cpe_with_wildcards_and_escapes() {
        let c = parse_cpe(
            r"cpe:2.3:a:linuxfoundation:backstage\/techdocs-common:*:*:*:*:*:node.js:*:*",
        )
        .unwrap();
        assert_eq!(c.product, "backstage/techdocs-common");
        assert_eq!(c.version, None);

        let c = parse_cpe(r"cpe:2.3:a:ven\:dor:Prod:-:*:*:*:*:*:*:*").unwrap();
        assert_eq!(c.vendor, "ven:dor");
        assert_eq!(c.product, "prod");
        assert_eq!(c.version, None);
    }

    #[test]
    fn rejects_bad_cpe() {
        assert!(parse_cpe("").is_none());
        assert!(parse_cpe("cpe:/a:vendor:product").is_none());
        assert!(parse_cpe("cpe:2.3:x:v:p").is_none());
        assert!(parse_cpe("cpe:2.3:a:v").is_none());
        assert!(parse_cpe("cpe:2.3:a::p").is_none());
    }

    #[test]
    fn splits_product_lists() {
        assert_eq!(
            split_product_list("FortiOS and FortiProxy"),
            ["fortios", "fortiproxy"]
        );
        assert_eq!(
            split_product_list("IOS, IOS XR, and IOS XE"),
            ["ios", "ios xr", "ios xe"]
        );
        assert_eq!(split_product_list("EOS"), ["eos"]);
        assert!(is_unknown_product("Multiple Products"));
        assert_eq!(slugify("FortiClient EMS"), "forticlient-ems");
    }
}
