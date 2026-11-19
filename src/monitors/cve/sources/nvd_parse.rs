//! NVD JSON 2.0 record parser shared by the `modified` feed and the REST API
//! (both use the `{"vulnerabilities":[{"cve":{...}}]}` shape).

use std::{fmt, io::Read};

use anyhow::{Context, Result};
use serde::{
    Deserialize,
    de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};

use crate::db::cve_repo::{NvdUpsert, normalize_ts};
use crate::model::{Affected, Cvss, CvssSource};

fn yes() -> bool {
    true
}

#[derive(Debug, Default, Deserialize)]
pub struct NvdVuln {
    #[serde(default)]
    pub cve: NvdCve,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NvdCve {
    pub id: String,
    pub published: Option<String>,
    pub last_modified: Option<String>,
    pub vuln_status: Option<String>,
    pub descriptions: Vec<Desc>,
    pub metrics: Metrics,
    pub configurations: Vec<Configuration>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Desc {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Metrics {
    pub cvss_metric_v40: Vec<Metric>,
    pub cvss_metric_v31: Vec<Metric>,
    pub cvss_metric_v30: Vec<Metric>,
    pub cvss_metric_v2: Vec<Metric>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Metric {
    pub r#type: Option<String>,
    pub cvss_data: CvssData,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct CvssData {
    pub version: Option<String>,
    pub vector_string: Option<String>,
    pub base_score: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Configuration {
    pub nodes: Vec<Node>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Node {
    pub negate: bool,
    pub cpe_match: Vec<CpeMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CpeMatch {
    #[serde(default = "yes")]
    pub vulnerable: bool,
    #[serde(default)]
    pub criteria: String,
    pub version_start_including: Option<String>,
    pub version_start_excluding: Option<String>,
    pub version_end_including: Option<String>,
    pub version_end_excluding: Option<String>,
}

/// `{"vulnerabilities": [...]}` page of the REST API.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NvdPage {
    pub results_per_page: usize,
    pub start_index: usize,
    pub total_results: usize,
    pub vulnerabilities: Vec<NvdVuln>,
}

fn version_rank(v: &str) -> u32 {
    match v {
        "4.0" => 4,
        "3.1" => 3,
        "3.0" => 2,
        _ => 1,
    }
}

impl NvdCve {
    /// Convert to the persisted shape. `None` when the record has no id.
    pub fn into_upsert(self) -> Option<NvdUpsert> {
        if self.id.is_empty() {
            return None;
        }
        // Collect every metric, then select: Primary first, then newest version.
        let groups = [
            (&self.metrics.cvss_metric_v40, "4.0"),
            (&self.metrics.cvss_metric_v31, "3.1"),
            (&self.metrics.cvss_metric_v30, "3.0"),
            (&self.metrics.cvss_metric_v2, "2.0"),
        ];
        let mut cvss_all = Vec::new();
        for (list, default_version) in groups {
            for m in list {
                let Some(score) = m.cvss_data.base_score else {
                    continue;
                };
                cvss_all.push(Cvss {
                    score,
                    vector: m.cvss_data.vector_string.clone(),
                    version: m
                        .cvss_data
                        .version
                        .clone()
                        .unwrap_or_else(|| default_version.to_owned()),
                    source: CvssSource::Nvd,
                    primary: m.r#type.as_deref() == Some("Primary"),
                });
            }
        }
        let cvss = cvss_all
            .iter()
            .max_by_key(|c| (c.primary, version_rank(&c.version)))
            .cloned();

        let mut affected: Vec<Affected> = Vec::new();
        let mut fixed: Vec<String> = Vec::new();
        for conf in &self.configurations {
            for node in conf.nodes.iter().filter(|n| !n.negate) {
                for m in node.cpe_match.iter().filter(|m| m.vulnerable) {
                    if m.criteria.is_empty() {
                        continue;
                    }
                    let mut range = serde_json::Map::new();
                    for (k, v) in [
                        ("versionStartIncluding", &m.version_start_including),
                        ("versionStartExcluding", &m.version_start_excluding),
                        ("versionEndIncluding", &m.version_end_including),
                        ("versionEndExcluding", &m.version_end_excluding),
                    ] {
                        if let Some(v) = v {
                            range.insert(k.into(), json!(v));
                        }
                    }
                    if let Some(f) = &m.version_end_excluding
                        && !fixed.contains(f)
                    {
                        fixed.push(f.clone());
                    }
                    let versions = if range.is_empty() {
                        json!([])
                    } else {
                        Value::Array(vec![Value::Object(range)])
                    };
                    let row = Affected {
                        source: CvssSource::Nvd,
                        vendor: None,
                        product: None,
                        cpe: Some(m.criteria.clone()),
                        versions,
                    };
                    if !affected.contains(&row) {
                        affected.push(row);
                    }
                }
            }
        }

        let description = self
            .descriptions
            .iter()
            .find(|d| d.lang == "en")
            .or(self.descriptions.first())
            .map(|d| d.value.clone())
            .unwrap_or_default();
        let status = self.vuln_status.clone();
        let rejected = status
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("rejected"));
        let published = self.published.as_deref().map(normalize_ts);
        let last_modified = self
            .last_modified
            .as_deref()
            .map(normalize_ts)
            .or_else(|| published.clone())?;
        Some(NvdUpsert {
            cve_id: self.id,
            state: if rejected { "REJECTED" } else { "PUBLISHED" }.into(),
            description,
            published,
            last_modified,
            vuln_status: status,
            cvss,
            cvss_all,
            affected,
            fixed_versions: fixed,
        })
    }
}

/// Fields of the `.meta` sidecar file.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NvdMeta {
    pub last_modified_date: Option<String>,
    pub sha256: Option<String>,
}

pub fn parse_meta(text: &str) -> NvdMeta {
    let mut m = NvdMeta::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        match k.trim() {
            "lastModifiedDate" => m.last_modified_date = Some(v.trim().to_owned()),
            "sha256" => m.sha256 = Some(v.trim().to_ascii_lowercase()),
            _ => {}
        }
    }
    m
}

/// Visit each element of `vulnerabilities` without materialising the document.
struct FeedVisitor<'a>(&'a mut dyn FnMut(NvdVuln) -> Result<()>);

impl<'de> Visitor<'de> for FeedVisitor<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an NVD feed object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "vulnerabilities" {
                map.next_value_seed(VulnSeq(&mut *self.0))?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct VulnSeq<'a>(&'a mut dyn FnMut(NvdVuln) -> Result<()>);

impl<'de> DeserializeSeed<'de> for VulnSeq<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for VulnSeq<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an array of vulnerabilities")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(v) = seq.next_element::<NvdVuln>()? {
            (self.0)(v).map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

/// Stream a feed/page document from `reader` (should be buffered), calling `f`
/// for every vulnerability. Memory use is one record, not the whole file.
pub fn stream_vulnerabilities<R: Read>(
    reader: R,
    mut f: impl FnMut(NvdVuln) -> Result<()>,
) -> Result<()> {
    let mut de = serde_json::Deserializer::from_reader(reader);
    de.deserialize_map(FeedVisitor(&mut f))
        .context("parsing NVD feed JSON")?;
    de.end().context("trailing data after NVD feed JSON")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitors::cve::sources::testutil::fixture;

    fn parse_fixture() -> Vec<NvdUpsert> {
        let bytes = fixture("nvd-modified.json");
        let mut out = Vec::new();
        stream_vulnerabilities(&bytes[..], |v| {
            out.extend(v.cve.into_upsert());
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn parses_analyzed_record_with_ranges_and_primary_score() {
        let recs = parse_fixture();
        assert_eq!(recs.len(), 3);
        let a = &recs[0];
        assert_eq!(a.cve_id, "CVE-2020-25657");
        assert_eq!(a.vuln_status.as_deref(), Some("Analyzed"));
        assert_eq!(a.last_modified, "2026-11-19T19:49:58.280Z");
        assert_eq!(a.published.as_deref(), Some("2021-01-12T15:15:13.720Z"));
        let c = a.cvss.as_ref().unwrap();
        assert!(c.primary);
        assert_eq!(c.version, "3.1");
        assert_eq!(c.score, 5.9);
        assert!(a.cvss_all.len() >= 2, "v3.1 and v2 are both kept");
        assert!(a.fixed_versions.contains(&"0.39.0".to_owned()));
        let ranged = a
            .affected
            .iter()
            .find(|r| r.cpe.as_deref().is_some_and(|c| c.contains("m2crypto")))
            .unwrap();
        assert_eq!(ranged.versions[0]["versionEndExcluding"], "0.39.0");
        assert!(a.affected.len() > 3);
    }

    #[test]
    fn secondary_only_and_rejected_records() {
        let recs = parse_fixture();
        let b = &recs[1];
        assert_eq!(b.vuln_status.as_deref(), Some("Received"));
        let c = b.cvss.as_ref().unwrap();
        assert!(!c.primary);
        assert_eq!(c.version, "4.0");
        assert!(b.affected.is_empty(), "no configurations before analysis");
        let r = &recs[2];
        assert_eq!(r.state, "REJECTED");
        assert!(r.cvss.is_none());
    }

    #[test]
    fn primary_beats_newer_secondary() {
        let v: NvdVuln = serde_json::from_value(json!({"cve": {
            "id": "CVE-1-1", "lastModified": "2026-01-01T00:00:00.000",
            "metrics": {
                "cvssMetricV40": [{"type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 9.0}}],
                "cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.0}}]
            }}}))
        .unwrap();
        let u = v.cve.into_upsert().unwrap();
        assert_eq!(u.cvss.unwrap().score, 7.0);
        assert_eq!(u.cvss_all.len(), 2);
    }

    #[test]
    fn non_vulnerable_and_negated_matches_are_ignored() {
        let v: NvdVuln = serde_json::from_value(json!({"cve": {
            "id": "CVE-1-2", "lastModified": "2026-01-01T00:00:00.000",
            "configurations": [{"nodes": [
                {"negate": false, "cpeMatch": [
                    {"vulnerable": true, "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndIncluding": "2.0"},
                    {"vulnerable": false, "criteria": "cpe:2.3:o:v:os:*:*:*:*:*:*:*:*"}]},
                {"negate": true, "cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}]}
            ]}]}}))
        .unwrap();
        let u = v.cve.into_upsert().unwrap();
        assert_eq!(u.affected.len(), 1);
        assert!(
            u.fixed_versions.is_empty(),
            "versionEndIncluding gives no fix"
        );
    }

    #[test]
    fn meta_parses() {
        let m = parse_meta(&String::from_utf8(fixture("nvd-modified.meta")).unwrap());
        assert_eq!(m.sha256.as_deref(), Some("abcdef"));
        assert_eq!(
            m.last_modified_date.as_deref(),
            Some("2026-11-19T16:00:08-05:00")
        );
    }

    #[test]
    fn page_shape_parses() {
        let page: NvdPage = serde_json::from_slice(&fixture("nvd-modified.json")).unwrap();
        assert_eq!(page.total_results, 3);
        assert_eq!(page.vulnerabilities.len(), 3);
    }
}
