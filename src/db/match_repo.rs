//! DB glue for the matcher: load CVE facts, write `cve_product_matches`
//! idempotently (removing stale rows on re-evaluation) and re-evaluate one
//! product against every stored CVE.

use std::collections::{HashMap, HashSet};

use rusqlite::{Connection, params, params_from_iter};

use super::{DbResult, repo};
use crate::model::now_rfc3339;
use crate::monitors::cve::matcher::{
    AffectedFacts, CompiledProduct, CveFacts, MatchedBy, compile_all,
};

/// SQLite's default bound-variable limit is 32766; stay well below it.
const CHUNK: usize = 400;

fn placeholders(n: usize) -> String {
    vec!["?"; n].join(",")
}

/// Load matcher input for `ids`. Rejected CVEs are returned with `rejected = true`.
/// CVE ids that are not stored are omitted.
fn load_facts(conn: &Connection, ids: &[String]) -> DbResult<Vec<(CveFacts, bool)>> {
    let mut out: Vec<(CveFacts, bool)> = Vec::with_capacity(ids.len());
    for chunk in ids.chunks(CHUNK) {
        let ph = placeholders(chunk.len());
        let mut by_id: HashMap<String, usize> = HashMap::new();
        {
            let mut st = conn.prepare_cached(&format!(
                "SELECT cve_id, description, state FROM cves WHERE cve_id IN ({ph})"
            ))?;
            let rows = st.query_map(params_from_iter(chunk), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (cve_id, description, state) = row?;
                by_id.insert(cve_id.clone(), out.len());
                out.push((
                    CveFacts {
                        cve_id,
                        description,
                        affected: Vec::new(),
                        kev: None,
                    },
                    state.eq_ignore_ascii_case("REJECTED"),
                ));
            }
        }
        {
            let mut st = conn.prepare_cached(&format!(
                "SELECT cve_id, vendor_raw, product_raw, cpe_vendor, cpe_product \
                 FROM cve_affected WHERE cve_id IN ({ph})"
            ))?;
            let rows = st.query_map(params_from_iter(chunk), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })?;
            for row in rows {
                let (id, v, p, cv, cp) = row?;
                if let Some(&i) = by_id.get(&id) {
                    out[i].0.affected.push(AffectedFacts::new(
                        v.as_deref(),
                        p.as_deref(),
                        cv.as_deref(),
                        cp.as_deref(),
                    ));
                }
            }
        }
        {
            let mut st = conn.prepare_cached(&format!(
                "SELECT cve_id, vendor_project, product FROM kev WHERE cve_id IN ({ph})"
            ))?;
            let rows = st.query_map(params_from_iter(chunk), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?;
            for row in rows {
                let (id, v, p) = row?;
                if let Some(&i) = by_id.get(&id) {
                    out[i].0.kev = Some((v.unwrap_or_default(), p.unwrap_or_default()));
                }
            }
        }
    }
    Ok(out)
}

/// Evaluate `ids` against `products` and make `cve_product_matches` reflect the
/// result exactly for those CVEs (new rows inserted, changed `matched_by`
/// updated, stale rows removed; `matched_at` of unchanged rows is kept).
/// Returns the number of matches now stored for `ids`.
pub fn evaluate_cves(
    conn: &mut Connection,
    products: &[CompiledProduct],
    ids: &[String],
) -> DbResult<usize> {
    let tx = conn.transaction()?;
    let now = now_rfc3339();
    let mut total = 0;
    for chunk in ids.chunks(CHUNK) {
        for (facts, rejected) in load_facts(&tx, chunk)? {
            let wanted: HashMap<String, MatchedBy> = if rejected {
                HashMap::new()
            } else {
                products
                    .iter()
                    .filter_map(|p| p.matches(&facts).map(|m| (p.id.clone(), m)))
                    .collect()
            };
            let existing: HashSet<String> = {
                let mut st = tx.prepare_cached(
                    "SELECT product_id FROM cve_product_matches WHERE cve_id = ?1",
                )?;
                st.query_map([&facts.cve_id], |r| r.get(0))?
                    .collect::<Result<_, _>>()?
            };
            for stale in existing.iter().filter(|p| !wanted.contains_key(*p)) {
                tx.prepare_cached(
                    "DELETE FROM cve_product_matches WHERE cve_id = ?1 AND product_id = ?2",
                )?
                .execute(params![facts.cve_id, stale])?;
            }
            for (pid, by) in &wanted {
                upsert_match(&tx, &facts.cve_id, pid, *by, &now)?;
            }
            total += wanted.len();
        }
    }
    tx.commit()?;
    Ok(total)
}

fn upsert_match(
    conn: &Connection,
    cve_id: &str,
    product_id: &str,
    by: MatchedBy,
    now: &str,
) -> DbResult<()> {
    conn.prepare_cached(
        "INSERT INTO cve_product_matches (cve_id, product_id, matched_by, matched_at) \
         VALUES (?1, ?2, ?3, ?4) \
         ON CONFLICT(cve_id, product_id) DO UPDATE SET matched_by = excluded.matched_by \
         WHERE matched_by != excluded.matched_by",
    )?
    .execute(params![cve_id, product_id, by.as_str(), now])?;
    Ok(())
}

/// Convenience for the sync: match `ids` against all tracked products.
pub fn match_cves(conn: &mut Connection, ids: &[String]) -> DbResult<usize> {
    let products = compile_all(&repo::list_products(conn)?);
    evaluate_cves(conn, &products, ids)
}

/// Outcome of [`rematch_product`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RematchStats {
    /// CVEs that passed the SQL prefilter and were evaluated.
    pub candidates: usize,
    /// Matches stored for the product afterwards.
    pub matched: usize,
}

fn longest_alnum_run(s: &str) -> Option<String> {
    s.split(|c: char| !c.is_ascii_alphanumeric())
        .max_by_key(|t| t.len())
        .filter(|t| t.len() >= 2)
        .map(str::to_lowercase)
}

/// Superset of the CVEs that could match `p` (cheap indexed / LIKE queries);
/// the matcher makes the final call.
fn candidate_ids(
    conn: &Connection,
    p: &CompiledProduct,
    keywords: &[String],
) -> DbResult<Vec<String>> {
    let mut ids: HashSet<String> = HashSet::new();
    let collect = |conn: &Connection,
                   sql: &str,
                   args: &[String],
                   ids: &mut HashSet<String>|
     -> DbResult<()> {
        let mut st = conn.prepare(sql)?;
        for r in st.query_map(params_from_iter(args), |r| r.get::<_, String>(0))? {
            ids.insert(r?);
        }
        Ok(())
    };

    if p.uses_names() {
        for (v, prod) in p.cpe_keys() {
            collect(
                conn,
                "SELECT DISTINCT cve_id FROM cve_affected \
                 WHERE cpe_vendor IS NOT NULL AND cpe_vendor = ?1 AND cpe_product = ?2",
                &[v.clone(), prod.clone()],
                &mut ids,
            )?;
        }
        let (forms, vendors) = p.name_forms();
        let mut exact: HashSet<String> = HashSet::new();
        for f in &forms {
            exact.insert(f.clone());
            for v in &vendors {
                exact.insert(format!("{v}{f}"));
            }
        }
        let exact: Vec<String> = exact.into_iter().collect();
        for chunk in exact.chunks(CHUNK) {
            collect(
                conn,
                &format!(
                    "SELECT DISTINCT cve_id FROM cve_affected WHERE product_squash IN ({})",
                    placeholders(chunk.len())
                ),
                chunk,
                &mut ids,
            )?;
        }
        // Forms inside list-like / vendor-prefixed products ("ciscoiosandiosxe").
        let likes: Vec<String> = forms
            .iter()
            .filter(|f| f.chars().count() >= 5)
            .map(|f| format!("%{f}%"))
            .collect();
        for chunk in likes.chunks(50) {
            let cond = vec!["product_squash LIKE ?"; chunk.len()].join(" OR ");
            collect(
                conn,
                &format!("SELECT DISTINCT cve_id FROM cve_affected WHERE {cond}"),
                chunk,
                &mut ids,
            )?;
        }
    }

    // KEV is small (~2k rows): compare in memory.
    {
        let mut st = conn.prepare("SELECT cve_id, vendor_project, product FROM kev")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        for r in rows {
            let (id, v, prod) = r?;
            if p.matches_kev(&v.unwrap_or_default(), &prod.unwrap_or_default()) {
                ids.insert(id);
            }
        }
    }

    let runs: Vec<String> = keywords
        .iter()
        .filter_map(|k| longest_alnum_run(k))
        .map(|t| format!("%{t}%"))
        .collect();
    for chunk in runs.chunks(50) {
        let cond = vec!["description LIKE ?"; chunk.len()].join(" OR ");
        collect(
            conn,
            &format!("SELECT cve_id FROM cves WHERE {cond}"),
            chunk,
            &mut ids,
        )?;
    }
    Ok(ids.into_iter().collect())
}

/// Evaluate ONE product against ALL stored CVEs and make its matches exact
/// (stale ones removed). Call right after add/update of a tracked product.
/// Returns `None` if the product does not exist.
pub fn rematch_product(conn: &mut Connection, product_id: &str) -> DbResult<Option<RematchStats>> {
    let Some(tp) = repo::get_product(conn, product_id)? else {
        return Ok(None);
    };
    let compiled = CompiledProduct::new(&tp);
    let candidates = candidate_ids(conn, &compiled, &tp.keywords)?;

    let tx = conn.transaction()?;
    let now = now_rfc3339();
    let mut wanted: HashMap<String, MatchedBy> = HashMap::new();
    for chunk in candidates.chunks(CHUNK) {
        for (facts, rejected) in load_facts(&tx, chunk)? {
            if rejected {
                continue;
            }
            if let Some(by) = compiled.matches(&facts) {
                wanted.insert(facts.cve_id, by);
            }
        }
    }
    let existing: Vec<String> = {
        let mut st = tx.prepare("SELECT cve_id FROM cve_product_matches WHERE product_id = ?1")?;
        st.query_map([product_id], |r| r.get(0))?
            .collect::<Result<_, _>>()?
    };
    for cve_id in existing.iter().filter(|c| !wanted.contains_key(*c)) {
        tx.execute(
            "DELETE FROM cve_product_matches WHERE cve_id = ?1 AND product_id = ?2",
            params![cve_id, product_id],
        )?;
    }
    for (cve_id, by) in &wanted {
        upsert_match(&tx, cve_id, product_id, *by, &now)?;
    }
    tx.commit()?;
    Ok(Some(RematchStats {
        candidates: candidates.len(),
        matched: wanted.len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::model::{CnaName, CpeRef, KevName, MatchMode, TrackedProduct};
    use crate::monitors::cve::normalize::{normalize_product, normalize_vendor, squash};

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
            created_at: "2026-01-01T00:00:00.000Z".into(),
            updated_at: "2026-01-01T00:00:00.000Z".into(),
        }
    }

    fn add_cve(conn: &Connection, id: &str, desc: &str, state: &str) {
        conn.execute(
            "INSERT INTO cves (cve_id, state, description, last_modified, first_seen_at) \
             VALUES (?1, ?2, ?3, 'x', 'x')",
            params![id, state, desc],
        )
        .unwrap();
    }

    fn add_aff(
        conn: &Connection,
        id: &str,
        v: Option<&str>,
        p: Option<&str>,
        cpe: Option<(&str, &str)>,
    ) {
        conn.execute(
            "INSERT INTO cve_affected (cve_id, source, vendor_raw, product_raw, vendor_norm, \
                 product_norm, product_squash, cpe_vendor, cpe_product) \
             VALUES (?1, 'cna', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                v,
                p,
                v.map(normalize_vendor),
                p.map(normalize_product),
                p.map(squash),
                cpe.map(|c| c.0),
                cpe.map(|c| c.1)
            ],
        )
        .unwrap();
    }

    fn matches(conn: &Connection) -> Vec<(String, String, String)> {
        let mut st = conn
            .prepare("SELECT cve_id, product_id, matched_by FROM cve_product_matches ORDER BY 1, 2")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    fn seed(conn: &Connection) {
        add_cve(conn, "CVE-1", "SQLi in FortiClientEMS", "PUBLISHED");
        add_aff(
            conn,
            "CVE-1",
            Some("Fortinet"),
            Some("FortiClientEMS"),
            None,
        );
        add_cve(conn, "CVE-2", "x", "PUBLISHED");
        add_aff(
            conn,
            "CVE-2",
            None,
            None,
            Some(("fortinet", "forticlientems")),
        );
        add_cve(conn, "CVE-3", "x", "PUBLISHED");
        conn.execute(
            "INSERT INTO kev (cve_id, vendor_project, product, first_seen_at) \
             VALUES ('CVE-3', 'Fortinet', 'FortiClient EMS', 'x')",
            [],
        )
        .unwrap();
        add_cve(conn, "CVE-4", "XSS in FortiOS", "PUBLISHED");
        add_aff(
            conn,
            "CVE-4",
            Some("Fortinet"),
            Some("FortiOS"),
            Some(("fortinet", "fortios")),
        );
        add_cve(conn, "CVE-5", "Vates XCP-ng toolstack issue", "PUBLISHED");
        add_cve(conn, "CVE-6", "FortiClientEMS issue", "REJECTED");
        add_aff(
            conn,
            "CVE-6",
            Some("Fortinet"),
            Some("FortiClientEMS"),
            None,
        );
        add_cve(
            conn,
            "CVE-7",
            "In the Linux kernel: libceph: bug",
            "PUBLISHED",
        );
        add_aff(conn, "CVE-7", Some("Linux"), Some("Linux"), None);
    }

    fn forticlient() -> TrackedProduct {
        let mut p = product("forticlient-ems", "FortiClient EMS");
        p.cpes = vec![CpeRef {
            part: "a".into(),
            vendor: "fortinet".into(),
            product: "forticlientems".into(),
            note: None,
        }];
        p.cna_names = vec![CnaName {
            vendor: "Fortinet".into(),
            product: "FortiClientEMS".into(),
            source_cna: None,
        }];
        p.kev_names = vec![KevName {
            vendor_project: "Fortinet".into(),
            product: "FortiClient EMS".into(),
        }];
        p
    }

    fn xcpng() -> TrackedProduct {
        let mut p = product("xcp-ng", "XCP-ng");
        p.match_mode = MatchMode::Keyword;
        p.keywords = vec!["xcp-ng".into()];
        p
    }

    #[test]
    fn evaluate_is_idempotent_and_removes_stale() {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| {
            seed(c);
            repo::upsert_product(c, &forticlient())?;
            repo::upsert_product(c, &xcpng())?;
            let ids: Vec<String> = (1..=7).map(|i| format!("CVE-{i}")).collect();
            assert_eq!(match_cves(c, &ids)?, 4);
            let expect = vec![
                (
                    "CVE-1".to_string(),
                    "forticlient-ems".to_string(),
                    "cna_name".to_string(),
                ),
                ("CVE-2".into(), "forticlient-ems".into(), "cpe".into()),
                ("CVE-3".into(), "forticlient-ems".into(), "kev_name".into()),
                ("CVE-5".into(), "xcp-ng".into(), "keyword".into()),
            ];
            assert_eq!(matches(c), expect);
            let at: String = c.query_row(
                "SELECT matched_at FROM cve_product_matches WHERE cve_id = 'CVE-1'",
                [],
                |r| r.get(0),
            )?;
            match_cves(c, &ids)?;
            assert_eq!(matches(c), expect);
            let at2: String = c.query_row(
                "SELECT matched_at FROM cve_product_matches WHERE cve_id = 'CVE-1'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(at, at2, "unchanged matches keep matched_at");

            // CVE-1 is re-evaluated after its affected rows change: stale match removed.
            c.execute("DELETE FROM cve_affected WHERE cve_id = 'CVE-1'", [])?;
            c.execute(
                "UPDATE cves SET description = 'nothing' WHERE cve_id = 'CVE-1'",
                [],
            )?;
            match_cves(c, &["CVE-1".to_string()])?;
            assert!(!matches(c).iter().any(|m| m.0 == "CVE-1"));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn rematch_product_covers_all_candidate_paths() {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| {
            seed(c);
            repo::upsert_product(c, &forticlient())?;
            let st = rematch_product(c, "forticlient-ems")?.unwrap();
            assert_eq!(st.matched, 3);
            assert!(st.candidates >= 3 && st.candidates < 7, "{st:?}");
            let got: Vec<String> = matches(c).into_iter().map(|m| m.0).collect();
            assert_eq!(got, ["CVE-1", "CVE-2", "CVE-3"]);

            // keyword product found by description scan; unrelated kernel CVE not matched
            repo::upsert_product(c, &xcpng())?;
            let st = rematch_product(c, "xcp-ng")?.unwrap();
            assert_eq!(
                st,
                RematchStats {
                    candidates: 1,
                    matched: 1
                }
            );

            // narrowing the definition removes stale matches
            let mut p = forticlient();
            p.kev_names.clear();
            p.cpes.clear();
            repo::upsert_product(c, &p)?;
            rematch_product(c, "forticlient-ems")?;
            let got: Vec<String> = matches(c)
                .into_iter()
                .filter(|m| m.1 == "forticlient-ems")
                .map(|m| m.0)
                .collect();
            assert_eq!(
                got,
                ["CVE-1", "CVE-3"],
                "CVE-3 still matches via cna-name keys on KEV"
            );
            assert!(rematch_product(c, "nope")?.is_none());
            Ok(())
        })
        .unwrap();
    }
}
