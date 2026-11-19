//! Operations on tracked products used by the CLI and (later) the MCP tools:
//! add / update / remove / list. Adding or updating always re-matches the
//! product against every stored CVE; the feed's backfill policy then decides
//! what is surfaced (see `feed`).

use anyhow::{Result, bail};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Serialize;

use super::discovery::{Candidate, Overrides, to_tracked_product};
use super::matcher::CompiledProduct;
use super::normalize::slugify;
use super::sources::{SourceContext, nvd_api::NvdApi};
use crate::db::{Db, match_repo, repo};
use crate::model::{TrackedProduct, now_rfc3339};

/// Most KEV CVEs fetched from NVD in one go (NVD allows ~10 requests/minute without a key).
const MAX_KEV_FETCH: usize = 15;

#[derive(Debug, Clone, Serialize)]
pub struct AddResult {
    pub product: TrackedProduct,
    /// CVEs that passed the SQL prefilter.
    pub candidates: usize,
    /// Matches stored for the product.
    pub matched: usize,
    /// KEV CVEs that were not stored locally and were fetched from NVD.
    pub kev_fetched: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrackedSummary {
    pub product: TrackedProduct,
    pub matches: usize,
    pub last_match: Option<String>,
}

/// Fetch from NVD the KEV CVEs that match one of `products` but are not stored
/// (a KEV addition for an old CVE that no feed delivered). Only entries added to
/// KEV on/after `min_date` and (if given) listed in `only_ids` are considered.
/// Returns the ids stored.
pub async fn fetch_missing_kev(
    ctx: &SourceContext,
    api: &NvdApi,
    products: &[TrackedProduct],
    only_ids: Option<&[String]>,
    min_date: DateTime<Utc>,
) -> Result<Vec<String>> {
    let compiled: Vec<CompiledProduct> = products.iter().map(CompiledProduct::new).collect();
    if compiled.is_empty() {
        return Ok(vec![]);
    }
    let rows: Vec<(String, String, String, String)> = ctx
        .db
        .call(|c| {
            let mut st = c.prepare(
                "SELECT cve_id, COALESCE(vendor_project, ''), COALESCE(product, ''), \
                        COALESCE(date_added, '') FROM kev \
                 WHERE cve_id NOT IN (SELECT cve_id FROM cves)",
            )?;
            Ok(st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<_, _>>()?)
        })
        .await?;
    let wanted: Vec<String> = rows
        .into_iter()
        .filter(|(id, ..)| only_ids.is_none_or(|ids| ids.contains(id)))
        .filter(|(.., added)| {
            NaiveDate::parse_from_str(added, "%Y-%m-%d")
                .ok()
                .is_some_and(|d| d.and_hms_opt(0, 0, 0).expect("midnight").and_utc() >= min_date)
        })
        .filter(|(_, v, p, _)| compiled.iter().any(|c| c.matches_kev(v, p)))
        .map(|(id, ..)| id)
        .take(MAX_KEV_FETCH)
        .collect();
    let mut stored = Vec::new();
    for id in wanted {
        match api.lookup_and_store(ctx, &id).await {
            Ok(true) => stored.push(id),
            Ok(false) => tracing::debug!(%id, "KEV CVE not (yet) in NVD"),
            Err(e) => tracing::warn!(%id, error = %format!("{e:#}"), "fetching KEV CVE failed"),
        }
    }
    Ok(stored)
}

/// Save `product` (new or replacing the same id), re-match it against all stored
/// CVEs and pull in recent KEV CVEs we do not have yet. `api = None` skips the
/// NVD lookups.
pub async fn add(
    ctx: &SourceContext,
    api: Option<&NvdApi>,
    mut product: TrackedProduct,
    backfill_days: i64,
) -> Result<AddResult> {
    if product.name.trim().is_empty() {
        bail!("product name is empty");
    }
    if product.id.trim().is_empty() {
        product.id = slugify(&product.name);
    }
    if product.id.is_empty() {
        bail!("product name has no letters or digits");
    }
    let now = now_rfc3339();
    if product.created_at.is_empty() {
        product.created_at = now.clone();
    }
    product.updated_at = now;
    let p = product.clone();
    ctx.db.call(move |c| repo::upsert_product(c, &p)).await?;

    let saved = ctx
        .db
        .call({
            let id = product.id.clone();
            move |c| repo::get_product(c, &id)
        })
        .await?
        .expect("just upserted");
    let mut kev_fetched = 0;
    if let Some(api) = api {
        let min = DateTime::parse_from_rfc3339(&saved.created_at)
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now())
            - Duration::days(backfill_days);
        kev_fetched = fetch_missing_kev(ctx, api, std::slice::from_ref(&saved), None, min)
            .await?
            .len();
    }
    let id = saved.id.clone();
    let stats = ctx
        .db
        .call(move |c| match_repo::rematch_product(c, &id))
        .await?
        .expect("just upserted");
    Ok(AddResult {
        product: saved,
        candidates: stats.candidates,
        matched: stats.matched,
        kev_fetched,
    })
}

/// Add a discovery candidate with the agent's edits.
pub async fn add_candidate(
    ctx: &SourceContext,
    api: Option<&NvdApi>,
    candidate: &Candidate,
    overrides: Overrides,
    backfill_days: i64,
) -> Result<AddResult> {
    add(
        ctx,
        api,
        to_tracked_product(candidate, overrides),
        backfill_days,
    )
    .await
}

/// Apply `overrides` to an existing product and re-match. `None` if it does not exist.
pub async fn update(
    ctx: &SourceContext,
    api: Option<&NvdApi>,
    id: &str,
    overrides: Overrides,
    backfill_days: i64,
) -> Result<Option<AddResult>> {
    let key = id.to_owned();
    let Some(existing) = ctx.db.call(move |c| repo::get_product(c, &key)).await? else {
        return Ok(None);
    };
    let created = existing.created_at.clone();
    let candidate = Candidate {
        product: existing,
        score: 0.0,
        evidence: Default::default(),
    };
    let mut p = to_tracked_product(
        &candidate,
        Overrides {
            id: None, // the id is the key; renaming is remove + add
            ..overrides
        },
    );
    p.created_at = created;
    Ok(Some(add(ctx, api, p, backfill_days).await?))
}

/// Delete a product; its matches and every consumer's delivered rows go with it.
pub async fn remove(db: &Db, id: &str) -> Result<bool> {
    let id = id.to_owned();
    Ok(db
        .call(move |c| {
            let tx = c.transaction()?;
            tx.execute("DELETE FROM delivered WHERE product_id = ?1", [&id])?;
            let removed = repo::delete_product(&tx, &id)?;
            tx.commit()?;
            Ok(removed)
        })
        .await?)
}

/// Every tracked product with its current match count.
pub async fn list(db: &Db) -> Result<Vec<TrackedSummary>> {
    Ok(db
        .call(|c| {
            let mut out = Vec::new();
            for product in repo::list_products(c)? {
                let (matches, last_match): (i64, Option<String>) = c.query_row(
                    "SELECT COUNT(*), MAX(matched_at) FROM cve_product_matches WHERE product_id = ?1",
                    [&product.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                out.push(TrackedSummary {
                    product,
                    matches: matches as usize,
                    last_match,
                });
            }
            Ok(out)
        })
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CnaName, MatchMode};
    use crate::monitors::cve::sources::testutil::ctx;

    fn candidate() -> Candidate {
        Candidate {
            product: TrackedProduct {
                id: "widget".into(),
                name: "Widget".into(),
                cpes: vec![],
                cna_names: vec![CnaName {
                    vendor: "Acme".into(),
                    product: "Widget".into(),
                    source_cna: None,
                }],
                kev_names: vec![],
                aliases: vec![],
                keywords: vec![],
                exclude_keywords: vec![],
                match_mode: MatchMode::CpeNames,
                confirmed_by: "discovery".into(),
                created_at: String::new(),
                updated_at: String::new(),
            },
            score: 1.0,
            evidence: Default::default(),
        }
    }

    #[tokio::test]
    async fn add_update_list_remove() {
        let ctx = ctx();
        ctx.db
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO cves (cve_id, description, last_modified, first_seen_at) \
                     VALUES ('CVE-2026-1', 'x', 'x', 'x')",
                    [],
                )?;
                c.execute(
                    "INSERT INTO cve_affected (cve_id, source, vendor_raw, product_raw, product_keys) \
                     VALUES ('CVE-2026-1', 'cna', 'Acme Inc', 'Widget', ' widget ')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let r = add_candidate(&ctx, None, &candidate(), Overrides::default(), 14)
            .await
            .unwrap();
        assert_eq!((r.matched, r.product.id.as_str()), (1, "widget"));
        assert!(!r.product.created_at.is_empty());
        let created = r.product.created_at.clone();

        let l = list(&ctx.db).await.unwrap();
        assert_eq!((l.len(), l[0].matches), (1, 1));

        // update: rename; created_at stays, match survives (alias is not touched)
        let u = update(
            &ctx,
            None,
            "widget",
            Overrides {
                name: Some("Widget Pro".into()),
                ..Default::default()
            },
            14,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(u.product.name, "Widget Pro");
        assert_eq!(u.product.created_at, created);
        assert_eq!(u.matched, 1);
        assert!(
            update(&ctx, None, "nope", Overrides::default(), 14)
                .await
                .unwrap()
                .is_none()
        );

        // narrowing the definition drops the match
        let u = update(
            &ctx,
            None,
            "widget",
            Overrides {
                cna_names: Some(vec![]),
                aliases: Some(vec![]),
                name: Some("Gadget".into()),
                ..Default::default()
            },
            14,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(u.matched, 0);

        ctx.db
            .with_conn(|c| {
                c.execute(
                    "INSERT INTO delivered (consumer, cve_id, product_id, delivered_at) \
                     VALUES ('me', 'CVE-2026-1', 'widget', 'x')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        assert!(remove(&ctx.db, "widget").await.unwrap());
        assert!(!remove(&ctx.db, "widget").await.unwrap());
        assert!(list(&ctx.db).await.unwrap().is_empty());
        let n: i64 = ctx
            .db
            .with_conn(|c| Ok(c.query_row("SELECT COUNT(*) FROM delivered", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(n, 0);
    }
}
