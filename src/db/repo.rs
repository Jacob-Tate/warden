//! Repository functions. They take a `&Connection` so callers choose the
//! transaction/threading model (see [`super::Db::call`]).

use rusqlite::{Connection, OptionalExtension, Row, params};

use super::DbResult;
use crate::model::{MatchMode, SourceStatus, TrackedProduct, now_rfc3339};

// ---- tracked products ----------------------------------------------------

const PRODUCT_COLS: &str = "id, name, cpes, cna_names, kev_names, aliases, keywords, \
     exclude_keywords, match_mode, confirmed_by, created_at, updated_at";

fn json_col<T: serde::de::DeserializeOwned>(row: &Row, i: usize) -> rusqlite::Result<T> {
    let s: String = row.get(i)?;
    serde_json::from_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(i, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn product_from_row(r: &Row) -> rusqlite::Result<TrackedProduct> {
    let mode: String = r.get(8)?;
    Ok(TrackedProduct {
        id: r.get(0)?,
        name: r.get(1)?,
        cpes: json_col(r, 2)?,
        cna_names: json_col(r, 3)?,
        kev_names: json_col(r, 4)?,
        aliases: json_col(r, 5)?,
        keywords: json_col(r, 6)?,
        exclude_keywords: json_col(r, 7)?,
        match_mode: MatchMode::parse(&mode).unwrap_or(MatchMode::CpeNames),
        confirmed_by: r.get(9)?,
        created_at: r.get(10)?,
        updated_at: r.get(11)?,
    })
}

/// Insert or update a product, preserving the original `created_at` on update.
pub fn upsert_product(conn: &Connection, p: &TrackedProduct) -> DbResult<()> {
    conn.execute(
        "INSERT INTO tracked_products (id, name, cpes, cna_names, kev_names, aliases, keywords, \
             exclude_keywords, match_mode, confirmed_by, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, cpes = excluded.cpes, \
             cna_names = excluded.cna_names, kev_names = excluded.kev_names, \
             aliases = excluded.aliases, keywords = excluded.keywords, \
             exclude_keywords = excluded.exclude_keywords, match_mode = excluded.match_mode, \
             confirmed_by = excluded.confirmed_by, updated_at = excluded.updated_at",
        params![
            p.id,
            p.name,
            serde_json::to_string(&p.cpes)?,
            serde_json::to_string(&p.cna_names)?,
            serde_json::to_string(&p.kev_names)?,
            serde_json::to_string(&p.aliases)?,
            serde_json::to_string(&p.keywords)?,
            serde_json::to_string(&p.exclude_keywords)?,
            p.match_mode.as_str(),
            p.confirmed_by,
            p.created_at,
            p.updated_at,
        ],
    )?;
    Ok(())
}

pub fn get_product(conn: &Connection, id: &str) -> DbResult<Option<TrackedProduct>> {
    Ok(conn
        .query_row(
            &format!("SELECT {PRODUCT_COLS} FROM tracked_products WHERE id = ?1"),
            [id],
            product_from_row,
        )
        .optional()?)
}

pub fn list_products(conn: &Connection) -> DbResult<Vec<TrackedProduct>> {
    let mut st = conn.prepare(&format!(
        "SELECT {PRODUCT_COLS} FROM tracked_products ORDER BY id"
    ))?;
    let rows = st.query_map([], product_from_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Returns true if a product was removed (its matches cascade).
pub fn delete_product(conn: &Connection, id: &str) -> DbResult<bool> {
    Ok(conn.execute("DELETE FROM tracked_products WHERE id = ?1", [id])? > 0)
}

// ---- per-source cursors / status ----------------------------------------

const STATUS_COLS: &str = "source, cursor, etag, last_attempt, last_success, last_error";

fn status_from_row(r: &Row) -> rusqlite::Result<SourceStatus> {
    Ok(SourceStatus {
        source: r.get(0)?,
        cursor: r.get(1)?,
        etag: r.get(2)?,
        last_attempt: r.get(3)?,
        last_success: r.get(4)?,
        last_error: r.get(5)?,
    })
}

pub fn get_source_status(conn: &Connection, source: &str) -> DbResult<Option<SourceStatus>> {
    Ok(conn
        .query_row(
            &format!("SELECT {STATUS_COLS} FROM source_status WHERE source = ?1"),
            [source],
            status_from_row,
        )
        .optional()?)
}

pub fn list_source_status(conn: &Connection) -> DbResult<Vec<SourceStatus>> {
    let mut st = conn.prepare(&format!(
        "SELECT {STATUS_COLS} FROM source_status ORDER BY source"
    ))?;
    let rows = st.query_map([], status_from_row)?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Record that a sync run started (does not touch cursor or last_success).
pub fn mark_attempt(conn: &Connection, source: &str) -> DbResult<()> {
    conn.execute(
        "INSERT INTO source_status (source, last_attempt) VALUES (?1, ?2) \
         ON CONFLICT(source) DO UPDATE SET last_attempt = excluded.last_attempt",
        params![source, now_rfc3339()],
    )?;
    Ok(())
}

/// Persist a successful run: new cursor/etag, clear the error.
pub fn mark_success(
    conn: &Connection,
    source: &str,
    cursor: Option<&str>,
    etag: Option<&str>,
) -> DbResult<()> {
    conn.execute(
        "INSERT INTO source_status (source, cursor, etag, last_attempt, last_success, last_error) \
         VALUES (?1, ?2, ?3, ?4, ?4, NULL) \
         ON CONFLICT(source) DO UPDATE SET cursor = excluded.cursor, etag = excluded.etag, \
             last_attempt = excluded.last_attempt, last_success = excluded.last_success, \
             last_error = NULL",
        params![source, cursor, etag, now_rfc3339()],
    )?;
    Ok(())
}

/// Persist a failed run; the cursor and last_success are kept.
pub fn mark_error(conn: &Connection, source: &str, error: &str) -> DbResult<()> {
    conn.execute(
        "INSERT INTO source_status (source, last_attempt, last_error) VALUES (?1, ?2, ?3) \
         ON CONFLICT(source) DO UPDATE SET last_attempt = excluded.last_attempt, \
             last_error = excluded.last_error",
        params![source, now_rfc3339(), error],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::model::{CnaName, CpeRef, KevName};

    fn sample() -> TrackedProduct {
        TrackedProduct {
            id: "fortios".into(),
            name: "FortiOS".into(),
            cpes: vec![CpeRef {
                part: "o".into(),
                vendor: "fortinet".into(),
                product: "fortios".into(),
                note: Some("NVD, 271 entries".into()),
            }],
            cna_names: vec![CnaName {
                vendor: "Fortinet".into(),
                product: "FortiOS".into(),
                source_cna: Some("fortinet".into()),
            }],
            kev_names: vec![KevName {
                vendor_project: "Fortinet".into(),
                product: "FortiOS".into(),
            }],
            aliases: vec!["forti os".into()],
            keywords: vec![],
            exclude_keywords: vec!["radios".into()],
            match_mode: MatchMode::CpeNames,
            confirmed_by: "agent".into(),
            created_at: "2026-11-19T00:00:00.000Z".into(),
            updated_at: "2026-11-19T00:00:00.000Z".into(),
        }
    }

    #[test]
    fn product_round_trip() {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| {
            assert!(list_products(c)?.is_empty());
            let mut p = sample();
            upsert_product(c, &p)?;
            assert_eq!(get_product(c, "fortios")?.as_ref(), Some(&p));

            p.keywords = vec!["forti".into()];
            p.created_at = "ignored".into();
            p.updated_at = "2026-11-20T00:00:00.000Z".into();
            upsert_product(c, &p)?;
            let got = get_product(c, "fortios")?.unwrap();
            assert_eq!(got.keywords, ["forti"]);
            assert_eq!(got.created_at, "2026-11-19T00:00:00.000Z");
            assert_eq!(list_products(c)?.len(), 1);

            assert!(delete_product(c, "fortios")?);
            assert!(!delete_product(c, "fortios")?);
            assert!(get_product(c, "fortios")?.is_none());
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn source_status_lifecycle() {
        let db = Db::open_in_memory().unwrap();
        db.with_conn(|c| {
            assert!(get_source_status(c, "kev")?.is_none());
            mark_error(c, "kev", "boom")?;
            let s = get_source_status(c, "kev")?.unwrap();
            assert_eq!(s.last_error.as_deref(), Some("boom"));
            assert!(s.last_success.is_none());

            mark_success(c, "kev", Some("{\"v\":1}"), Some("\"etag\""))?;
            mark_error(c, "kev", "later failure")?;
            let s = get_source_status(c, "kev")?.unwrap();
            assert_eq!(s.cursor.as_deref(), Some("{\"v\":1}"));
            assert!(s.last_success.is_some());
            assert_eq!(s.last_error.as_deref(), Some("later failure"));
            assert_eq!(list_source_status(c)?.len(), 1);
            Ok(())
        })
        .unwrap();
    }
}
