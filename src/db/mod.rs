//! SQLite access: connection pool, migrations and repository functions.
//!
//! Pool choice: `r2d2` + `r2d2_sqlite`. SQLite in WAL mode allows many readers
//! plus one writer, so a small pool of connections (each used from a blocking
//! task via [`Db::call`]) gives real read concurrency and avoids the
//! single-`Mutex<Connection>` pattern where every handler serialises on one
//! lock and a panic poisons everything. `busy_timeout` makes concurrent
//! writers queue instead of failing.

pub mod repo;

use std::{path::Path, sync::LazyLock, time::Duration};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use rusqlite_migration::{M, Migrations};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("pool: {0}")]
    Pool(#[from] r2d2::Error),
    #[error("migration: {0}")]
    Migration(#[from] rusqlite_migration::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("background task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type DbResult<T> = Result<T, DbError>;

static MIGRATIONS: LazyLock<Migrations<'static>> = LazyLock::new(|| {
    Migrations::new(vec![
        M::up(include_str!("migrations/001_core.sql")),
        M::up(include_str!("migrations/002_oauth.sql")),
    ])
});

/// Cheaply cloneable handle to the connection pool.
#[derive(Clone)]
pub struct Db {
    pool: Pool<SqliteConnectionManager>,
}

fn init_conn(c: &mut Connection) -> rusqlite::Result<()> {
    c.busy_timeout(Duration::from_secs(5))?;
    c.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;",
    )
}

impl Db {
    /// Open (creating if needed) the database file and apply migrations.
    pub fn open(path: &Path) -> DbResult<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let manager = SqliteConnectionManager::file(path).with_init(init_conn);
        Self::from_manager(manager, 8)
    }

    /// Private in-memory database (single connection, since each in-memory
    /// connection would otherwise be its own database). For tests.
    pub fn open_in_memory() -> DbResult<Self> {
        let manager = SqliteConnectionManager::memory().with_init(init_conn);
        Self::from_manager(manager, 1)
    }

    fn from_manager(manager: SqliteConnectionManager, size: u32) -> DbResult<Self> {
        let pool = Pool::builder().max_size(size).build(manager)?;
        let db = Self { pool };
        db.with_conn(|c| MIGRATIONS.to_latest(c).map_err(DbError::from))?;
        Ok(db)
    }

    /// Run `f` with a pooled connection on the current thread.
    pub fn with_conn<T>(&self, f: impl FnOnce(&mut Connection) -> DbResult<T>) -> DbResult<T> {
        let mut conn = self.pool.get()?;
        f(&mut conn)
    }

    /// Run `f` with a pooled connection on the blocking thread pool.
    pub async fn call<T, F>(&self, f: F) -> DbResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> DbResult<T> + Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.with_conn(f)).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_valid() {
        MIGRATIONS.validate().unwrap();
    }

    #[test]
    fn migrations_apply_to_in_memory_db() {
        let db = Db::open_in_memory().unwrap();
        let tables: Vec<String> = db
            .with_conn(|c| {
                let mut st =
                    c.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")?;
                Ok(st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
            })
            .unwrap();
        for t in [
            "tracked_products",
            "cves",
            "cve_affected",
            "cve_product_matches",
            "kev",
            "epss",
            "delivered",
            "source_status",
            "oauth_clients",
            "oauth_codes",
            "oauth_tokens",
        ] {
            assert!(tables.iter().any(|n| n == t), "missing table {t}");
        }
    }
}
