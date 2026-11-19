//! CVE monitor: syncs vulnerability data, filters it to tracked products and
//! builds the "what's new" feed.
//!
//! Data flow: `sources::*` fetch -> `sync` upserts normalized records ->
//! `matcher` links CVEs to tracked products -> `feed` serves undelivered or
//! changed items per consumer. `discovery` helps the agent build a
//! `TrackedProduct` from a plain product name.

pub mod discovery;
pub mod feed;
pub mod matcher;
pub mod normalize;
pub mod sources;
pub mod sync;
