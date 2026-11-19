//! Monitors. Each monitor owns its own sources, sync logic and agent-facing
//! feed. CVE is the first; SSL-cert and HTTP-uptime monitors will be added as
//! sibling modules. There is deliberately no plugin trait yet: add one when a
//! second monitor shows what is actually shared.

pub mod cve;
