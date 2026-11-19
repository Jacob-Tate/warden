//! Shared in-memory rate-limit primitives: address keys and a bounded per-key counter table.
//!
//! Used by the failed-bearer limiter (`auth`), the `/token` + `/revoke` failure limiter,
//! the registration limiter and the passphrase limiter (`oauth`).
//!
//! - Keys: IPv4 as is, IPv4-mapped IPv6 as the IPv4 address, other IPv6 by its /64 (a
//!   single subscriber normally owns a whole /64, so per-full-address keys would let one
//!   host mint unlimited identities).
//! - The table is bounded (`cap` entries). Expired entries are swept at most once per
//!   quarter-window or when the table is full; if it is still full, the oldest eighth is
//!   evicted, so every operation is O(1) amortized and memory is bounded.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    time::{Duration, Instant},
};

/// Normalize an address into the key the limiters count under.
pub fn key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut o = v6.octets();
                o[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(o))
            }
        },
    }
}

/// When a counter stops counting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// `window` after the first hit (fixed window).
    Fixed,
    /// `window` after the most recent hit.
    Idle,
}

#[derive(Clone, Copy, Debug)]
pub struct Counter {
    pub count: u32,
    pub first: Instant,
    pub last: Instant,
}

impl Counter {
    pub fn new(now: Instant) -> Self {
        Self {
            count: 0,
            first: now,
            last: now,
        }
    }

    pub fn expired(&self, now: Instant, window: Duration, mode: Expiry) -> bool {
        let base = match mode {
            Expiry::Fixed => self.first,
            Expiry::Idle => self.last,
        };
        now.saturating_duration_since(base) >= window
    }

    /// Count one hit, starting a fresh window first if this one has expired.
    pub fn hit(&mut self, now: Instant, window: Duration, mode: Expiry) -> u32 {
        if self.expired(now, window, mode) {
            *self = Counter::new(now);
        }
        self.count += 1;
        self.last = now;
        self.count
    }
}

/// Bounded map from address key to [`Counter`].
pub struct Table {
    map: HashMap<IpAddr, Counter>,
    window: Duration,
    mode: Expiry,
    cap: usize,
    last_sweep: Instant,
}

impl Table {
    pub fn new(window: Duration, mode: Expiry, cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            window,
            mode,
            cap: cap.max(8),
            last_sweep: Instant::now(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// The live counter for `ip`, if any.
    pub fn get(&self, ip: IpAddr, now: Instant) -> Option<Counter> {
        self.map
            .get(&key(ip))
            .filter(|c| !c.expired(now, self.window, self.mode))
            .copied()
    }

    /// Count a hit for `ip`; returns the new count.
    pub fn hit(&mut self, ip: IpAddr, now: Instant) -> u32 {
        let k = key(ip);
        if !self.map.contains_key(&k) {
            self.make_room(now);
        }
        let (w, m) = (self.window, self.mode);
        self.map
            .entry(k)
            .or_insert_with(|| Counter::new(now))
            .hit(now, w, m)
    }

    /// Undo one hit (e.g. a reservation that turned out not to count).
    pub fn unhit(&mut self, ip: IpAddr) {
        let k = key(ip);
        if let Some(c) = self.map.get_mut(&k) {
            c.count = c.count.saturating_sub(1);
            if c.count == 0 {
                self.map.remove(&k);
            }
        }
    }

    pub fn remove(&mut self, ip: IpAddr) {
        self.map.remove(&key(ip));
    }

    fn make_room(&mut self, now: Instant) {
        let full = self.map.len() >= self.cap;
        if !full && now.saturating_duration_since(self.last_sweep) < self.window / 4 {
            return;
        }
        self.last_sweep = now;
        let (w, m) = (self.window, self.mode);
        self.map.retain(|_, c| !c.expired(now, w, m));
        if self.map.len() >= self.cap {
            // Still full of live entries: evict the oldest eighth in one pass.
            let mut by_age: Vec<(Instant, IpAddr)> =
                self.map.iter().map(|(k, c)| (c.last, *k)).collect();
            let n = (self.cap / 8).max(1);
            by_age.select_nth_unstable_by_key(n - 1, |(t, _)| *t);
            for (_, k) in by_age.into_iter().take(n) {
                self.map.remove(&k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_collapse_v6_and_mapped_v4() {
        let k = |s: &str| key(s.parse().unwrap());
        assert_eq!(k("2001:db8:1:2::1"), k("2001:db8:1:2:ffff::9"));
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
        assert_eq!(k("::ffff:203.0.113.9"), k("203.0.113.9"));
        assert_eq!(k("203.0.113.9"), "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn table_is_bounded_and_expires() {
        let mut t = Table::new(Duration::from_secs(60), Expiry::Fixed, 64);
        let now = Instant::now();
        for i in 0..1000u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
            t.hit(ip, now);
            assert!(t.len() <= 64, "len {}", t.len());
        }
        let ip: IpAddr = "10.9.9.9".parse().unwrap();
        assert_eq!(t.hit(ip, now), 1);
        assert_eq!(t.hit(ip, now), 2);
        assert_eq!(t.get(ip, now).unwrap().count, 2);
        let later = now + Duration::from_secs(61);
        assert!(t.get(ip, later).is_none());
        assert_eq!(t.hit(ip, later), 1);
        t.unhit(ip);
        assert!(t.get(ip, later).is_none());
    }
}
