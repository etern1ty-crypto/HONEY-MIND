//! Per-source-IP connection rate limit.
//!
//! Simple sliding-window counter: track the timestamp of each accepted
//! connection per source IP for the last 60 seconds. New connections beyond
//! the configured rate are rejected.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

/// In-memory rate limiter. Cheap enough for typical honeypot loads
/// (thousands of unique IPs per minute on commodity hardware).
pub struct RateLimiter {
    /// 0 disables the limiter.
    limit: u32,
    inner: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(limit_per_min: u32) -> Self {
        Self {
            limit: limit_per_min,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if a new connection from this IP is allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.limit == 0 {
            return true;
        }
        let now = Instant::now();
        let cutoff = now - WINDOW;
        let mut guard = self.inner.lock().expect("ratelimit mutex poisoned");
        let entry = guard.entry(ip).or_default();
        while let Some(&front) = entry.front() {
            if front < cutoff {
                entry.pop_front();
            } else {
                break;
            }
        }
        if entry.len() as u32 >= self.limit {
            return false;
        }
        entry.push_back(now);
        true
    }

    /// Drop empty entries. Should be called periodically (e.g. once per minute)
    /// to prevent unbounded memory growth from scanners that hit once and never
    /// come back.
    pub fn evict_idle(&self) {
        if self.limit == 0 {
            return;
        }
        let cutoff = Instant::now() - WINDOW;
        let mut guard = self.inner.lock().expect("ratelimit mutex poisoned");
        guard.retain(|_, q| {
            while let Some(&front) = q.front() {
                if front < cutoff {
                    q.pop_front();
                } else {
                    break;
                }
            }
            !q.is_empty()
        });
    }

    /// Number of source IPs currently tracked.
    pub fn tracked_ips(&self) -> usize {
        self.inner.lock().expect("ratelimit mutex poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn zero_limit_allows_everything() {
        let rl = RateLimiter::new(0);
        for _ in 0..1000 {
            assert!(rl.check(ip("1.2.3.4")));
        }
    }

    #[test]
    fn blocks_after_limit() {
        let rl = RateLimiter::new(3);
        let addr = ip("1.2.3.4");
        assert!(rl.check(addr));
        assert!(rl.check(addr));
        assert!(rl.check(addr));
        assert!(!rl.check(addr));
        assert!(!rl.check(addr));
    }

    #[test]
    fn independent_per_ip() {
        let rl = RateLimiter::new(2);
        assert!(rl.check(ip("1.1.1.1")));
        assert!(rl.check(ip("1.1.1.1")));
        assert!(!rl.check(ip("1.1.1.1")));
        assert!(rl.check(ip("2.2.2.2")));
        assert!(rl.check(ip("2.2.2.2")));
        assert!(!rl.check(ip("2.2.2.2")));
    }

    #[test]
    fn evict_idle_removes_empty_buckets() {
        let rl = RateLimiter::new(1);
        rl.check(ip("3.3.3.3"));
        assert_eq!(rl.tracked_ips(), 1);
        // Force the bucket to be considered idle by manipulating the time
        // directly is not portable; instead we just verify the method runs.
        rl.evict_idle();
        // Still tracked because not expired yet.
        assert_eq!(rl.tracked_ips(), 1);
    }
}
