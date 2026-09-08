//! Exact sliding 60-second window with hard bounds on tracked addresses.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::canonical_ip;

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    RateLimit,
    Capacity,
    Unavailable,
}

impl Decision {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::RateLimit => "rate_limit",
            Self::Capacity => "rate_limit_capacity",
            Self::Unavailable => "rate_limiter_unavailable",
        }
    }
}

pub struct RateLimiter {
    limit: u32,
    max_ips: usize,
    inner: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(limit: u32, max_ips: usize) -> Self {
        Self {
            limit,
            max_ips,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, ip: IpAddr) -> Decision {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> Decision {
        if self.limit == 0 {
            return Decision::Allowed;
        }
        // Fail closed on poisoning, instead of panicking every accept task.
        let Ok(mut map) = self.inner.lock() else {
            return Decision::Unavailable;
        };
        let ip = canonical_ip(ip);
        if !map.contains_key(&ip) && map.len() >= self.max_ips {
            // Do not rescan the whole map for every hostile new address.
            // The once-per-second maintenance task reclaims idle buckets.
            return Decision::Capacity;
        }
        let window = map.entry(ip).or_default();
        expire(window, now);
        if window.len() >= self.limit as usize {
            return Decision::RateLimit;
        }
        window.push_back(now);
        Decision::Allowed
    }

    pub fn evict_idle(&self) {
        self.evict_at(Instant::now());
    }

    fn evict_at(&self, now: Instant) {
        if let Ok(mut map) = self.inner.lock() {
            map.retain(|_, window| {
                expire(window, now);
                !window.is_empty()
            });
        }
    }

    pub fn tracked_ips(&self) -> usize {
        self.inner.lock().map(|map| map.len()).unwrap_or(0)
    }
}

fn expire(window: &mut VecDeque<Instant>, now: Instant) {
    while window
        .front()
        .is_some_and(|time| now.saturating_duration_since(*time) >= WINDOW)
    {
        window.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn disabled_limiter_does_not_allocate() {
        let limiter = RateLimiter::new(0, 1);
        for _ in 0..100 {
            assert_eq!(limiter.check(ip("192.0.2.1")), Decision::Allowed);
        }
        assert_eq!(limiter.tracked_ips(), 0);
    }

    #[test]
    fn independently_limits_ips() {
        let limiter = RateLimiter::new(1, 2);
        assert_eq!(limiter.check(ip("192.0.2.1")), Decision::Allowed);
        assert_eq!(limiter.check(ip("192.0.2.1")), Decision::RateLimit);
        assert_eq!(limiter.check(ip("192.0.2.2")), Decision::Allowed);
    }

    #[test]
    fn timestamp_at_exact_boundary_expires() {
        let limiter = RateLimiter::new(1, 1);
        let now = Instant::now();
        let addr = ip("192.0.2.1");
        assert_eq!(limiter.check_at(addr, now), Decision::Allowed);
        assert_eq!(
            limiter.check_at(addr, now + WINDOW - Duration::from_nanos(1)),
            Decision::RateLimit
        );
        assert_eq!(limiter.check_at(addr, now + WINDOW), Decision::Allowed);
    }

    #[test]
    fn table_is_bounded_and_idle_buckets_are_reclaimed() {
        let limiter = RateLimiter::new(1, 1);
        let now = Instant::now();
        assert_eq!(limiter.check_at(ip("192.0.2.1"), now), Decision::Allowed);
        assert_eq!(limiter.check_at(ip("192.0.2.2"), now), Decision::Capacity);
        assert_eq!(limiter.tracked_ips(), 1);
        limiter.evict_at(now + WINDOW);
        assert_eq!(limiter.tracked_ips(), 0);
        assert_eq!(
            limiter.check_at(ip("192.0.2.2"), now + WINDOW),
            Decision::Allowed
        );
    }

    #[test]
    fn mapped_ipv6_shares_the_ipv4_bucket() {
        let limiter = RateLimiter::new(1, 2);
        assert_eq!(limiter.check(ip("192.0.2.1")), Decision::Allowed);
        assert_eq!(limiter.check(ip("::ffff:192.0.2.1")), Decision::RateLimit);
        assert_eq!(limiter.tracked_ips(), 1);
    }
}
