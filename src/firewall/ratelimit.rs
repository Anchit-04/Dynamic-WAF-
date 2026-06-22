use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    inner: Mutex<HashMap<String, (usize, Instant)>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_secs: u64) -> Self {
        RateLimiter {
            inner: Mutex::new(HashMap::new()),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    pub fn check(&self, key: &str) -> bool {
        let mut map = self.inner.lock().unwrap();

        if map.len() > 10000 {
            let now = Instant::now();
            map.retain(|_, &mut (_, last)| now - last <= self.window);
        }

        let now = Instant::now();
        let entry = map.entry(key.to_string()).or_insert((0, now));

        if now - entry.1 > self.window {
            *entry = (1, now);
            true
        } else {
            entry.0 += 1;
            entry.0 <= self.max_requests
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_allows_within_limit() {
        let limiter = RateLimiter::new(5, 60);
        for _ in 0..5 {
            assert!(limiter.check("test"));
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.check("test"));
        assert!(limiter.check("test"));
        assert!(limiter.check("test"));
        assert!(!limiter.check("test"));
    }

    #[test]
    fn test_different_keys_independent() {
        let limiter = RateLimiter::new(2, 60);
        assert!(limiter.check("a"));
        assert!(limiter.check("a"));
        assert!(!limiter.check("a"));
        assert!(limiter.check("b"));
    }

    #[test]
    fn test_window_expires() {
        let limiter = RateLimiter::new(2, 1);
        assert!(limiter.check("test"));
        assert!(limiter.check("test"));
        assert!(!limiter.check("test"));
        thread::sleep(Duration::from_secs(1));
        assert!(limiter.check("test"));
    }
}
