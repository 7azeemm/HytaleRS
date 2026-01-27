use parking_lot::Mutex;
use tokio::time::Instant;

pub struct RateLimiter {
    max_tokens: u32,
    refill_rate: u32,
    state: Mutex<RateLimiterState>,
}

struct RateLimiterState {
    tokens: u32,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            max_tokens,
            refill_rate,
            state: Mutex::new(RateLimiterState {
                tokens: max_tokens,
                last_refill: Instant::now()
            })
        }
    }

    /// Try to consume one token
    /// Returns true if successful, false if rate limit exceeded
    #[inline]
    pub fn consume(&self) -> bool {
        // Refill tokens
        let now = Instant::now();
        let mut state = self.state.lock();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        state.tokens = (state.tokens + (elapsed * self.refill_rate as f64) as u32).min(self.max_tokens);
        state.last_refill = now;

        // Try to consume token
        if state.tokens >= 1 {
            state.tokens -= 1;
            true
        } else {
            false
        }
    }
}