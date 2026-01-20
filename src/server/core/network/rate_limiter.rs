use tokio::time::Instant;

pub struct RateLimiter {
    max_tokens: u32,
    refill_rate: u32,
    tokens: u32,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            max_tokens,
            refill_rate,
            tokens: max_tokens,
            last_refill: Instant::now(),
        }
    }

    pub fn consume(&mut self) -> bool {
        // Refill tokens
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let refill = (elapsed * self.refill_rate as f64).floor() as u32;
        if refill > 0 {
            self.tokens = (self.tokens + refill).min(self.max_tokens);
            self.last_refill = now;
        }

        if self.tokens == 0 {
            return false;
        }

        // Consume one token
        self.tokens -= 1;
        true
    }
}