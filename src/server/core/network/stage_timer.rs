use std::time::{Duration, Instant};

pub struct StageTimer {
    start: Instant,
    timeout: Option<Duration>,
}

impl StageTimer {
    pub fn new(timeout: Option<Duration>) -> Self {
        Self {
            start: Instant::now(),
            timeout,
        }
    }

    pub fn is_timed_out(&self) -> bool {
        match self.timeout {
            Some(duration) => self.start.elapsed() > duration,
            None => false,
        }
    }

    pub fn remaining_time(&self) -> Option<Duration> {
        match self.timeout {
            Some(duration) => {
                let elapsed = self.start.elapsed();
                if elapsed >= duration {
                    Some(Duration::from_secs(0))
                } else {
                    Some(duration - elapsed)
                }
            }
            None => None,
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}