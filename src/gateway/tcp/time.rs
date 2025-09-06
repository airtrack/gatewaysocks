use std::time::Instant;

pub(super) struct StreamTime {
    init: Instant,
    alive: Instant,
}

impl StreamTime {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            init: now,
            alive: now,
        }
    }

    pub(super) fn elapsed_millis(&self, now: Instant) -> u32 {
        (now - self.init).as_millis() as u32
    }

    pub(super) fn alive_time(&self) -> Instant {
        self.alive
    }

    pub(super) fn update_alive(&mut self, now: Instant) {
        self.alive = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_timestamp() {
        let now = Instant::now();
        let time = StreamTime::new(now);
        let duration = Duration::from_millis(u32::MAX as u64);

        let now = time.init + duration;
        let t1 = time.elapsed_millis(now);
        assert_eq!(t1, u32::MAX);

        let now = now + Duration::from_millis(1);
        let t2 = time.elapsed_millis(now);
        assert_eq!(t2, 0);

        let now = now + Duration::from_millis(10);
        let t3 = time.elapsed_millis(now);
        assert_eq!(t3, 10);

        let now = now + duration;
        let t4 = time.elapsed_millis(now);
        assert_eq!(t4, 9);
    }
}
