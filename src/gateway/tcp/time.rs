use std::time::Instant;

/// TCP stream timing tracker for timestamps and connection lifecycle.
///
/// Manages timing information for a TCP connection including initialization
/// time for timestamp generation and last activity time for timeout detection.
/// Handles timestamp wraparound correctly for the TCP timestamp option.
pub(super) struct StreamTime {
    /// Stream initialization time used as base for timestamp calculations
    init: Instant,
    /// Last time the stream was active
    alive: Instant,
}

impl StreamTime {
    /// Creates a new stream time tracker initialized to the given instant.
    ///
    /// Both initialization and last alive times are set to the provided timestamp.
    pub(super) fn new(now: Instant) -> Self {
        Self {
            init: now,
            alive: now,
        }
    }

    /// Returns elapsed milliseconds since stream initialization as u32 timestamp.
    ///
    /// This is used for TCP timestamp option values. The result wraps around
    /// at u32::MAX, which is handled correctly by TCP timestamp processing.
    /// The wraparound behavior is intentional and tested.
    ///
    /// # Arguments
    ///
    /// * `now` - Current time to calculate elapsed duration from
    pub(super) fn elapsed_millis(&self, now: Instant) -> u32 {
        (now - self.init).as_millis() as u32
    }

    /// Returns the last time this stream was active.
    pub(super) fn alive_time(&self) -> Instant {
        self.alive
    }

    /// Updates the last activity time to the current timestamp.
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

        // Test timestamp at u32::MAX
        let now = time.init + duration;
        let t1 = time.elapsed_millis(now);
        assert_eq!(t1, u32::MAX);

        // Test wraparound: u32::MAX + 1 wraps to 0
        let now = now + Duration::from_millis(1);
        let t2 = time.elapsed_millis(now);
        assert_eq!(t2, 0);

        // Test continued counting after wraparound
        let now = now + Duration::from_millis(10);
        let t3 = time.elapsed_millis(now);
        assert_eq!(t3, 10);

        // Test another full cycle: should wrap again
        let now = now + duration;
        let t4 = time.elapsed_millis(now);
        assert_eq!(t4, 9); // 10 - 1 (due to previous +1)
    }
}
