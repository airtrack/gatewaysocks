use std::time::{Duration, Instant};

/// TCP packet pacer that implements token bucket rate limiting.
///
/// The pacer controls the transmission rate of TCP segments by maintaining
/// a token bucket that refills at a rate proportional to the estimated
/// bandwidth-delay product. This helps avoid overwhelming the network
/// and provides smoother traffic patterns.
pub(super) struct Pacer {
    /// Time granularity for pacing calculations
    granularity: Duration,
    /// Number of bytes that can be sent per granularity period
    granu_bytes: usize,
    /// Current number of tokens (bytes) available for transmission
    token_bytes: usize,
    /// Current congestion window size in bytes
    window: usize,
    /// Maximum Segment Size
    mss: usize,
    /// Smoothed round-trip time
    srtt: Duration,
    /// Last time tokens were replenished
    last: Instant,
}

impl Pacer {
    /// Creates a new TCP pacer with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `srtt` - Smoothed round-trip time estimate
    /// * `window` - Initial congestion window size in bytes
    /// * `granularity` - Time granularity for pacing calculations
    /// * `mss` - Maximum Segment Size
    pub(super) fn new(srtt: Duration, window: usize, granularity: Duration, mss: usize) -> Self {
        let mut pacer = Self {
            granularity,
            granu_bytes: 0,
            token_bytes: 0,
            window,
            mss,
            srtt,
            last: Instant::now(),
        };
        pacer.update_granularity(srtt, window);
        pacer.token_bytes = pacer.granu_bytes;
        pacer
    }

    /// Records that bytes have been sent, consuming tokens from the bucket.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes that were transmitted
    pub(super) fn on_sent(&mut self, bytes: usize) {
        self.token_bytes = self.token_bytes.saturating_sub(bytes);
    }

    /// Determines if sending is allowed or calculates when it will be allowed.
    ///
    /// This method implements the core pacing logic by checking if sufficient
    /// tokens are available for transmission. If not, it calculates when
    /// enough tokens will be available based on the token replenishment rate.
    ///
    /// # Arguments
    ///
    /// * `send_bytes` - Number of bytes wanting to be sent
    /// * `now` - Current timestamp
    /// * `srtt` - Current smoothed round-trip time
    /// * `window` - Current congestion window size
    ///
    /// # Returns
    ///
    /// - `None` if sending is allowed immediately
    /// - `Some(Instant)` indicating when sending will be allowed
    pub(super) fn wait_until(
        &mut self,
        send_bytes: usize,
        now: Instant,
        srtt: Duration,
        window: usize,
    ) -> Option<Instant> {
        // Update pacing parameters if congestion window or RTT has changed
        if self.window != window || self.srtt != srtt {
            self.update_granularity(srtt, window);
            self.srtt = srtt;
            self.window = window;
            self.token_bytes = self.granu_bytes.min(self.token_bytes);
        }

        if self.token_bytes >= send_bytes {
            return None;
        }

        // Calculate token replenishment based on elapsed time
        // Tokens are replenished at a rate of (window / srtt) bytes per second
        let inc_rtts = (now - self.last).as_secs_f64() / self.srtt.as_secs_f64();
        let inc_bytes = (inc_rtts * window as f64) as usize;

        self.token_bytes = self
            .token_bytes
            .saturating_add(inc_bytes as usize)
            .min(self.granu_bytes);
        self.last = now;

        if self.token_bytes >= send_bytes {
            return None;
        }

        // Calculate delay needed to accumulate sufficient tokens
        let diff = (send_bytes - self.token_bytes).max(self.granu_bytes) as f64;
        let duration = diff * self.srtt.as_secs_f64() / self.window as f64;
        let delay = Duration::from_secs_f64(duration);
        Some(now + delay)
    }

    /// Updates the granularity-based token bucket parameters.
    ///
    /// Calculates how many bytes can be sent per granularity period
    /// based on the current RTT and congestion window size.
    fn update_granularity(&mut self, srtt: Duration, window: usize) {
        let srtt = srtt.as_secs_f64();
        let unit = self.granularity.as_secs_f64();
        let bytes = ((unit * window as f64) / srtt) as usize;
        self.granu_bytes = bytes.max(self.mss);
    }
}
