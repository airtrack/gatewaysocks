use std::time::{Duration, Instant};

pub(super) struct Pacer {
    granularity: Duration,
    granu_bytes: usize,
    token_bytes: usize,
    window: usize,
    mss: usize,
    srtt: Duration,
    last: Instant,
}

impl Pacer {
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

    pub(super) fn on_sent(&mut self, bytes: usize) {
        self.token_bytes = self.token_bytes.saturating_sub(bytes);
    }

    pub(super) fn wait_until(
        &mut self,
        send_bytes: usize,
        now: Instant,
        srtt: Duration,
        window: usize,
    ) -> Option<Instant> {
        if self.window != window || self.srtt != srtt {
            self.update_granularity(srtt, window);
            self.srtt = srtt;
            self.window = window;
            self.token_bytes = self.granu_bytes.min(self.token_bytes);
        }

        if self.token_bytes >= send_bytes {
            return None;
        }

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

        let diff = (send_bytes - self.token_bytes).max(self.granu_bytes) as f64;
        let duration = diff * self.srtt.as_secs_f64() / self.window as f64;
        let delay = Duration::from_secs_f64(duration);
        Some(now + delay)
    }

    fn update_granularity(&mut self, srtt: Duration, window: usize) {
        let srtt = srtt.as_secs_f64();
        let unit = self.granularity.as_secs_f64();
        let bytes = ((unit * window as f64) / srtt) as usize;
        self.granu_bytes = bytes.max(self.mss);
    }
}
