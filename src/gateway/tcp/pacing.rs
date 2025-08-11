use std::time::{Duration, Instant};

pub(super) struct Pacer {
    granularity: Duration,
    granu_bytes: usize,
    bytes: usize,
    window: usize,
    srtt: Duration,
    prev: Instant,
}

impl Pacer {
    pub(super) fn new(srtt: Duration, window: usize, granularity: Duration) -> Self {
        let granu_bytes = Self::granularity_bytes(srtt, window, granularity);
        Self {
            granularity,
            granu_bytes,
            bytes: granu_bytes,
            window,
            srtt,
            prev: Instant::now(),
        }
    }

    fn granularity_bytes(srtt: Duration, window: usize, granularity: Duration) -> usize {
        let srtt = srtt.as_secs_f64();
        let unit = granularity.as_secs_f64();
        ((unit * window as f64) / srtt) as usize
    }

    pub(super) fn consume(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_sub(bytes);
    }

    pub(super) fn delay(
        &mut self,
        send_bytes: usize,
        now: Instant,
        srtt: Duration,
        window: usize,
    ) -> Option<Instant> {
        if self.window != window {
            self.granu_bytes = Self::granularity_bytes(srtt, window, self.granularity);
            self.bytes = self.granu_bytes.min(self.bytes);
            self.srtt = srtt;
            self.window = window;
        }

        if self.bytes >= send_bytes {
            return None;
        }

        let inc_rtts = (now - self.prev).as_secs_f64() / self.srtt.as_secs_f64();
        let inc_bytes = (inc_rtts * window as f64) as usize;
        self.bytes = self
            .bytes
            .saturating_add(inc_bytes as usize)
            .min(self.granu_bytes);
        self.prev = now;

        if self.bytes >= send_bytes {
            return None;
        }

        let diff = (send_bytes.max(self.granu_bytes) - self.bytes) as f64;
        let duration = diff * self.srtt.as_secs_f64() / self.window as f64;
        let delay = Duration::from_secs_f64(duration);
        Some(now + delay)
    }
}
