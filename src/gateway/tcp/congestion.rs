use std::time::{Duration, Instant};

use crate::gateway::tcp::rtt::RttEstimator;

pub(super) trait Controller: Send {
    fn window(&self) -> usize;
    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: usize, rtt: &RttEstimator);
    fn on_congestion(&mut self, now: Instant, sent: Instant, persistent: bool);
}

const BETA_CUBIC: f64 = 0.7;
const C: f64 = 0.4;

#[derive(Default)]
struct CubicState {
    k: f64,
    w_max: f64,
    cwnd_inc: usize,
}

impl CubicState {
    fn cubic_k(&self, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;
        (w_max * (1.0 - BETA_CUBIC) / C).cbrt()
    }

    fn w_cubic(&self, t: Duration, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;
        (C * (t.as_secs_f64() - self.k).powi(3) + w_max) * max_datagram_size as f64
    }

    fn w_est(&self, t: Duration, rtt: Duration, max_datagram_size: usize) -> f64 {
        let w_max = self.w_max / max_datagram_size as f64;
        (w_max * BETA_CUBIC
            + 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC) * t.as_secs_f64() / rtt.as_secs_f64())
            * max_datagram_size as f64
    }
}

#[allow(unused)]
struct Cubic {
    mtu: usize,
    window: usize,
    ssthresh: usize,
    state: CubicState,
    recovery_start_time: Option<Instant>,
}

#[allow(unused)]
impl Cubic {
    fn new(mtu: usize) -> Box<Self> {
        Box::new(Self {
            mtu,
            window: 200 * mtu,
            ssthresh: usize::MAX,
            state: CubicState::default(),
            recovery_start_time: None,
        })
    }

    fn minimum_window(&self) -> usize {
        200 * self.mtu
    }
}

#[allow(unused)]
impl Controller for Cubic {
    fn window(&self) -> usize {
        self.window
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: usize, rtt: &RttEstimator) {
        if self.recovery_start_time.map(|t| sent <= t).unwrap_or(false) {
            return;
        }

        if self.window < self.ssthresh {
            self.window += bytes;
        } else {
            let start_time = match self.recovery_start_time {
                Some(t) => t,
                None => {
                    self.recovery_start_time = Some(now);
                    self.state.w_max = self.window as f64;
                    self.state.k = 0.0;
                    now
                }
            };

            let t = now - start_time;
            let rtt = rtt.get();
            let w_cubic = self.state.w_cubic(t + rtt, self.mtu);
            let w_est = self.state.w_est(t, rtt, self.mtu);

            let mut cubic_cwnd = self.window;
            if w_cubic < w_est {
                cubic_cwnd = std::cmp::max(cubic_cwnd, w_est as usize);
            } else if cubic_cwnd < w_cubic as usize {
                let cubic_inc = (w_cubic - cubic_cwnd as f64) / cubic_cwnd as f64 * self.mtu as f64;
                cubic_cwnd += cubic_inc as usize;
            }

            self.state.cwnd_inc += cubic_cwnd - self.window;
            if self.state.cwnd_inc >= self.mtu {
                self.window += self.mtu;
                self.state.cwnd_inc = 0;
            }
        }
    }

    fn on_congestion(&mut self, now: Instant, sent: Instant, persistent: bool) {
        if self.recovery_start_time.map(|t| sent <= t).unwrap_or(false) {
            return;
        }

        self.recovery_start_time = Some(now);

        if (self.window as f64) < self.state.w_max {
            self.state.w_max = self.window as f64 * (1.0 + BETA_CUBIC) / 2.0;
        } else {
            self.state.w_max = self.window as f64;
        }

        self.ssthresh = std::cmp::max(
            (self.state.w_max * BETA_CUBIC) as usize,
            self.minimum_window(),
        );

        self.window = self.ssthresh;
        self.state.k = self.state.cubic_k(self.mtu);
        self.state.cwnd_inc = (self.state.cwnd_inc as f64 * BETA_CUBIC) as usize;

        if persistent {
            self.recovery_start_time = None;
            self.state.w_max = self.window as f64;
            self.ssthresh = std::cmp::max(
                (self.window as f64 * BETA_CUBIC) as usize,
                self.minimum_window(),
            );

            self.state.cwnd_inc = 0;
            self.window = self.minimum_window();
        }
    }
}

pub(super) struct FixBandwidth;

impl FixBandwidth {
    pub(super) fn new() -> Box<Self> {
        Box::new(Self {})
    }
}

#[allow(unused)]
impl Controller for FixBandwidth {
    fn window(&self) -> usize {
        128000
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: usize, rtt: &RttEstimator) {}

    fn on_congestion(&mut self, now: Instant, sent: Instant, persistent: bool) {}
}
