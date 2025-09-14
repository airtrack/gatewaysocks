use std::time::{Duration, Instant};

use crate::gateway::tcp::{StreamStats, rtt::RttEstimator, stats};

/// Trait for TCP congestion control algorithms.
///
/// Defines the interface that all congestion control algorithms must implement
/// to manage the congestion window and respond to network events.
pub(super) trait Controller: Send {
    /// Returns the current congestion window size in bytes.
    fn window(&self) -> usize;

    /// Called when data is sent to track in-flight bytes.
    ///
    /// # Arguments
    /// * `now` - Current timestamp
    /// * `bytes` - Number of bytes being sent
    fn on_sent(&mut self, now: Instant, bytes: usize);

    /// Called when an ACK is received to update the congestion window.
    ///
    /// # Arguments
    /// * `now` - Current timestamp
    /// * `sent` - Timestamp when the acknowledged data was sent
    /// * `bytes` - Number of bytes acknowledged
    /// * `rtt` - RTT estimator for current network conditions
    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: usize, rtt: &RttEstimator);

    /// Called when congestion is detected to reduce the window.
    ///
    /// # Arguments
    /// * `now` - Current timestamp
    /// * `sent` - Timestamp when the lost packet was sent
    fn on_congestion(&mut self, now: Instant, sent: Instant);
}

/// CUBIC multiplicative decrease factor (RFC 8312)
const BETA_CUBIC: f32 = 0.7;
/// CUBIC scaling constant (RFC 8312)
const C: f32 = 0.4;

/// Internal state for the CUBIC congestion control algorithm.
///
/// Maintains the mathematical state needed for CUBIC window calculations
/// according to RFC 8312.
#[derive(Default)]
struct CubicState {
    /// Time period over which CUBIC function increases to w_max
    k: f32,
    /// Window size before the last congestion event
    w_max: f32,
    /// Last maximum window size for fast convergence
    w_last_max: f32,
}

impl CubicState {
    /// Calculates the K parameter for the CUBIC function.
    ///
    /// K represents the time period over which the CUBIC function increases
    /// from the current window to w_max in the absence of further loss events.
    /// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.1>
    /// K = cubic_root(W_max*(1-beta_cubic)/C) (Eq. 2)
    fn cubic_k(&self, mss: usize, start_cwnd: f32) -> f32 {
        let w_max = self.w_max / mss as f32;
        let w_start = start_cwnd / mss as f32;
        ((w_max - w_start) / C).cbrt()
    }

    /// Calculates the CUBIC window size at time t.
    ///
    /// This is the core CUBIC function from RFC 8312.
    /// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.1>
    /// W_cubic(t) = C*(t-K)^3 + W_max (Eq. 1)
    fn w_cubic(&self, t: Duration, mss: usize) -> f32 {
        let w_max = self.w_max / mss as f32;
        (C * (t.as_secs_f32() - self.k).powi(3) + w_max) * mss as f32
    }

    /// Calculates the TCP-friendly window size estimate.
    ///
    /// Used in the TCP-friendly region to ensure CUBIC is not more aggressive
    /// than standard TCP.
    /// <https://datatracker.ietf.org/doc/html/rfc8312#section-4.2>
    /// W_est(t) = W_max*beta_cubic +
    ///              [3*(1-beta_cubic)/(1+beta_cubic)] * (t/RTT) (Eq. 4)
    fn w_est(&self, t: Duration, rtt: Duration, mss: usize) -> f32 {
        let w_max = self.w_max / mss as f32;
        let w_est = w_max * BETA_CUBIC
            + 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC) * t.as_secs_f32() / rtt.as_secs_f32();
        w_est * mss as f32
    }
}

/// CUBIC congestion control states.
///
/// Represents the different phases of CUBIC congestion control operation.
enum State {
    SlowStart,
    Recovery(Instant),
    CongestionAvoidance(AvoidanceTiming),
}

/// Timing state for CUBIC congestion avoidance phase.
///
/// Tracks time periods and handles application-limited scenarios during
/// congestion avoidance. This ensures that time spent in application-limited
/// state doesn't affect CUBIC's time-based calculations, maintaining accurate
/// congestion window growth behavior.
/// <https://datatracker.ietf.org/doc/html/rfc8312#section-5.8>
struct AvoidanceTiming {
    /// Start time of the current congestion avoidance phase
    start_time: Instant,
    /// Last time congestion avoidance calculations were performed
    last_avoidance_time: Instant,
    /// Time when the connection became application-limited (if any)
    last_app_limited_time: Option<Instant>,
}

impl AvoidanceTiming {
    /// Creates a new timing tracker for congestion avoidance phase.
    ///
    /// # Arguments
    /// * `now` - Current timestamp when entering congestion avoidance
    fn new(now: Instant) -> Self {
        Self {
            start_time: now,
            last_avoidance_time: now,
            last_app_limited_time: None,
        }
    }

    /// Returns the elapsed time since congestion avoidance began.
    ///
    /// This time excludes periods when the connection was application-limited,
    /// ensuring CUBIC calculations are based only on congestion-limited time.
    ///
    /// # Arguments
    /// * `now` - Current timestamp
    fn t(&self, now: Instant) -> Duration {
        now - self.start_time
    }

    /// Records when the connection becomes application-limited.
    ///
    /// Application-limited periods should not contribute to CUBIC's time-based
    /// window calculations, as they don't reflect network congestion conditions.
    ///
    /// # Arguments
    /// * `now` - Timestamp when application limiting began
    fn on_app_limited(&mut self, now: Instant) {
        self.last_app_limited_time = Some(now);
    }

    /// Updates timing state when performing congestion avoidance calculations.
    ///
    /// If there was an application-limited period, adjusts the start time to
    /// exclude that period from CUBIC calculations. This ensures that time
    /// spent not sending due to application limits doesn't affect the cubic
    /// function's growth behavior.
    ///
    /// # Arguments
    /// * `now` - Current timestamp
    fn on_avoidance(&mut self, now: Instant) {
        if let Some(app_limited_time) = self.last_app_limited_time.take() {
            // Adjust start time to exclude application-limited period
            self.start_time += app_limited_time - self.last_avoidance_time;
        }

        self.last_avoidance_time = now;
    }
}

/// CUBIC congestion control implementation (RFC 8312).
pub(super) struct Cubic {
    mss: usize,
    window: usize,
    ssthresh: usize,
    in_flight: usize,
    app_limited: bool,
    state: State,
    cubic: CubicState,
    stats: StreamStats,
}

impl Cubic {
    /// Creates a new CUBIC congestion controller.
    pub(super) fn new(mss: usize, stats: StreamStats) -> Box<Self> {
        let window = 16 * mss;
        stats.set_congestion_limited(false);
        stats.set_congestion_window(window);
        stats.set_congestion_state(stats::CongestionState::SlowStart);

        Box::new(Self {
            mss,
            window,
            ssthresh: usize::MAX,
            in_flight: 0,
            app_limited: true,
            state: State::SlowStart,
            cubic: CubicState::default(),
            stats,
        })
    }

    /// Returns the minimum congestion window size (2 MSS).
    fn minimum_window(&self) -> usize {
        2 * self.mss
    }

    /// Determines if the sender is congestion-limited.
    ///
    /// Returns true if the available window space is less than 3 MSS,
    /// indicating that congestion control is limiting transmission.
    fn is_congestion_limited(&self) -> bool {
        let available_bytes = self.window.saturating_sub(self.in_flight);
        available_bytes < 3 * self.mss
    }

    /// Performs multiplicative decrease when congestion is detected.
    ///
    /// Implements RFC 8312 Section 4.5 (Multiplicative Decrease) and
    /// Section 4.6 (Fast Convergence) to reduce the window size and
    /// update CUBIC state parameters.
    fn multiplicative_decrease(&mut self) {
        // <https://datatracker.ietf.org/doc/html/rfc8312#section-4.5>
        // Multiplicative Decrease
        let cwnd = self.window as f32;
        self.cubic.w_max = cwnd;
        self.ssthresh = (cwnd * BETA_CUBIC) as usize;
        self.ssthresh = self.ssthresh.max(self.minimum_window());
        self.window = self.ssthresh;

        // <https://datatracker.ietf.org/doc/html/rfc8312#section-4.6>
        // Fast Convergence
        if self.cubic.w_max < self.cubic.w_last_max {
            self.cubic.w_last_max = self.cubic.w_max;
            self.cubic.w_max *= (1.0 + BETA_CUBIC) / 2.0;
        } else {
            self.cubic.w_last_max = self.cubic.w_max;
        }

        self.cubic.w_max = self.cubic.w_max.max(self.minimum_window() as f32);
        self.cubic.k = self.cubic.cubic_k(self.mss, self.window as f32);
    }

    /// Updates the congestion window during congestion avoidance phase.
    fn congestion_avoidance(&mut self, t: Duration, rtt: Duration) {
        let w_cubic = self.cubic.w_cubic(t, self.mss);
        let w_est = self.cubic.w_est(t, rtt, self.mss);

        let mut cwnd = self.window;
        if w_cubic < w_est {
            // <https://datatracker.ietf.org/doc/html/rfc8312#section-4.2>
            // TCP-Friendly Region
            cwnd = w_est as usize;
        } else {
            // <https://datatracker.ietf.org/doc/html/rfc8312#section-4.3>
            // <https://datatracker.ietf.org/doc/html/rfc8312#section-4.4>
            // Concave Region and Convex Region has the same increment:
            // (W_cubic(t+RTT) - cwnd)/cwnd for each received ACK, where
            // W_cubic(t+RTT) is calculated using Eq. 1.
            let w_cubic = self.cubic.w_cubic(t + rtt, self.mss);
            let inc = (w_cubic - cwnd as f32) / cwnd as f32 * self.mss as f32;
            cwnd += inc as usize;
        }

        self.window = cwnd;
    }
}

impl Controller for Cubic {
    fn window(&self) -> usize {
        self.window
    }

    fn on_sent(&mut self, _now: Instant, bytes: usize) {
        self.in_flight += bytes;

        let congestion_limited = self.is_congestion_limited();
        self.app_limited = !congestion_limited;

        self.stats.set_congestion_limited(congestion_limited);
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: usize, rtt: &RttEstimator) {
        self.in_flight -= bytes;

        if self.app_limited {
            if let State::CongestionAvoidance(ref mut timing) = self.state {
                timing.on_app_limited(now);
            }

            return;
        }

        match self.state {
            State::SlowStart => {
                self.window += bytes;
                if self.window >= self.ssthresh {
                    self.state = State::CongestionAvoidance(AvoidanceTiming::new(now));
                    self.cubic.w_max = self.window as f32;
                    self.cubic.k = 0.0;

                    self.stats
                        .set_congestion_state(stats::CongestionState::CongestionAvoidance);
                }
            }
            State::Recovery(start_time) => {
                if sent >= start_time {
                    self.state = State::CongestionAvoidance(AvoidanceTiming::new(now));
                    self.stats
                        .set_congestion_state(stats::CongestionState::CongestionAvoidance);
                }
            }
            State::CongestionAvoidance(ref mut timing) => {
                timing.on_avoidance(now);
                let t = timing.t(now);
                self.congestion_avoidance(t, rtt.get());
            }
        }

        self.stats.set_congestion_window(self.window);
    }

    fn on_congestion(&mut self, now: Instant, _sent: Instant) {
        if matches!(self.state, State::Recovery(_)) {
            return;
        }

        self.state = State::Recovery(now);
        self.multiplicative_decrease();

        self.stats.set_congestion_window(self.window);
        self.stats
            .set_congestion_state(stats::CongestionState::Recovery);
    }
}

/// Fixed bandwidth congestion controller for testing.
///
/// Provides a constant congestion window size regardless of network
/// conditions. Useful for testing and debugging scenarios where
/// variable congestion control behavior is not desired.
pub(super) struct FixedBandwidth;

#[allow(unused)]
impl FixedBandwidth {
    pub(super) fn new() -> Box<Self> {
        Box::new(Self {})
    }
}

#[allow(unused)]
impl Controller for FixedBandwidth {
    fn window(&self) -> usize {
        128000
    }

    fn on_sent(&mut self, now: Instant, bytes: usize) {}

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: usize, rtt: &RttEstimator) {}

    fn on_congestion(&mut self, now: Instant, sent: Instant) {}
}
