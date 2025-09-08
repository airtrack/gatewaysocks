use std::time::Duration;

/// TCP Round-Trip Time estimator implementing RFC 6298 algorithms.
///
/// Maintains smoothed RTT estimates and calculates retransmission timeouts
/// based on measured round-trip times. Uses exponential weighted moving
/// averages to smooth out RTT variations and variance estimates.
pub(super) struct RttEstimator {
    /// Smoothed Round-Trip Time (SRTT) - exponentially weighted average of RTT samples
    srtt: Option<Duration>,
    /// Latest RTT measurement
    latest: Duration,
    /// RTT variance estimate for RTO calculation
    var: Duration,
    /// Current Retransmission Timeout value
    rto: Duration,
    /// Timer granularity for minimum RTO calculation
    granu: Duration,
}

impl RttEstimator {
    /// Creates a new RTT estimator with initial values.
    ///
    /// # Arguments
    ///
    /// * `init_rtt` - Initial RTT estimate before any measurements
    /// * `init_rto` - Initial retransmission timeout value
    /// * `granularity` - Timer granularity for minimum RTO bounds
    pub(super) fn new(init_rtt: Duration, init_rto: Duration, granularity: Duration) -> Self {
        Self {
            srtt: None,
            latest: init_rtt,
            var: Duration::default(),
            rto: init_rto,
            granu: granularity,
        }
    }

    /// Returns the current smoothed RTT estimate.
    ///
    /// If no RTT samples have been processed yet, returns the initial RTT value.
    pub(super) fn get(&self) -> Duration {
        self.srtt.unwrap_or(self.latest)
    }

    /// Returns the current retransmission timeout value.
    pub(super) fn rto(&self) -> Duration {
        self.rto
    }

    /// Returns the most recent RTT measurement.
    pub(super) fn latest(&self) -> Duration {
        self.latest
    }

    /// Updates RTT estimates with a new measurement using RFC 6298 algorithms.
    ///
    /// # Arguments
    ///
    /// * `rtt` - New RTT measurement to incorporate into estimates
    pub(super) fn update(&mut self, rtt: Duration) {
        self.latest = rtt;

        if let Some(srtt) = self.srtt {
            let var = if rtt > srtt { rtt - srtt } else { srtt - rtt };
            self.var = (3 * self.var + var) / 4;
            self.srtt = Some((7 * srtt + rtt) / 8);
        } else {
            self.srtt = Some(rtt);
            self.var = rtt / 2;
        }

        self.rto = self.srtt.unwrap() + self.granu.max(4 * self.var);
    }
}
