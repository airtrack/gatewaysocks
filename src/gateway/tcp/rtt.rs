use std::time::Duration;

pub(super) struct RttEstimator {
    srtt: Option<Duration>,
    latest: Duration,
    var: Duration,
    rto: Duration,
    granu: Duration,
}

impl RttEstimator {
    pub(super) fn new(init_rtt: Duration, init_rto: Duration, granularity: Duration) -> Self {
        Self {
            srtt: None,
            latest: init_rtt,
            var: Duration::default(),
            rto: init_rto,
            granu: granularity,
        }
    }

    pub(super) fn get(&self) -> Duration {
        self.srtt.unwrap_or(self.latest)
    }

    pub(super) fn rto(&self) -> Duration {
        self.rto
    }

    pub(super) fn latest(&self) -> Duration {
        self.latest
    }

    pub(super) fn update(&mut self, rtt: Duration) {
        self.latest = rtt;
        // According to RFC6298.
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
