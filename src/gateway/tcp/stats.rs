use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use dashmap::DashMap;

use crate::gateway::tcp::types::{AddrPair, State};

/// Thread-safe map of TCP connection statistics indexed by address pairs.
///
/// Provides concurrent access to statistics for multiple TCP connections,
/// allowing safe monitoring from multiple threads without blocking.
#[derive(Clone, Default)]
pub struct StatsMap {
    pub(super) map: Arc<DashMap<AddrPair, StreamStats>>,
}

impl StatsMap {
    /// Creates a new empty statistics map.
    #[inline]
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Iterates over all connection statistics, calling the provided function
    /// for each address pair and its associated statistics.
    ///
    /// # Arguments
    ///
    /// * `f` - Function to call for each (address_pair, stats) entry
    #[inline]
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&AddrPair, &StreamStats),
    {
        self.map.iter().for_each(|item| {
            f(item.key(), item.value());
        });
    }
}

/// Thread-safe statistics for a single TCP stream connection.
///
/// Tracks connection state and queue sizes using atomic operations
/// for lock-free concurrent access. Can be safely shared across
/// multiple threads and tasks.
#[derive(Clone)]
pub struct StreamStats {
    stats: Arc<StreamStatsInner>,
}

impl StreamStats {
    /// Creates a new stream statistics tracker with default values.
    #[inline]
    pub(super) fn new() -> Self {
        Self {
            stats: Arc::new(StreamStatsInner::default()),
        }
    }

    /// Updates the TCP connection state.
    ///
    /// # Arguments
    ///
    /// * `state` - New TCP state (Listen, SynRcvd, Estab, etc.)
    #[inline]
    pub(super) fn set_state(&self, state: State) {
        self.stats.state.store(state as usize, Ordering::Relaxed);
    }

    /// Updates the send queue size in bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes currently queued for transmission
    #[inline]
    pub(super) fn set_send_queue(&self, bytes: usize) {
        self.stats.send_queue.store(bytes, Ordering::Relaxed);
    }

    /// Updates the receive queue size in bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes currently queued for reading
    #[inline]
    pub(super) fn set_recv_queue(&self, bytes: usize) {
        self.stats.recv_queue.store(bytes, Ordering::Relaxed);
    }

    /// Updates whether the connection is currently limited by congestion control.
    ///
    /// # Arguments
    ///
    /// * `congestion_limited` - True if transmission is limited by congestion window
    #[inline]
    pub(super) fn set_congestion_limited(&self, congestion_limited: bool) {
        self.stats
            .congestion_limited
            .store(congestion_limited, Ordering::Relaxed);
    }

    /// Updates the current congestion control state.
    ///
    /// # Arguments
    ///
    /// * `state` - New congestion state (SlowStart, Recovery, or CongestionAvoidance)
    #[inline]
    pub(super) fn set_congestion_state(&self, state: CongestionState) {
        self.stats
            .congestion_state
            .store(state as usize, Ordering::Relaxed);
    }

    /// Updates the congestion window size in bytes.
    ///
    /// # Arguments
    ///
    /// * `cwnd` - Current congestion window size in bytes
    #[inline]
    pub(super) fn set_congestion_window(&self, cwnd: usize) {
        self.stats.congestion_window.store(cwnd, Ordering::Relaxed);
    }

    /// Returns the current TCP connection state.
    ///
    /// Returns State::Closed if the stored state value is invalid.
    #[inline]
    pub fn get_state(&self) -> State {
        let value = self.stats.state.load(Ordering::Relaxed);
        State::from_integer(value).unwrap_or(State::Closed)
    }

    /// Returns the current send queue size in bytes.
    #[inline]
    pub fn get_send_queue(&self) -> usize {
        self.stats.send_queue.load(Ordering::Relaxed)
    }

    /// Returns the current receive queue size in bytes.
    #[inline]
    pub fn get_recv_queue(&self) -> usize {
        self.stats.recv_queue.load(Ordering::Relaxed)
    }

    /// Returns whether the connection is currently limited by congestion control.
    #[inline]
    pub fn get_congestion_limited(&self) -> bool {
        self.stats.congestion_limited.load(Ordering::Relaxed)
    }

    /// Returns the current congestion control state.
    ///
    /// Returns SlowStart if the stored state value is invalid.
    #[inline]
    pub fn get_congestion_state(&self) -> CongestionState {
        let state = self.stats.congestion_state.load(Ordering::Relaxed);
        CongestionState::from_integer(state).unwrap_or(CongestionState::SlowStart)
    }

    /// Returns the congestion window size in bytes.
    #[inline]
    pub fn get_congestion_window(&self) -> usize {
        self.stats.congestion_window.load(Ordering::Relaxed)
    }
}

/// Internal statistics storage using atomic operations for thread safety.
#[derive(Default)]
struct StreamStatsInner {
    /// Current TCP connection state stored as usize
    state: AtomicUsize,
    /// Number of bytes queued for transmission
    send_queue: AtomicUsize,
    /// Number of bytes queued for reading
    recv_queue: AtomicUsize,
    /// Whether transmission is limited by congestion control
    congestion_limited: AtomicBool,
    /// Current congestion control state
    congestion_state: AtomicUsize,
    /// Current congestion window size in bytes
    congestion_window: AtomicUsize,
}

/// TCP congestion control states according to congestion control algorithms.
///
/// Represents the different phases of TCP congestion control, each with
/// specific behavior for handling acknowledgments and congestion events.
pub enum CongestionState {
    SlowStart = 0,
    Recovery,
    CongestionAvoidance,
}

impl CongestionState {
    /// Converts an integer value back to a congestion state.
    ///
    /// Returns None for invalid values.
    #[inline]
    fn from_integer(state: usize) -> Option<Self> {
        match state {
            0 => Some(CongestionState::SlowStart),
            1 => Some(CongestionState::Recovery),
            2 => Some(CongestionState::CongestionAvoidance),
            _ => None,
        }
    }

    /// Returns the string representation of the congestion state.
    #[inline]
    pub fn to_str(&self) -> &'static str {
        match self {
            CongestionState::SlowStart => "SlowStart",
            CongestionState::Recovery => "Recovery",
            CongestionState::CongestionAvoidance => "CongestionAvoidance",
        }
    }
}
