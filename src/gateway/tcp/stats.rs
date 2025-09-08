use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
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
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Iterates over all connection statistics, calling the provided function
    /// for each address pair and its associated statistics.
    ///
    /// # Arguments
    ///
    /// * `f` - Function to call for each (address_pair, stats) entry
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
    pub(super) fn set_state(&self, state: State) {
        self.stats.state.store(state as usize, Ordering::Relaxed);
    }

    /// Updates the send queue size in bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes currently queued for transmission
    pub(super) fn set_send_queue(&self, bytes: usize) {
        self.stats.send_queue.store(bytes, Ordering::Relaxed);
    }

    /// Updates the receive queue size in bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes currently queued for reading
    pub(super) fn set_recv_queue(&self, bytes: usize) {
        self.stats.recv_queue.store(bytes, Ordering::Relaxed);
    }

    /// Returns the current TCP connection state.
    ///
    /// Returns State::Closed if the stored state value is invalid.
    pub fn get_state(&self) -> State {
        let value = self.stats.state.load(Ordering::Relaxed);
        State::from_integer(value).unwrap_or(State::Closed)
    }

    /// Returns the current send queue size in bytes.
    pub fn get_send_queue(&self) -> usize {
        self.stats.send_queue.load(Ordering::Relaxed)
    }

    /// Returns the current receive queue size in bytes.
    pub fn get_recv_queue(&self) -> usize {
        self.stats.recv_queue.load(Ordering::Relaxed)
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
}
