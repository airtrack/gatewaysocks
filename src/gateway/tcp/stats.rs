use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use dashmap::DashMap;

use crate::gateway::tcp::types::{AddrPair, State};

#[derive(Clone, Default)]
pub struct StatsMap {
    pub(super) map: Arc<DashMap<AddrPair, StreamStats>>,
}

impl StatsMap {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&AddrPair, &StreamStats),
    {
        self.map.iter().for_each(|item| {
            f(item.key(), item.value());
        });
    }
}

#[derive(Clone)]
pub struct StreamStats {
    stats: Arc<StreamStatsInner>,
}

impl StreamStats {
    pub(super) fn new() -> Self {
        Self {
            stats: Arc::new(StreamStatsInner::default()),
        }
    }

    pub(super) fn set_state(&self, state: State) {
        self.stats.state.store(state as usize, Ordering::Relaxed);
    }

    pub(super) fn set_send_queue(&self, bytes: usize) {
        self.stats.send_queue.store(bytes, Ordering::Relaxed);
    }

    pub(super) fn set_recv_queue(&self, bytes: usize) {
        self.stats.recv_queue.store(bytes, Ordering::Relaxed);
    }

    pub fn get_state(&self) -> State {
        let value = self.stats.state.load(Ordering::Relaxed);
        State::from_integer(value).unwrap_or(State::Closed)
    }

    pub fn get_send_queue(&self) -> usize {
        self.stats.send_queue.load(Ordering::Relaxed)
    }

    pub fn get_recv_queue(&self) -> usize {
        self.stats.recv_queue.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct StreamStatsInner {
    state: AtomicUsize,
    send_queue: AtomicUsize,
    recv_queue: AtomicUsize,
}
