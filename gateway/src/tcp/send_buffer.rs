use std::{
    cell::Cell,
    collections::{VecDeque, vec_deque::Iter},
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};

/// Represents a data segment that has been sent but not yet acknowledged.
pub(super) struct InFlight {
    seq: u32,
    data: Bytes,
    retry: Cell<u32>,
    sent: Cell<Instant>,
}

impl InFlight {
    fn new(seq: u32, data: Bytes, now: Instant) -> Self {
        Self {
            seq,
            data,
            retry: Cell::new(0),
            sent: Cell::new(now),
        }
    }

    /// Calculates when this segment will timeout using exponential backoff.
    ///
    /// Formula: sent_time + (rto * 2^retry_count)
    /// This implements the standard TCP exponential backoff algorithm.
    fn timeout(&self, rto: Duration) -> Instant {
        self.sent.get() + rto * 2u32.pow(self.retry.get())
    }

    pub(super) fn seq(&self) -> u32 {
        self.seq
    }

    pub(super) fn as_ref(&self) -> &[u8] {
        &self.data
    }

    pub(super) fn len(&self) -> usize {
        self.data.len()
    }

    pub(super) fn sent_time(&self) -> Instant {
        self.sent.get()
    }

    pub(super) fn num_of_retries(&self) -> u32 {
        self.retry.get()
    }

    /// Marks this segment as retried at the given time and increments retry count.
    pub(super) fn retried_at(&self, t: Instant) {
        self.sent.set(t);
        self.retry.set(self.retry.get() + 1);
    }
}

/// Control structure for tracking SYN-ACK and FIN segments.
pub(super) struct InFlightCtl {
    retry: Cell<u32>,
    sent: Cell<Instant>,
}

impl InFlightCtl {
    fn new(now: Instant) -> Self {
        Self {
            retry: Cell::new(0),
            sent: Cell::new(now),
        }
    }

    pub(super) fn timeout(&self, rto: Duration) -> Instant {
        self.sent.get() + rto * 2u32.pow(self.retry.get())
    }

    pub(super) fn num_of_retries(&self) -> u32 {
        self.retry.get()
    }

    pub(super) fn retried_at(&self, t: Instant) {
        self.sent.set(t);
        self.retry.set(self.retry.get() + 1);
    }
}

/// TCP send buffer that manages pending and in-flight data segments.
///
/// Handles data segmentation, retransmission tracking, and flow control.
/// The buffer has a fixed capacity and maintains separate tracking for:
/// - Pending data: waiting to be sent when window space is available
/// - In-flight data: sent but not yet acknowledged
/// - Control segments: SYN-ACK and FIN packets with separate retry logic
pub(super) struct SendBuffer {
    capacity: usize,
    in_flight_bytes: usize,
    pending_bytes: usize,

    in_flight: VecDeque<InFlight>,
    pending: VecDeque<Bytes>,

    in_flight_syn_ack: Option<InFlightCtl>,
    in_flight_fin: Option<InFlightCtl>,
    pending_fin: bool,
}

impl SendBuffer {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            in_flight_bytes: 0,
            pending_bytes: 0,
            in_flight: VecDeque::new(),
            pending: VecDeque::new(),
            in_flight_syn_ack: None,
            in_flight_fin: None,
            pending_fin: false,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.in_flight.is_empty() && self.pending.is_empty()
    }

    pub(super) fn is_full(&self) -> bool {
        self.in_flight_bytes + self.pending_bytes >= self.capacity
    }

    pub(super) fn has_pending_fin(&self) -> bool {
        self.pending_fin
    }

    pub(super) fn in_flight(&self) -> usize {
        self.in_flight_bytes
    }

    pub(super) fn len(&self) -> usize {
        self.in_flight_bytes + self.pending_bytes
    }

    pub(super) fn sent_syn_ack(&mut self, now: Instant) {
        self.in_flight_syn_ack = Some(InFlightCtl::new(now));
    }

    pub(super) fn in_flight_syn_ack(&self) -> Option<&InFlightCtl> {
        self.in_flight_syn_ack.as_ref()
    }

    pub(super) fn sent_fin(&mut self, now: Instant) {
        self.in_flight_fin = Some(InFlightCtl::new(now));
    }

    pub(super) fn in_flight_fin(&self) -> Option<&InFlightCtl> {
        self.in_flight_fin.as_ref()
    }

    pub(super) fn pending_fin(&mut self) {
        self.pending_fin = true;
    }

    /// Adds data to the pending queue, segmenting it according to MSS.
    /// Returns the total number of bytes added.
    pub(super) fn push_pending(&mut self, mut data: Bytes, mss: usize) -> usize {
        let bytes = data.len();
        while data.len() > mss {
            let segment = data.split_to(mss);
            self.pending.push_back(segment);
        }

        self.pending.push_back(data);
        self.pending_bytes += bytes;
        bytes
    }

    pub(super) fn next_resend_time(&self, rto: Duration) -> Option<Instant> {
        let in_flight = self.in_flight.front()?;
        Some(in_flight.timeout(rto))
    }

    pub(super) fn resend_iter(&self, now: Instant, rto: Duration) -> ResendIterator<'_> {
        ResendIterator {
            index: 0,
            now,
            rto,
            in_flight: &self.in_flight,
        }
    }

    pub(super) fn pending_iter(&self) -> PendingIterator<'_> {
        PendingIterator {
            iter: self.pending.iter(),
        }
    }

    /// Moves pending data to in-flight status up to the specified size.
    /// Used when the send window opens up and data can be transmitted.
    pub(super) fn slide_in_flight(&mut self, mut seq: u32, mut size: usize, now: Instant) {
        while size > 0 && !self.pending.is_empty() {
            let mut data = self.pending.pop_front().unwrap();
            let bytes = data.len().min(size);
            let in_flight = InFlight::new(seq, data.split_to(bytes), now);

            if !data.is_empty() {
                self.pending.push_front(data);
            }

            self.in_flight.push_back(in_flight);
            self.in_flight_bytes += bytes;
            self.pending_bytes -= bytes;

            seq = seq.wrapping_add(bytes as u32);
            size -= bytes;
        }
    }

    /// Acknowledges in-flight data up to the given ACK number.
    /// Calls `on_ack` for each acknowledged segment with send time and byte count.
    /// Handles partial acknowledgments by splitting segments.
    pub(super) fn ack_in_flight<F>(&mut self, ack: u32, mut on_ack: F)
    where
        F: FnMut(Instant, usize),
    {
        while !self.in_flight.is_empty() {
            let in_flight = self.in_flight.front_mut().unwrap();
            let begin_seq = in_flight.seq();
            let end_seq = begin_seq.wrapping_add(in_flight.len() as u32);

            if begin_seq.wrapping_sub(ack) as i32 >= 0 {
                break;
            }

            if end_seq.wrapping_sub(ack) as i32 <= 0 {
                let bytes = in_flight.len();
                on_ack(in_flight.sent_time(), bytes);

                self.in_flight.pop_front();
                self.in_flight_bytes -= bytes;
            } else {
                let bytes = ack.wrapping_sub(begin_seq) as usize;
                on_ack(in_flight.sent_time(), bytes);

                in_flight.seq = ack;
                in_flight.data.advance(bytes);
                self.in_flight_bytes -= bytes;
            }
        }
    }
}

/// Iterator over in-flight segments that have timed out and need retransmission.
pub(super) struct ResendIterator<'a> {
    index: usize,
    now: Instant,
    rto: Duration,
    in_flight: &'a VecDeque<InFlight>,
}

impl<'a> Iterator for ResendIterator<'a> {
    type Item = &'a InFlight;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.index;

        if index < self.in_flight.len() {
            if self.in_flight[index].timeout(self.rto) <= self.now {
                self.index += 1;
                return Some(&self.in_flight[index]);
            }
        }

        None
    }
}

/// Iterator over pending data segments waiting to be sent.
pub(super) struct PendingIterator<'a> {
    iter: Iter<'a, Bytes>,
}

impl<'a> Iterator for PendingIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let data = self.iter.next()?;
        Some(&data)
    }
}
