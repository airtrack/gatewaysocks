use std::future::Future;
use std::net::SocketAddrV4;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::Waker;
use std::time::{Duration, Instant};

use bytes::Bytes;
use log::{error, trace, warn};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumbers, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use tokio::time::{Sleep, sleep_until};

use crate::gateway::GatewaySender;
use crate::gateway::tcp::StreamCloser;
use crate::gateway::tcp::congestion::{Controller, FixBandwidth};
use crate::gateway::tcp::pacing::Pacer;
use crate::gateway::tcp::recv_buffer::RecvBuffer;
use crate::gateway::tcp::rtt::RttEstimator;
use crate::gateway::tcp::send_buffer::SendBuffer;
use crate::gateway::tcp::stats::StreamStats;
use crate::gateway::tcp::time::StreamTime;
use crate::gateway::tcp::types::{AddrPair, State};

const MSL_2: Duration = Duration::from_secs(60);
const FIN_TIMEOUT: Duration = Duration::from_secs(600);
const DEFAULT_RTO: Duration = Duration::from_millis(50);
const DEFAULT_RTT: Duration = Duration::from_millis(10);
const GRANULARITY: Duration = Duration::from_millis(1);
const MAX_RETRY_TIMES: u32 = 5;
const LOCAL_WINDOW: u32 = 256 * 1024;
const DEFAULT_MSS: usize = 1500;
const MAX_TCP_HEADER_LEN: usize = 60;
const MAX_SEND_BUFFER: usize = 128 * 1024;

/// Checks if a TCP packet has the SYN flag set.
pub(super) fn is_syn_packet(request: &TcpPacket) -> bool {
    request.get_flags() & TcpFlags::SYN != 0
}

/// Thread-safe wrapper around the TCP stream control block.
///
/// Provides a mutex-protected interface to the TCP connection state
/// and operations, allowing safe concurrent access from multiple tasks.
pub(super) struct TcpStreamInner {
    cb: Mutex<TcpStreamControlBlock>,
}

impl TcpStreamInner {
    pub(super) fn new(
        mac: MacAddr,
        pair: AddrPair,
        stream_closer: StreamCloser,
        gw_sender: GatewaySender,
        stats: StreamStats,
    ) -> Self {
        TcpStreamInner {
            cb: Mutex::new(TcpStreamControlBlock::new(
                mac,
                pair,
                stream_closer,
                gw_sender,
                stats,
            )),
        }
    }

    pub(super) fn source_addr(&self) -> SocketAddrV4 {
        self.cb.lock().unwrap().addr_pair.source
    }

    pub(super) fn destination_addr(&self) -> SocketAddrV4 {
        self.cb.lock().unwrap().addr_pair.destination
    }

    pub(super) fn close(&self) {
        self.cb.lock().unwrap().close();
    }

    pub(super) fn poll_read(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.cb.lock().unwrap().poll_read(cx, buf)
    }

    pub(super) fn poll_write(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.cb.lock().unwrap().poll_write(cx, buf)
    }

    pub(super) fn poll_shutdown(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.cb.lock().unwrap().poll_shutdown(cx)
    }

    pub(super) fn poll_state(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        self.cb.lock().unwrap().poll_state(cx)
    }

    pub(super) fn handle_tcp_packet(&self, packet: Bytes) -> Option<()> {
        let request = TcpPacket::new(&packet)?;
        self.cb.lock().unwrap().handle_tcp_packet(&request, &packet);
        Some(())
    }
}

/// TCP connection state data including sequence numbers and negotiated options.
struct StateData {
    /// Our sequence number (next byte to send)
    seq: u32,
    /// Acknowledgment number (next byte we expect to receive)
    ack: u32,
    /// Our advertised receive window size
    local_window: u32,
    /// Remote peer's advertised window size
    remote_window: u32,

    /// Remote timestamp value for timestamp option
    remote_ts: u32,
    /// Maximum Segment Size negotiated with peer
    mss: u16,
    /// Window scale factor negotiated with peer
    wscale: u8,
    /// Whether Selective Acknowledgment (SACK) is enabled
    sack: bool,
}

impl StateData {
    fn new() -> Self {
        Self {
            seq: rand::random(),
            ack: 0,
            local_window: LOCAL_WINDOW,
            remote_window: 0,
            remote_ts: 0,
            mss: DEFAULT_MSS as u16,
            wscale: 0,
            sack: false,
        }
    }
}

/// Types of timers used in TCP connection management.
enum TimerType {
    /// Retransmission timeout timer
    Rto = 0,
    /// Pacing timer for congestion control
    Pacing = 1,
    /// Total count of timer types (used for array sizing)
    Count,
}

/// Table for managing multiple TCP timers efficiently.
#[derive(Default)]
struct TimerTable {
    table: [Option<Instant>; TimerType::Count as usize],
}

impl TimerTable {
    fn set(&mut self, index: TimerType, deadline: Instant) {
        self.table[index as usize] = Some(deadline);
    }

    fn stop(&mut self, index: TimerType) {
        self.table[index as usize] = None;
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.table.iter().filter_map(|&x| x).min()
    }
}

/// Core TCP stream control block containing all connection state and logic.
///
/// This structure manages the complete TCP connection including state machine,
/// buffers, timers, congestion control, and async task coordination.
struct TcpStreamControlBlock {
    stats: StreamStats,
    src_mac: MacAddr,
    addr_pair: AddrPair,
    closer: StreamCloser,
    gw_sender: GatewaySender,
    timer: Pin<Box<Sleep>>,
    timers: TimerTable,
    shutdown: bool,
    state: State,
    pacing: Pacer,
    time: StreamTime,
    rtt: RttEstimator,
    state_data: StateData,
    recv_buffer: RecvBuffer,
    send_buffer: SendBuffer,
    congestion: Box<dyn Controller>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    driver_waker: Option<Waker>,
}

impl TcpStreamControlBlock {
    fn new(
        src_mac: MacAddr,
        addr_pair: AddrPair,
        closer: StreamCloser,
        gw_sender: GatewaySender,
        stats: StreamStats,
    ) -> Self {
        let now = Instant::now();
        let congestion = FixBandwidth::new();
        let pacing = Pacer::new(DEFAULT_RTT, congestion.window(), GRANULARITY, DEFAULT_MSS);
        let rtt = RttEstimator::new(DEFAULT_RTT, DEFAULT_RTO, GRANULARITY);

        Self {
            stats,
            src_mac,
            addr_pair,
            closer,
            gw_sender,
            timer: Box::pin(sleep_until(now.into())),
            timers: TimerTable::default(),
            shutdown: false,
            state: State::Listen,
            pacing: pacing,
            time: StreamTime::new(now),
            rtt: rtt,
            state_data: StateData::new(),
            recv_buffer: RecvBuffer::new(),
            send_buffer: SendBuffer::new(MAX_SEND_BUFFER),
            congestion: congestion,
            read_waker: None,
            write_waker: None,
            driver_waker: None,
        }
    }

    /// Processes an incoming TCP packet and updates connection state.
    ///
    /// Handles RST packets immediately and then dispatches to appropriate
    /// state handler based on current TCP state machine state.
    fn handle_tcp_packet(&mut self, request: &TcpPacket, packet: &Bytes) {
        if request.get_flags() & TcpFlags::RST != 0 {
            trace!(
                "{}[{}]: recv RST, change state to Closed",
                self.addr_pair, self.state
            );
            self.set_state(State::Closed);
        }

        self.time.update_alive(Instant::now());

        match self.state {
            State::Listen => self.state_listen(request),
            State::SynRcvd => self.state_syn_rcvd(request, packet),
            State::Estab => self.state_estab(request, packet),
            State::FinWait1 => self.state_fin_wait1(request, packet),
            State::FinWait2 => self.state_fin_wait2(request, packet),
            State::Closing => self.state_closing(request),
            State::TimeWait => self.state_time_wait(request),
            State::CloseWait => self.state_close_wait(request),
            State::LastAck => self.state_last_ack(request),
            State::Closed => self.state_closed(),
        }
    }

    /// Drives the TCP connection state machine and handles periodic tasks.
    ///
    /// This is the main driver function that handles retransmissions, timeouts,
    /// and state transitions. Returns std::task::Poll::Ready(()) when the
    /// connection should be closed.
    fn poll_state(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let close = match self.state {
            State::Listen => unreachable!("cannot poll state while in State::Listen"),
            State::SynRcvd => self.resend_syn_ack().is_err(),
            State::Estab | State::CloseWait => self.send_packets().is_err(),
            State::FinWait1 | State::Closing | State::LastAck => self.resend_fin().is_err(),
            State::FinWait2 => self.wait_finwait2_timeout(),
            State::TimeWait => self.wait_timewait_timeout(),
            State::Closed => true,
        };

        if close {
            self.set_state(State::Closed);
            self.state_closed();
            self.closer.close(self.addr_pair);
            return std::task::Poll::Ready(());
        }

        if let Some(ref mut waker) = self.driver_waker {
            waker.clone_from(cx.waker());
        } else {
            self.driver_waker = Some(cx.waker().clone());
        }

        if let Some(deadline) = self.timers.next_deadline() {
            if self.timer.deadline().into_std() != deadline {
                Sleep::reset(self.timer.as_mut(), deadline.into());
            }

            if Future::poll(self.timer.as_mut(), cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }

        std::task::Poll::Pending
    }

    /// Attempts to read data from the receive buffer into the provided buffer.
    ///
    /// Returns immediately if data is available, otherwise registers a waker
    /// for notification when data becomes available.
    fn poll_read(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.recv_buffer.readable() {
            let size = self.recv_buffer.read(buf.initialize_unfilled());
            buf.advance(size);
            self.stats.set_recv_queue(self.recv_buffer.readable_size());
            return std::task::Poll::Ready(Ok(()));
        }

        if self.state == State::SynRcvd
            || self.state == State::Estab
            || self.state == State::FinWait1
            || self.state == State::FinWait2
        {
            self.read_waker = Some(cx.waker().clone());
            return std::task::Poll::Pending;
        }

        return std::task::Poll::Ready(Ok(()));
    }

    /// Attempts to write data to the send buffer.
    ///
    /// Returns immediately if buffer space is available, otherwise registers
    /// a waker. Data is segmented according to MSS and queued for transmission.
    fn poll_write(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        if self.shutdown
            || (self.state != State::SynRcvd
                && self.state != State::Estab
                && self.state != State::CloseWait)
        {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "stream can no longer be written to",
            )));
        }

        if self.state == State::SynRcvd || self.send_buffer.is_full() {
            self.write_waker = Some(cx.waker().clone());
            return std::task::Poll::Pending;
        }

        let size = self.send_buffer.push_pending(
            Bytes::copy_from_slice(buf),
            self.state_data.mss as usize - MAX_TCP_HEADER_LEN,
        );

        self.driver_waker.as_ref().map(|waker| waker.wake_by_ref());
        self.stats.set_send_queue(self.send_buffer.len());

        std::task::Poll::Ready(Ok(size))
    }

    /// Initiates graceful connection shutdown by sending FIN.
    ///
    /// Marks the connection for shutdown and queues a FIN packet to be sent
    /// after any pending data. Returns Ready when shutdown is complete.
    fn poll_shutdown(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if self.state != State::SynRcvd
            && self.state != State::Estab
            && self.state != State::CloseWait
        {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "shutdown at error state",
            )));
        }

        if self.send_buffer.is_empty() {
            self.send_fin();
            self.send_buffer.sent_fin(Instant::now());
            self.driver_waker.as_ref().map(|waker| waker.wake_by_ref());
            std::task::Poll::Ready(Ok(()))
        } else {
            self.shutdown = true;
            self.send_buffer.pending_fin();
            self.write_waker = Some(cx.waker().clone());
            std::task::Poll::Pending
        }
    }

    /// Closes the connection, sending RST if the state is incorrect and
    /// transitioning to Closed state.
    fn close(&mut self) {
        if self.state != State::Closed
            && self.state != State::TimeWait
            && self.state != State::LastAck
            && self.state != State::Closing
        {
            self.send_tcp_rst_packet();
            self.set_state(State::Closed);
            self.state_closed();
            self.driver_waker.as_ref().map(|waker| waker.wake_by_ref());
        }
    }

    /// Handles SYN-ACK retransmission in SYN_RCVD state.
    ///
    /// Retransmits SYN-ACK packet if timeout has occurred, implements
    /// exponential backoff, and gives up after maximum retries.
    fn resend_syn_ack(&mut self) -> std::io::Result<()> {
        let now = Instant::now();
        let rto = self.rtt.rto().max(DEFAULT_RTO);
        let syn_ack = self
            .send_buffer
            .in_flight_syn_ack()
            .expect("SYN-ACK not sent");
        let mut deadline = syn_ack.timeout(rto);

        if deadline <= now {
            if syn_ack.num_of_retries() >= MAX_RETRY_TIMES {
                warn!(
                    "{}[{}]: SYN-ACK has been resent more than {} times",
                    self.addr_pair, self.state, MAX_RETRY_TIMES
                );

                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "SYN-ACK sending timeout",
                ));
            }

            self.send_tcp_syn_ack_packet();

            syn_ack.retried_at(now);
            deadline = syn_ack.timeout(rto);
        }

        self.timers.set(TimerType::Rto, deadline);
        Ok(())
    }

    /// Sends pending data packets when conditions allow.
    ///
    /// Handles retransmissions of timed-out segments and transmission of
    /// new pending data, subject to congestion control and flow control.
    fn send_packets(&mut self) -> std::io::Result<()> {
        let now = Instant::now();
        let rto = self.rtt.rto().max(DEFAULT_RTO);

        self.stream_conn_ok(now, rto)?;

        if let Some(until_time) = self.resend_in_flight(now, rto) {
            self.timers.set(TimerType::Pacing, until_time);
        } else if let Some(until_time) = self.send_pending(now) {
            self.timers.set(TimerType::Pacing, until_time);
        } else {
            self.timers.stop(TimerType::Pacing);
        }

        match self.send_buffer.next_resend_time(rto) {
            Some(deadline) => self.timers.set(TimerType::Rto, deadline),
            None => self.timers.stop(TimerType::Rto),
        }

        if self.send_buffer.is_empty() {
            if self.send_buffer.has_pending_fin() {
                if let Some(waker) = self.write_waker.take() {
                    waker.wake();
                }
            }
        }

        Ok(())
    }

    /// Handles FIN packet retransmission during connection teardown.
    ///
    /// Retransmits FIN packet if timeout has occurred and gives up
    /// after maximum retries, transitioning to appropriate state.
    fn resend_fin(&mut self) -> std::io::Result<()> {
        let now = Instant::now();
        let rto = self.rtt.rto().max(DEFAULT_RTO);
        let fin = self.send_buffer.in_flight_fin().expect("FIN not sent");
        let mut deadline = fin.timeout(rto);

        if deadline <= now {
            if fin.num_of_retries() >= MAX_RETRY_TIMES {
                warn!(
                    "{}[{}]: FIN has been resent more than {} times",
                    self.addr_pair, self.state, MAX_RETRY_TIMES
                );

                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "FIN sending timeout",
                ));
            }

            self.send_tcp_fin_packet();

            fin.retried_at(now);
            deadline = fin.timeout(rto);
        }

        self.timers.set(TimerType::Rto, deadline);
        Ok(())
    }

    /// Waits for timeout in FIN_WAIT2 state to prevent indefinite waiting.
    ///
    /// Returns true if timeout has elapsed and connection should be closed.
    fn wait_finwait2_timeout(&mut self) -> bool {
        let deadline = self.time.alive_time() + FIN_TIMEOUT;
        let timeout = Instant::now() >= deadline;

        if timeout {
            warn!(
                "{}[{}]: timeout for receiving the peer FIN",
                self.addr_pair, self.state
            );
        } else {
            self.timers.set(TimerType::Rto, deadline);
        }

        timeout
    }

    /// Waits for 2*MSL timeout in TIME_WAIT state before final closure.
    ///
    /// Returns true when the TIME_WAIT period has elapsed.
    fn wait_timewait_timeout(&mut self) -> bool {
        let deadline = self.time.alive_time() + MSL_2;
        let timeout = Instant::now() >= deadline;

        if timeout {
            trace!("{}[{}]: TimeWait timeout", self.addr_pair, self.state);
        } else {
            self.timers.set(TimerType::Rto, deadline);
        }

        timeout
    }

    fn set_state(&mut self, state: State) {
        self.state = state;
        self.stats.set_state(state);
    }

    /// Handles incoming packets in LISTEN state - processes SYN packets to begin connection.
    ///
    /// Parses TCP options (MSS, SACK, window scale, timestamps) and sends SYN/ACK response.
    /// Transitions to SYN_RCVD state when SYN is received.
    fn state_listen(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::SYN != 0 {
            trace!(
                "{}[{}]: tcp SYN, ISN: {}",
                self.addr_pair,
                self.state,
                request.get_sequence()
            );
            self.state_data.ack = request.get_sequence() + 1;
            self.recv_buffer.initialize_ack(self.state_data.ack);
            self.update_remote_window(request);

            for opt in request.get_options_iter() {
                match opt.get_number() {
                    TcpOptionNumbers::MSS => {
                        let mut payload = [0u8; 2];
                        payload.copy_from_slice(&opt.payload()[0..2]);
                        self.state_data.mss = u16::from_be_bytes(payload);
                        trace!("tcp mss: {}", self.state_data.mss);
                    }
                    TcpOptionNumbers::SACK_PERMITTED => {
                        self.state_data.sack = false;
                        trace!("tcp sack permitted {}", self.state_data.sack);
                    }
                    TcpOptionNumbers::WSCALE => {
                        self.state_data.wscale = opt.payload()[0];
                        trace!("tcp window scale: {}", self.state_data.wscale);

                        self.state_data.wscale = std::cmp::min(self.state_data.wscale, 14);
                        self.update_remote_window(request);
                        trace!("tcp window size: {}", self.state_data.remote_window);
                    }
                    TcpOptionNumbers::TIMESTAMPS => {
                        let mut payload = [0u8; 4];
                        payload.copy_from_slice(&opt.payload()[0..4]);
                        self.state_data.remote_ts = u32::from_be_bytes(payload);
                        trace!("tcp remote ts: {}", self.state_data.remote_ts);
                    }
                    TcpOptionNumbers::NOP | TcpOptionNumbers::EOL => {}
                    _ => {
                        trace!("tcp unknown option {}", opt.get_number().0);
                    }
                }
            }

            self.send_tcp_syn_ack_packet();
            self.set_state(State::SynRcvd);
            self.send_buffer.sent_syn_ack(Instant::now());
            trace!(
                "{}[{}]: change state to SynRcvd",
                self.addr_pair, self.state
            );
        }
    }

    /// Handles packets in SYN_RCVD state - completes three-way handshake.
    ///
    /// Retransmits SYN-ACK if another SYN is received. Transitions to ESTABLISHED
    /// when valid ACK is received, then processes any payload data.
    fn state_syn_rcvd(&mut self, request: &TcpPacket, packet: &Bytes) {
        if request.get_flags() & TcpFlags::SYN != 0 {
            self.send_tcp_syn_ack_packet();
        }

        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.state_data.seq + 1 {
                trace!(
                    "{}[{}]: change state to Estab, payload size: {}",
                    self.addr_pair,
                    self.state,
                    request.payload().len()
                );
                self.state_data.seq += 1;
                self.set_state(State::Estab);

                self.process_payload(request, packet);
            }
        }
    }

    /// Handles packets in ESTABLISHED state - normal data transfer operations.
    ///
    /// Processes acknowledgments, updates flow control windows, handles data payload,
    /// and transitions to CLOSE_WAIT if FIN is received.
    fn state_estab(&mut self, request: &TcpPacket, packet: &Bytes) {
        trace!(
            "{}[{}]: recv packet flags: {:b}, seq: {}, payload size: {}",
            self.addr_pair,
            self.state,
            request.get_flags(),
            request.get_sequence(),
            request.payload().len()
        );

        self.update_remote_window(request);
        self.process_acknowledgement(request);

        if request.get_flags() & TcpFlags::FIN != 0 {
            if request.get_sequence() == self.state_data.ack {
                trace!(
                    "{}[{}]: recv FIN, change state to CloseWait",
                    self.addr_pair, self.state
                );
                return self.process_fin(request);
            }
        }

        self.process_payload(request, packet);
    }

    /// Handles packets in FIN_WAIT1 state - waiting for FIN acknowledgment.
    ///
    /// Processes ACKs and transitions to FIN_WAIT2 when FIN is acknowledged.
    /// Transitions to CLOSING if FIN is received.
    fn state_fin_wait1(&mut self, request: &TcpPacket, packet: &Bytes) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            if request.get_sequence() == self.state_data.ack {
                trace!(
                    "{}[{}]: recv FIN, change state to Closing",
                    self.addr_pair, self.state
                );
                return self.process_fin(request);
            }
        }

        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.state_data.seq + 1 {
                self.set_state(State::FinWait2);
            }
        }

        self.process_payload(request, packet);
    }

    /// Handles packets in FIN_WAIT2 state - waiting for remote FIN.
    ///
    /// Processes final data segments and transitions to TIME_WAIT when FIN is received.
    fn state_fin_wait2(&mut self, request: &TcpPacket, packet: &Bytes) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            if request.get_sequence() == self.state_data.ack {
                trace!(
                    "{}[{}]: recv FIN, change state to TimeWait",
                    self.addr_pair, self.state
                );
                return self.process_fin(request);
            }
        }

        self.process_payload(request, packet);
    }

    /// Handles packets in CLOSING state - simultaneous close scenario.
    ///
    /// Waits for ACK of our FIN and transitions to TIME_WAIT when received.
    fn state_closing(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            return self.process_fin(request);
        }

        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.state_data.seq + 1 {
                trace!(
                    "{}[{}]: recv FIN ack, change state to TimeWait",
                    self.addr_pair, self.state
                );
                self.set_state(State::TimeWait);
            }
        }
    }

    /// Handles packets in TIME_WAIT state - final cleanup phase.
    ///
    /// Responds to any retransmitted FINs with ACK to handle network delays.
    fn state_time_wait(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            self.process_fin(request);
        }
    }

    /// Handles packets in CLOSE_WAIT state - remote has closed, local can still send.
    ///
    /// Processes acknowledgments for any remaining data being sent.
    fn state_close_wait(&mut self, request: &TcpPacket) {
        self.update_remote_window(request);
        self.process_acknowledgement(request);

        if request.get_flags() & TcpFlags::FIN != 0 {
            self.process_fin(request);
        }
    }

    /// Handles packets in LAST_ACK state - waiting for final ACK after sending FIN.
    ///
    /// Transitions to CLOSED when ACK for our FIN is received.
    fn state_last_ack(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.state_data.seq + 1 {
                self.set_state(State::Closed);
                trace!(
                    "{}[{}]: recv last ACK, change state to Closed",
                    self.addr_pair, self.state
                );
            }
        }
    }

    /// Handles CLOSED state - connection is terminated.
    ///
    /// Cleans up resources and notifies any waiting tasks that connection is closed.
    fn state_closed(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }

    /// Checks if the connection is healthy and hasn't exceeded retry limits.
    ///
    /// Returns error if segments have been retransmitted too many times,
    /// indicating the connection should be terminated.
    fn stream_conn_ok(&self, now: Instant, rto: Duration) -> std::io::Result<()> {
        if let Some(in_flight) = self.send_buffer.resend_iter(now, rto).next() {
            if in_flight.num_of_retries() >= MAX_RETRY_TIMES
                && self.time.alive_time() + MSL_2 <= now
            {
                warn!(
                    "{}[{}]: data {}:{} has been resent more than {} times",
                    self.addr_pair,
                    self.state,
                    in_flight.seq(),
                    in_flight.seq().wrapping_add(in_flight.len() as u32),
                    MAX_RETRY_TIMES
                );

                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "data sending timeout",
                ));
            }
        }

        Ok(())
    }

    /// Retransmits segments that have timed out based on RTO.
    ///
    /// Returns the next time when more data can be sent due to pacing.
    fn resend_in_flight(&mut self, now: Instant, rto: Duration) -> Option<Instant> {
        let mut until_time = None;
        let mut latest_loss_sent = None;

        for in_flight in self.send_buffer.resend_iter(now, rto) {
            let bytes = in_flight.len();

            if let Some(t) =
                self.pacing
                    .wait_until(bytes, now, self.rtt.get(), self.congestion.window())
            {
                until_time = Some(t);
                break;
            }

            trace!(
                "{}[{}]: resend data at seq: {}, len: {}, rto: {}({})ms",
                self.addr_pair,
                self.state,
                in_flight.seq(),
                in_flight.len(),
                rto.as_millis(),
                self.rtt.rto().as_millis()
            );

            if let Some(sent) = latest_loss_sent {
                if in_flight.sent_time() > sent {
                    latest_loss_sent = Some(in_flight.sent_time());
                }
            } else {
                latest_loss_sent = Some(in_flight.sent_time());
            }

            self.send_tcp_data_packet(in_flight.seq(), in_flight.as_ref());
            self.pacing.on_sent(bytes);
            in_flight.retried_at(now);
        }

        if let Some(sent) = latest_loss_sent {
            self.congestion.on_congestion(now, sent, false);
        }

        until_time
    }

    /// Sends pending data packets up to congestion and flow control limits.
    ///
    /// Respects congestion window and pacing constraints.
    /// Returns the next time when more data can be sent due to pacing.
    fn send_pending(&mut self, now: Instant) -> Option<Instant> {
        let srtt = self.rtt.get();
        let cwnd = self.congestion.window();
        let sent_seq = self.state_data.seq;

        let mut until_time = None;
        let mut window = cwnd.saturating_sub(self.send_buffer.in_flight());
        let mut sent_bytes = 0;

        for data in self.send_buffer.pending_iter() {
            if window == 0 {
                break;
            }

            let bytes = data.len().min(window);
            if let Some(t) = self.pacing.wait_until(bytes, now, srtt, cwnd) {
                until_time = Some(t);
                break;
            }

            self.send_tcp_data_packet(self.state_data.seq, &data[..bytes]);
            self.pacing.on_sent(bytes);
            self.state_data.seq += bytes as u32;

            sent_bytes += bytes;
            window -= bytes;

            trace!(
                "{}[{}]: send pending data: {}, cwnd: {}, remote wnd: {}, in-flight: {}",
                self.addr_pair,
                self.state,
                bytes,
                cwnd,
                self.state_data.remote_window,
                self.send_buffer.in_flight()
            );
        }

        self.send_buffer.slide_in_flight(sent_seq, sent_bytes, now);
        until_time
    }

    /// Sends a FIN packet to initiate connection close.
    fn send_fin(&mut self) {
        self.send_tcp_fin_packet();

        match self.state {
            State::SynRcvd | State::Estab => self.set_state(State::FinWait1),
            State::CloseWait => self.set_state(State::LastAck),
            _ => self.close(),
        }
    }

    /// Updates remote window size from received packet, applying window scaling if negotiated.
    fn update_remote_window(&mut self, request: &TcpPacket) {
        self.state_data.remote_window = request.get_window() as u32;
        self.state_data.remote_window <<= self.state_data.wscale;
        trace!(
            "{}[{}]: update remote window size: {}",
            self.addr_pair, self.state, self.state_data.remote_window
        );
    }

    /// Gets current timestamp in milliseconds for TCP timestamp option.
    fn timestamp(&self) -> u32 {
        self.time.elapsed_millis(Instant::now())
    }

    /// Adds TCP timestamp option with proper padding to options list.
    fn add_tcp_option_timestamp(&self, opts: &mut Vec<TcpOption>, opts_size: &mut usize) {
        opts.push(TcpOption::nop());
        opts.push(TcpOption::nop());
        opts.push(TcpOption::timestamp(
            self.timestamp(),
            self.state_data.remote_ts,
        ));
        *opts_size += 12;
    }

    /// Sends SYN-ACK packet with negotiated options during connection establishment.
    fn send_tcp_syn_ack_packet(&self) {
        let mut opts = Vec::new();
        let mut opts_size = 0;
        let payload = [0u8; 0];

        opts.push(TcpOption::mss(self.state_data.mss));
        opts_size += 4;

        opts.push(TcpOption::wscale(self.state_data.wscale));
        opts.push(TcpOption::nop());
        opts_size += 4;

        if self.state_data.sack {
            opts.push(TcpOption::nop());
            opts.push(TcpOption::nop());
            opts.push(TcpOption::sack_perm());
            opts_size += 4;
        }

        self.add_tcp_option_timestamp(&mut opts, &mut opts_size);

        self.send_tcp_packet(
            self.state_data.seq,
            TcpFlags::SYN | TcpFlags::ACK,
            &opts,
            opts_size,
            &payload,
        );
    }

    /// Sends data packet, segmenting if necessary to fit within MSS limits.
    fn send_tcp_data_packet(&self, mut seq: u32, data: &[u8]) {
        let mut opts = Vec::new();
        let mut opts_size = 0;

        self.add_tcp_option_timestamp(&mut opts, &mut opts_size);

        let mut index = 0;
        let mut len = data.len();
        let max_payload_len = self.state_data.mss as usize - MAX_TCP_HEADER_LEN;

        while len > 0 {
            let payload_len = std::cmp::min(len, max_payload_len);
            let payload = &data[index..index + payload_len];

            self.send_tcp_packet(
                seq,
                TcpFlags::ACK | TcpFlags::PSH,
                &opts,
                opts_size,
                payload,
            );

            index += payload_len;
            seq += payload_len as u32;
            len -= payload_len;
        }
    }

    /// Sends standalone ACK packet to acknowledge received data.
    fn send_tcp_acknowledge_packet(&self) {
        self.send_tcp_control_packet(TcpFlags::ACK);
        trace!(
            "{}[{}]: send acknowledge ack: {}",
            self.addr_pair, self.state, self.state_data.ack
        );
    }

    /// Sends FIN+ACK packet to initiate connection close.
    fn send_tcp_fin_packet(&self) {
        self.send_tcp_control_packet(TcpFlags::ACK | TcpFlags::FIN);
        trace!("{}[{}]: send FIN", self.addr_pair, self.state);
    }

    /// Sends RST+ACK packet to forcibly reset the connection.
    fn send_tcp_rst_packet(&self) {
        self.send_tcp_control_packet(TcpFlags::ACK | TcpFlags::RST);
        trace!("{}[{}]: send RST", self.addr_pair, self.state);
    }

    /// Sends control packet (ACK, FIN, RST) with timestamp option.
    fn send_tcp_control_packet(&self, flags: u8) {
        let mut opts = Vec::new();
        let mut opts_size = 0;
        let payload = [0u8; 0];

        self.add_tcp_option_timestamp(&mut opts, &mut opts_size);
        self.send_tcp_packet(self.state_data.seq, flags, &opts, opts_size, &payload);
    }

    /// Builds and sends a complete TCP packet with Ethernet and IPv4 headers.
    fn send_tcp_packet(
        &self,
        seq: u32,
        flags: u8,
        opts: &[TcpOption],
        opts_size: usize,
        payload: &[u8],
    ) {
        trace!(
            "{}[{}]: send packet flags: {:b}, seq: {}, payload size: {}",
            self.addr_pair,
            self.state,
            flags,
            seq,
            payload.len()
        );

        let tcp_packet_len = 20 + opts_size + payload.len();
        let ipv4_packet_len = 20 + tcp_packet_len;
        let ethernet_packet_len = 14 + ipv4_packet_len;

        self.gw_sender
            .build_and_send(1, ethernet_packet_len, &mut |buffer| {
                let mut ethernet_packet = MutableEthernetPacket::new(buffer).unwrap();
                ethernet_packet.set_destination(self.src_mac);
                ethernet_packet.set_source(self.gw_sender.info.mac);
                ethernet_packet.set_ethertype(EtherTypes::Ipv4);

                let mut ipv4_packet =
                    MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
                ipv4_packet.set_version(4);
                ipv4_packet.set_header_length(5);
                ipv4_packet.set_dscp(0);
                ipv4_packet.set_ecn(0);
                ipv4_packet.set_total_length(ipv4_packet_len as u16);
                ipv4_packet.set_identification(0);
                ipv4_packet.set_flags(0);
                ipv4_packet.set_fragment_offset(0);
                ipv4_packet.set_ttl(64);
                ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
                ipv4_packet.set_checksum(0);
                ipv4_packet.set_source(*self.addr_pair.destination.ip());
                ipv4_packet.set_destination(*self.addr_pair.source.ip());

                let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
                tcp_packet.set_source(self.addr_pair.destination.port());
                tcp_packet.set_destination(self.addr_pair.source.port());
                tcp_packet.set_sequence(seq);
                tcp_packet.set_acknowledgement(self.state_data.ack);
                tcp_packet.set_data_offset(((20 + opts_size) / 4) as u8);
                tcp_packet.set_reserved(0);
                tcp_packet.set_flags(flags);
                tcp_packet
                    .set_window((self.state_data.local_window >> self.state_data.wscale) as u16);
                tcp_packet.set_checksum(0);
                tcp_packet.set_urgent_ptr(0);
                tcp_packet.set_options(opts);
                tcp_packet.set_payload(payload);
                tcp_packet.set_checksum(tcp::ipv4_checksum(
                    &tcp_packet.to_immutable(),
                    self.addr_pair.destination.ip(),
                    self.addr_pair.source.ip(),
                ));

                ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));
            });
    }

    /// Processes and updates remote timestamp from TCP timestamp option.
    ///
    /// Only updates if the new timestamp is newer (handles wraparound).
    fn process_remote_timestamp(&mut self, request: &TcpPacket) {
        for opt in request.get_options_iter() {
            if opt.get_number() == TcpOptionNumbers::TIMESTAMPS {
                let mut payload = [0u8; 4];
                payload.copy_from_slice(&opt.payload()[0..4]);

                let new_ts = u32::from_be_bytes(payload);
                if (new_ts - self.state_data.remote_ts) as i32 >= 0 {
                    self.state_data.remote_ts = new_ts;
                    trace!(
                        "{}[{}]: update remote timestamp: {}",
                        self.addr_pair, self.state, self.state_data.remote_ts
                    );
                }
            }
        }
    }

    /// Processes echoed timestamp for RTT measurement.
    ///
    /// Updates RTT estimator when our timestamp is echoed back by the peer.
    fn process_echo_timestamp(&mut self, request: &TcpPacket) {
        for opt in request.get_options_iter() {
            if opt.get_number() == TcpOptionNumbers::TIMESTAMPS {
                let mut payload = [0u8; 4];
                payload.copy_from_slice(&opt.payload()[4..8]);

                let echo_ts = u32::from_be_bytes(payload);
                if echo_ts != 0 {
                    let rtt = self.timestamp() - echo_ts;
                    self.rtt.update(Duration::from_millis(rtt as u64));
                    trace!(
                        "{}[{}]: rtt {}ms, srtt {}ms, rto {}ms",
                        self.addr_pair,
                        self.state,
                        self.rtt.latest().as_millis(),
                        self.rtt.get().as_millis(),
                        self.rtt.rto().as_millis(),
                    );
                }
            }
        }
    }

    /// Processes incoming ACK to advance send window and update congestion control.
    ///
    /// Acknowledges sent data, updates RTT estimates, and notifies congestion control.
    fn process_acknowledgement(&mut self, request: &TcpPacket) {
        let now = Instant::now();
        let ack = request.get_acknowledgement();
        let in_flight = self.send_buffer.in_flight();
        trace!("{}[{}]: process ack: {}", self.addr_pair, self.state, ack);

        self.send_buffer.ack_in_flight(ack, |sent_time, bytes| {
            self.congestion.on_ack(now, sent_time, bytes, &self.rtt);
        });

        if in_flight != self.send_buffer.in_flight() {
            self.process_echo_timestamp(request);
        }

        if !self.send_buffer.is_full() {
            if let Some(waker) = self.write_waker.take() {
                waker.wake();
            }
        }

        self.stats.set_send_queue(self.send_buffer.len());
    }

    /// Processes incoming data payload and updates receive buffer.
    ///
    /// Handles out-of-order data, sends ACKs, and wakes read tasks when data is available.
    fn process_payload(&mut self, request: &TcpPacket, packet: &Bytes) {
        if request.get_sequence() == (self.state_data.ack - 1) {
            trace!(
                "{}[{}]: keep-alive request, payload size: {}",
                self.addr_pair,
                self.state,
                request.payload().len()
            );
            if request.payload().len() <= 1 {
                return self.send_tcp_acknowledge_packet();
            }
        }

        let payload = request.payload();
        if payload.is_empty() {
            return;
        }

        let ack = self.state_data.ack;
        let seq = request.get_sequence();
        let data = packet.slice_ref(payload);
        self.state_data.ack = self.recv_buffer.write(seq, data).unwrap();

        if ack != self.state_data.ack {
            self.process_remote_timestamp(request);
        }

        if self.recv_buffer.readable() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake();
            }
        }

        self.send_tcp_acknowledge_packet();
        self.stats.set_recv_queue(self.recv_buffer.readable_size());
    }

    /// Processes incoming FIN packet and transitions connection state.
    ///
    /// Updates receive buffer, sends ACK, and transitions to appropriate close state.
    fn process_fin(&mut self, request: &TcpPacket) {
        self.state_data.ack = request.get_sequence() + 1;
        self.send_tcp_acknowledge_packet();

        match self.state {
            State::Estab | State::CloseWait => self.set_state(State::CloseWait),
            State::FinWait1 | State::Closing => self.set_state(State::Closing),
            State::FinWait2 | State::TimeWait => self.set_state(State::TimeWait),
            _ => {
                error!(
                    "{}[{}]: process fin on error state",
                    self.addr_pair, self.state
                );
            }
        }

        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
    }
}
