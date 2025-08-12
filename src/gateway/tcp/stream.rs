use std::collections::VecDeque;
use std::fmt::Display;
use std::future::Future;
use std::net::SocketAddrV4;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::Waker;
use std::time::{Duration, Instant};
use std::usize;

use bytes::{Buf, Bytes};
use log::{error, trace, warn};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumbers, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use tokio::time::{sleep_until, Sleep};

use crate::gateway::tcp::congestion::{Controller, FixBandwidth};
use crate::gateway::tcp::pacing::Pacer;
use crate::gateway::tcp::rtt::RttEstimator;
use crate::gateway::tcp::{AddrPair, StreamCloser};
use crate::gateway::GatewaySender;

const MSL_2: Duration = Duration::from_millis(30000);
const DEFAULT_RTO: Duration = Duration::from_millis(50);
const DEFAULT_RTT: Duration = Duration::from_millis(10);
const GRANULARITY: Duration = Duration::from_millis(1);
const LOCAL_WINDOW: u32 = 256 * 1024;
const DEFAULT_MSS: usize = 1400;
const MAX_TCP_HEADER_LEN: usize = 60;
const MAX_SEND_BUFFER: usize = 128 * 1024;

pub(super) fn is_syn_packet(request: &TcpPacket) -> bool {
    request.get_flags() & TcpFlags::SYN != 0
}

pub(super) struct TcpStreamInner {
    cb: Mutex<TcpStreamControlBlock>,
}

impl TcpStreamInner {
    pub(super) fn new(
        mac: MacAddr,
        pair: AddrPair,
        stream_closer: StreamCloser,
        gw_sender: GatewaySender,
    ) -> Self {
        TcpStreamInner {
            cb: Mutex::new(TcpStreamControlBlock::new(
                mac,
                pair,
                stream_closer,
                gw_sender,
            )),
        }
    }

    pub(super) fn local_addr(&self) -> SocketAddrV4 {
        self.cb.lock().unwrap().addr_pair.0
    }

    pub(super) fn remote_addr(&self) -> SocketAddrV4 {
        self.cb.lock().unwrap().addr_pair.1
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
        self.cb.lock().unwrap().handle_tcp_packet(&request);
        Some(())
    }
}

#[derive(PartialEq, Debug)]
enum State {
    Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
    Closed,
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

struct StreamTime {
    init: Instant,
    alive: Instant,
}

impl StreamTime {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            init: now,
            alive: now,
        }
    }

    fn timestamp_millis(&self) -> u32 {
        (Instant::now() - self.init).as_millis() as u32
    }

    fn alive_time(&self) -> Instant {
        self.alive
    }

    fn update_alive(&mut self) {
        self.alive = Instant::now();
    }
}

struct RecvBuffer {
    recved: VecDeque<u8>,
    buffer: VecDeque<u8>,
    ranges: VecDeque<(u32, u32)>,
}

impl RecvBuffer {
    fn new() -> Self {
        let recved = VecDeque::new();
        let mut buffer = VecDeque::new();
        buffer.resize(LOCAL_WINDOW as usize, 0);
        let ranges = VecDeque::new();

        Self {
            recved,
            buffer,
            ranges,
        }
    }
}

struct SendingData {
    sent: Instant,
    seq: u32,
    data: Bytes,
}

impl SendingData {
    fn new(seq: u32, data: Bytes) -> Self {
        Self {
            sent: Instant::now(),
            seq,
            data,
        }
    }

    fn timeout(&self, rto: Duration) -> Instant {
        self.sent + self.adjust_rto(rto)
    }

    fn adjust_rto(&self, rto: Duration) -> Duration {
        rto.max(DEFAULT_RTO)
    }
}

enum PendingData {
    Data(Bytes),
    Fin,
}

struct SendBuffer {
    inflight: usize,
    pending_size: usize,
    sending: VecDeque<SendingData>,
    pending: VecDeque<PendingData>,
}

impl SendBuffer {
    fn new() -> Self {
        Self {
            inflight: 0,
            pending_size: 0,
            sending: VecDeque::new(),
            pending: VecDeque::new(),
        }
    }

    fn is_full(&self) -> bool {
        self.inflight + self.pending_size >= MAX_SEND_BUFFER
    }
}

struct StateData {
    seq: u32,
    ack: u32,
    local_window: u32,
    remote_window: u32,

    remote_ts: u32,
    mss: u16,
    wscale: u8,
    sack: bool,
}

impl StateData {
    fn new() -> Self {
        Self {
            seq: 0,
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

enum TimerType {
    Rto = 0,
    Pacing = 1,
    TimeWait = 2,
    Count,
}

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

struct TcpStreamControlBlock {
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
    ) -> Self {
        let deadline = Instant::now();
        let congestion = FixBandwidth::new();
        let pacing = Pacer::new(DEFAULT_RTT, congestion.window(), GRANULARITY);
        let rtt = RttEstimator::new(DEFAULT_RTT, DEFAULT_RTO, GRANULARITY);

        Self {
            src_mac,
            addr_pair,
            closer,
            gw_sender,
            timer: Box::pin(sleep_until(deadline.into())),
            timers: TimerTable::default(),
            shutdown: false,
            state: State::Listen,
            pacing: pacing,
            time: StreamTime::new(),
            rtt: rtt,
            state_data: StateData::new(),
            recv_buffer: RecvBuffer::new(),
            send_buffer: SendBuffer::new(),
            congestion: congestion,
            read_waker: None,
            write_waker: None,
            driver_waker: None,
        }
    }

    fn handle_tcp_packet(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::RST != 0 {
            trace!(
                "{}[{}]: recv RST, change state to Closed",
                self.addr_pair,
                self.state
            );
            self.state = State::Closed;
        }

        self.time.update_alive();

        match self.state {
            State::Listen => self.state_listen(request),
            State::SynRcvd => self.state_syn_rcvd(request),
            State::Estab => self.state_estab(request),
            State::FinWait1 => self.state_fin_wait1(request),
            State::FinWait2 => self.state_fin_wait2(request),
            State::Closing => self.state_closing(request),
            State::TimeWait => self.state_time_wait(request),
            State::CloseWait => self.state_close_wait(request),
            State::LastAck => self.state_last_ack(request),
            State::Closed => self.state_closed(),
        }
    }

    fn poll_state(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        if self.is_closed() {
            self.closer.close(self.addr_pair);
            return std::task::Poll::Ready(());
        }

        if self.is_timewait_timeout() {
            trace!(
                "{}[{}]: TimeWait timeout, change state to Closed",
                self.addr_pair,
                self.state
            );
            self.state = State::Closed;
            self.closer.close(self.addr_pair);
            return std::task::Poll::Ready(());
        }

        if self.driver_waker.is_none() {
            self.driver_waker = Some(cx.waker().clone());
        }

        if self.state == State::Estab || self.state == State::CloseWait {
            self.send_packets();
        }

        let deadline = self.timers.next_deadline();
        if deadline.is_none() {
            return std::task::Poll::Pending;
        }

        let deadline = deadline.unwrap();
        if self.timer.deadline().into_std() != deadline {
            Sleep::reset(self.timer.as_mut(), deadline.into());
        }

        if Future::poll(self.timer.as_mut(), cx).is_ready() {
            cx.waker().wake_by_ref();
        }

        std::task::Poll::Pending
    }

    fn poll_read(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.recv_buffer.recved.is_empty() {
            let size = buf.remaining().min(self.recv_buffer.recved.len());
            let data = self.recv_buffer.recved.drain(..size).collect::<Vec<u8>>();
            buf.put_slice(&data);
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

        let size = buf.len();
        self.send_buffer
            .pending
            .push_back(PendingData::Data(Bytes::copy_from_slice(buf)));
        self.send_buffer.pending_size += size;
        self.driver_waker.as_ref().map(|waker| waker.wake_by_ref());
        std::task::Poll::Ready(Ok(size))
    }

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

        if self.send_buffer.sending.is_empty() && self.send_buffer.pending.is_empty() {
            self.send_fin();
            std::task::Poll::Ready(Ok(()))
        } else {
            if !self.shutdown {
                self.shutdown = true;
                self.send_buffer.pending.push_back(PendingData::Fin);
            }
            self.write_waker = Some(cx.waker().clone());
            std::task::Poll::Pending
        }
    }

    fn close(&mut self) {
        if self.state != State::Closed
            && self.state != State::TimeWait
            && self.state != State::LastAck
            && self.state != State::Closing
        {
            self.send_tcp_rst_packet();
            self.state = State::Closed;
            self.state_closed();
            self.driver_waker.as_ref().map(|waker| waker.wake_by_ref());
        }
    }

    fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    fn is_timewait_timeout(&mut self) -> bool {
        if self.state != State::TimeWait {
            return false;
        }

        let deadline = self.time.alive_time() + MSL_2;
        self.timers.set(TimerType::TimeWait, deadline);

        Instant::now() >= deadline
    }

    fn send_packets(&mut self) {
        if let Some(until_time) = self.resend_sending_data() {
            self.timers.set(TimerType::Pacing, until_time);
        } else if let Some(until_time) = self.send_pending_data() {
            self.timers.set(TimerType::Pacing, until_time);
        } else {
            self.timers.stop(TimerType::Pacing);
        }

        if self.send_buffer.sending.is_empty() {
            self.timers.stop(TimerType::Rto);
        } else {
            let front = self.send_buffer.sending.front().unwrap();
            self.timers
                .set(TimerType::Rto, front.timeout(self.rtt.rto()));
        }
    }

    fn state_listen(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::SYN != 0 {
            trace!(
                "{}[{}]: tcp SYN, ISN: {}",
                self.addr_pair,
                self.state,
                request.get_sequence()
            );
            self.state_data.ack = request.get_sequence() + 1;
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
            self.state = State::SynRcvd;
            trace!(
                "{}[{}]: change state to SynRcvd",
                self.addr_pair,
                self.state
            );
        }
    }

    fn state_syn_rcvd(&mut self, request: &TcpPacket) {
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
                self.state = State::Estab;

                self.process_payload(request);
            }
        }
    }

    fn state_estab(&mut self, request: &TcpPacket) {
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
                    self.addr_pair,
                    self.state
                );
                return self.process_fin(request);
            }
        }

        self.process_payload(request);
    }

    fn state_fin_wait1(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            if request.get_sequence() == self.state_data.ack {
                trace!(
                    "{}[{}]: recv FIN, change state to Closing",
                    self.addr_pair,
                    self.state
                );
                return self.process_fin(request);
            }
        }

        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.state_data.seq + 1 {
                self.state = State::FinWait2;
            }
        }

        self.process_payload(request);
    }

    fn state_fin_wait2(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            if request.get_sequence() == self.state_data.ack {
                trace!(
                    "{}[{}]: recv FIN, change state to TimeWait",
                    self.addr_pair,
                    self.state
                );
                return self.process_fin(request);
            }
        }

        self.process_payload(request);
    }

    fn state_closing(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            return self.process_fin(request);
        }

        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.state_data.seq + 1 {
                trace!(
                    "{}[{}]: recv FIN ack, change state to TimeWait",
                    self.addr_pair,
                    self.state
                );
                self.state = State::TimeWait;
            }
        }
    }

    fn state_time_wait(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            self.process_fin(request);
        }
    }

    fn state_close_wait(&mut self, request: &TcpPacket) {
        self.update_remote_window(request);
        self.process_acknowledgement(request);

        if request.get_flags() & TcpFlags::FIN != 0 {
            self.process_fin(request);
        }
    }

    fn state_last_ack(&mut self, request: &TcpPacket) {
        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.state_data.seq + 1 {
                self.state = State::Closed;
                trace!(
                    "{}[{}]: recv last ACK, change state to Closed",
                    self.addr_pair,
                    self.state
                );
            }
        }
    }

    fn state_closed(&mut self) {
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }

    fn send_data(&mut self, data: Bytes) {
        let sending_data = SendingData::new(self.state_data.seq, data);
        let bytes = sending_data.data.len();

        self.state_data.seq += bytes as u32;
        self.send_buffer.inflight += bytes;
        self.pacing.on_sent(bytes);

        self.send_tcp_data_packet(&sending_data);
        self.send_buffer.sending.push_back(sending_data);
    }

    fn resend_sending_data(&mut self) -> Option<Instant> {
        let now = Instant::now();
        let mut until_time = None;
        let mut latest_loss_sent = None;

        for index in 0..self.send_buffer.sending.len() {
            let sending_data = &self.send_buffer.sending[index];
            if now < sending_data.timeout(self.rtt.rto()) {
                break;
            }

            let send_bytes = sending_data.data.len();
            if let Some(t) =
                self.pacing
                    .wait_until(send_bytes, now, self.rtt.get(), self.congestion.window())
            {
                until_time = Some(t);
                break;
            }

            trace!(
                "{}[{}]: resend data at seq: {}, len: {}, rto: {}({})ms",
                self.addr_pair,
                self.state,
                sending_data.seq,
                sending_data.data.len(),
                sending_data.adjust_rto(self.rtt.rto()).as_millis(),
                self.rtt.rto().as_millis()
            );

            if let Some(sent) = latest_loss_sent {
                if sending_data.sent > sent {
                    latest_loss_sent = Some(sending_data.sent);
                }
            } else {
                latest_loss_sent = Some(sending_data.sent);
            }

            self.pacing.on_sent(send_bytes);
            self.send_tcp_data_packet(sending_data);
            self.send_buffer.sending[index].sent = now;
        }

        if let Some(sent) = latest_loss_sent {
            self.congestion.on_congestion(now, sent, false);
        }

        until_time
    }

    fn send_pending_data(&mut self) -> Option<Instant> {
        let now = Instant::now();
        let mut until_time = None;
        let mut window = self
            .congestion
            .window()
            .saturating_sub(self.send_buffer.inflight);

        trace!(
            "{}[{}]: remote wnd: {}, congestion wnd: {}, inflight: {}",
            self.addr_pair,
            self.state,
            self.state_data.remote_window,
            self.congestion.window(),
            self.send_buffer.inflight,
        );

        while !self.send_buffer.pending.is_empty() && window > 0 {
            let front = self.send_buffer.pending.pop_front().unwrap();

            match front {
                PendingData::Data(mut data) => {
                    let send_bytes = data.len().min(window);
                    if let Some(t) = self.pacing.wait_until(
                        send_bytes,
                        now,
                        self.rtt.get(),
                        self.congestion.window(),
                    ) {
                        until_time = Some(t);
                        self.send_buffer.pending.push_front(PendingData::Data(data));
                        break;
                    }

                    if data.len() > send_bytes {
                        let tail = data.split_off(send_bytes);
                        self.send_buffer.pending.push_front(PendingData::Data(tail));
                    }

                    self.send_data(data);
                    self.send_buffer.pending_size -= send_bytes;
                    window -= send_bytes;

                    trace!(
                        "{}[{}]: send pending data: {}, inflight: {}",
                        self.addr_pair,
                        self.state,
                        send_bytes,
                        self.send_buffer.inflight
                    );
                }
                PendingData::Fin => {
                    if self.send_buffer.sending.is_empty() {
                        if let Some(waker) = self.write_waker.take() {
                            waker.wake();
                        }
                    } else {
                        self.send_buffer.pending.push_front(PendingData::Fin);
                    }
                    break;
                }
            }
        }

        if self.state == State::Estab || self.state == State::CloseWait {
            if !self.send_buffer.is_full() {
                if let Some(waker) = self.write_waker.take() {
                    waker.wake();
                }
            }
        }

        until_time
    }

    fn send_fin(&mut self) {
        self.send_tcp_fin_packet();

        match self.state {
            State::SynRcvd | State::Estab => self.state = State::FinWait1,
            State::CloseWait => self.state = State::LastAck,
            _ => self.close(),
        }
    }

    fn update_remote_window(&mut self, request: &TcpPacket) {
        self.state_data.remote_window = request.get_window() as u32;
        self.state_data.remote_window <<= self.state_data.wscale;
        trace!(
            "{}[{}]: update remote window size: {}",
            self.addr_pair,
            self.state,
            self.state_data.remote_window
        );
    }

    fn timestamp(&self) -> u32 {
        self.time.timestamp_millis()
    }

    fn add_tcp_option_timestamp(&self, opts: &mut Vec<TcpOption>, opts_size: &mut usize) {
        opts.push(TcpOption::nop());
        opts.push(TcpOption::nop());
        opts.push(TcpOption::timestamp(
            self.timestamp(),
            self.state_data.remote_ts,
        ));
        *opts_size += 12;
    }

    fn add_tcp_option_sack(
        &self,
        opts: &mut Vec<TcpOption>,
        opts_size: &mut usize,
        seq_range: Option<(u32, u32)>,
    ) {
        if !self.state_data.sack {
            return;
        }

        let mut blocks = 3;
        let mut acks = Vec::new();

        if let Some(seq_range) = seq_range {
            if ((self.state_data.ack - seq_range.0) as i32) < 0 {
                acks.push(seq_range.0);
                acks.push(seq_range.1);
                blocks -= 1;
            }
        }

        for range in &self.recv_buffer.ranges {
            if blocks == 0 {
                break;
            }
            acks.push(range.0);
            acks.push(range.1);
            blocks -= 1;
        }

        if !acks.is_empty() {
            opts.push(TcpOption::nop());
            opts.push(TcpOption::nop());
            opts.push(TcpOption::selective_ack(&acks));
            *opts_size += 4 + 4 * acks.len();
        }
    }

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

    fn send_tcp_data_packet(&self, data: &SendingData) {
        let mut opts = Vec::new();
        let mut opts_size = 0;

        self.add_tcp_option_timestamp(&mut opts, &mut opts_size);
        self.add_tcp_option_sack(&mut opts, &mut opts_size, None);

        let mut index = 0;
        let mut seq = data.seq;
        let mut len = data.data.len();
        let max_payload_len = self.state_data.mss as usize - MAX_TCP_HEADER_LEN;

        while len > 0 {
            let payload_len = std::cmp::min(len, max_payload_len);
            let payload = &data.data[index..index + payload_len];

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

    fn send_tcp_acknowledge_packet(&self, seq_range: Option<(u32, u32)>) {
        self.send_tcp_control_packet(TcpFlags::ACK, seq_range);
        trace!(
            "{}[{}]: send acknowledge ack: {}",
            self.addr_pair,
            self.state,
            self.state_data.ack
        );
    }

    fn send_tcp_fin_packet(&self) {
        self.send_tcp_control_packet(TcpFlags::ACK | TcpFlags::FIN, None);
        trace!("{}[{}]: send FIN", self.addr_pair, self.state);
    }

    fn send_tcp_rst_packet(&self) {
        self.send_tcp_control_packet(TcpFlags::ACK | TcpFlags::RST, None);
        trace!("{}[{}]: send RST", self.addr_pair, self.state);
    }

    fn send_tcp_control_packet(&self, flags: u8, seq_range: Option<(u32, u32)>) {
        let mut opts = Vec::new();
        let mut opts_size = 0;
        let payload = [0u8; 0];

        self.add_tcp_option_timestamp(&mut opts, &mut opts_size);
        self.add_tcp_option_sack(&mut opts, &mut opts_size, seq_range);
        self.send_tcp_packet(self.state_data.seq, flags, &opts, opts_size, &payload);
    }

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
                ipv4_packet.set_source(*self.addr_pair.1.ip());
                ipv4_packet.set_destination(*self.addr_pair.0.ip());

                let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
                tcp_packet.set_source(self.addr_pair.1.port());
                tcp_packet.set_destination(self.addr_pair.0.port());
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
                    self.addr_pair.1.ip(),
                    self.addr_pair.0.ip(),
                ));

                ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));
            });
    }

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
                        self.addr_pair,
                        self.state,
                        self.state_data.remote_ts
                    );
                }
            }
        }
    }

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

    fn process_acknowledgement(&mut self, request: &TcpPacket) {
        let now = Instant::now();
        let ack = request.get_acknowledgement();
        let inflight = self.send_buffer.inflight;
        trace!("{}[{}]: process ack: {}", self.addr_pair, self.state, ack);

        while !self.send_buffer.sending.is_empty() {
            let front = self.send_buffer.sending.front_mut().unwrap();
            let begin_seq = front.seq;
            let end_seq = begin_seq + front.data.len() as u32;

            if ((begin_seq - ack) as i32) >= 0 {
                break;
            }

            if ((end_seq - ack) as i32) <= 0 {
                let bytes = front.data.len();
                self.congestion.on_ack(now, front.sent, bytes, &self.rtt);
                self.send_buffer.sending.pop_front();
                self.send_buffer.inflight -= bytes;
            } else {
                let bytes = (ack - begin_seq) as usize;
                self.congestion.on_ack(now, front.sent, bytes, &self.rtt);
                front.seq = ack;
                front.data.advance(bytes);
                self.send_buffer.inflight -= bytes;
            }
        }

        if inflight != self.send_buffer.inflight {
            self.process_echo_timestamp(request);
        }
    }

    fn process_payload(&mut self, request: &TcpPacket) {
        if request.get_sequence() == (self.state_data.ack - 1) {
            trace!(
                "{}[{}]: keep-alive request, payload size: {}",
                self.addr_pair,
                self.state,
                request.payload().len()
            );
            if request.payload().len() <= 1 {
                return self.send_tcp_acknowledge_packet(None);
            }
        }

        let payload = request.payload();
        if payload.is_empty() {
            return;
        }

        let seq = request.get_sequence();
        let range = (seq, seq + payload.len() as u32);
        let window = (
            self.state_data.ack,
            self.state_data.ack + self.state_data.local_window,
        );

        let range_left = ((range.0 - window.0) as i32, (range.1 - window.0) as i32);
        let range_right = ((range.0 - window.1) as i32, (range.1 - window.1) as i32);
        if range_left.1 <= 0 || range_right.0 >= 0 {
            warn!(
                "{}[{}]: payload [{}, {}) out of local window [{}, {})",
                self.addr_pair, self.state, range.0, range.1, window.0, window.1
            );
            return self.send_tcp_acknowledge_packet(None);
        }

        let mut data_index = 0usize;
        let mut data_len = payload.len();
        if range_left.0 < 0 {
            data_index = range_left.0.abs() as usize;
            data_len -= data_index;
        }

        if range_right.1 > 0 {
            data_len -= range_right.1 as usize;
        }

        let buffer_index = if range_left.0 > 0 {
            warn!(
                "{}[{}]: local window hole [{}, {})",
                self.addr_pair, self.state, window.0, range.0
            );
            range_left.0 as usize
        } else {
            0usize
        };

        self.copy_to_recv_buffer(buffer_index, &payload[data_index..data_index + data_len]);

        let seq_range = (
            seq + data_index as u32,
            seq + data_index as u32 + data_len as u32,
        );

        self.update_recv_ranges(seq_range);
        self.handle_recv_buffer(request);
        self.send_tcp_acknowledge_packet(Some(seq_range));
    }

    fn process_fin(&mut self, request: &TcpPacket) {
        self.state_data.ack = request.get_sequence() + 1;
        self.send_tcp_acknowledge_packet(None);

        match self.state {
            State::Estab | State::CloseWait => self.state = State::CloseWait,
            State::FinWait1 | State::Closing => self.state = State::Closing,
            State::FinWait2 | State::TimeWait => self.state = State::TimeWait,
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

    fn copy_to_recv_buffer(&mut self, mut index: usize, buffer: &[u8]) {
        let slices = self.recv_buffer.buffer.as_mut_slices();

        let mut consumed = 0usize;
        let mut remain = buffer.len();
        if index < slices.0.len() {
            let len = std::cmp::min(slices.0.len() - index, remain);
            slices.0[index..index + len].copy_from_slice(&buffer[0..len]);

            index += len;
            remain -= len;
            consumed = len;
        }

        if remain == 0 {
            return;
        }

        index -= slices.0.len();
        let len = std::cmp::min(slices.1.len() - index, remain);
        slices.1[index..index + len].copy_from_slice(&buffer[consumed..consumed + len]);
    }

    fn update_recv_ranges(&mut self, seq_range: (u32, u32)) {
        for index in 0..self.recv_buffer.ranges.len() {
            let diff = (seq_range.0 - self.recv_buffer.ranges[index].0) as i32;
            if diff < 0 {
                return self.recv_buffer.ranges.insert(index, seq_range);
            }
        }

        self.recv_buffer.ranges.push_back(seq_range);
    }

    fn handle_recv_buffer(&mut self, request: &TcpPacket) {
        let mut range = self.recv_buffer.ranges.front().unwrap().clone();
        if self.state_data.ack != range.0 {
            return;
        }

        loop {
            self.recv_buffer.ranges.pop_front();
            if self.recv_buffer.ranges.is_empty() {
                break;
            }

            let front = self.recv_buffer.ranges.front().unwrap().clone();
            if ((front.0 - range.1) as i32) > 0 {
                break;
            }

            if ((front.1 - range.1) as i32) > 0 {
                range.1 = front.1;
            }
        }

        self.state_data.ack = range.1;
        self.process_remote_timestamp(request);

        let len = (range.1 - range.0) as usize;
        let mut data: VecDeque<u8> = self.recv_buffer.buffer.drain(0..len).collect();
        self.recv_buffer.recved.append(&mut data);
        self.recv_buffer
            .buffer
            .resize(self.state_data.local_window as usize, 0);

        if !self.recv_buffer.recved.is_empty() {
            if let Some(waker) = self.read_waker.take() {
                waker.wake();
            }
        }
    }
}
