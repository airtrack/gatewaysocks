use std::collections::{HashMap, VecDeque};
use std::fmt::Display;
use std::future::Future;
use std::net::{SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Waker;
use std::time::{Duration, Instant};
use std::usize;

use bytes::Bytes;
use log::{error, trace, warn};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumbers, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{
    channel, unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender,
};
use tokio::time::{sleep_until, Sleep};

use crate::gateway::GatewaySender;

const MSL_2: Duration = Duration::from_millis(30000);
const DEFAULT_RTO: Duration = Duration::from_millis(100);
const DEFAULT_RTT: Duration = Duration::from_millis(10);
const GRANULARITY: Duration = Duration::from_millis(1);
const MAX_TCP_HEADER_LEN: usize = 60;
const LOCAL_WINDOW: u32 = 256 * 1024;
const DEFAULT_MSS: usize = 1400;

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

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct AddrPair(SocketAddrV4, SocketAddrV4);

impl Display for AddrPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("({}, {})", self.0, self.1))
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

struct RttEstimator {
    srtt: Option<Duration>,
    latest: Duration,
    var: Duration,
    rto: Duration,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            srtt: None,
            latest: Duration::default(),
            var: Duration::default(),
            rto: DEFAULT_RTO,
        }
    }

    fn get(&self) -> Duration {
        self.srtt.unwrap_or(DEFAULT_RTT)
    }

    fn rto(&self) -> Duration {
        self.rto.max(DEFAULT_RTO / 2)
    }

    fn latest(&self) -> Duration {
        self.latest
    }

    fn update(&mut self, rtt: Duration) {
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

        self.rto = self.srtt.unwrap() + GRANULARITY.max(4 * self.var);
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
    data: Vec<u8>,
}

impl SendingData {
    fn new(seq: u32, data: Vec<u8>) -> Self {
        Self {
            sent: Instant::now(),
            seq,
            data,
        }
    }

    fn timeout(&self, rto: Duration) -> Instant {
        self.sent + rto
    }
}

enum PendingData {
    Data(Vec<u8>),
    Fin,
}

struct SendBuffer {
    size: usize,
    buffer: VecDeque<SendingData>,
    pending: VecDeque<PendingData>,
}

impl SendBuffer {
    fn new() -> Self {
        Self {
            size: 0,
            buffer: VecDeque::new(),
            pending: VecDeque::new(),
        }
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

trait CController: Send {
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
    fn new() -> Box<Self> {
        Box::new(Self {
            mtu: DEFAULT_MSS,
            window: 200 * DEFAULT_MSS,
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
impl CController for Cubic {
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

struct FixBandwidth;

impl FixBandwidth {
    fn new() -> Box<Self> {
        Box::new(Self {})
    }
}

#[allow(unused)]
impl CController for FixBandwidth {
    fn window(&self) -> usize {
        128000
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: usize, rtt: &RttEstimator) {}

    fn on_congestion(&mut self, now: Instant, sent: Instant, persistent: bool) {}
}

struct Pacer {
    granu: usize,
    bytes: usize,
    window: usize,
    srtt: Duration,
    prev: Instant,
}

impl Pacer {
    fn new(srtt: Duration, window: usize) -> Self {
        let granu = Self::granularity(srtt, window);
        Self {
            granu,
            bytes: granu,
            window,
            srtt,
            prev: Instant::now(),
        }
    }

    fn granularity(srtt: Duration, window: usize) -> usize {
        let srtt = srtt.as_secs_f64();
        let unit = GRANULARITY.as_secs_f64();
        ((unit * window as f64) / srtt) as usize
    }

    fn consume(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_sub(bytes);
    }

    fn delay(
        &mut self,
        send_bytes: usize,
        now: Instant,
        srtt: Duration,
        window: usize,
    ) -> Option<Instant> {
        if self.window != window {
            self.granu = Self::granularity(srtt, window);
            self.bytes = self.granu.min(self.bytes);
            self.srtt = srtt;
            self.window = window;
        }

        if self.bytes >= send_bytes {
            return None;
        }

        let inc_rtts = (now - self.prev).as_secs_f64() / self.srtt.as_secs_f64();
        let inc_bytes = (inc_rtts * window as f64) as usize;
        self.bytes = self
            .bytes
            .saturating_add(inc_bytes as usize)
            .min(self.granu);
        self.prev = now;

        if self.bytes >= send_bytes {
            return None;
        }

        let diff = (send_bytes.max(self.granu) - self.bytes) as f64;
        let duration = diff * self.srtt.as_secs_f64() / self.window as f64;
        let delay = Duration::from_secs_f64(duration);
        Some(now + delay)
    }
}

enum TimerType {
    Rto = 0,
    Pacing = 1,
    TimeWait = 2,
}

#[derive(Default)]
struct TimerTable {
    table: [Option<Instant>; 3],
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

pub(super) fn new_tcp(
    channel: UnboundedReceiver<Bytes>,
    gw_sender: GatewaySender,
) -> (TcpHandler, TcpListener) {
    let (new_stream, streams) = unbounded_channel();
    let (close_stream, close_streams) = unbounded_channel();
    let handler = TcpHandler {
        channel,
        gw_sender,
        new_stream,
        close_stream,
        close_streams,
        streams: HashMap::new(),
    };
    let listener = TcpListener { streams };
    (handler, listener)
}

pub struct TcpHandler {
    channel: UnboundedReceiver<Bytes>,
    gw_sender: GatewaySender,
    new_stream: UnboundedSender<TcpStream>,
    close_stream: UnboundedSender<AddrPair>,
    close_streams: UnboundedReceiver<AddrPair>,
    streams: HashMap<AddrPair, Sender<Bytes>>,
}

impl TcpHandler {
    pub fn start(mut self) {
        tokio::spawn(async move {
            self.handle_loop().await;
        });
    }

    async fn handle_loop(&mut self) -> Option<()> {
        loop {
            tokio::select! {
                Some(addr_pair) = self.close_streams.recv() => {
                    self.remove_stream(addr_pair);
                }
                Some(packet) = self.channel.recv() => {
                    self.handle_packet(packet);
                }
            }
        }
    }

    fn remove_stream(&mut self, addr_pair: AddrPair) {
        self.streams.remove(&addr_pair);
    }

    fn handle_packet(&mut self, packet: Bytes) -> Option<()> {
        let ethernet_packet = EthernetPacket::new(&packet)?;
        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
        let tcp_request = TcpPacket::new(ipv4_packet.payload())?;
        let mac = ethernet_packet.get_source();
        let src = SocketAddrV4::new(ipv4_packet.get_source(), tcp_request.get_source());
        let dst = SocketAddrV4::new(ipv4_packet.get_destination(), tcp_request.get_destination());
        let pair = AddrPair(src, dst);
        let data = packet.slice_ref(ipv4_packet.payload());

        match self.streams.get(&pair) {
            Some(sender) => sender.try_send(data).ok()?,
            None => {
                if TcpStreamCore::is_syn_packet(&tcp_request) {
                    let (packets_tx, packets_rx) = channel(32);
                    let inner = Arc::new(TcpStreamInner {
                        core: Mutex::new(TcpStreamCore::new(
                            self.close_stream.clone(),
                            mac,
                            pair,
                            self.gw_sender.clone(),
                        )),
                    });
                    let driver = TcpStreamDriver {
                        packets: packets_rx,
                        inner: inner.clone(),
                    };
                    let stream = TcpStream { inner };

                    packets_tx.try_send(data).ok()?;
                    self.streams.insert(pair, packets_tx);
                    self.new_stream.send(stream).ok()?;
                    driver.start();
                }
            }
        }

        Some(())
    }
}

pub struct TcpListener {
    streams: UnboundedReceiver<TcpStream>,
}

impl TcpListener {
    pub async fn accept(&mut self) -> std::io::Result<TcpStream> {
        self.streams.recv().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "TCP handler broken",
        ))
    }
}

pub struct TcpStream {
    inner: Arc<TcpStreamInner>,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.inner.close();
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.inner.local_addr())
    }

    pub fn remote_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.inner.remote_addr())
    }

    pub fn split<'a>(&'a mut self) -> (ReadHalf<'a>, WriteHalf<'a>) {
        (ReadHalf(&*self), WriteHalf(&*self))
    }

    fn poll_read(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.inner.poll_read(cx, buf)
    }

    fn poll_write(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.inner.poll_write(cx, buf)
    }

    fn poll_shutdown(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.inner.poll_shutdown(cx)
    }
}

pub struct ReadHalf<'a>(&'a TcpStream);

pub struct WriteHalf<'a>(&'a TcpStream);

impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_read(cx, buf)
    }
}

impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.0.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.0.poll_shutdown(cx)
    }
}

struct TcpStreamDriver {
    packets: Receiver<Bytes>,
    inner: Arc<TcpStreamInner>,
}

impl TcpStreamDriver {
    fn start(self) {
        tokio::spawn(async move {
            self.await;
        });
    }
}

impl Future for TcpStreamDriver {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        loop {
            match self.packets.poll_recv(cx) {
                std::task::Poll::Ready(Some(packet)) => {
                    self.inner.handle_tcp_packet(packet);
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                std::task::Poll::Pending => return self.inner.poll_state(cx),
            }
        }
    }
}

struct TcpStreamInner {
    core: Mutex<TcpStreamCore>,
}

impl TcpStreamInner {
    fn local_addr(&self) -> SocketAddrV4 {
        self.core.lock().unwrap().addr_pair.0
    }

    fn remote_addr(&self) -> SocketAddrV4 {
        self.core.lock().unwrap().addr_pair.1
    }

    fn close(&self) {
        self.core.lock().unwrap().close();
    }

    fn poll_read(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.core.lock().unwrap().poll_read(cx, buf)
    }

    fn poll_write(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.core.lock().unwrap().poll_write(cx, buf)
    }

    fn poll_shutdown(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.core.lock().unwrap().poll_shutdown(cx)
    }

    fn poll_state(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        self.core.lock().unwrap().poll_state(cx)
    }

    fn handle_tcp_packet(&self, packet: Bytes) -> Option<()> {
        let request = TcpPacket::new(&packet)?;
        self.core.lock().unwrap().handle_tcp_packet(&request);
        Some(())
    }
}

struct TcpStreamCore {
    close_stream: UnboundedSender<AddrPair>,
    src_mac: MacAddr,
    addr_pair: AddrPair,
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
    congestion: Box<dyn CController>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    driver_waker: Option<Waker>,
}

impl TcpStreamCore {
    fn new(
        close_stream: UnboundedSender<AddrPair>,
        src_mac: MacAddr,
        addr_pair: AddrPair,
        gw_sender: GatewaySender,
    ) -> Self {
        let deadline = Instant::now();
        let congestion = FixBandwidth::new();
        let srtt = DEFAULT_RTT;

        Self {
            close_stream,
            src_mac,
            addr_pair,
            gw_sender,
            timer: Box::pin(sleep_until(deadline.into())),
            timers: TimerTable::default(),
            shutdown: false,
            state: State::Listen,
            pacing: Pacer::new(srtt, congestion.window()),
            time: StreamTime::new(),
            rtt: RttEstimator::new(),
            state_data: StateData::new(),
            recv_buffer: RecvBuffer::new(),
            send_buffer: SendBuffer::new(),
            congestion: congestion,
            read_waker: None,
            write_waker: None,
            driver_waker: None,
        }
    }

    fn is_syn_packet(request: &TcpPacket) -> bool {
        request.get_flags() & TcpFlags::SYN != 0
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
            self.close_stream.send(self.addr_pair).ok();
            return std::task::Poll::Ready(());
        }

        if self.is_timewait_timeout() {
            trace!(
                "{}[{}]: TimeWait timeout, change state to Closed",
                self.addr_pair,
                self.state
            );
            self.state = State::Closed;
            self.close_stream.send(self.addr_pair).ok();
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

        if self.state == State::SynRcvd || !self.send_buffer.pending.is_empty() {
            self.write_waker = Some(cx.waker().clone());
            return std::task::Poll::Pending;
        }

        let size = buf.len();
        self.send_buffer
            .pending
            .push_back(PendingData::Data(buf.into()));
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

        if self.send_buffer.buffer.is_empty() && self.send_buffer.pending.is_empty() {
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
        if let Some(delay) = self.resend_sending_data() {
            self.timers.set(TimerType::Pacing, delay);
        } else if let Some(delay) = self.send_pending_data() {
            self.timers.set(TimerType::Pacing, delay);
        } else {
            self.timers.stop(TimerType::Pacing);
        }

        if self.send_buffer.buffer.is_empty() {
            self.timers.stop(TimerType::Rto);
        } else {
            let front = self.send_buffer.buffer.front().unwrap();
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

    fn send_data(&mut self, data: Vec<u8>) {
        let sending_data = SendingData::new(self.state_data.seq, data);
        let bytes = sending_data.data.len();

        self.state_data.seq += bytes as u32;
        self.send_buffer.size += bytes;
        self.pacing.consume(bytes);

        self.send_tcp_data_packet(&sending_data);
        self.send_buffer.buffer.push_back(sending_data);
    }

    fn resend_sending_data(&mut self) -> Option<Instant> {
        let now = Instant::now();
        let mut delay = None;
        let mut latest_loss_sent = None;

        for index in 0..self.send_buffer.buffer.len() {
            let sending_data = &self.send_buffer.buffer[index];
            if now < sending_data.timeout(self.rtt.rto()) {
                break;
            }

            let send_bytes = sending_data.data.len();
            if let Some(t) =
                self.pacing
                    .delay(send_bytes, now, self.rtt.get(), self.congestion.window())
            {
                delay = Some(t);
                break;
            }

            trace!(
                "{}[{}]: resend data at seq: {}, len: {}, rto: {}",
                self.addr_pair,
                self.state,
                sending_data.seq,
                sending_data.data.len(),
                self.rtt.rto().as_millis()
            );

            if let Some(sent) = latest_loss_sent {
                if sending_data.sent > sent {
                    latest_loss_sent = Some(sending_data.sent);
                }
            } else {
                latest_loss_sent = Some(sending_data.sent);
            }

            self.pacing.consume(send_bytes);
            self.send_tcp_data_packet(sending_data);
            self.send_buffer.buffer[index].sent = now;
        }

        if let Some(sent) = latest_loss_sent {
            self.congestion.on_congestion(now, sent, false);
        }

        delay
    }

    fn send_pending_data(&mut self) -> Option<Instant> {
        let now = Instant::now();
        let mut delay = None;
        let mut window = self
            .congestion
            .window()
            .saturating_sub(self.send_buffer.size);

        trace!(
            "{}[{}]: remote wnd: {}, congestion wnd: {}, inflight: {}",
            self.addr_pair,
            self.state,
            self.state_data.remote_window,
            self.congestion.window(),
            self.send_buffer.size,
        );

        while !self.send_buffer.pending.is_empty() && window > 0 {
            let front = self.send_buffer.pending.pop_front().unwrap();

            match front {
                PendingData::Data(mut data) => {
                    let send_bytes = data.len().min(window);
                    if let Some(t) =
                        self.pacing
                            .delay(send_bytes, now, self.rtt.get(), self.congestion.window())
                    {
                        delay = Some(t);
                        self.send_buffer.pending.push_front(PendingData::Data(data));
                        break;
                    }

                    if data.len() > send_bytes {
                        let tail = data.split_off(send_bytes);
                        self.send_buffer.pending.push_front(PendingData::Data(tail));
                    }

                    trace!(
                        "{}[{}]: send pending data size: {}",
                        self.addr_pair,
                        self.state,
                        send_bytes
                    );
                    self.send_data(data);
                    window -= send_bytes;
                }
                PendingData::Fin => {
                    if self.send_buffer.buffer.is_empty() {
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
            if self.send_buffer.pending.is_empty() {
                if let Some(waker) = self.write_waker.take() {
                    waker.wake();
                }
            }
        }

        delay
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
        let send_buffer_size = self.send_buffer.size;
        trace!("{}[{}]: process ack: {}", self.addr_pair, self.state, ack);

        while !self.send_buffer.buffer.is_empty() {
            let front = self.send_buffer.buffer.front_mut().unwrap();
            let begin_seq = front.seq;
            let end_seq = begin_seq + front.data.len() as u32;

            if ((begin_seq - ack) as i32) >= 0 {
                break;
            }

            if ((end_seq - ack) as i32) <= 0 {
                let bytes = front.data.len();
                self.congestion.on_ack(now, front.sent, bytes, &self.rtt);
                self.send_buffer.buffer.pop_front();
                self.send_buffer.size -= bytes;
            } else {
                let bytes = (ack - begin_seq) as usize;
                self.congestion.on_ack(now, front.sent, bytes, &self.rtt);
                front.seq = ack;
                front.data.drain(0..bytes);
                self.send_buffer.size -= bytes;
            }
        }

        if send_buffer_size != self.send_buffer.size {
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
