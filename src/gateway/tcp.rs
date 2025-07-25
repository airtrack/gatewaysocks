use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Instant;

use log::{error, info, trace, warn};
use pnet::datalink::DataLinkSender;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{
    self, MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumbers, TcpOptionPacket, TcpPacket,
};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use super::is_to_gateway;
use crate::prometheus::metrics;

pub enum TcpLayerPacket {
    Connect((String, SocketAddrV4)),
    Established(String),
    Push((String, Vec<u8>)),
    Shutdown(String),
    Close(String),
}

pub trait TcpConnectionHandler {
    fn handle_input_tcp_packet(&mut self) -> Option<TcpLayerPacket>;
    fn handle_output_tcp_packet(&mut self, packet: TcpLayerPacket);
}

pub struct TcpProcessor {
    mac: MacAddr,
    gateway: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    heartbeat: Instant,
    connections: HashMap<String, TcpConnection>,
    new_conn_handler: Box<dyn FnMut(&str, SocketAddrV4) -> Box<dyn TcpConnectionHandler>>,
}

impl TcpProcessor {
    pub fn new(
        mac: MacAddr,
        gateway: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        new_conn_handler: impl FnMut(&str, SocketAddrV4) -> Box<dyn TcpConnectionHandler> + 'static,
    ) -> Self {
        Self {
            mac,
            gateway,
            subnet_mask,
            heartbeat: Instant::now(),
            connections: HashMap::new(),
            new_conn_handler: Box::new(new_conn_handler),
        }
    }

    pub fn heartbeat(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        let now = Instant::now();
        if (now - self.heartbeat).as_micros() < 1000 {
            return;
        }

        self.heartbeat = now;
        metrics::TCP_CONNS.set(self.connections.len() as i64);

        // 1000 Mbps ethenet, 120000 * 8 * 1000 = 960Mbps
        let mut total_pacing = 120000;
        self.connections.retain(|key, connection| -> bool {
            let pacing = std::cmp::min(20000, total_pacing);
            connection.send_buffer.pacing = pacing;

            let alive = connection.heartbeat(tx);
            if !alive {
                metrics::TCP_TX_BYTES
                    .remove_label_values(&[&connection.key])
                    .unwrap_or_else(|e| {
                        error!("remove tcp_tx_bytes error: {}", e);
                    });
                metrics::TCP_RX_BYTES
                    .remove_label_values(&[&connection.key])
                    .unwrap_or_else(|e| {
                        error!("remove tcp_rx_bytes error: {}", e);
                    });
                info!("{}[{}]: remove tcp connection", key, connection.state);
            }

            total_pacing -= pacing - connection.send_buffer.pacing;
            alive
        });
    }

    pub fn handle_input_packet(
        &mut self,
        tx: &mut Box<dyn DataLinkSender>,
        source_mac: MacAddr,
        request: &Ipv4Packet,
    ) {
        if !is_to_gateway(self.gateway, self.subnet_mask, request.get_source()) {
            return;
        }

        trace!(
            "TCP packet {} -> {}",
            request.get_source(),
            request.get_destination()
        );

        if let Some(tcp_request) = TcpPacket::new(request.payload()) {
            let src = SocketAddrV4::new(request.get_source(), tcp_request.get_source());
            let dst = SocketAddrV4::new(request.get_destination(), tcp_request.get_destination());
            let key = src.to_string() + "-" + &dst.to_string();

            if let Some(connection) = self.connections.get_mut(&key) {
                return connection.handle_tcp_packet(&tcp_request, tx);
            }

            if TcpConnection::is_syn_packet(&tcp_request) {
                info!("{}: add tcp connection", key);
                let handler = (self.new_conn_handler)(&key, dst);
                let mut connection =
                    TcpConnection::new(&key, self.mac, source_mac, src, dst, handler);
                connection.handle_tcp_packet(&tcp_request, tx);
                self.connections.insert(key, connection);
            }
        }
    }
}

struct TcpLayerHandler {
    key: String,
    dst_addr: SocketAddrV4,
    connect: bool,
    shutdown: bool,
    handler: Box<dyn TcpConnectionHandler>,
}

impl TcpLayerHandler {
    fn new(key: &str, dst_addr: SocketAddrV4, handler: Box<dyn TcpConnectionHandler>) -> Self {
        Self {
            key: key.to_string(),
            dst_addr,
            connect: false,
            shutdown: false,
            handler,
        }
    }

    fn handle_input_tcp_packet(&mut self) -> Option<TcpLayerPacket> {
        self.handler.handle_input_tcp_packet()
    }

    fn handle_connect(&mut self) {
        if self.connect {
            return;
        }

        self.connect = true;
        self.handler
            .handle_output_tcp_packet(TcpLayerPacket::Connect((self.key.clone(), self.dst_addr)));
    }

    fn handle_recv(&mut self, data: Vec<u8>) {
        trace!("{}: recv data size: {}", self.key, data.len());
        self.handler
            .handle_output_tcp_packet(TcpLayerPacket::Push((self.key.clone(), data)));
    }

    fn handle_recv_fin(&mut self) {
        if self.shutdown {
            return;
        }

        self.shutdown = true;
        self.handler
            .handle_output_tcp_packet(TcpLayerPacket::Shutdown(self.key.clone()));
    }

    fn handle_reset(&mut self) {
        self.handler
            .handle_output_tcp_packet(TcpLayerPacket::Close(self.key.clone()));
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

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

struct Time {
    init: Instant,
    alive: Instant,
}

impl Time {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            init: now,
            alive: now,
        }
    }
}

struct Address {
    mac: MacAddr,
    src_mac: MacAddr,
    src_addr: SocketAddrV4,
    dst_addr: SocketAddrV4,
}

impl Address {
    fn new(mac: MacAddr, src_mac: MacAddr, src: SocketAddrV4, dst: SocketAddrV4) -> Self {
        Self {
            mac,
            src_mac,
            src_addr: src,
            dst_addr: dst,
        }
    }
}

struct RtoVars {
    rto: u32,
    srtt: u32,
    rttvar: u32,
}

impl RtoVars {
    fn new() -> Self {
        Self {
            rto: MAX_RTO,
            srtt: DEFAULT_RTT,
            rttvar: 0,
        }
    }
}

struct RecvBuffer {
    buffer: VecDeque<u8>,
    ranges: VecDeque<(u32, u32)>,
}

impl RecvBuffer {
    fn new() -> Self {
        let mut buffer = VecDeque::new();
        buffer.resize(LOCAL_WINDOW as usize, 0);
        let ranges = VecDeque::new();

        Self { buffer, ranges }
    }
}

struct SendingData {
    send_time: Instant,
    seq: u32,
    data: Vec<u8>,
}

impl SendingData {
    fn new(seq: u32, data: Vec<u8>) -> Self {
        Self {
            send_time: Instant::now(),
            seq,
            data,
        }
    }
}

enum PendingData {
    Data(Vec<u8>),
    Fin,
}

struct SendBuffer {
    size: usize,
    pacing: usize,
    buffer: VecDeque<SendingData>,
    pending: VecDeque<PendingData>,
}

impl SendBuffer {
    fn new() -> Self {
        Self {
            size: 0,
            pacing: 0,
            buffer: VecDeque::new(),
            pending: VecDeque::new(),
        }
    }
}

struct TcpData {
    seq: u32,
    ack: u32,
    local_window: u32,
    remote_window: u32,

    remote_ts: u32,
    mss: u16,
    wscale: u8,
    sack: bool,
}

impl TcpData {
    fn new() -> Self {
        Self {
            seq: 0,
            ack: 0,
            local_window: LOCAL_WINDOW,
            remote_window: 0,
            remote_ts: 0,
            mss: 1400,
            wscale: 0,
            sack: false,
        }
    }
}

const MSL_2: u128 = 30000;
const MAX_TCP_HEADER_LEN: usize = 60;
const LOCAL_WINDOW: u32 = 256 * 1024;
const DEFAULT_RTT: u32 = 100;
const MAX_RTO: u32 = 100;
const MIN_RTO: u32 = 1;

struct TcpConnection {
    key: String,
    state: State,
    time: Time,
    addr: Address,
    rto_vars: RtoVars,
    recv_buffer: RecvBuffer,
    send_buffer: SendBuffer,
    tcp_data: TcpData,
    handler: TcpLayerHandler,
}

impl TcpConnection {
    fn new(
        key: &str,
        mac: MacAddr,
        src_mac: MacAddr,
        src_addr: SocketAddrV4,
        dst_addr: SocketAddrV4,
        handler: Box<dyn TcpConnectionHandler>,
    ) -> Self {
        Self {
            key: key.to_string(),
            state: State::Listen,
            time: Time::new(),
            addr: Address::new(mac, src_mac, src_addr, dst_addr),
            rto_vars: RtoVars::new(),
            recv_buffer: RecvBuffer::new(),
            send_buffer: SendBuffer::new(),
            tcp_data: TcpData::new(),
            handler: TcpLayerHandler::new(key, dst_addr, handler),
        }
    }

    fn is_syn_packet(request: &TcpPacket) -> bool {
        request.get_flags() & TcpFlags::SYN != 0
    }

    fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    fn is_timewait_timeout(&self) -> bool {
        self.state == State::TimeWait && (Instant::now() - self.time.alive).as_millis() >= MSL_2
    }

    fn handle_tcp_packet(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        metrics::TCP_TX_BYTES
            .with_label_values(&[&self.key])
            .inc_by(request.payload().len() as u64);

        if request.get_flags() & TcpFlags::RST != 0 {
            trace!(
                "{}[{}]: recv RST, change state to Closed",
                self.key,
                self.state
            );
            self.state = State::Closed;
            return self.handler.handle_reset();
        }

        self.time.alive = Instant::now();

        match self.state {
            State::Listen => self.state_listen(request, tx),
            State::SynRcvd => self.state_syn_rcvd(request, tx),
            State::Estab => self.state_estab(request, tx),
            State::FinWait1 => self.state_fin_wait1(request, tx),
            State::FinWait2 => self.state_fin_wait2(request, tx),
            State::Closing => self.state_closing(request, tx),
            State::TimeWait => self.state_time_wait(request, tx),
            State::CloseWait => self.state_close_wait(request, tx),
            State::LastAck => self.state_last_ack(request, tx),
            State::Closed => {}
        }
    }

    fn handle_output_packet(&mut self, tx: &mut Box<dyn DataLinkSender>, packet: TcpLayerPacket) {
        match packet {
            TcpLayerPacket::Connect(_) => unreachable!(),
            TcpLayerPacket::Established(_) => {
                self.connected(tx);
            }
            TcpLayerPacket::Push((_, data)) => {
                self.push(data, tx);
            }
            TcpLayerPacket::Shutdown(_) => {
                self.shutdown(tx);
            }
            TcpLayerPacket::Close(_) => {
                info!("{}[{}]: close tcp connection", self.key, self.state);
                self.close(tx);
            }
        }
    }

    fn heartbeat(&mut self, tx: &mut Box<dyn DataLinkSender>) -> bool {
        if self.send_buffer.pending.len() < 16 {
            loop {
                if let Some(packet) = self.handler.handle_input_tcp_packet() {
                    self.handle_output_packet(tx, packet);
                } else {
                    break;
                }
            }
        }

        if self.is_closed() {
            return false;
        }

        if self.is_timewait_timeout() {
            trace!(
                "{}[{}]: TimeWait timeout, change state to Closed",
                self.key,
                self.state
            );
            self.state = State::Closed;
            return false;
        }

        self.resend_sending_data(tx);
        self.send_pending_data(tx);
        return true;
    }

    fn connected(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        self.send_tcp_syn_ack_packet(tx);
        self.state = State::SynRcvd;
        trace!(
            "{}[{}]: connected, change state to SynRcvd",
            self.key,
            self.state
        );
    }

    fn push(&mut self, mut data: Vec<u8>, tx: &mut Box<dyn DataLinkSender>) {
        if (self.state != State::Estab && self.state != State::CloseWait)
            || !self.send_buffer.pending.is_empty()
        {
            trace!(
                "{}[{}]: pending data size: {}",
                self.key,
                self.state,
                data.len()
            );
            return self.send_buffer.pending.push_back(PendingData::Data(data));
        }

        let remote_window = self.tcp_data.remote_window as usize;
        if self.send_buffer.size >= remote_window {
            trace!(
                "{}[{}]: pending data size: {}",
                self.key,
                self.state,
                data.len()
            );
            return self.send_buffer.pending.push_back(PendingData::Data(data));
        }

        let size = std::cmp::min(
            remote_window - self.send_buffer.size,
            self.send_buffer.pacing,
        );

        if data.len() <= size {
            trace!(
                "{}[{}]: send data size: {}",
                self.key,
                self.state,
                data.len()
            );
            return self.send_data(tx, data);
        }

        let pending_data = data.split_off(size);

        trace!(
            "{}[{}]: send data size: {}",
            self.key,
            self.state,
            data.len()
        );
        self.send_data(tx, data);

        trace!(
            "{}[{}]: pending data size: {}",
            self.key,
            self.state,
            pending_data.len()
        );
        self.send_buffer
            .pending
            .push_back(PendingData::Data(pending_data));
    }

    fn shutdown(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        if self.state == State::SynRcvd {
            return self.send_buffer.pending.push_back(PendingData::Fin);
        }

        if self.state != State::Estab && self.state != State::CloseWait {
            return error!("{}[{}]: shutdown on error state", self.key, self.state);
        }

        if self.send_buffer.buffer.is_empty() && self.send_buffer.pending.is_empty() {
            return self.send_fin(tx);
        }

        trace!("{}[{}]: pending FIN", self.key, self.state);
        self.send_buffer.pending.push_back(PendingData::Fin);
    }

    fn close(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        self.send_tcp_rst_packet(tx);
        self.state = State::Closed;
    }

    fn state_listen(&mut self, request: &TcpPacket, _tx: &mut Box<dyn DataLinkSender>) {
        if request.get_flags() & TcpFlags::SYN != 0 {
            trace!(
                "{}[{}]: tcp SYN, ISN: {}",
                self.key,
                self.state,
                request.get_sequence()
            );
            self.tcp_data.ack = request.get_sequence() + 1;
            self.update_remote_window(request);

            for opt in request.get_options_iter() {
                match opt.get_number() {
                    TcpOptionNumbers::MSS => {
                        let mut payload = [0u8; 2];
                        payload.copy_from_slice(&opt.payload()[0..2]);
                        self.tcp_data.mss = u16::from_be_bytes(payload);
                        trace!("tcp mss: {}", self.tcp_data.mss);
                    }
                    TcpOptionNumbers::SACK_PERMITTED => {
                        self.tcp_data.sack = true;
                        trace!("tcp sack permitted");
                    }
                    TcpOptionNumbers::WSCALE => {
                        self.tcp_data.wscale = opt.payload()[0];
                        trace!("tcp window scale: {}", self.tcp_data.wscale);

                        self.tcp_data.wscale = std::cmp::min(self.tcp_data.wscale, 14);
                        self.update_remote_window(request);
                        trace!("tcp window size: {}", self.tcp_data.remote_window);
                    }
                    TcpOptionNumbers::TIMESTAMPS => {
                        self.process_remote_timestamp(&opt);
                        trace!("tcp remote ts: {}", self.tcp_data.remote_ts);
                    }
                    TcpOptionNumbers::NOP | TcpOptionNumbers::EOL => {}
                    _ => {
                        trace!("tcp unknown option {}", opt.get_number().0);
                    }
                }
            }

            self.handler.handle_connect();
        }
    }

    fn state_syn_rcvd(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        if request.get_flags() & TcpFlags::SYN != 0 {
            self.send_tcp_syn_ack_packet(tx);
        }

        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.tcp_data.seq + 1 {
                trace!(
                    "{}[{}]: change state to Estab, payload size: {}",
                    self.key,
                    self.state,
                    request.payload().len()
                );
                self.tcp_data.seq += 1;
                self.state = State::Estab;

                self.process_payload(request, tx);
            }
        }
    }

    fn state_estab(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        trace!(
            "{}[{}]: recv packet flags: {:b}, seq: {}, payload size: {}",
            self.key,
            self.state,
            request.get_flags(),
            request.get_sequence(),
            request.payload().len()
        );

        for opt in request.get_options_iter() {
            match opt.get_number() {
                TcpOptionNumbers::TIMESTAMPS => {
                    self.process_remote_timestamp(&opt);
                }
                _ => {}
            }
        }

        self.update_remote_window(request);
        self.process_acknowledgement(request, tx);

        if request.get_flags() & TcpFlags::FIN != 0 {
            if request.get_sequence() == self.tcp_data.ack {
                trace!(
                    "{}[{}]: recv FIN, change state to CloseWait",
                    self.key,
                    self.state
                );
                return self.process_fin(request, tx);
            }
        }

        self.process_payload(request, tx);
    }

    fn state_fin_wait1(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            if request.get_sequence() == self.tcp_data.ack {
                trace!(
                    "{}[{}]: recv FIN, change state to Closing",
                    self.key,
                    self.state
                );
                return self.process_fin(request, tx);
            }
        }

        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.tcp_data.seq + 1 {
                self.state = State::FinWait2;
            }
        }

        self.process_payload(request, tx);
    }

    fn state_fin_wait2(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            if request.get_sequence() == self.tcp_data.ack {
                trace!(
                    "{}[{}]: recv FIN, change state to TimeWait",
                    self.key,
                    self.state
                );
                return self.process_fin(request, tx);
            }
        }

        self.process_payload(request, tx);
    }

    fn state_closing(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            return self.process_fin(request, tx);
        }

        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.tcp_data.seq + 1 {
                trace!(
                    "{}[{}]: recv FIN ack, change state to TimeWait",
                    self.key,
                    self.state
                );
                self.state = State::TimeWait;
            }
        }
    }

    fn state_time_wait(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        if request.get_flags() & TcpFlags::FIN != 0 {
            self.process_fin(request, tx);
        }
    }

    fn state_close_wait(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        self.update_remote_window(request);
        self.process_acknowledgement(request, tx);

        if request.get_flags() & TcpFlags::FIN != 0 {
            self.process_fin(request, tx);
        }
    }

    fn state_last_ack(&mut self, request: &TcpPacket, _tx: &mut Box<dyn DataLinkSender>) {
        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.tcp_data.seq + 1 {
                self.state = State::Closed;
                trace!(
                    "{}[{}]: recv last ACK, change state to Closed",
                    self.key,
                    self.state
                );
            }
        }
    }

    fn send_data(&mut self, tx: &mut Box<dyn DataLinkSender>, data: Vec<u8>) {
        let sending_data = SendingData::new(self.tcp_data.seq, data);
        self.tcp_data.seq += sending_data.data.len() as u32;
        self.send_buffer.size += sending_data.data.len();
        self.send_buffer.pacing -= sending_data.data.len();

        self.send_tcp_data_packet(tx, &sending_data);
        self.send_buffer.buffer.push_back(sending_data);
    }

    fn resend_sending_data(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        let now = Instant::now();
        for index in 0..self.send_buffer.buffer.len() {
            let sending_data = &self.send_buffer.buffer[index];
            if (now - sending_data.send_time).as_millis() < self.rto_vars.rto as u128 {
                break;
            }

            if self.send_buffer.pacing < sending_data.data.len() {
                break;
            }

            self.send_buffer.pacing -= sending_data.data.len();
            self.send_tcp_data_packet(tx, sending_data);
            self.send_buffer.buffer[index].send_time = now;
            trace!(
                "{}[{}]: resend data at seq: {}, len: {}, rto: {}",
                self.key,
                self.state,
                self.send_buffer.buffer[index].seq,
                self.send_buffer.buffer[index].data.len(),
                self.rto_vars.rto
            );
        }
    }

    fn send_pending_data(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        let remote_window = self.tcp_data.remote_window as usize;
        let mut window;

        if remote_window == 0 && self.send_buffer.size == 0 {
            window = 1;
        } else if remote_window > self.send_buffer.size {
            window = remote_window - self.send_buffer.size;
        } else {
            window = 0;
        }

        while !self.send_buffer.pending.is_empty() && self.send_buffer.pacing > 0 && window > 0 {
            let front = self.send_buffer.pending.pop_front().unwrap();

            match front {
                PendingData::Data(mut data) => {
                    let len = data.len();
                    if len <= window {
                        trace!(
                            "{}[{}]: send pending data size: {}",
                            self.key,
                            self.state,
                            data.len()
                        );
                        self.send_data(tx, data);

                        window -= len;
                    } else {
                        let size = std::cmp::min(window, self.send_buffer.pacing);
                        let tail = data.split_off(size);

                        trace!(
                            "{}[{}]: send pending data size: {}",
                            self.key,
                            self.state,
                            data.len()
                        );
                        self.send_data(tx, data);

                        window -= size;
                        self.send_buffer.pending.push_front(PendingData::Data(tail));
                    }
                }
                PendingData::Fin => {
                    if self.send_buffer.buffer.is_empty() {
                        self.send_fin(tx);
                    } else {
                        self.send_buffer.pending.push_front(PendingData::Fin);
                    }
                    break;
                }
            }
        }
    }

    fn send_fin(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        self.send_tcp_fin_packet(tx);

        match self.state {
            State::Estab => self.state = State::FinWait1,
            State::CloseWait => self.state = State::LastAck,
            _ => self.close(tx),
        }
    }

    fn update_remote_window(&mut self, request: &TcpPacket) {
        self.tcp_data.remote_window = request.get_window() as u32;
        self.tcp_data.remote_window <<= self.tcp_data.wscale;
        trace!(
            "{}[{}]: update remote window size: {}",
            self.key,
            self.state,
            self.tcp_data.remote_window
        );
    }

    fn update_rto(&mut self, echo_ts: u32) {
        let rtt = self.timestamp() - echo_ts;
        self.rto_vars.srtt = (self.rto_vars.srtt * 9 + rtt) / 10;

        let delta = if rtt > self.rto_vars.srtt {
            rtt - self.rto_vars.srtt
        } else {
            self.rto_vars.srtt - rtt
        };

        self.rto_vars.rttvar = (self.rto_vars.rttvar * 3 + delta) / 4;
        let rto = self.rto_vars.srtt + 4 * self.rto_vars.rttvar;
        self.rto_vars.rto = std::cmp::min(std::cmp::max(rto, MIN_RTO), MAX_RTO);
    }

    fn timestamp(&self) -> u32 {
        (Instant::now() - self.time.init).as_millis() as u32
    }

    fn add_tcp_option_timestamp(&self, opts: &mut Vec<TcpOption>, opts_size: &mut usize) {
        opts.push(TcpOption::nop());
        opts.push(TcpOption::nop());
        opts.push(TcpOption::timestamp(
            self.timestamp(),
            self.tcp_data.remote_ts,
        ));
        *opts_size += 12;
    }

    fn add_tcp_option_sack(
        &self,
        opts: &mut Vec<TcpOption>,
        opts_size: &mut usize,
        seq_range: Option<(u32, u32)>,
    ) {
        let mut blocks = 3;
        let mut acks = Vec::new();

        if let Some(seq_range) = seq_range {
            if ((self.tcp_data.ack - seq_range.0) as i32) < 0 {
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

    fn send_tcp_syn_ack_packet(&self, tx: &mut Box<dyn DataLinkSender>) {
        let mut opts = Vec::new();
        let mut opts_size = 0;
        let payload = [0u8; 0];

        opts.push(TcpOption::mss(self.tcp_data.mss));
        opts_size += 4;

        opts.push(TcpOption::wscale(self.tcp_data.wscale));
        opts.push(TcpOption::nop());
        opts_size += 4;

        opts.push(TcpOption::nop());
        opts.push(TcpOption::nop());
        opts.push(TcpOption::sack_perm());
        opts_size += 4;

        self.add_tcp_option_timestamp(&mut opts, &mut opts_size);

        self.send_tcp_packet(
            tx,
            self.tcp_data.seq,
            TcpFlags::SYN | TcpFlags::ACK,
            &opts,
            opts_size,
            &payload,
        );
    }

    fn send_tcp_data_packet(&self, tx: &mut Box<dyn DataLinkSender>, data: &SendingData) {
        let mut opts = Vec::new();
        let mut opts_size = 0;

        self.add_tcp_option_timestamp(&mut opts, &mut opts_size);
        self.add_tcp_option_sack(&mut opts, &mut opts_size, None);

        let mut index = 0;
        let mut seq = data.seq;
        let mut len = data.data.len();
        let max_payload_len = self.tcp_data.mss as usize - MAX_TCP_HEADER_LEN;

        while len > 0 {
            let payload_len = std::cmp::min(len, max_payload_len);
            let payload = &data.data[index..index + payload_len];

            self.send_tcp_packet(
                tx,
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

    fn send_tcp_acknowledge_packet(
        &self,
        seq_range: Option<(u32, u32)>,
        tx: &mut Box<dyn DataLinkSender>,
    ) {
        self.send_tcp_control_packet(tx, TcpFlags::ACK, seq_range);
        trace!(
            "{}[{}]: send acknowledge ack: {}",
            self.key,
            self.state,
            self.tcp_data.ack
        );
    }

    fn send_tcp_fin_packet(&self, tx: &mut Box<dyn DataLinkSender>) {
        self.send_tcp_control_packet(tx, TcpFlags::ACK | TcpFlags::FIN, None);
        trace!("{}[{}]: send FIN", self.key, self.state);
    }

    fn send_tcp_rst_packet(&self, tx: &mut Box<dyn DataLinkSender>) {
        self.send_tcp_control_packet(tx, TcpFlags::ACK | TcpFlags::RST, None);
        trace!("{}[{}]: send RST", self.key, self.state);
    }

    fn send_tcp_control_packet(
        &self,
        tx: &mut Box<dyn DataLinkSender>,
        flags: u8,
        seq_range: Option<(u32, u32)>,
    ) {
        let mut opts = Vec::new();
        let mut opts_size = 0;
        let payload = [0u8; 0];

        self.add_tcp_option_timestamp(&mut opts, &mut opts_size);
        self.add_tcp_option_sack(&mut opts, &mut opts_size, seq_range);
        self.send_tcp_packet(tx, self.tcp_data.seq, flags, &opts, opts_size, &payload);
    }

    fn send_tcp_packet(
        &self,
        tx: &mut Box<dyn DataLinkSender>,
        seq: u32,
        flags: u8,
        opts: &[TcpOption],
        opts_size: usize,
        payload: &[u8],
    ) {
        metrics::TCP_RX_BYTES
            .with_label_values(&[&self.key])
            .inc_by(payload.len() as u64);

        trace!(
            "{}:[{}]: send tcp packet {}[{}] -> {}[{}]",
            self.key,
            self.state,
            self.addr.dst_addr,
            self.addr.mac,
            self.addr.src_addr,
            self.addr.src_mac
        );

        let tcp_packet_len = 20 + opts_size + payload.len();
        let ipv4_packet_len = 20 + tcp_packet_len;
        let ethernet_packet_len = 14 + ipv4_packet_len;

        tx.build_and_send(1, ethernet_packet_len, &mut |buffer| {
            let mut ethernet_packet = MutableEthernetPacket::new(buffer).unwrap();
            ethernet_packet.set_destination(self.addr.src_mac);
            ethernet_packet.set_source(self.addr.mac);
            ethernet_packet.set_ethertype(EtherTypes::Ipv4);

            let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
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
            ipv4_packet.set_source(*self.addr.dst_addr.ip());
            ipv4_packet.set_destination(*self.addr.src_addr.ip());

            let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut()).unwrap();
            tcp_packet.set_source(self.addr.dst_addr.port());
            tcp_packet.set_destination(self.addr.src_addr.port());
            tcp_packet.set_sequence(seq);
            tcp_packet.set_acknowledgement(self.tcp_data.ack);
            tcp_packet.set_data_offset(((20 + opts_size) / 4) as u8);
            tcp_packet.set_reserved(0);
            tcp_packet.set_flags(flags);
            tcp_packet.set_window((self.tcp_data.local_window >> self.tcp_data.wscale) as u16);
            tcp_packet.set_checksum(0);
            tcp_packet.set_urgent_ptr(0);
            tcp_packet.set_options(opts);
            tcp_packet.set_payload(payload);
            tcp_packet.set_checksum(tcp::ipv4_checksum(
                &tcp_packet.to_immutable(),
                self.addr.dst_addr.ip(),
                self.addr.src_addr.ip(),
            ));

            ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));
        });
    }

    fn process_remote_timestamp(&mut self, opt: &TcpOptionPacket) {
        let mut payload = [0u8; 4];
        payload.copy_from_slice(&opt.payload()[0..4]);
        self.tcp_data.remote_ts = u32::from_be_bytes(payload);
        trace!(
            "{}[{}]: remote timestamp: {}",
            self.key,
            self.state,
            self.tcp_data.remote_ts
        );
    }

    fn process_echo_timestamp(&mut self, request: &TcpPacket) {
        for opt in request.get_options_iter() {
            if opt.get_number() == TcpOptionNumbers::TIMESTAMPS {
                let mut payload = [0u8; 4];
                payload.copy_from_slice(&opt.payload()[4..8]);

                let echo_ts = u32::from_be_bytes(payload);
                if echo_ts != 0 {
                    self.update_rto(echo_ts);
                }
            }
        }
    }

    fn process_acknowledgement(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        let ack = request.get_acknowledgement();
        let send_buffer_size = self.send_buffer.size;
        trace!("{}[{}]: process ack: {}", self.key, self.state, ack);

        while !self.send_buffer.buffer.is_empty() {
            let front = self.send_buffer.buffer.front_mut().unwrap();
            let begin_seq = front.seq;
            let end_seq = begin_seq + front.data.len() as u32;

            if ((begin_seq - ack) as i32) >= 0 {
                break;
            }

            if ((end_seq - ack) as i32) <= 0 {
                self.send_buffer.size -= front.data.len();
                self.send_buffer.buffer.pop_front();
                continue;
            }

            let len = (ack - begin_seq) as usize;
            front.data.drain(0..len);
            front.seq = ack;
            self.send_buffer.size -= len;
        }

        if send_buffer_size != self.send_buffer.size {
            self.process_echo_timestamp(request);
        }

        self.send_pending_data(tx);
    }

    fn process_payload(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        if request.get_sequence() == (self.tcp_data.ack - 1) {
            trace!(
                "{}[{}]: keep-alive request, payload size: {}",
                self.key,
                self.state,
                request.payload().len()
            );
            if request.payload().len() <= 1 {
                return self.send_tcp_acknowledge_packet(None, tx);
            }
        }

        let payload = request.payload();
        if payload.is_empty() {
            return;
        }

        let seq = request.get_sequence();
        let range = (seq, seq + payload.len() as u32);
        let window = (
            self.tcp_data.ack,
            self.tcp_data.ack + self.tcp_data.local_window,
        );

        let range_left = ((range.0 - window.0) as i32, (range.1 - window.0) as i32);
        let range_right = ((range.0 - window.1) as i32, (range.1 - window.1) as i32);
        if range_left.1 <= 0 || range_right.0 >= 0 {
            warn!(
                "{}[{}]: payload [{}, {}) out of local window [{}, {})",
                self.key, self.state, range.0, range.1, window.0, window.1
            );
            return self.send_tcp_acknowledge_packet(None, tx);
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
                self.key, self.state, window.0, range.0
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
        self.handle_recv_buffer();
        self.send_tcp_acknowledge_packet(Some(seq_range), tx);
    }

    fn process_fin(&mut self, request: &TcpPacket, tx: &mut Box<dyn DataLinkSender>) {
        self.tcp_data.ack = request.get_sequence() + 1;
        self.send_tcp_acknowledge_packet(None, tx);

        match self.state {
            State::Estab | State::CloseWait => self.state = State::CloseWait,
            State::FinWait1 | State::Closing => self.state = State::Closing,
            State::FinWait2 | State::TimeWait => self.state = State::TimeWait,
            _ => {
                error!("{}[{}]: process fin on error state", self.key, self.state);
            }
        }

        self.handler.handle_recv_fin();
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

    fn handle_recv_buffer(&mut self) {
        let mut range = self.recv_buffer.ranges.front().unwrap().clone();
        if self.tcp_data.ack != range.0 {
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

        self.tcp_data.ack = range.1;

        let len = (range.1 - range.0) as usize;
        let data = self.recv_buffer.buffer.drain(0..len).collect();
        self.recv_buffer
            .buffer
            .resize(self.tcp_data.local_window as usize, 0);
        self.handler.handle_recv(data);
    }
}
