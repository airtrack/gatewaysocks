use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Instant;

use log::info;
use pnet::datalink::DataLinkSender;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumbers, TcpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use super::is_to_gateway;

pub struct TcpProcessor {
    mac: MacAddr,
    gateway: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    connections: HashMap<String, Connection>,
}

pub enum TcpLayerPacket {
    Connect((String, SocketAddrV4)),
    Established(String),
    Push((String, Vec<u8>)),
    Shutdown(String),
    Close(String),
}

impl TcpProcessor {
    pub fn new(mac: MacAddr, gateway: Ipv4Addr, subnet_mask: Ipv4Addr) -> Self {
        Self {
            mac: mac,
            gateway,
            subnet_mask,
            connections: HashMap::new(),
        }
    }

    pub fn heartbeat(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        for (_, connection) in self.connections.iter_mut() {
            connection.heartbeat(tx);
        }
    }

    pub fn handle_input_packet(
        &mut self,
        tx: &mut Box<dyn DataLinkSender>,
        source_mac: MacAddr,
        request: &Ipv4Packet,
    ) -> Option<TcpLayerPacket> {
        if !is_to_gateway(self.gateway, self.subnet_mask, request.get_source()) {
            return None;
        }

        info!(
            "TCP packet {} -> {}",
            request.get_source(),
            request.get_destination()
        );

        if let Some(tcp_request) = TcpPacket::new(request.payload()) {
            let src = SocketAddrV4::new(request.get_source(), tcp_request.get_source());
            let dst = SocketAddrV4::new(request.get_destination(), tcp_request.get_destination());
            let key = src.to_string() + "|" + &dst.to_string();

            if let Some(connection) = self.connections.get_mut(&key) {
                return connection.handle_tcp_packet(&tcp_request, tx);
            }

            let mut connection = Connection::new(key.clone(), self.mac, source_mac, src, dst);
            let result = connection.handle_tcp_packet(&tcp_request, tx);

            self.connections.insert(key, connection);
            return result;
        }

        None
    }

    pub fn handle_output_packet(
        &mut self,
        tx: &mut Box<dyn DataLinkSender>,
        packet: TcpLayerPacket,
    ) {
        match packet {
            TcpLayerPacket::Connect(_) => unreachable!(),
            TcpLayerPacket::Established(key) => {
                if let Some(connection) = self.connections.get_mut(&key) {
                    connection.connected(tx);
                }
            }
            TcpLayerPacket::Push((key, data)) => {
                if let Some(connection) = self.connections.get_mut(&key) {
                    connection.push(data, tx);
                }
            }
            TcpLayerPacket::Shutdown(key) => {
                if let Some(connection) = self.connections.get_mut(&key) {
                    connection.shutdown(tx);
                }
            }
            TcpLayerPacket::Close(key) => {
                if let Some(connection) = self.connections.get_mut(&key) {
                    connection.close(tx);
                    self.connections.remove(&key);
                }
            }
        }
    }
}

struct LayerHandler {
    key: String,
    dst_addr: SocketAddrV4,
    connect: bool,
}

impl LayerHandler {
    fn new(key: String, dst_addr: SocketAddrV4) -> Self {
        Self {
            key,
            dst_addr,
            connect: false,
        }
    }

    fn handle_connect(&mut self) -> Option<TcpLayerPacket> {
        if self.connect {
            return None;
        }

        self.connect = true;
        Some(TcpLayerPacket::Connect((self.key.clone(), self.dst_addr)))
    }
}

enum State {
    Listen,
    SynRcvd,
    Estab,
    _FinWait1,
    _FinWait2,
    _Closing,
    _TimeWait,
    _CloseWait,
    _LastAck,
}

const LOCAL_WINDOW: u32 = 2 * 1024 * 1024;

struct Connection {
    handler: LayerHandler,

    key: String,
    state: State,
    init_time: Instant,

    mac: MacAddr,
    src_mac: MacAddr,
    src_addr: SocketAddrV4,
    dst_addr: SocketAddrV4,

    seq: u32,
    ack: u32,
    local_window: u32,
    remote_window: u32,

    mss: u16,
    sack: bool,
    wscale: u8,
    remote_ts: u32,
}

impl Connection {
    fn new(
        key: String,
        mac: MacAddr,
        src_mac: MacAddr,
        src_addr: SocketAddrV4,
        dst_addr: SocketAddrV4,
    ) -> Self {
        Self {
            handler: LayerHandler::new(key.clone(), dst_addr),
            key,
            state: State::Listen,
            init_time: Instant::now(),
            mac,
            src_mac,
            src_addr,
            dst_addr,
            seq: 0,
            ack: 0,
            local_window: LOCAL_WINDOW,
            remote_window: 0,
            mss: 1400,
            sack: false,
            wscale: 0,
            remote_ts: 0,
        }
    }

    fn handle_tcp_packet(
        &mut self,
        request: &TcpPacket,
        tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        match self.state {
            State::Listen => self.state_listen(request, tx),
            State::SynRcvd => self.state_syn_rcvd(request, tx),
            State::Estab => self.state_estab(request, tx),
            State::_FinWait1 => self.state_fin_wait1(request, tx),
            State::_FinWait2 => self.state_fin_wait2(request, tx),
            State::_Closing => self.state_closing(request, tx),
            State::_TimeWait => self.state_time_wait(request, tx),
            State::_CloseWait => self.state_close_wait(request, tx),
            State::_LastAck => self.state_last_ack(request, tx),
        }
    }

    fn heartbeat(&mut self, _tx: &mut Box<dyn DataLinkSender>) {}

    fn connected(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        info!("{}: connected, change state to SynRcvd", self.key);
        let mut opts = Vec::new();
        let mut opts_size = 0;
        let payload = [0u8; 0];

        opts.push(TcpOption::mss(self.mss));
        opts_size = opts_size + 4;

        opts.push(TcpOption::wscale(self.wscale));
        opts.push(TcpOption::nop());
        opts_size = opts_size + 4;

        opts.push(TcpOption::sack_perm());
        opts_size = opts_size + 2;

        opts.push(TcpOption::timestamp(self.timestamp(), self.remote_ts));
        opts_size = opts_size + 10;

        self.send_tcp_packet(
            tx,
            TcpFlags::SYN | TcpFlags::ACK,
            &opts,
            opts_size,
            &payload,
        );
        self.seq = self.seq + 1;
        self.state = State::SynRcvd;
    }

    fn push(&mut self, _data: Vec<u8>, _tx: &mut Box<dyn DataLinkSender>) {}

    fn shutdown(&mut self, _tx: &mut Box<dyn DataLinkSender>) {}

    fn close(&mut self, _tx: &mut Box<dyn DataLinkSender>) {}

    fn state_listen(
        &mut self,
        request: &TcpPacket,
        _tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        if request.get_flags() & TcpFlags::SYN != 0 {
            info!("{}: tcp SYN", self.key);
            self.ack = request.get_sequence() + 1;
            self.remote_window = request.get_window() as u32;

            for opt in request.get_options_iter() {
                match opt.get_number() {
                    TcpOptionNumbers::MSS => {
                        let mut payload = [0u8; 2];
                        payload.copy_from_slice(&opt.payload()[0..2]);
                        self.mss = u16::from_be_bytes(payload);
                        info!("tcp mss: {}", self.mss);
                    }
                    TcpOptionNumbers::SACK_PERMITTED => {
                        self.sack = true;
                        info!("tcp sack permitted");
                    }
                    TcpOptionNumbers::WSCALE => {
                        self.wscale = opt.payload()[0];
                        info!("tcp window scale: {}", self.wscale);

                        self.wscale = std::cmp::min(self.wscale, 14);
                        self.remote_window = self.remote_window << self.wscale;
                        info!("tcp window size: {}", self.remote_window);
                    }
                    TcpOptionNumbers::TIMESTAMPS => {
                        let mut payload = [0u8; 4];
                        payload.copy_from_slice(&opt.payload()[0..4]);
                        self.remote_ts = u32::from_be_bytes(payload);
                        info!("tcp remote ts: {}", self.remote_ts);
                    }
                    TcpOptionNumbers::NOP | TcpOptionNumbers::EOL => {}
                    _ => {
                        info!("tcp unknown option {}", opt.get_number().0);
                    }
                }
            }

            return self.handler.handle_connect();
        }

        None
    }

    fn state_syn_rcvd(
        &mut self,
        request: &TcpPacket,
        _tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        if request.get_flags() & TcpFlags::ACK != 0 {
            if request.get_acknowledgement() == self.seq {
                info!(
                    "{}: change state to Estab, payload size: {}",
                    self.key,
                    request.payload().len()
                );
                self.state = State::Estab;
            }
        }

        None
    }

    fn state_estab(
        &mut self,
        request: &TcpPacket,
        _tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        info!(
            "{}: recv packet at state Estab, flags: {:b}, payload size: {}",
            self.key,
            request.get_flags(),
            request.payload().len()
        );
        None
    }

    fn state_fin_wait1(
        &mut self,
        _request: &TcpPacket,
        _tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        None
    }

    fn state_fin_wait2(
        &mut self,
        _request: &TcpPacket,
        _tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        None
    }

    fn state_closing(
        &mut self,
        _request: &TcpPacket,
        _tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        None
    }

    fn state_time_wait(
        &mut self,
        _request: &TcpPacket,
        _tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        None
    }

    fn state_close_wait(
        &mut self,
        _request: &TcpPacket,
        _tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        None
    }

    fn state_last_ack(
        &mut self,
        _request: &TcpPacket,
        _tx: &mut Box<dyn DataLinkSender>,
    ) -> Option<TcpLayerPacket> {
        None
    }

    fn timestamp(&self) -> u32 {
        (Instant::now() - self.init_time).as_millis() as u32
    }

    fn send_tcp_packet(
        &self,
        tx: &mut Box<dyn DataLinkSender>,
        flags: u16,
        opts: &[TcpOption],
        opts_size: usize,
        payload: &[u8],
    ) {
        let tcp_packet_len = 20 + opts_size + payload.len();
        let mut tcp_buffer = vec![0u8; tcp_packet_len];
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();

        tcp_packet.set_source(self.dst_addr.port());
        tcp_packet.set_destination(self.src_addr.port());
        tcp_packet.set_sequence(self.seq);
        tcp_packet.set_acknowledgement(self.ack);
        tcp_packet.set_data_offset(((20 + opts_size) / 4) as u8);
        tcp_packet.set_reserved(0);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window((self.local_window >> self.wscale) as u16);
        tcp_packet.set_checksum(0);
        tcp_packet.set_urgent_ptr(0);
        tcp_packet.set_options(opts);
        tcp_packet.set_payload(payload);

        tcp_packet.set_checksum(tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            self.dst_addr.ip(),
            self.src_addr.ip(),
        ));

        let ipv4_packet_len = 20 + tcp_packet_len;
        let mut ipv4_buffer = vec![0u8; ipv4_packet_len];
        let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();

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
        ipv4_packet.set_source(*self.dst_addr.ip());
        ipv4_packet.set_destination(*self.src_addr.ip());
        ipv4_packet.set_payload(tcp_packet.packet());

        ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

        let ethernet_packet_len = 14 + ipv4_packet_len;
        let mut ethernet_buffer = vec![0u8; ethernet_packet_len];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        ethernet_packet.set_destination(self.src_mac);
        ethernet_packet.set_source(self.mac);
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
        ethernet_packet.set_payload(ipv4_packet.packet());

        tx.send_to(ethernet_packet.packet(), None);
    }
}
