use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashSet;
use log::trace;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use tokio::sync::Mutex;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{
    Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};

use crate::gateway::GatewaySender;

pub(super) fn new(
    channel: UnboundedReceiver<Bytes>,
    gw_sender: GatewaySender,
) -> (UdpHandler, UdpBinder) {
    let (new_socket, sockets) = unbounded_channel();
    let (socket_closer, closed_socket) = unbounded_channel();

    let handler = UdpHandler {
        channel,
        gw_sender,
        new_socket,
        socket_closer,
        closed_socket,
        sockets: HashMap::new(),
        stats: StatsSet::new(),
    };

    let binder = UdpBinder {
        stats: handler.stats.clone(),
        sockets,
    };

    (handler, binder)
}

pub(super) struct UdpHandler {
    channel: UnboundedReceiver<Bytes>,
    gw_sender: GatewaySender,
    new_socket: UnboundedSender<UdpSocket>,
    socket_closer: UnboundedSender<SocketAddrV4>,
    closed_socket: UnboundedReceiver<SocketAddrV4>,
    sockets: HashMap<SocketAddrV4, UdpSocketInner>,
    stats: StatsSet,
}

impl UdpHandler {
    pub(super) fn start(mut self) {
        tokio::spawn(async move {
            self.handle_loop().await;
        });
    }

    async fn handle_loop(&mut self) {
        loop {
            tokio::select! {
                Some(addr) = self.closed_socket.recv() => {
                    self.remove_socket(addr);
                }
                Some(packet) = self.channel.recv() => {
                    self.handle_packet(packet);
                }
            }
        }
    }

    fn remove_socket(&mut self, addr: SocketAddrV4) {
        self.sockets.remove(&addr);
        self.stats.set.remove(&addr);
    }

    fn handle_packet(&mut self, packet: Bytes) -> Option<()> {
        let ethernet_packet = EthernetPacket::new(&packet)?;
        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
        let udp_packet = UdpPacket::new(ipv4_packet.payload())?;

        let mac = ethernet_packet.get_source();
        let src = SocketAddrV4::new(ipv4_packet.get_source(), udp_packet.get_source());
        let dst = SocketAddrV4::new(ipv4_packet.get_destination(), udp_packet.get_destination());

        let data = packet.slice_ref(udp_packet.payload());

        match self.sockets.get(&src) {
            Some(inner) => inner.try_input_packet(data, dst).ok()?,
            None => {
                let (packets_tx, packets_rx) = channel(32);

                let socket = UdpSocket {
                    source_mac: mac,
                    source_addr: src,
                    gw_sender: self.gw_sender.clone(),
                    packets: Mutex::new(packets_rx),
                    socket_closer: self.socket_closer.clone(),
                };

                let inner = UdpSocketInner {
                    packets: packets_tx,
                };

                inner.try_input_packet(data, dst).ok()?;
                self.sockets.insert(src, inner);
                self.stats.set.insert(src);
                self.new_socket.send(socket).ok()?;
            }
        }

        Some(())
    }
}

#[derive(Clone, Default)]
pub struct StatsSet {
    set: Arc<DashSet<SocketAddrV4>>,
}

impl StatsSet {
    fn new() -> Self {
        Self::default()
    }

    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&SocketAddrV4),
    {
        for item in self.set.iter() {
            f(item.key());
        }
    }
}

pub struct UdpBinder {
    stats: StatsSet,
    sockets: UnboundedReceiver<UdpSocket>,
}

impl UdpBinder {
    pub async fn accept(&mut self) -> std::io::Result<UdpSocket> {
        self.sockets.recv().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "UDP handler broken",
        ))
    }

    pub fn get_stats(&self) -> StatsSet {
        self.stats.clone()
    }
}

pub struct UdpSocket {
    source_mac: MacAddr,
    source_addr: SocketAddrV4,
    gw_sender: GatewaySender,
    packets: Mutex<Receiver<(Bytes, SocketAddrV4)>>,
    socket_closer: UnboundedSender<SocketAddrV4>,
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.socket_closer.send(self.source_addr).ok();
    }
}

impl UdpSocket {
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddrV4)> {
        let mut packets = self.packets.lock().await;
        let (data, dst) = packets.recv().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "socket has been closed",
        ))?;

        trace!("{} send data({}) to {}", self.source_addr, data.len(), dst);

        let size = data.len().min(buf.len());
        buf[..size].copy_from_slice(&data[..size]);
        Ok((size, dst))
    }

    pub fn try_send(&self, buf: &[u8], from: SocketAddrV4) -> std::io::Result<()> {
        trace!(
            "{} recv data({}) from {}",
            self.source_addr,
            buf.len(),
            from
        );

        let udp_packet_len = 8 + buf.len();
        let ipv4_packet_len = 20 + udp_packet_len;
        let ethernet_packet_len = 14 + ipv4_packet_len;

        self.gw_sender
            .build_and_send(1, ethernet_packet_len, &mut |buffer| {
                let mut ethernet_packet = MutableEthernetPacket::new(buffer).unwrap();
                ethernet_packet.set_destination(self.source_mac);
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
                ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                ipv4_packet.set_checksum(0);
                ipv4_packet.set_source(*from.ip());
                ipv4_packet.set_destination(*self.source_addr.ip());

                let mut udp_packet = MutableUdpPacket::new(ipv4_packet.payload_mut()).unwrap();
                udp_packet.set_source(from.port());
                udp_packet.set_destination(self.source_addr.port());
                udp_packet.set_length(udp_packet_len as u16);
                udp_packet.set_checksum(0);
                udp_packet.set_payload(buf);
                udp_packet.set_checksum(udp::ipv4_checksum(
                    &udp_packet.to_immutable(),
                    from.ip(),
                    self.source_addr.ip(),
                ));

                ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));
            });

        Ok(())
    }

    pub fn source_addr(&self) -> SocketAddrV4 {
        self.source_addr
    }
}

struct UdpSocketInner {
    packets: Sender<(Bytes, SocketAddrV4)>,
}

impl UdpSocketInner {
    fn try_input_packet(&self, packet: Bytes, dst: SocketAddrV4) -> std::io::Result<()> {
        self.packets
            .try_send((packet, dst))
            .map_err(|error| match error {
                TrySendError::Full(_) => std::io::Error::new(std::io::ErrorKind::WouldBlock, error),
                TrySendError::Closed(_) => {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, error)
                }
            })
    }
}
