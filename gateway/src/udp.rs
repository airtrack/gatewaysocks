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

use crate::GatewaySender;

/// Creates a new UDP handler and binder pair.
///
/// The handler processes incoming UDP packets and manages socket lifecycle,
/// while the binder provides an interface for accepting new UDP sockets.
///
/// # Arguments
///
/// * `channel` - Receiver for incoming UDP packets from the gateway
/// * `gw_sender` - Gateway sender for outgoing packets
///
/// # Returns
///
/// A tuple containing (UdpHandler, UdpBinder)
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

/// UDP packet handler that processes incoming packets and manages sockets.
///
/// Routes UDP packets to existing sockets or creates new sockets for
/// new connections. Handles socket lifecycle and cleanup.
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
    /// Starts the UDP handler in a background task.
    pub(super) fn start(mut self) {
        tokio::spawn(async move {
            self.handle_loop().await;
        });
    }

    /// Main event loop that processes packets and socket events.
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

    /// Removes a closed socket from the active sockets map.
    fn remove_socket(&mut self, addr: SocketAddrV4) {
        self.sockets.remove(&addr);
        self.stats.set.remove(&addr);
    }

    /// Processes an incoming UDP packet.
    ///
    /// Routes the packet to existing sockets or creates new sockets for
    /// new connections. Parses the complete packet stack from Ethernet
    /// through UDP layers.
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

/// Thread-safe set for tracking active UDP socket addresses.
///
/// Provides concurrent access to the set of active UDP sockets
/// for statistics and monitoring purposes.
#[derive(Clone, Default)]
pub struct StatsSet {
    set: Arc<DashSet<SocketAddrV4>>,
}

impl StatsSet {
    /// Creates a new empty statistics set.
    #[inline]
    fn new() -> Self {
        Self::default()
    }

    /// Iterates over all active socket addresses, calling the provided function.
    ///
    /// # Arguments
    ///
    /// * `f` - Function to call for each active socket address
    #[inline]
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&SocketAddrV4),
    {
        for item in self.set.iter() {
            f(item.key());
        }
    }
}

/// UDP socket binder for accepting incoming UDP connections.
///
/// Provides an interface for applications to accept new UDP sockets
/// and access connection statistics.
pub struct UdpBinder {
    stats: StatsSet,
    sockets: UnboundedReceiver<UdpSocket>,
}

impl UdpBinder {
    /// Accepts the next incoming UDP socket.
    ///
    /// This method waits for a new UDP socket to be created by the handler
    /// and returns it for application use.
    pub async fn accept(&mut self) -> std::io::Result<UdpSocket> {
        self.sockets.recv().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "UDP handler broken",
        ))
    }

    /// Returns a clone of the current socket statistics set.
    pub fn get_stats(&self) -> StatsSet {
        self.stats.clone()
    }
}

/// UDP socket for bidirectional communication.
///
/// Represents a single UDP connection endpoint that can send and receive
/// UDP datagrams. Handles packet construction and transmission at the
/// network layer.
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
    /// Receives a UDP datagram from the socket.
    ///
    /// Waits for an incoming packet and copies it into the provided buffer.
    /// Returns the number of bytes received and the destination address.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to store received data
    ///
    /// # Returns
    ///
    /// Tuple of (bytes_received, destination_address)
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

    /// Sends a UDP datagram through the socket.
    ///
    /// Constructs a complete network packet (Ethernet + IPv4 + UDP) and
    /// transmits it through the gateway sender. Handles all protocol
    /// stack construction and checksum calculation.
    ///
    /// # Arguments
    ///
    /// * `buf` - Data to send
    /// * `from` - Source address for the packet (where it appears to come from)
    pub fn try_send(&self, buf: &[u8], from: SocketAddrV4) -> std::io::Result<()> {
        trace!(
            "{} recv data({}) from {}",
            self.source_addr,
            buf.len(),
            from
        );

        // Calculate packet sizes: UDP header (8) + payload
        let udp_packet_len = 8 + buf.len();
        // IPv4 header (20) + UDP packet
        let ipv4_packet_len = 20 + udp_packet_len;
        // Ethernet header (14) + IPv4 packet
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

    /// Returns the source address of this UDP socket.
    pub fn source_addr(&self) -> SocketAddrV4 {
        self.source_addr
    }
}

/// Internal UDP socket state for packet queuing.
///
/// Handles the channel communication between the UDP handler
/// and individual socket instances.
struct UdpSocketInner {
    /// Channel for sending packets to the socket
    packets: Sender<(Bytes, SocketAddrV4)>,
}

impl UdpSocketInner {
    /// Attempts to queue an incoming packet for the socket.
    ///
    /// # Arguments
    ///
    /// * `packet` - Packet data to queue
    /// * `dst` - Destination address of the packet
    ///
    /// # Errors
    ///
    /// Returns `WouldBlock` if the queue is full or `BrokenPipe` if closed
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
