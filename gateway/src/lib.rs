//! Network gateway module for intercepting and processing network packets.
//!
//! This module implements a network gateway that captures packets at the data link layer,
//! processes them based on protocol type (ARP, UDP, TCP), and provides application-level
//! interfaces for network communication. It acts as a bridge between raw network packets
//! and high-level async I/O abstractions.
//!
//! # Architecture
//!
//! - `GatewayReceiver`: Captures raw packets and routes them to protocol handlers
//! - `GatewaySender`: Sends packets back to the network interface
//! - Protocol handlers: ARP, UDP, and TCP processing modules
//! - Application interfaces: `UdpBinder`, `TcpListener` for async I/O

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use pnet::datalink::{self, DataLinkReceiver};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::util::MacAddr;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::mpsc::unbounded_channel;

pub use tcp::TcpListener;
pub use tcp::TcpStream;
pub use udp::UdpBinder;
pub use udp::UdpSocket;

mod arp;
pub mod tcp;
pub mod udp;

/// Creates a new network gateway on the specified interface.
///
/// This function sets up a complete network stack including packet capture,
/// protocol processing, and application-level interfaces for UDP and TCP.
///
/// # Arguments
///
/// * `addr` - Gateway IPv4 address
/// * `mask` - Subnet mask for determining local network
/// * `iface_name` - Network interface name (empty string for auto-detection)
///
/// # Returns
///
/// A tuple containing (UdpBinder, TcpListener) for application use
///
/// # Errors
///
/// Returns error if:
/// - Network interface not found or unavailable
/// - MAC address not available
/// - Interface is not Ethernet-compatible
pub fn new(
    addr: Ipv4Addr,
    mask: Ipv4Addr,
    iface_name: &str,
) -> std::io::Result<(UdpBinder, TcpListener)> {
    // Find suitable network interface by name or auto-detect
    let interface = datalink::interfaces()
        .into_iter()
        .filter(|iface| {
            if !iface_name.is_empty() {
                // Use specific interface if name provided
                iface_name == iface.name
            } else {
                // Auto-detect: non-loopback, has MAC, has IPv4
                !iface.is_loopback()
                    && iface.mac.is_some()
                    && !iface.mac.as_ref().unwrap().is_zero()
                    && !iface.ips.is_empty()
                    && iface.ips.as_slice().into_iter().any(|ip| ip.is_ipv4())
            }
        })
        .next()
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find local network interface.",
        ))?;
    let mac = interface.mac.ok_or(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "mac address not available",
    ))?;

    let config = datalink::Config::default();
    let datalink::Channel::Ethernet(datalink_tx, datalink_rx) =
        datalink::channel(&interface, config)?
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "not ethernet interface",
        ));
    };

    let (arp_tx, arp_rx) = unbounded_channel();
    let (udp_tx, udp_rx) = unbounded_channel();
    let (tcp_tx, tcp_rx) = unbounded_channel();

    let info = GatewayInfo { mac, addr, mask };
    let gw_sender = GatewaySender {
        info,
        datalink_tx: Arc::new(Mutex::new(datalink_tx)),
    };
    let gw_receiver = GatewayReceiver {
        info,
        datalink_rx,
        arp_channel: arp_tx,
        udp_channel: udp_tx,
        tcp_channel: tcp_tx,
    };

    let arp_handler = arp::new_arp(arp_rx, gw_sender.clone());
    let (udp_handler, udp_binder) = udp::new(udp_rx, gw_sender.clone());
    let (tcp_handler, tcp_listener) = tcp::new(tcp_rx, gw_sender);

    gw_receiver.start();
    arp_handler.start();
    udp_handler.start();
    tcp_handler.start();

    Ok((udp_binder, tcp_listener))
}

/// Gateway configuration information shared across components.
#[derive(Clone, Copy)]
struct GatewayInfo {
    /// MAC address of the gateway interface
    mac: MacAddr,
    /// IPv4 address of the gateway
    addr: Ipv4Addr,
    /// Subnet mask for determining local network scope
    mask: Ipv4Addr,
}

impl GatewayInfo {
    /// Checks if the source address is within the gateway's subnet.
    ///
    /// Used to filter packets that should be processed by this gateway.
    fn in_subnet(&self, source: Ipv4Addr) -> bool {
        is_to_gateway(self.addr, self.mask, source)
    }
}

/// Thread-safe packet sender for transmitting packets to the network interface.
#[derive(Clone)]
struct GatewaySender {
    info: GatewayInfo,
    /// Data link layer transmitter (thread-safe)
    datalink_tx: Arc<Mutex<Box<dyn datalink::DataLinkSender>>>,
}

impl GatewaySender {
    /// Builds and sends packets using the provided construction function.
    ///
    /// # Arguments
    ///
    /// * `num_packets` - Number of packets to send
    /// * `packet_size` - Size of each packet in bytes
    /// * `func` - Function to construct packet data
    fn build_and_send(
        &self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) {
        self.datalink_tx
            .lock()
            .unwrap()
            .as_mut()
            .build_and_send(num_packets, packet_size, func);
    }
}

/// Packet receiver that captures and routes network packets to protocol handlers.
struct GatewayReceiver {
    info: GatewayInfo,
    /// Data link layer receiver for capturing packets
    datalink_rx: Box<dyn DataLinkReceiver>,
    /// Channel for sending ARP packets to ARP handler
    arp_channel: UnboundedSender<Bytes>,
    /// Channel for sending UDP packets to UDP handler
    udp_channel: UnboundedSender<Bytes>,
    /// Channel for sending TCP packets to TCP handler
    tcp_channel: UnboundedSender<Bytes>,
}

impl GatewayReceiver {
    /// Starts the packet receiver in a background thread.
    fn start(mut self) {
        std::thread::spawn(move || {
            self.recv();
        });
    }

    /// Main packet reception loop that processes incoming packets.
    ///
    /// Continuously captures packets, parses them, and routes them to
    /// appropriate protocol handlers based on packet type.
    fn recv(&mut self) {
        loop {
            match self.datalink_rx.next() {
                Ok(packet) => {
                    let data = Bytes::copy_from_slice(packet);

                    if let Some(ethernet_packet) = EthernetPacket::new(&data) {
                        match ethernet_packet.get_ethertype() {
                            EtherTypes::Ipv4 => {
                                if let Some(ipv4_packet) =
                                    Ipv4Packet::new(ethernet_packet.payload())
                                {
                                    // Only process packets from our subnet
                                    if !self.info.in_subnet(ipv4_packet.get_source()) {
                                        continue;
                                    }

                                    // Route based on IP protocol
                                    match ipv4_packet.get_next_level_protocol() {
                                        IpNextHeaderProtocols::Udp => self.handle_udp(data),
                                        IpNextHeaderProtocols::Tcp => self.handle_tcp(data),
                                        _ => {}
                                    }
                                }
                            }
                            EtherTypes::Arp => self.handle_arp(data),
                            _ => {}
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    /// Routes ARP packets to the ARP handler.
    fn handle_arp(&self, data: Bytes) {
        self.arp_channel.send(data).unwrap();
    }

    /// Routes UDP packets to the UDP handler.
    fn handle_udp(&self, data: Bytes) {
        self.udp_channel.send(data).unwrap();
    }

    /// Routes TCP packets to the TCP handler.
    fn handle_tcp(&self, data: Bytes) {
        self.tcp_channel.send(data).unwrap();
    }
}

/// Determines if a packet from the source should be processed by the gateway.
///
/// Returns true if the source is in the same subnet as the gateway but is not
/// the gateway itself (to avoid processing our own packets).
#[inline]
fn is_to_gateway(gateway: Ipv4Addr, subnet_mask: Ipv4Addr, source: Ipv4Addr) -> bool {
    source != gateway && is_same_subnet(source, gateway, subnet_mask)
}

/// Checks if two IPv4 addresses are in the same subnet.
///
/// Applies the subnet mask to both addresses and compares the results.
/// Returns true if both addresses have the same network portion.
#[inline]
fn is_same_subnet(addr1: Ipv4Addr, addr2: Ipv4Addr, subnet_mask: Ipv4Addr) -> bool {
    let mask = subnet_mask.to_bits();
    let a1 = addr1.to_bits();
    let a2 = addr2.to_bits();
    a1 & mask == a2 & mask
}
