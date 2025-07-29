use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use pnet::datalink::{self, DataLinkReceiver};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::mpsc::UnboundedSender;

pub use tcp::TcpListener;
pub use tcp::TcpStream;
pub use udp::UdpBinder;
pub use udp::UdpSocket;

mod arp;
mod tcp;
mod udp;

pub fn new_gateway(
    addr: Ipv4Addr,
    mask: Ipv4Addr,
    iface_name: &str,
) -> std::io::Result<(UdpBinder, TcpListener)> {
    let interface = datalink::interfaces()
        .into_iter()
        .filter(|iface| {
            if !iface_name.is_empty() {
                iface_name == iface.name
            } else {
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
    let (udp_handler, udp_binder) = udp::new_udp(udp_rx, gw_sender.clone());
    let (tcp_handler, tcp_listener) = tcp::new_tcp(tcp_rx, gw_sender);

    gw_receiver.start();
    arp_handler.start();
    udp_handler.start();
    tcp_handler.start();

    Ok((udp_binder, tcp_listener))
}

#[derive(Clone, Copy)]
struct GatewayInfo {
    mac: MacAddr,
    addr: Ipv4Addr,
    mask: Ipv4Addr,
}

impl GatewayInfo {
    fn in_subnet(&self, source: Ipv4Addr) -> bool {
        is_to_gateway(self.addr, self.mask, source)
    }
}

#[derive(Clone)]
struct GatewaySender {
    info: GatewayInfo,
    datalink_tx: Arc<Mutex<Box<dyn datalink::DataLinkSender>>>,
}

impl GatewaySender {
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

struct GatewayReceiver {
    info: GatewayInfo,
    datalink_rx: Box<dyn DataLinkReceiver>,
    arp_channel: UnboundedSender<Bytes>,
    udp_channel: UnboundedSender<Bytes>,
    tcp_channel: UnboundedSender<Bytes>,
}

impl GatewayReceiver {
    fn start(mut self) {
        std::thread::spawn(move || {
            self.recv();
        });
    }

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
                                    if !self.info.in_subnet(ipv4_packet.get_source()) {
                                        continue;
                                    }

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

    fn handle_arp(&self, data: Bytes) {
        self.arp_channel.send(data).unwrap();
    }

    fn handle_udp(&self, data: Bytes) {
        self.udp_channel.send(data).unwrap();
    }

    fn handle_tcp(&self, data: Bytes) {
        self.tcp_channel.send(data).unwrap();
    }
}

fn is_to_gateway(gateway: Ipv4Addr, subnet_mask: Ipv4Addr, source: Ipv4Addr) -> bool {
    source != gateway && is_same_subnet(source, gateway, subnet_mask)
}

fn is_same_subnet(addr1: Ipv4Addr, addr2: Ipv4Addr, subnet_mask: Ipv4Addr) -> bool {
    let mask = subnet_mask.octets();
    let a1 = addr1.octets();
    let a2 = addr2.octets();
    (a1[0] & mask[0] == a2[0] & mask[0])
        && (a1[1] & mask[1] == a2[1] & mask[1])
        && (a1[2] & mask[2] == a2[2] & mask[2])
        && (a1[3] & mask[3] == a2[3] & mask[3])
}
