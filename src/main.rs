use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use pnet::datalink::{self, Config, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use tokio::runtime::Runtime;
use tokio::sync::mpsc::error::TryRecvError;

use gatewaysocks::gateway::arp::ArpHandler;
use gatewaysocks::gateway::udp::{UdpLayerPacket, UdpProcessor};
use gatewaysocks::socks5::udp::UdpSocks5;
use gatewaysocks::socks5::{socks_channel, SocksChannel, SocksData};

fn socks5_main(socks5: SocketAddr, udp_channel: SocksChannel) {
    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let mut udp_socks5 = UdpSocks5::new(socks5, udp_channel);
        udp_socks5.run().await;
    });
}

fn start_socks5(socks5: SocketAddr, udp_channel: SocksChannel) {
    thread::spawn(move || {
        socks5_main(socks5, udp_channel);
    });
}

fn handle_udp_from_ethernet(
    udp_processor: &mut UdpProcessor,
    udp_channel: &SocksChannel,
    ethernet_packet: &EthernetPacket,
    ipv4_packet: &Ipv4Packet,
) {
    let udp_data = udp_processor.handle_input_packet(ethernet_packet.get_source(), ipv4_packet);

    if let Some(data) = udp_data {
        let _ = udp_channel.tx.send(SocksData {
            key: data.key,
            data: data.data,
            addr: data.addr,
        });
    }
}

fn handle_udp_from_socks5(
    udp_processor: &UdpProcessor,
    udp_channel: &mut SocksChannel,
    tx: &mut Box<dyn DataLinkSender>,
) {
    loop {
        match udp_channel.rx.try_recv() {
            Ok(data) => {
                let udp_data = UdpLayerPacket {
                    key: data.key,
                    data: data.data,
                    addr: data.addr,
                };
                udp_processor.handle_output_packet(tx, &udp_data);
            }
            Err(TryRecvError::Empty) => break,
            Err(_) => {}
        }
    }
}

fn gateway_main(
    mac: MacAddr,
    gateway: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    interface: &NetworkInterface,
    mut udp_channel: SocksChannel,
) {
    let config = Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(Duration::from_millis(10)),
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };

    let (mut tx, mut rx) = match datalink::channel(interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    let arp_handler = ArpHandler::new(mac, gateway);
    let mut udp_processor = UdpProcessor::new(mac, gateway, subnet_mask);

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                match ethernet_packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                            match ipv4_packet.get_next_level_protocol() {
                                IpNextHeaderProtocols::Udp => {
                                    handle_udp_from_ethernet(
                                        &mut udp_processor,
                                        &udp_channel,
                                        &ethernet_packet,
                                        &ipv4_packet,
                                    );
                                }
                                IpNextHeaderProtocols::Tcp => {
                                    println!("tcp packet");
                                }
                                _ => {}
                            }
                        }
                    }
                    EtherTypes::Arp => arp_handler.handle_packet(&mut tx, &ethernet_packet),
                    _ => {}
                }
            }
            Err(_) => {}
        }

        handle_udp_from_socks5(&udp_processor, &mut udp_channel, &mut tx);
    }
}

fn main() {
    let socks5 = "127.0.0.1:1080".parse::<SocketAddr>().unwrap();
    let gateway = "10.6.0.1".parse::<Ipv4Addr>().unwrap();
    let subnet_mask = "255.255.255.0".parse::<Ipv4Addr>().unwrap();
    let interface = datalink::interfaces()
        .into_iter()
        .filter(|iface| {
            !iface.is_loopback()
                && iface.mac.is_some()
                && !iface.mac.as_ref().unwrap().is_zero()
                && !iface.ips.is_empty()
                && iface.ips.as_slice().into_iter().any(|ip| ip.is_ipv4())
        })
        .next()
        .unwrap_or_else(|| panic!("Could not find local network interface."));
    let mac = interface.mac.unwrap();

    let (udp_channel, channel_udp) = socks_channel();
    start_socks5(socks5, channel_udp);
    gateway_main(mac, gateway, subnet_mask, &interface, udp_channel);
}
