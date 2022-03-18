use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use log::info;
use simple_logger::SimpleLogger;

use pnet::datalink::{self, Config, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use tokio::runtime::Runtime;
use tokio::sync::mpsc::error::TryRecvError;

use gatewaysocks::gateway::arp::ArpHandler;
use gatewaysocks::gateway::tcp::{TcpLayerPacket, TcpProcessor};
use gatewaysocks::gateway::udp::{UdpLayerPacket, UdpProcessor};
use gatewaysocks::socks5::tcp::{TcpSocks5, TcpSocks5Data};
use gatewaysocks::socks5::udp::{UdpSocks5, UdpSocks5Data};
use gatewaysocks::socks5::{socks5_channel, Socks5Channel};

fn socks5_main(
    socks5: SocketAddr,
    tcp_channel: Socks5Channel<TcpSocks5Data>,
    udp_channel: Socks5Channel<UdpSocks5Data>,
) {
    let rt = Runtime::new().unwrap();

    rt.block_on(async move {
        tokio::spawn(async move {
            let mut tcp_socks5 = TcpSocks5::new(socks5, tcp_channel);
            tcp_socks5.run().await;
        });

        let mut udp_socks5 = UdpSocks5::new(socks5, udp_channel);
        udp_socks5.run().await;
    });
}

fn start_socks5(
    socks5: SocketAddr,
    tcp_channel: Socks5Channel<TcpSocks5Data>,
    udp_channel: Socks5Channel<UdpSocks5Data>,
) {
    thread::spawn(move || {
        socks5_main(socks5, tcp_channel, udp_channel);
    });
}

fn handle_tcp_from_gateway(
    tcp_processor: &mut TcpProcessor,
    tcp_channel: &Socks5Channel<TcpSocks5Data>,
    ethernet_packet: &EthernetPacket,
    ipv4_packet: &Ipv4Packet,
) {
    let tcp_data = tcp_processor.handle_input_packet(ethernet_packet.get_source(), ipv4_packet);

    if let Some(data) = tcp_data {
        let _ = tcp_channel.tx.send(match data {
            TcpLayerPacket::Connect(v) => TcpSocks5Data::Connect(v),
            TcpLayerPacket::Push(v) => TcpSocks5Data::Push(v),
            TcpLayerPacket::Shutdown(v) => TcpSocks5Data::Shutdown(v),
            TcpLayerPacket::Close(v) => TcpSocks5Data::Close(v),
        });
    }
}

fn handle_udp_from_gateway(
    udp_processor: &mut UdpProcessor,
    udp_channel: &Socks5Channel<UdpSocks5Data>,
    ethernet_packet: &EthernetPacket,
    ipv4_packet: &Ipv4Packet,
) {
    let udp_data = udp_processor.handle_input_packet(ethernet_packet.get_source(), ipv4_packet);

    if let Some(data) = udp_data {
        let _ = udp_channel.tx.send(UdpSocks5Data {
            key: data.key,
            data: data.data,
            addr: data.addr,
        });
    }
}

fn handle_tcp_from_socks5(
    tcp_processor: &TcpProcessor,
    tcp_channel: &mut Socks5Channel<TcpSocks5Data>,
    tx: &mut Box<dyn DataLinkSender>,
) {
    loop {
        match tcp_channel.rx.try_recv() {
            Ok(data) => {
                let tcp_data = match data {
                    TcpSocks5Data::Connect(v) => TcpLayerPacket::Connect(v),
                    TcpSocks5Data::Push(v) => TcpLayerPacket::Push(v),
                    TcpSocks5Data::Shutdown(v) => TcpLayerPacket::Shutdown(v),
                    TcpSocks5Data::Close(v) => TcpLayerPacket::Close(v),
                };
                tcp_processor.handle_output_packet(tx, &tcp_data);
            }
            Err(TryRecvError::Empty) => break,
            Err(_) => {}
        }
    }
}

fn handle_udp_from_socks5(
    udp_processor: &UdpProcessor,
    udp_channel: &mut Socks5Channel<UdpSocks5Data>,
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
    mut tcp_channel: Socks5Channel<TcpSocks5Data>,
    mut udp_channel: Socks5Channel<UdpSocks5Data>,
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
    let mut tcp_processor = TcpProcessor::new(mac, gateway, subnet_mask);
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
                                    handle_udp_from_gateway(
                                        &mut udp_processor,
                                        &udp_channel,
                                        &ethernet_packet,
                                        &ipv4_packet,
                                    );
                                }
                                IpNextHeaderProtocols::Tcp => {
                                    handle_tcp_from_gateway(
                                        &mut tcp_processor,
                                        &tcp_channel,
                                        &ethernet_packet,
                                        &ipv4_packet,
                                    );
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

        handle_tcp_from_socks5(&tcp_processor, &mut tcp_channel, &mut tx);
        handle_udp_from_socks5(&udp_processor, &mut udp_channel, &mut tx);
    }
}

fn main() {
    SimpleLogger::new()
        .env()
        .with_utc_timestamps()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

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

    info!("start gatewaysocks on {}({}) ...", gateway, subnet_mask);

    let (tcp_channel, channel_tcp) = socks5_channel();
    let (udp_channel, channel_udp) = socks5_channel();
    start_socks5(socks5, channel_tcp, channel_udp);
    gateway_main(
        mac,
        gateway,
        subnet_mask,
        &interface,
        tcp_channel,
        udp_channel,
    );
}
