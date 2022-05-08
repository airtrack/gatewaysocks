use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use getopts::Options;
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

fn send_tcp_data_to_socks5(tcp_channel: &Socks5Channel<TcpSocks5Data>, data: TcpLayerPacket) {
    let _ = tcp_channel.tx.send(match data {
        TcpLayerPacket::Connect(v) => TcpSocks5Data::Connect(v),
        TcpLayerPacket::Established(v) => TcpSocks5Data::Established(v),
        TcpLayerPacket::Push(v) => TcpSocks5Data::Push(v),
        TcpLayerPacket::Shutdown(v) => TcpSocks5Data::Shutdown(v),
        TcpLayerPacket::Close(v) => TcpSocks5Data::Close(v),
    });
}

fn send_udp_data_to_socks5(udp_channel: &Socks5Channel<UdpSocks5Data>, data: UdpLayerPacket) {
    let _ = udp_channel.tx.send(UdpSocks5Data {
        key: data.key,
        data: data.data,
        addr: data.addr,
    });
}

fn handle_ipv4_from_gateway(
    ethernet_packet: &EthernetPacket,
    tx: &mut Box<dyn DataLinkSender>,
    tcp_processor: &mut TcpProcessor,
    udp_processor: &mut UdpProcessor,
    tcp_channel: &Socks5Channel<TcpSocks5Data>,
    udp_channel: &Socks5Channel<UdpSocks5Data>,
) {
    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                tcp_processor.handle_input_packet(
                    tx,
                    ethernet_packet.get_source(),
                    &ipv4_packet,
                    |data| {
                        send_tcp_data_to_socks5(tcp_channel, data);
                    },
                );
            }
            IpNextHeaderProtocols::Udp => {
                udp_processor.handle_input_packet(
                    ethernet_packet.get_source(),
                    &ipv4_packet,
                    |data| {
                        send_udp_data_to_socks5(udp_channel, data);
                    },
                );
            }
            _ => {}
        }
    }
}

fn handle_tcp_from_socks5(
    tcp_processor: &mut TcpProcessor,
    tcp_channel: &mut Socks5Channel<TcpSocks5Data>,
    tx: &mut Box<dyn DataLinkSender>,
) {
    loop {
        match tcp_channel.rx.try_recv() {
            Ok(data) => {
                let tcp_data = match data {
                    TcpSocks5Data::Connect(v) => TcpLayerPacket::Connect(v),
                    TcpSocks5Data::Established(v) => TcpLayerPacket::Established(v),
                    TcpSocks5Data::Push(v) => TcpLayerPacket::Push(v),
                    TcpSocks5Data::Shutdown(v) => TcpLayerPacket::Shutdown(v),
                    TcpSocks5Data::Close(v) => TcpLayerPacket::Close(v),
                };
                tcp_processor.handle_output_packet(tx, tcp_data);
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
                udp_processor.handle_output_packet(tx, udp_data);
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
        read_timeout: Some(Duration::from_millis(1)),
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
                        handle_ipv4_from_gateway(
                            &ethernet_packet,
                            &mut tx,
                            &mut tcp_processor,
                            &mut udp_processor,
                            &tcp_channel,
                            &udp_channel,
                        );
                    }
                    EtherTypes::Arp => arp_handler.handle_packet(&mut tx, &ethernet_packet),
                    _ => {}
                }
            }
            Err(_) => {}
        }

        handle_tcp_from_socks5(&mut tcp_processor, &mut tcp_channel, &mut tx);
        handle_udp_from_socks5(&udp_processor, &mut udp_channel, &mut tx);

        tcp_processor.heartbeat(&mut tx, |data| {
            send_tcp_data_to_socks5(&tcp_channel, data);
        });
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();

    opts.optopt("s", "socks5", "socks5 address", "socks5");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => return println!("{}", opts.short_usage(&args[0])),
    };

    let socks5_addr = matches.opt_str("s").unwrap_or("127.0.0.1:1080".to_string());

    SimpleLogger::new()
        .with_utc_timestamps()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .unwrap();

    let socks5 = socks5_addr.parse::<SocketAddr>().unwrap();
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

    info!(
        "start gatewaysocks on {}({}), relay to socks5://{} ...",
        gateway, subnet_mask, socks5
    );

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
