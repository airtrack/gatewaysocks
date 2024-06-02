use std::env;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
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

use gatewaysocks::gateway::arp::ArpProcessor;
use gatewaysocks::gateway::tcp::{TcpConnectionHandler, TcpLayerPacket, TcpProcessor};
use gatewaysocks::gateway::udp::{UdpLayerPacket, UdpProcessor};
use gatewaysocks::socks5::tcp::{
    tcp_socks5, TcpSocks5Client, TcpSocks5Handle, TcpSocks5Message, TcpSocks5Service,
};
use gatewaysocks::socks5::udp::{UdpSocks5, UdpSocks5Data};
use gatewaysocks::socks5::{socks5_channel, Socks5Channel};

struct TcpConnectionToSocks5 {
    socks5_client: TcpSocks5Client,
}

impl TcpConnectionHandler for TcpConnectionToSocks5 {
    fn handle_input_tcp_packet(&mut self) -> Option<Vec<TcpLayerPacket>> {
        if let Some(messages) = self.socks5_client.recv_socks5_messages() {
            let packets = messages
                .into_iter()
                .map(|message| match message {
                    TcpSocks5Message::Connect(v) => TcpLayerPacket::Connect(v),
                    TcpSocks5Message::Established(v) => TcpLayerPacket::Established(v),
                    TcpSocks5Message::Push(v) => TcpLayerPacket::Push(v),
                    TcpSocks5Message::Shutdown(v) => TcpLayerPacket::Shutdown(v),
                    TcpSocks5Message::Close(v) => TcpLayerPacket::Close(v),
                })
                .collect();
            return Some(packets);
        }

        None
    }

    fn handle_output_tcp_packet(&mut self, packet: TcpLayerPacket) {
        match packet {
            TcpLayerPacket::Connect(_) => {}
            TcpLayerPacket::Established(_) => {
                unreachable!();
            }
            TcpLayerPacket::Push((key, data)) => {
                self.socks5_client
                    .send_socks5_message(TcpSocks5Message::Push((key, data)));
            }
            TcpLayerPacket::Shutdown(key) => {
                self.socks5_client
                    .send_socks5_message(TcpSocks5Message::Shutdown(key));
            }
            TcpLayerPacket::Close(_) => {}
        }
    }
}

fn socks5_main(
    socks5: SocketAddr,
    mut tcp_socks5_service: TcpSocks5Service,
    udp_channel: Socks5Channel<UdpSocks5Data>,
) {
    let rt = Runtime::new().unwrap();

    rt.block_on(async move {
        let mut udp_socks5 = UdpSocks5::new(socks5, udp_channel);
        futures::join!(tcp_socks5_service.run(), udp_socks5.run());
    });
}

fn start_socks5(
    socks5: SocketAddr,
    tcp_socks5_service: TcpSocks5Service,
    udp_channel: Socks5Channel<UdpSocks5Data>,
) {
    thread::spawn(move || {
        socks5_main(socks5, tcp_socks5_service, udp_channel);
    });
}

fn send_udp_data_to_socks5(udp_channel: &Socks5Channel<UdpSocks5Data>, data: UdpLayerPacket) {
    let _ = udp_channel.tx.send(UdpSocks5Data {
        src: data.src,
        dst: data.dst,
        mac: data.mac,
        data: data.data,
    });
}

fn handle_ipv4_from_gateway(
    ethernet_packet: &EthernetPacket,
    tx: &mut Box<dyn DataLinkSender>,
    tcp_processor: &mut TcpProcessor,
    udp_processor: &mut UdpProcessor,
    udp_channel: &Socks5Channel<UdpSocks5Data>,
) {
    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                tcp_processor.handle_input_packet(tx, ethernet_packet.get_source(), &ipv4_packet);
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

fn handle_udp_from_socks5(
    udp_processor: &UdpProcessor,
    udp_channel: &mut Socks5Channel<UdpSocks5Data>,
    tx: &mut Box<dyn DataLinkSender>,
) {
    loop {
        match udp_channel.rx.try_recv() {
            Ok(data) => {
                let udp_data = UdpLayerPacket {
                    src: data.src,
                    dst: data.dst,
                    mac: data.mac,
                    data: data.data,
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
    mut tcp_socks5_handle: TcpSocks5Handle,
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

    let mut tcp_processor = TcpProcessor::new(
        mac,
        gateway,
        subnet_mask,
        move |key: &str, destination: SocketAddrV4| {
            let client = tcp_socks5_handle.start_connection(key, destination);
            Box::new(TcpConnectionToSocks5 {
                socks5_client: client,
            })
        },
    );

    let mut arp_processor = ArpProcessor::new(mac, gateway);
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
                            &udp_channel,
                        );
                    }
                    EtherTypes::Arp => arp_processor.handle_packet(&mut tx, &ethernet_packet),
                    _ => {}
                }
            }
            Err(_) => {}
        }

        handle_udp_from_socks5(&udp_processor, &mut udp_channel, &mut tx);

        arp_processor.heartbeat(&mut tx);
        tcp_processor.heartbeat(&mut tx);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();

    opts.optopt("i", "interface", "ether interface", "interface");
    opts.optopt("s", "socks5", "socks5 address", "socks5");
    opts.optopt("", "gateway-ip", "gateway ip", "gateway");
    opts.optopt("", "subnet-mask", "subnet mask", "subnet");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => return println!("{}", opts.short_usage(&args[0])),
    };

    let iface_name = matches.opt_str("i").unwrap_or("".to_string());
    let socks5_addr = matches.opt_str("s").unwrap_or("127.0.0.1:1080".to_string());
    let gateway_addr = matches
        .opt_str("gateway-ip")
        .unwrap_or("10.6.0.1".to_string());
    let subnet_addr = matches
        .opt_str("subnet-mask")
        .unwrap_or("255.255.255.0".to_string());

    SimpleLogger::new()
        .without_timestamps()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .unwrap();

    let socks5 = socks5_addr.parse::<SocketAddr>().unwrap();
    let gateway = gateway_addr.parse::<Ipv4Addr>().unwrap();
    let subnet_mask = subnet_addr.parse::<Ipv4Addr>().unwrap();
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
        .unwrap_or_else(|| panic!("Could not find local network interface."));
    let mac = interface.mac.unwrap();

    info!(
        "start gatewaysocks on {}[{}]: {}({}), relay to socks5://{} ...",
        interface.name, mac, gateway, subnet_mask, socks5
    );

    let (tcp_socks5_handle, tcp_socks5_service) = tcp_socks5(socks5);
    let (udp_channel, channel_udp) = socks5_channel();

    start_socks5(socks5, tcp_socks5_service, channel_udp);
    gateway_main(
        mac,
        gateway,
        subnet_mask,
        &interface,
        tcp_socks5_handle,
        udp_channel,
    );
}
