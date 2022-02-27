use gatewaysocks::arp::ArpHandler;

use pnet::datalink::{self, Config};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

use std::net::Ipv4Addr;
use std::time::Duration;

fn main() {
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

    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Unable to create channel: {}", e),
    };

    let arp_handler = ArpHandler::new(
        interface.mac.unwrap(),
        "10.6.0.1".parse::<Ipv4Addr>().unwrap(),
    );

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                match ethernet_packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        println!("ipv4 packet");
                    }
                    EtherTypes::Arp => arp_handler.handle_packet(&mut tx, &ethernet_packet),
                    _ => {}
                }
            }
            Err(_) => {}
        }
    }
}
