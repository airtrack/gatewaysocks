use gatewaysocks::arp::ArpHandler;

use pnet::datalink;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};

use std::net::Ipv4Addr;

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

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
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
