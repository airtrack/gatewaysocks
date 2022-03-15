use std::net::Ipv4Addr;

use log::info;

use pnet::datalink::DataLinkSender;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

pub struct ArpHandler {
    mac: MacAddr,
    gateway: Ipv4Addr,
}

impl ArpHandler {
    pub fn new(mac: MacAddr, gateway: Ipv4Addr) -> Self {
        Self { mac, gateway }
    }

    pub fn handle_packet(&self, tx: &mut Box<dyn DataLinkSender>, request: &EthernetPacket) {
        if let Some(arp_request) = ArpPacket::new(request.payload()) {
            if arp_request.get_operation() != ArpOperations::Request {
                return;
            }

            if arp_request.get_target_proto_addr() != self.gateway {
                return;
            }

            let mut ethernet_buffer = [0u8; 42];
            let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

            ethernet_packet.set_destination(request.get_source());
            ethernet_packet.set_source(self.mac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);

            let mut arp_buffer = [0u8; 28];
            let mut arp_response = MutableArpPacket::new(&mut arp_buffer).unwrap();
            let source_mac = request.get_source();
            let source_ip = arp_request.get_sender_proto_addr();

            arp_response.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_response.set_protocol_type(EtherTypes::Ipv4);
            arp_response.set_hw_addr_len(6);
            arp_response.set_proto_addr_len(4);
            arp_response.set_operation(ArpOperations::Reply);
            arp_response.set_sender_hw_addr(self.mac);
            arp_response.set_sender_proto_addr(self.gateway);
            arp_response.set_target_hw_addr(source_mac);
            arp_response.set_target_proto_addr(source_ip);

            ethernet_packet.set_payload(arp_response.packet());

            info!("ARP reply to {}[{}]", source_ip, source_mac);
            tx.send_to(ethernet_packet.packet(), None);
        }
    }
}
