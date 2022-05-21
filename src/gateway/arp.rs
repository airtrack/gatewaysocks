use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use log::info;
use pnet::datalink::DataLinkSender;
use pnet::packet::arp::{
    ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket,
};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

pub struct ArpProcessor {
    mac: MacAddr,
    gateway: Ipv4Addr,
    active_time: Instant,
    caches: HashMap<Ipv4Addr, MacAddr>,
}

impl ArpProcessor {
    pub fn new(mac: MacAddr, gateway: Ipv4Addr) -> Self {
        Self {
            mac,
            gateway,
            active_time: Instant::now(),
            caches: HashMap::new(),
        }
    }

    pub fn heartbeat(&mut self, tx: &mut Box<dyn DataLinkSender>) {
        let now = Instant::now();
        if (now - self.active_time).as_secs() < 30 {
            return;
        }

        self.active_time = now;
        for (ip, mac) in &self.caches {
            self.send_arp_packet(tx, *mac, *ip, ArpOperations::Request);
        }
    }

    pub fn handle_packet(&mut self, tx: &mut Box<dyn DataLinkSender>, request: &EthernetPacket) {
        if let Some(arp_request) = ArpPacket::new(request.payload()) {
            if arp_request.get_operation() != ArpOperations::Request {
                return;
            }

            if arp_request.get_target_proto_addr() != self.gateway {
                return;
            }

            let source_mac = request.get_source();
            let source_ip = arp_request.get_sender_proto_addr();

            self.send_arp_packet(tx, source_mac, source_ip, ArpOperations::Reply);
            self.caches.insert(source_ip, source_mac);
        }
    }

    fn send_arp_packet(
        &self,
        tx: &mut Box<dyn DataLinkSender>,
        destination_mac: MacAddr,
        destination_ip: Ipv4Addr,
        operation: ArpOperation,
    ) {
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        ethernet_packet.set_destination(destination_mac);
        ethernet_packet.set_source(self.mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        let target_hw_addr = if operation == ArpOperations::Request {
            MacAddr::zero()
        } else {
            destination_mac
        };

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(operation);
        arp_packet.set_sender_hw_addr(self.mac);
        arp_packet.set_sender_proto_addr(self.gateway);
        arp_packet.set_target_hw_addr(target_hw_addr);
        arp_packet.set_target_proto_addr(destination_ip);

        ethernet_packet.set_payload(arp_packet.packet());

        info!(
            "ARP {:?} to {}[{}]",
            operation, destination_ip, destination_mac
        );
        tx.send_to(ethernet_packet.packet(), None);
    }
}
