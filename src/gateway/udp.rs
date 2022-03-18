use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use pnet::datalink::DataLinkSender;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use super::is_to_gateway;

pub struct UdpProcessor {
    mac: MacAddr,
    gateway: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    slots: HashMap<String, Slot>,
}

pub struct UdpLayerPacket {
    pub key: String,
    pub data: Vec<u8>,
    pub addr: SocketAddrV4,
}

struct Slot {
    mac: MacAddr,
    addr: SocketAddrV4,
}

impl UdpProcessor {
    pub fn new(mac: MacAddr, gateway: Ipv4Addr, subnet_mask: Ipv4Addr) -> Self {
        Self {
            mac,
            gateway,
            subnet_mask,
            slots: HashMap::new(),
        }
    }

    pub fn handle_input_packet(
        &mut self,
        source_mac: MacAddr,
        request: &Ipv4Packet,
    ) -> Option<UdpLayerPacket> {
        if !is_to_gateway(self.gateway, self.subnet_mask, request.get_source()) {
            return None;
        }

        if let Some(udp_request) = UdpPacket::new(request.payload()) {
            let data = udp_request.payload().to_owned();
            let src = SocketAddrV4::new(request.get_source(), udp_request.get_source());
            let dst = SocketAddrV4::new(request.get_destination(), udp_request.get_destination());
            let key = src.to_string();

            if !self.slots.contains_key(&key) {
                self.slots.insert(
                    key.clone(),
                    Slot {
                        mac: source_mac,
                        addr: src,
                    },
                );
            }

            return Some(UdpLayerPacket {
                key,
                data,
                addr: dst,
            });
        }

        None
    }

    pub fn handle_output_packet(&self, tx: &mut Box<dyn DataLinkSender>, packet: &UdpLayerPacket) {
        if let Some(slot) = self.slots.get(&packet.key) {
            let udp_packet_len = 8 + packet.data.len();
            let mut udp_buffer = vec![0u8; udp_packet_len];
            let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();

            udp_packet.set_source(packet.addr.port());
            udp_packet.set_destination(slot.addr.port());
            udp_packet.set_length(udp_packet_len as u16);
            udp_packet.set_checksum(0);
            udp_packet.set_payload(&packet.data);

            udp_packet.set_checksum(udp::ipv4_checksum(
                &udp_packet.to_immutable(),
                packet.addr.ip(),
                slot.addr.ip(),
            ));

            let ipv4_packet_len = 20 + udp_packet_len;
            let mut ipv4_buffer = vec![0u8; ipv4_packet_len];
            let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();

            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_dscp(0);
            ipv4_packet.set_ecn(0);
            ipv4_packet.set_total_length(ipv4_packet_len as u16);
            ipv4_packet.set_identification(0);
            ipv4_packet.set_flags(0);
            ipv4_packet.set_fragment_offset(0);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4_packet.set_checksum(0);
            ipv4_packet.set_source(*packet.addr.ip());
            ipv4_packet.set_destination(*slot.addr.ip());
            ipv4_packet.set_payload(udp_packet.packet());

            ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

            let ethernet_packet_len = 14 + ipv4_packet_len;
            let mut ethernet_buffer = vec![0u8; ethernet_packet_len];
            let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

            ethernet_packet.set_destination(slot.mac);
            ethernet_packet.set_source(self.mac);
            ethernet_packet.set_ethertype(EtherTypes::Ipv4);
            ethernet_packet.set_payload(ipv4_packet.packet());

            tx.send_to(ethernet_packet.packet(), None);
        }
    }
}
