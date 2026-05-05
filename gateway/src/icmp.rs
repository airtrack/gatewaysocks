use std::net::Ipv4Addr;

use bytes::Bytes;
use log::trace;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_reply::{IcmpCodes as EchoReplyCodes, MutableEchoReplyPacket};
use pnet::packet::icmp::echo_request::{EchoRequestPacket, IcmpCodes as EchoRequestCodes};
use pnet::packet::icmp::{self, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::GatewaySender;

pub(super) fn new(channel: UnboundedReceiver<Bytes>, gw_sender: GatewaySender) -> IcmpHandler {
    IcmpHandler { channel, gw_sender }
}

pub(super) struct IcmpHandler {
    channel: UnboundedReceiver<Bytes>,
    gw_sender: GatewaySender,
}

impl IcmpHandler {
    pub(super) fn start(mut self) {
        tokio::spawn(async move {
            self.handle_loop().await;
        });
    }

    async fn handle_loop(&mut self) -> Option<()> {
        loop {
            let packet = self.channel.recv().await?;
            self.handle_packet(packet);
        }
    }

    fn handle_packet(&mut self, packet: Bytes) -> Option<()> {
        let ethernet_packet = EthernetPacket::new(&packet)?;
        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;

        if ipv4_packet.get_destination() != self.gw_sender.info.addr {
            return None;
        }

        if is_fragment(&ipv4_packet) {
            return None;
        }

        let icmp_packet = IcmpPacket::new(ipv4_packet.payload())?;
        if icmp_packet.get_icmp_type() != IcmpTypes::EchoRequest {
            return None;
        }

        let echo_request = EchoRequestPacket::new(ipv4_packet.payload())?;
        if echo_request.get_icmp_code() != EchoRequestCodes::NoCode {
            return None;
        }

        let destination_mac = ethernet_packet.get_source();
        let destination_ip = ipv4_packet.get_source();

        self.send_echo_reply(destination_mac, destination_ip, &echo_request);
        Some(())
    }

    fn send_echo_reply(
        &mut self,
        destination_mac: MacAddr,
        destination_ip: Ipv4Addr,
        echo_request: &EchoRequestPacket,
    ) {
        trace!("ICMP echo reply to {}[{}]", destination_ip, destination_mac);

        let icmp_packet_len = echo_request.packet().len();
        let ipv4_packet_len = 20 + icmp_packet_len;
        let ethernet_packet_len = 14 + ipv4_packet_len;

        self.gw_sender
            .build_and_send(1, ethernet_packet_len, &mut |buffer| {
                build_echo_reply(
                    buffer,
                    self.gw_sender.info.mac,
                    destination_mac,
                    self.gw_sender.info.addr,
                    destination_ip,
                    echo_request,
                );
            });
    }
}

fn is_fragment(packet: &Ipv4Packet) -> bool {
    packet.get_fragment_offset() != 0 || packet.get_flags() & Ipv4Flags::MoreFragments != 0
}

fn build_echo_reply(
    buffer: &mut [u8],
    source_mac: MacAddr,
    destination_mac: MacAddr,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    echo_request: &EchoRequestPacket,
) {
    let icmp_packet_len = echo_request.packet().len();
    let ipv4_packet_len = 20 + icmp_packet_len;

    let mut ethernet_packet = MutableEthernetPacket::new(buffer).unwrap();
    ethernet_packet.set_destination(destination_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_dscp(0);
    ipv4_packet.set_ecn(0);
    ipv4_packet.set_total_length(ipv4_packet_len as u16);
    ipv4_packet.set_identification(0);
    ipv4_packet.set_flags(0);
    ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_checksum(0);
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(destination_ip);

    let mut icmp_packet = MutableEchoReplyPacket::new(ipv4_packet.payload_mut()).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoReply);
    icmp_packet.set_icmp_code(EchoReplyCodes::NoCode);
    icmp_packet.set_checksum(0);
    icmp_packet.set_identifier(echo_request.get_identifier());
    icmp_packet.set_sequence_number(echo_request.get_sequence_number());
    icmp_packet.set_payload(echo_request.payload());
    icmp_packet.set_checksum(icmp::checksum(
        &IcmpPacket::new(icmp_packet.packet()).unwrap(),
    ));

    ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
    use pnet::packet::icmp::{IcmpType, MutableIcmpPacket};

    use super::*;

    #[test]
    fn builds_echo_reply_from_echo_request() {
        let source_mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let destination_mac = MacAddr::new(6, 5, 4, 3, 2, 1);
        let source_ip = Ipv4Addr::new(10, 6, 0, 1);
        let destination_ip = Ipv4Addr::new(10, 6, 0, 2);
        let request = echo_request(7, 42, b"hello");
        let echo_request = EchoRequestPacket::new(&request).unwrap();
        let mut reply = vec![0u8; 14 + 20 + request.len()];

        build_echo_reply(
            &mut reply,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            &echo_request,
        );

        let ethernet_packet = EthernetPacket::new(&reply).unwrap();
        assert_eq!(ethernet_packet.get_source(), source_mac);
        assert_eq!(ethernet_packet.get_destination(), destination_mac);
        assert_eq!(ethernet_packet.get_ethertype(), EtherTypes::Ipv4);

        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
        assert_eq!(ipv4_packet.get_source(), source_ip);
        assert_eq!(ipv4_packet.get_destination(), destination_ip);
        assert_eq!(
            ipv4_packet.get_next_level_protocol(),
            IpNextHeaderProtocols::Icmp
        );
        assert_eq!(ipv4_packet.get_checksum(), ipv4::checksum(&ipv4_packet));

        let icmp_packet = IcmpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(icmp_packet.get_icmp_type(), IcmpTypes::EchoReply);
        assert_eq!(icmp_packet.get_checksum(), icmp::checksum(&icmp_packet));

        let echo_reply =
            pnet::packet::icmp::echo_reply::EchoReplyPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(echo_reply.get_identifier(), 7);
        assert_eq!(echo_reply.get_sequence_number(), 42);
        assert_eq!(echo_reply.payload(), b"hello");
    }

    #[test]
    fn detects_ipv4_fragments() {
        let mut packet = vec![0u8; 20 + 8];
        let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();

        ipv4_packet.set_fragment_offset(1);
        assert!(is_fragment(&ipv4_packet.to_immutable()));

        ipv4_packet.set_fragment_offset(0);
        ipv4_packet.set_flags(Ipv4Flags::MoreFragments);
        assert!(is_fragment(&ipv4_packet.to_immutable()));

        ipv4_packet.set_flags(0);
        assert!(!is_fragment(&ipv4_packet.to_immutable()));
    }

    #[test]
    fn ignores_non_echo_request_type() {
        let mut packet = echo_request(1, 2, b"payload");
        let mut icmp_packet = MutableIcmpPacket::new(&mut packet).unwrap();

        icmp_packet.set_icmp_type(IcmpType(3));

        assert_ne!(icmp_packet.get_icmp_type(), IcmpTypes::EchoRequest);
    }

    fn echo_request(identifier: u16, sequence_number: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 8 + payload.len()];
        let mut echo_request = MutableEchoRequestPacket::new(&mut packet).unwrap();

        echo_request.set_icmp_type(IcmpTypes::EchoRequest);
        echo_request.set_icmp_code(EchoRequestCodes::NoCode);
        echo_request.set_checksum(0);
        echo_request.set_identifier(identifier);
        echo_request.set_sequence_number(sequence_number);
        echo_request.set_payload(payload);
        echo_request.set_checksum(icmp::checksum(
            &IcmpPacket::new(echo_request.packet()).unwrap(),
        ));

        packet
    }
}
