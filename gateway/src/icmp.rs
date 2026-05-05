use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use log::{trace, warn};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_reply::{IcmpCodes as EchoReplyCodes, MutableEchoReplyPacket};
use pnet::packet::icmp::echo_request::{EchoRequestPacket, IcmpCodes as EchoRequestCodes};
use pnet::packet::icmp::{self, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{
    TransportChannelType, TransportProtocol, TransportReceiver, TransportSender, icmp_packet_iter,
    transport_channel,
};
use pnet::util::MacAddr;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::GatewaySender;

const FLOW_TTL: Duration = Duration::from_secs(60);
const ICMP_BUFFER_SIZE: usize = 2048;

pub(super) fn new(
    channel: UnboundedReceiver<Bytes>,
    gw_sender: GatewaySender,
) -> std::io::Result<IcmpHandler> {
    let (sender, receiver) = transport_channel(
        ICMP_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )?;
    let (transport_packet_sender, transport_packets) = unbounded_channel();

    Ok(IcmpHandler {
        channel,
        transport_packets,
        transport_packet_sender: Some(transport_packet_sender),
        gw_sender,
        sender,
        receiver: Some(receiver),
        flows: FlowTable::new(),
    })
}

struct TransportIcmpPacket {
    addr: IpAddr,
    data: Vec<u8>,
}

pub(super) struct IcmpHandler {
    channel: UnboundedReceiver<Bytes>,
    transport_packets: UnboundedReceiver<TransportIcmpPacket>,
    transport_packet_sender: Option<UnboundedSender<TransportIcmpPacket>>,
    gw_sender: GatewaySender,
    sender: TransportSender,
    receiver: Option<TransportReceiver>,
    flows: FlowTable,
}

impl IcmpHandler {
    pub(super) fn start(mut self) {
        let receiver = self.receiver.take().unwrap();
        let transport_packet_sender = self.transport_packet_sender.take().unwrap();
        start_transport_packet_reader(receiver, transport_packet_sender);

        tokio::spawn(async move {
            self.handle_loop().await;
        });
    }

    async fn handle_loop(&mut self) -> Option<()> {
        loop {
            tokio::select! {
                Some(packet) = self.channel.recv() => {
                    self.handle_packet(packet);
                }
                Some(packet) = self.transport_packets.recv() => {
                    self.handle_transport_packet(packet);
                }
                else => return None,
            }
        }
    }

    fn handle_packet(&mut self, packet: Bytes) -> Option<()> {
        let ethernet_packet = EthernetPacket::new(&packet)?;
        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;

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

        let client_mac = ethernet_packet.get_source();
        let client_ip = ipv4_packet.get_source();
        let target_ip = ipv4_packet.get_destination();

        if target_ip == self.gw_sender.info.addr {
            self.send_local_echo_reply(client_mac, client_ip, &echo_request);
        } else {
            self.forward_echo_request(client_mac, client_ip, target_ip, &echo_request)
                .inspect_err(|error| warn!("ICMP echo forward to {} failed: {}", target_ip, error))
                .ok()?;
        }

        Some(())
    }

    fn handle_transport_packet(&mut self, packet: TransportIcmpPacket) -> Option<()> {
        let target_ip = match packet.addr {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return None,
        };

        let icmp_packet = IcmpPacket::new(&packet.data)?;
        if icmp_packet.get_icmp_type() != IcmpTypes::EchoReply {
            return None;
        }

        let echo_reply =
            pnet::packet::icmp::echo_reply::EchoReplyPacket::new(icmp_packet.packet())?;
        if echo_reply.get_icmp_code() != EchoReplyCodes::NoCode {
            return None;
        }

        let flow = self
            .flows
            .flow_for_reply(target_ip, echo_reply.get_identifier())?;

        trace!(
            "ICMP echo reply forward {} -> {} id {}({})",
            target_ip, flow.client_ip, flow.original_identifier, flow.translated_identifier
        );

        self.send_forwarded_echo_reply(flow, &echo_reply);
        Some(())
    }

    fn send_local_echo_reply(
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
                build_echo_reply_packet(
                    buffer,
                    self.gw_sender.info.mac,
                    destination_mac,
                    self.gw_sender.info.addr,
                    destination_ip,
                    echo_request.get_identifier(),
                    echo_request.get_sequence_number(),
                    echo_request.payload(),
                );
            });
    }

    fn forward_echo_request(
        &mut self,
        client_mac: MacAddr,
        client_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        echo_request: &EchoRequestPacket,
    ) -> std::io::Result<()> {
        let flow = self.flows.flow_for_request(
            client_mac,
            client_ip,
            target_ip,
            echo_request.get_identifier(),
        );

        let Some(flow) = flow else {
            return Ok(());
        };

        trace!(
            "ICMP echo forward {} -> {} id {}({})",
            client_ip, target_ip, flow.translated_identifier, flow.original_identifier
        );

        let mut packet = vec![0u8; echo_request.packet().len()];
        build_echo_request_packet(
            &mut packet,
            flow.translated_identifier,
            echo_request.get_sequence_number(),
            echo_request.payload(),
        );

        let echo_request = EchoRequestPacket::new(&packet).unwrap();
        self.sender.send_to(echo_request, IpAddr::V4(target_ip))?;
        Ok(())
    }

    fn send_forwarded_echo_reply(
        &mut self,
        flow: Flow,
        echo_reply: &pnet::packet::icmp::echo_reply::EchoReplyPacket,
    ) {
        let icmp_packet_len = echo_reply.packet().len();
        let ipv4_packet_len = 20 + icmp_packet_len;
        let ethernet_packet_len = 14 + ipv4_packet_len;

        self.gw_sender
            .build_and_send(1, ethernet_packet_len, &mut |buffer| {
                build_echo_reply_packet(
                    buffer,
                    self.gw_sender.info.mac,
                    flow.client_mac,
                    flow.target_ip,
                    flow.client_ip,
                    flow.original_identifier,
                    echo_reply.get_sequence_number(),
                    echo_reply.payload(),
                );
            });
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct ClientKey {
    client_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    original_identifier: u16,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct ReplyKey {
    target_ip: Ipv4Addr,
    translated_identifier: u16,
}

#[derive(Clone, Copy)]
struct Flow {
    client_mac: MacAddr,
    client_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    original_identifier: u16,
    translated_identifier: u16,
    last_seen: Instant,
}

impl Flow {
    fn reply_key(&self) -> ReplyKey {
        ReplyKey {
            target_ip: self.target_ip,
            translated_identifier: self.translated_identifier,
        }
    }
}

struct FlowTable {
    next_identifier: AtomicU16,
    by_client: DashMap<ClientKey, Flow>,
    by_reply: DashMap<ReplyKey, Flow>,
}

impl FlowTable {
    fn new() -> Self {
        Self {
            next_identifier: AtomicU16::new(rand::random()),
            by_client: DashMap::new(),
            by_reply: DashMap::new(),
        }
    }

    fn flow_for_request(
        &self,
        client_mac: MacAddr,
        client_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        original_identifier: u16,
    ) -> Option<Flow> {
        let now = Instant::now();
        self.remove_expired(now);

        let client_key = ClientKey {
            client_ip,
            target_ip,
            original_identifier,
        };

        if let Some(mut flow_ref) = self.by_client.get_mut(&client_key) {
            flow_ref.client_mac = client_mac;
            flow_ref.last_seen = now;

            let flow = *flow_ref;
            drop(flow_ref);

            self.by_reply.insert(flow.reply_key(), flow);
            return Some(flow);
        }

        let translated_identifier = self.next_identifier(target_ip)?;
        let flow = Flow {
            client_mac,
            client_ip,
            target_ip,
            original_identifier,
            translated_identifier,
            last_seen: now,
        };

        self.by_client.insert(client_key, flow);
        self.by_reply.insert(flow.reply_key(), flow);
        Some(flow)
    }

    fn flow_for_reply(&self, target_ip: Ipv4Addr, translated_identifier: u16) -> Option<Flow> {
        self.remove_expired(Instant::now());
        self.by_reply
            .get(&ReplyKey {
                target_ip,
                translated_identifier,
            })
            .map(|flow| *flow)
    }

    fn next_identifier(&self, target_ip: Ipv4Addr) -> Option<u16> {
        for _ in 0..=u16::MAX {
            let translated_identifier = self.next_identifier.fetch_add(1, Ordering::Relaxed);
            let key = ReplyKey {
                target_ip,
                translated_identifier,
            };
            if !self.by_reply.contains_key(&key) {
                return Some(translated_identifier);
            }
        }

        None
    }

    fn remove_expired(&self, now: Instant) {
        self.by_client
            .retain(|_, flow| now.duration_since(flow.last_seen) < FLOW_TTL);
        self.by_reply
            .retain(|_, flow| now.duration_since(flow.last_seen) < FLOW_TTL);
    }
}

fn start_transport_packet_reader(
    mut receiver: TransportReceiver,
    packets_tx: UnboundedSender<TransportIcmpPacket>,
) {
    std::thread::spawn(move || {
        let mut packets = icmp_packet_iter(&mut receiver);

        loop {
            match packets.next() {
                Ok((packet, addr)) => {
                    let packet = TransportIcmpPacket {
                        addr,
                        data: packet.packet().to_vec(),
                    };

                    if packets_tx.send(packet).is_err() {
                        return;
                    }
                }
                Err(error) => warn!("ICMP echo receive failed: {}", error),
            }
        }
    });
}

fn is_fragment(packet: &Ipv4Packet) -> bool {
    packet.get_fragment_offset() != 0 || packet.get_flags() & Ipv4Flags::MoreFragments != 0
}

fn build_echo_request_packet(
    buffer: &mut [u8],
    identifier: u16,
    sequence_number: u16,
    payload: &[u8],
) {
    let mut icmp_packet =
        pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(buffer).unwrap();

    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(EchoRequestCodes::NoCode);
    icmp_packet.set_checksum(0);
    icmp_packet.set_identifier(identifier);
    icmp_packet.set_sequence_number(sequence_number);
    icmp_packet.set_payload(payload);
    icmp_packet.set_checksum(icmp::checksum(
        &IcmpPacket::new(icmp_packet.packet()).unwrap(),
    ));
}

fn build_echo_reply_packet(
    buffer: &mut [u8],
    source_mac: MacAddr,
    destination_mac: MacAddr,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    identifier: u16,
    sequence_number: u16,
    payload: &[u8],
) {
    let icmp_packet_len = 8 + payload.len();
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
    icmp_packet.set_identifier(identifier);
    icmp_packet.set_sequence_number(sequence_number);
    icmp_packet.set_payload(payload);
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
    fn builds_echo_reply_packet() {
        let source_mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let destination_mac = MacAddr::new(6, 5, 4, 3, 2, 1);
        let source_ip = Ipv4Addr::new(10, 6, 0, 1);
        let destination_ip = Ipv4Addr::new(10, 6, 0, 2);
        let mut reply = vec![0u8; 14 + 20 + 8 + b"hello".len()];

        build_echo_reply_packet(
            &mut reply,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            7,
            42,
            b"hello",
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
    fn builds_echo_request_packet() {
        let mut packet = vec![0u8; 8 + b"hello".len()];

        build_echo_request_packet(&mut packet, 9, 11, b"hello");

        let icmp_packet = IcmpPacket::new(&packet).unwrap();
        assert_eq!(icmp_packet.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_eq!(icmp_packet.get_checksum(), icmp::checksum(&icmp_packet));

        let echo_request = EchoRequestPacket::new(&packet).unwrap();
        assert_eq!(echo_request.get_identifier(), 9);
        assert_eq!(echo_request.get_sequence_number(), 11);
        assert_eq!(echo_request.payload(), b"hello");
    }

    #[test]
    fn reuses_flow_for_same_client_request() {
        let flows = FlowTable::new();
        let client_mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let client_ip = Ipv4Addr::new(10, 6, 0, 2);
        let target_ip = Ipv4Addr::new(8, 8, 8, 8);

        let first = flows
            .flow_for_request(client_mac, client_ip, target_ip, 7)
            .unwrap();
        let second = flows
            .flow_for_request(client_mac, client_ip, target_ip, 7)
            .unwrap();

        assert_eq!(first.translated_identifier, second.translated_identifier);
        assert_eq!(
            flows
                .flow_for_reply(target_ip, first.translated_identifier)
                .unwrap()
                .original_identifier,
            7
        );
    }

    #[test]
    fn allocates_different_flows_for_conflicting_clients() {
        let flows = FlowTable::new();
        let target_ip = Ipv4Addr::new(8, 8, 8, 8);

        let first = flows
            .flow_for_request(
                MacAddr::new(1, 2, 3, 4, 5, 6),
                Ipv4Addr::new(10, 6, 0, 2),
                target_ip,
                7,
            )
            .unwrap();
        let second = flows
            .flow_for_request(
                MacAddr::new(6, 5, 4, 3, 2, 1),
                Ipv4Addr::new(10, 6, 0, 3),
                target_ip,
                7,
            )
            .unwrap();

        assert_ne!(first.translated_identifier, second.translated_identifier);
        assert_eq!(
            flows
                .flow_for_reply(target_ip, second.translated_identifier)
                .unwrap()
                .client_ip,
            Ipv4Addr::new(10, 6, 0, 3)
        );
    }

    #[test]
    fn removes_expired_flows() {
        let flows = FlowTable::new();
        let client_ip = Ipv4Addr::new(10, 6, 0, 2);
        let target_ip = Ipv4Addr::new(8, 8, 8, 8);
        let flow = flows
            .flow_for_request(MacAddr::new(1, 2, 3, 4, 5, 6), client_ip, target_ip, 7)
            .unwrap();

        let client_key = ClientKey {
            client_ip,
            target_ip,
            original_identifier: 7,
        };
        let old = Instant::now() - FLOW_TTL - Duration::from_secs(1);
        flows.by_client.get_mut(&client_key).unwrap().last_seen = old;
        flows.by_reply.get_mut(&flow.reply_key()).unwrap().last_seen = old;

        flows.remove_expired(Instant::now());

        assert!(flows.by_client.is_empty());
        assert!(flows.by_reply.is_empty());
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
