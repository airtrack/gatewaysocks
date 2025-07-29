use std::net::Ipv4Addr;

use bytes::Bytes;
use log::info;
use pnet::packet::arp::{
    ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket,
};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::gateway::GatewaySender;

pub(super) fn new_arp(channel: UnboundedReceiver<Bytes>, gw_sender: GatewaySender) -> ArpHandler {
    ArpHandler { channel, gw_sender }
}

pub struct ArpHandler {
    channel: UnboundedReceiver<Bytes>,
    gw_sender: GatewaySender,
}

impl ArpHandler {
    pub fn start(mut self) {
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

        if let Some(arp_request) = ArpPacket::new(ethernet_packet.payload()) {
            if arp_request.get_operation() != ArpOperations::Request {
                return None;
            }

            if arp_request.get_target_proto_addr() != self.gw_sender.info.addr {
                return None;
            }

            let source_mac = ethernet_packet.get_source();
            let source_ip = arp_request.get_sender_proto_addr();

            self.send_packet(source_mac, source_ip, ArpOperations::Reply);
        }

        Some(())
    }

    fn send_packet(
        &mut self,
        destination_mac: MacAddr,
        destination_ip: Ipv4Addr,
        operation: ArpOperation,
    ) {
        info!(
            "ARP {:?} to {}[{}]",
            operation, destination_ip, destination_mac
        );

        self.gw_sender.build_and_send(1, 42, &mut |buffer| {
            let mut ethernet_packet = MutableEthernetPacket::new(buffer).unwrap();
            ethernet_packet.set_destination(destination_mac);
            ethernet_packet.set_source(self.gw_sender.info.mac);
            ethernet_packet.set_ethertype(EtherTypes::Arp);

            let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();
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
            arp_packet.set_sender_hw_addr(self.gw_sender.info.mac);
            arp_packet.set_sender_proto_addr(self.gw_sender.info.addr);
            arp_packet.set_target_hw_addr(target_hw_addr);
            arp_packet.set_target_proto_addr(destination_ip);
        });
    }
}
