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

/// Creates a new ARP handler with the given packet channel and gateway sender.
///
/// # Arguments
///
/// * `channel` - Receiver for incoming ARP packets from the gateway
/// * `gw_sender` - Gateway sender for transmitting ARP replies
pub(super) fn new_arp(channel: UnboundedReceiver<Bytes>, gw_sender: GatewaySender) -> ArpHandler {
    ArpHandler { channel, gw_sender }
}

/// ARP packet handler that responds to ARP requests for the gateway.
///
/// Processes incoming ARP packets and automatically responds to ARP requests
/// targeting the gateway's IP address with the appropriate ARP reply containing
/// the gateway's MAC address.
pub struct ArpHandler {
    /// Channel for receiving ARP packets from the gateway receiver
    channel: UnboundedReceiver<Bytes>,
    /// Gateway sender for transmitting ARP reply packets
    gw_sender: GatewaySender,
}

impl ArpHandler {
    /// Starts the ARP handler in a background task.
    ///
    /// Spawns an async task that continuously processes incoming ARP packets
    /// and responds to requests as needed.
    pub fn start(mut self) {
        tokio::spawn(async move {
            self.handle_loop().await;
        });
    }

    /// Main ARP processing loop that handles incoming packets.
    ///
    /// Continuously receives ARP packets from the channel and processes them.
    /// Returns None if the channel is closed.
    async fn handle_loop(&mut self) -> Option<()> {
        loop {
            let packet = self.channel.recv().await?;
            self.handle_packet(packet);
        }
    }

    /// Processes a single ARP packet and responds if appropriate.
    ///
    /// Parses the incoming packet as an ARP request and sends an ARP reply
    /// if the request is asking for the gateway's IP address.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw packet bytes containing Ethernet + ARP data
    fn handle_packet(&mut self, packet: Bytes) -> Option<()> {
        let ethernet_packet = EthernetPacket::new(&packet)?;

        if let Some(arp_request) = ArpPacket::new(ethernet_packet.payload()) {
            // Only respond to ARP requests (ignore replies)
            if arp_request.get_operation() != ArpOperations::Request {
                return None;
            }

            // Only respond if someone is asking for our IP address
            if arp_request.get_target_proto_addr() != self.gw_sender.info.addr {
                return None;
            }

            let source_mac = ethernet_packet.get_source();
            let source_ip = arp_request.get_sender_proto_addr();

            // Send ARP reply with our MAC address
            self.send_packet(source_mac, source_ip, ArpOperations::Reply);
        }

        Some(())
    }

    /// Constructs and sends an ARP packet (request or reply).
    ///
    /// Builds a complete Ethernet frame containing an ARP packet with the
    /// specified operation type and addressing information.
    ///
    /// # Arguments
    ///
    /// * `destination_mac` - Target MAC address for the Ethernet frame
    /// * `destination_ip` - Target IP address for the ARP packet
    /// * `operation` - ARP operation type (Request or Reply)
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

        // Build ARP packet: 14 bytes Ethernet + 28 bytes ARP = 42 bytes total
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
