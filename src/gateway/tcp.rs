use std::net::{Ipv4Addr, SocketAddrV4};

use log::info;
use pnet::datalink::DataLinkSender;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::util::MacAddr;

use super::is_to_gateway;

pub struct TcpProcessor {
    _mac: MacAddr,
    gateway: Ipv4Addr,
    subnet_mask: Ipv4Addr,
}

pub enum TcpLayerPacket {
    Connect((String, SocketAddrV4)),
    Push((String, Vec<u8>)),
    Shutdown(String),
    Close(String),
}

impl TcpProcessor {
    pub fn new(mac: MacAddr, gateway: Ipv4Addr, subnet_mask: Ipv4Addr) -> Self {
        Self {
            _mac: mac,
            gateway,
            subnet_mask,
        }
    }

    pub fn handle_input_packet(
        &mut self,
        _source_mac: MacAddr,
        request: &Ipv4Packet,
    ) -> Option<TcpLayerPacket> {
        if !is_to_gateway(self.gateway, self.subnet_mask, request.get_source()) {
            return None;
        }

        info!(
            "TCP packet {} -> {}",
            request.get_source(),
            request.get_destination()
        );

        None
    }

    pub fn handle_output_packet(
        &self,
        _tx: &mut Box<dyn DataLinkSender>,
        _packet: &TcpLayerPacket,
    ) {
    }
}
