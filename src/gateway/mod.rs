use std::net::Ipv4Addr;

pub mod arp;
pub mod tcp;
pub mod udp;

pub(crate) fn is_same_subnet(addr1: Ipv4Addr, addr2: Ipv4Addr, subnet_mask: Ipv4Addr) -> bool {
    let mask = subnet_mask.octets();
    let a1 = addr1.octets();
    let a2 = addr2.octets();
    (a1[0] & mask[0] == a2[0] & mask[0])
        && (a1[1] & mask[1] == a2[1] & mask[1])
        && (a1[2] & mask[2] == a2[2] & mask[2])
        && (a1[3] & mask[3] == a2[3] & mask[3])
}
