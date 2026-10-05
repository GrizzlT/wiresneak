use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct IpPacket {
    pub source: IpAddr,
    pub dest: IpAddr,
    pub content: Bytes,
}

pub fn parse_packet_addrs(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    if packet.is_empty() {
        return None;
    }
    let version = packet[0] >> 4;

    if packet.len() >= 40 && version == 6 {
        let src = Ipv6Addr::from_octets(packet[8..24].try_into().unwrap()).into();
        let dst = Ipv6Addr::from_octets(packet[24..40].try_into().unwrap()).into();
        return Some((src, dst));
    } else if packet.len() >= 20 && version == 4 {
        let src = Ipv4Addr::from_octets(packet[12..16].try_into().unwrap()).into();
        let dst = Ipv4Addr::from_octets(packet[16..20].try_into().unwrap()).into();
        return Some((src, dst));
    }
    None
}
