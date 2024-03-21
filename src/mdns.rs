use std::error::Error;
use std::fmt;
use std::sync::Arc;

use async_std::channel::Sender;
use async_std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
    UdpSocket,
};

use crate::service::Service;

const PROTOCOL: &str = "mDNS";

const MDNS_SERVICES: [&'static str; 3] = [
    "_googlecast._tcp.local",
    "_axis-video.tcp.local",
    "_http._tcp.local",
];

///
/// mDNS information
///
/// Contains information returned by mDNS
#[derive(Debug)]
pub struct MDNSInfo {
    domain_name: String,
}

impl fmt::Display for MDNSInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.domain_name)
    }
}

macro_rules! log_err {
    ($e:expr) => {
        eprintln!("[error]: {}: {}: {}", PROTOCOL, $e, $e.source().unwrap())
    };
}

// Get the mDNS socket address matching an IPv4/v6 address.
fn multicast_socket_addr(ip_addr: IpAddr) -> SocketAddr {
    match ip_addr {
        IpAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
        )),
        IpAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
            5353,
            0,
            0,
        )),
    }
}

fn build_packet(qname: &str) -> Vec<u8> {
    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(
        qname,
        true, // prefer unicast response
        dns_parser::QueryType::PTR,
        dns_parser::QueryClass::IN,
    );
    return builder.build().unwrap();
}

fn parse_response(data: &[u8]) -> Option<MDNSInfo> {
    if let Ok(packet) = dns_parser::Packet::parse(data) {
        if let Some(answer) = packet.answers.first() {
            if let dns_parser::rdata::RData::PTR(dns_parser::rdata::Ptr(name)) =
                &answer.data
            {
                return Some(MDNSInfo {
                    domain_name: name.to_string(),
                });
            }
        }
    };
    return None;
}

pub async fn scan(
    ip_addr: IpAddr,
    scope: Option<u32>,
    channel: Sender<Service>,
) {
    let socket_addr = match ip_addr {
        IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, 0)),
        IpAddr::V6(ipv6) => {
            SocketAddr::V6(SocketAddrV6::new(ipv6, 0, 0, scope.unwrap()))
        }
    };

    let socket = match UdpSocket::bind(socket_addr).await {
        Ok(socket) => socket,
        Err(err) => {
            return log_err!(err);
        }
    };

    let multicast_addr = multicast_socket_addr(ip_addr);

    for qname in MDNS_SERVICES {
        let packet = build_packet(qname);
        if let Err(err) = socket.send_to(&packet, &multicast_addr).await {
            return log_err!(err);
        };
    }

    let mut buf = [0_u8; 4096];
    loop {
        let (n_bytes, origin_addr) = match socket.recv_from(&mut buf).await {
            Ok(rsp) => rsp,
            Err(err) => {
                return log_err!(err);
            }
        };

        let src_ip = origin_addr.ip();
        let data = &buf[0..n_bytes];
        if let Some(info) = parse_response(data) {
            if let Err(err) = channel.send(Service::mdns(src_ip, info)).await {
                return log_err!(err);
            }
        }
    }
}
