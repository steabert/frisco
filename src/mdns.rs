use async_std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket,
};

use std::error::Error;
use std::sync;

const PROTOCOL: &str = "mDNS";

macro_rules! log_err {
    ($e:expr) => {
        eprintln!("[error]: {}: {}: {}", PROTOCOL, $e, $e.source().unwrap());
    };
}

macro_rules! log_fmt {
    ($ip:expr, $s:expr) => {
        format!("{:16} {:8} {}", $ip, PROTOCOL, $s);
    };
}

// Get the mDNS socket address matching an IPv4/v6 address.
fn multicast_socket_addr(ip_addr: IpAddr) -> SocketAddr {
    match ip_addr {
        IpAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353)),
        IpAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
            5353,
            0,
            0,
        )),
    }
}

fn build_packet() -> Vec<u8> {
    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(
        "_googlecast._tcp.local",
        true, // prefer unicast response
        dns_parser::QueryType::PTR,
        dns_parser::QueryClass::IN,
    );
    return builder.build().unwrap();
}

fn parse_response(data: &[u8]) -> Option<String> {
    if let Ok(packet) = dns_parser::Packet::parse(data) {
        for answer in packet.answers.first() {
            if let dns_parser::rdata::RData::PTR(dns_parser::rdata::Ptr(name)) = answer.data {
                return Some(name.to_string());
            }
        }
    };
    return None;
}

pub async fn scan(ip_addr: IpAddr, scope: u32, channel: sync::mpsc::Sender<String>) {
    let socket_addr = match ip_addr {
        IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, 0)),
        IpAddr::V6(ipv6) => SocketAddr::V6(SocketAddrV6::new(ipv6, 0, 0, scope)),
    };

    let socket = match UdpSocket::bind(socket_addr).await {
        Ok(socket) => socket,
        Err(err) => {
            return log_err!(err);
        }
    };

    let multicast_addr = multicast_socket_addr(ip_addr);
    let packet = build_packet();
    if let Err(err) = socket.send_to(&packet, &multicast_addr).await {
        return log_err!(err);
    };

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
        if let Some(name) = parse_response(data) {
            let log_msg = log_fmt!(src_ip, name.to_string());
            if let Err(err) = channel.send(log_msg) {
                return log_err!(err);
            }
        }
    }
}
