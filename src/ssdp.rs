use async_std::channel::Sender;
use async_std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
    UdpSocket,
};

use crate::service::Service;
use std::error::Error;
use std::fmt;

const PROTOCOL: &str = "SSDP";

///
/// SSDP information
///
/// Contains information returned by SSDP
#[derive(Debug)]
pub struct SSDPInfo {
    location: String,
    server: String,
}

impl fmt::Display for SSDPInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.server, self.location)
    }
}

macro_rules! log_err {
    ($e:expr) => {
        eprintln!("[error]: {}: {}: {}", PROTOCOL, $e, $e.source().unwrap())
    };
}

// Get the SSDP socket address matching an IPv4/v6 address.
fn multicast_socket_addr(ip_addr: IpAddr) -> SocketAddr {
    match ip_addr {
        IpAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(239, 255, 255, 250),
            1900,
        )),
        IpAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0xc),
            1900,
            0,
            0,
        )),
    }
}

fn build_packet(dst: &SocketAddr) -> Vec<u8> {
    let m_search = format!(
        "\
    M-SEARCH * HTTP/1.1\r\n\
    Host:{}\r\n\
    Man:\"ssdp:discover\"\r\n\
    ST: ssdp:all\r\n\
    MX: 1\r\n\r\n",
        dst.to_string()
    );

    return m_search.as_bytes().to_vec();
}

fn parse_response(data: &[u8]) -> Option<SSDPInfo> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    if let Ok(_) = response.parse(data) {
        let mut server = String::new();
        let mut location = String::new();
        for header in response.headers {
            if header.name.to_ascii_lowercase() == "server" {
                server = std::str::from_utf8(header.value).unwrap().to_string();
            }

            if header.name.to_ascii_lowercase() == "location" {
                location =
                    std::str::from_utf8(header.value).unwrap().to_string();
            }
        }
        return Some(SSDPInfo { location, server });
    }
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
    let packet = build_packet(&multicast_addr);
    if let Err(err) = socket.send_to(&packet, &multicast_addr).await {
        log_err!(err)
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
            if let Err(err) = channel.send(Service::ssdp(src_ip, info)).await {
                return log_err!(err);
            }
        }
    }
}
