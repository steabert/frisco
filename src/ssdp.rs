use async_std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
    UdpSocket,
};

use std::sync;

const PROTOCOL: &str = "SSDP";

macro_rules! log_err {
    ($s:expr, $($e:expr),*) => {
        eprintln!(concat!("[{}]: ", $s), PROTOCOL, $($e),*);
    };
}

macro_rules! log_fmt {
    ($s:expr, $($e:expr),*) => {
        format!(concat!("[{}]: ", $s), PROTOCOL, $($e),*);
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

fn parse_response(data: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    if let Ok(_) = response.parse(data) {
        for header in response.headers {
            if header.name.to_ascii_lowercase() == "server" {
                return Some(
                    std::str::from_utf8(header.value).unwrap().to_string(),
                );
            }
        }
    }
    return None;
}

pub async fn scan(
    ip_addr: IpAddr,
    scope: u32,
    channel: sync::mpsc::Sender<String>,
) {
    let socket_addr = match ip_addr {
        IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, 0)),
        IpAddr::V6(ipv6) => {
            SocketAddr::V6(SocketAddrV6::new(ipv6, 0, 0, scope))
        }
    };

    let socket = match UdpSocket::bind(socket_addr).await {
        Ok(socket) => socket,
        Err(msg) => {
            return log_err!("failed to bind {}: {}", socket_addr, msg);
        }
    };

    let multicast_addr = multicast_socket_addr(ip_addr);
    let packet = build_packet(&multicast_addr);
    if let Err(msg) = socket.send_to(&packet, &multicast_addr).await {
        return log_err!("failed to send to {}: {}", multicast_addr, msg);
    }

    let mut buf = [0_u8; 4096];
    loop {
        let (n_bytes, origin_addr) = match socket.recv_from(&mut buf).await {
            Ok(rsp) => rsp,
            Err(msg) => {
                return log_err!(
                    "failed to receive on {}: {}",
                    socket_addr,
                    msg
                );
            }
        };

        let src_ip = origin_addr.ip();
        let data = &buf[0..n_bytes];
        if let Some(name) = parse_response(data) {
            let log_msg = log_fmt!("{} {}", src_ip, name.to_string());
            if let Err(msg) = channel.send(log_msg) {
                return log_err!("logging failed: {}", msg);
            }
        }
    }
}
