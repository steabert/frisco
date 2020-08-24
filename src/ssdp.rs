use std::{
    io,
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
        UdpSocket,
    },
    sync,
    thread::{sleep, spawn, JoinHandle},
    time::Duration,
};

///
/// start an SSDP scanner thread
///
/// Setup a socket and send a question to the mDNS multicast address
/// requesting a unicast reply. The replies are gathered in a separate
/// thread and sent to a logging channel.
pub fn scan(
    local_ips: &[(std::net::IpAddr, u32)],
    channel: sync::mpsc::Sender<String>,
) -> std::io::Result<JoinHandle<()>> {
    //
    // Setup source/destination socket addresses
    //
    let ssdp_v4_socket_addr =
        SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
    let ssdp_v6_socket_addr = SocketAddrV6::new(
        Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0xc),
        1900,
        0,
        0,
    );

    let local_socket_addrs = local_ips.iter().map(|(ip, scope)| match ip {
        IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(*addr, 0)),
        IpAddr::V6(addr) => {
            SocketAddr::V6(SocketAddrV6::new(*addr, 0, 0, *scope))
        }
    });

    let senders: Vec<UdpSocket> = local_socket_addrs
        .filter_map(|addr| match UdpSocket::bind(addr) {
            Ok(socket) => Some(socket),
            Err(msg) => {
                eprintln!("skipped SSDP @ {} ({})", addr, msg);
                None
            }
        })
        .collect();

    let receivers: Vec<UdpSocket> = senders
        .iter()
        .map(|sender| {
            let receiver: UdpSocket = sender.try_clone().unwrap();
            receiver.set_nonblocking(true).unwrap();
            receiver
        })
        .collect();

    //
    // start to listen for mDNS responses
    //
    let handle = spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            let mut blocked_receivers = 0;
            for receiver in &receivers {
                match receiver.recv_from(&mut buffer) {
                    Ok((n_bytes, origin)) => {
                        let ip = origin.ip();
                        let data = &buffer[0..n_bytes];
                        if let Some(name) = parse_response(data) {
                            let log_msg = format!("{} {}", ip, name);
                            if channel.send(log_msg).is_err() {
                                println!("upstream error, abort scan");
                                return;
                            }
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        blocked_receivers += 1;
                        continue;
                    }
                    Err(msg) => {
                        panic!("error while reading from UDP socket: {}", msg);
                    }
                };
            }
            if blocked_receivers == receivers.len() {
                sleep(Duration::from_millis(103));
            }
        }
    });

    //
    // send SSDP M-SEARCH
    //

    for sender in senders {
        let ssdp_socket_addr = match sender.local_addr().unwrap().ip() {
            IpAddr::V4(_) => SocketAddr::V4(ssdp_v4_socket_addr),
            IpAddr::V6(_) => SocketAddr::V6(ssdp_v6_socket_addr),
        };
        let packet = build_packet(&ssdp_socket_addr);
        if let Err(msg) = sender.send_to(&packet, &ssdp_socket_addr) {
            eprintln!("Failed to send on {}: {}", ssdp_socket_addr, msg);
        };
    }

    // We're done!
    Ok(handle)
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
