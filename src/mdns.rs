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
/// start an mDNS scanner thread
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
    let mdns_v4_socket_addr =
        SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
    let mdns_v6_socket_addr = SocketAddrV6::new(
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
        5353,
        0,
        0,
    );

    let local_socket_addrs = local_ips.iter().map(|(addr, scope)| match addr {
        IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(*ipv4, 0)),
        IpAddr::V6(ipv6) => {
            SocketAddr::V6(SocketAddrV6::new(*ipv6, 0, 0, *scope))
        }
    });

    let senders: Vec<UdpSocket> = local_socket_addrs
        .filter_map(|addr| match UdpSocket::bind(addr) {
            Ok(socket) => Some(socket),
            Err(msg) => {
                eprintln!("skipped mDNS @ {} ({})", addr, msg);
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

    // start to listen for mDNS responses

    let handle = spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            let mut blocked_receivers = 0;
            for receiver in &receivers {
                match receiver.recv_from(&mut buffer) {
                    Ok((n_bytes, origin)) => {
                        let src_ip = origin.ip();
                        let data = &buffer[0..n_bytes];
                        if let Some(name) = parse_response(data) {
                            let log_msg =
                                format!("{} {}", src_ip, name.to_string());
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
                sleep(Duration::from_millis(97));
            }
        }
    });

    //
    // send mDNS question
    //
    let packet = build_packet();

    for sender in senders {
        let mdns_socket_addr = match sender.local_addr().unwrap().ip() {
            IpAddr::V4(_) => SocketAddr::V4(mdns_v4_socket_addr),
            IpAddr::V6(_) => SocketAddr::V6(mdns_v6_socket_addr),
        };
        if let Err(msg) = sender.send_to(&packet, &mdns_socket_addr) {
            eprintln!("Failed to send on {}: {}", mdns_socket_addr, msg);
        };
    }

    // We're done!
    Ok(handle)
}

fn build_packet() -> Vec<u8> {
    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(
        "_googlecast._tcp.local",
        true, // prefer unicast response
        dns_parser::QueryType::PTR,
        dns_parser::QueryClass::IN,
    );
    println!("{:?}", builder);
    return builder.build().unwrap();
}

fn parse_response(data: &[u8]) -> Option<String> {
    if let Ok(packet) = dns_parser::Packet::parse(data) {
        for answer in packet.answers.first() {
            if let dns_parser::rdata::RData::PTR(dns_parser::rdata::Ptr(name)) =
                answer.data
            {
                return Some(name.to_string());
            }
        }
    };
    return None;
}
