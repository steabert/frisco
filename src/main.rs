extern crate dns_parser;
extern crate httparse;
extern crate ipnetwork;
extern crate pnet;

use std::collections;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
    UdpSocket,
};
use std::sync;
use std::thread;

///
/// start an mDNS scanner thread
///
/// Setup a socket and send a question to the mDNS multicast address
/// requesting a unicast reply. The replies are gathered in a separate
/// thread and sent to a logging channel.

fn scan_mdns(
    ip: IpAddr,
    channel: sync::mpsc::Sender<String>,
) -> std::io::Result<thread::JoinHandle<()>> {
    //
    // Setup source/destination socket addresses
    //
    let (socket_addr, mdns_socket_addr) = match ip {
        IpAddr::V4(addr) => (
            SocketAddr::V4(SocketAddrV4::new(addr, 0)),
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(224, 0, 0, 251),
                5353,
            )),
        ),
        IpAddr::V6(addr) => (
            SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0)),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb),
                5353,
                0,
                0,
            )),
        ),
    };

    let sender = UdpSocket::bind(socket_addr)?;
    let receiver = sender.try_clone().unwrap();

    //
    // start to listen for mDNS responses
    //
    let handle = thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match receiver.recv_from(&mut buffer) {
                Ok((n_bytes, origin)) => {
                    let src_ip = origin.ip();
                    let data = &buffer[0..n_bytes];
                    if let Some(name) = parse_mdns_response(data) {
                        let log_msg =
                            format!("{} {}", src_ip, name.to_string());
                        if channel.send(log_msg).is_err() {
                            println!("upstream error, abort scan");
                            return;
                        }
                    }
                }
                Err(msg) => println!("noooo! {}", msg),
            }; // blocking
        }
    });

    //
    // send mDNS question
    //
    let packet_data = build_mdns_packet();
    sender.send_to(&packet_data, &mdns_socket_addr)?;

    // We're done!
    Ok(handle)
}

fn build_mdns_packet() -> Vec<u8> {
    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(
        "_googlecast._tcp.local",
        true, // prefer unicast response
        dns_parser::QueryType::PTR,
        dns_parser::QueryClass::IN,
    );
    return builder.build().unwrap();
}

fn parse_mdns_response(data: &[u8]) -> Option<String> {
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

///
/// start an SSDP scanner thread
///
/// Setup a socket and send a question to the mDNS multicast address
/// requesting a unicast reply. The replies are gathered in a separate
/// thread and sent to a logging channel.
fn scan_ssdp(
    ip: IpAddr,
    channel: sync::mpsc::Sender<String>,
) -> std::io::Result<thread::JoinHandle<()>> {
    //
    // Setup source/destination socket addresses
    //
    let (socket_addr, ssdp_socket_addr) = match ip {
        IpAddr::V4(addr) => (
            SocketAddr::V4(SocketAddrV4::new(addr, 0)),
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(239, 255, 255, 250),
                1900,
            )),
        ),
        IpAddr::V6(addr) => (
            SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0)),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc),
                1900,
                0,
                0,
            )),
        ),
    };

    let sender = UdpSocket::bind(socket_addr)?;
    let receiver = sender.try_clone().unwrap();

    //
    // start to listen for mDNS responses
    //
    let handle = thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match receiver.recv_from(&mut buffer) {
                Ok((n_bytes, origin)) => {
                    let ip = origin.ip();
                    let data = &buffer[0..n_bytes];
                    if let Some(name) = parse_ssdp_response(data) {
                        let log_msg = format!("{} {}", ip, name);
                        if channel.send(log_msg).is_err() {
                            println!("upstream error, abort scan");
                            return;
                        }
                    }
                }
                Err(msg) => println!("noooo! {}", msg),
            }; // blocking
        }
    });

    //
    // send SSDP M-SEARCH
    //
    let packet = build_ssdp_packet();
    sender.send_to(&packet, ssdp_socket_addr)?;

    // We're done!
    Ok(handle)
}

fn build_ssdp_packet() -> Vec<u8> {
    let m_search = "\
        M-SEARCH * HTTP/1.1\r\
        Host:239.255.255.250:1900\r\
        Man:\"ssdp:discover\"\r\
        ST: ssdp:all\rMX: 1\r\n\r\n";
    return m_search.as_bytes().to_vec();
}

fn parse_ssdp_response(data: &[u8]) -> Option<String> {
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

///
/// Loop over available interfaces and start a discovery scan
/// on each of their addresses.
///
fn main() {
    let interfaces = pnet::datalink::interfaces();

    let (sender, receiver) = sync::mpsc::channel::<String>();

    let mut scanner_thread_handles = Vec::<thread::JoinHandle<()>>::new();
    for interface in interfaces {
        println!("scanning on interface {}:", interface.name);
        for ip_network in interface.ips {
            let ip = ip_network.ip();
            println!("@ {}", ip);
            match scan_mdns(ip, sender.clone()) {
                Ok(handle) => {
                    scanner_thread_handles.push(handle);
                    println!("  mDNS [OK]")
                }
                Err(msg) => println!("  mDNS [FAILED] ({})", msg),
            };
            match scan_ssdp(ip, sender.clone()) {
                Ok(handle) => {
                    scanner_thread_handles.push(handle);
                    println!("  SSDP [OK]")
                }
                Err(msg) => println!("  SSDP [FAILED] ({})", msg),
            };
        }
    }

    println!("\nlistening for mDNS/SSDP replies...");
    let mut log_set = collections::HashSet::<String>::new();
    for log_msg in receiver.into_iter() {
        if log_set.contains(&log_msg) {
            continue;
        }
        println!("{}", log_msg);
        log_set.insert(log_msg);
    }

    for handle in scanner_thread_handles {
        handle.join().unwrap();
    }

    return;
}
