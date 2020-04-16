extern crate dns_parser;
extern crate httparse;
extern crate ipnetwork;
extern crate pnet;

use std::collections;
use std::net;
use std::sync;
use std::thread;

type DiscoveryResponse = (String, Vec<u8>);

fn start_scanner_thread(
    ip: ipnetwork::IpNetwork,
    sender: sync::mpsc::Sender<DiscoveryResponse>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let socket: net::UdpSocket = match ip {
        ipnetwork::IpNetwork::V4(ipv4_network) => {
            net::UdpSocket::bind(net::SocketAddrV4::new(ipv4_network.ip(), 0))?
        }

        ipnetwork::IpNetwork::V6(ipv6_network) => {
            net::UdpSocket::bind(net::SocketAddrV6::new(ipv6_network.ip(), 0, 0, 0))?
        }
    };

    let receiver = socket.try_clone().unwrap();
    let handle = thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match receiver.recv_from(&mut buffer) {
                Ok((n_bytes, origin)) => {
                    if sender
                        .send((origin.ip().to_string(), (&buffer[0..n_bytes]).to_vec()))
                        .is_err()
                    {
                        println!("upstream error, abort scan");
                        return;
                    }
                }
                Err(msg) => println!("noooo! {}", msg),
            }; // blocking
        }
    });

    send_discovery_packet(socket)?;

    Ok(handle)
}

// Send mDNS question and SSDP M-SEARCH from a socket
fn send_discovery_packet(socket: net::UdpSocket) -> std::io::Result<()> {
    //
    // send mDNS question
    //
    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(
        "_googlecast._tcp.local",
        true, // prefer unicast response
        dns_parser::QueryType::PTR,
        dns_parser::QueryClass::IN,
    );
    let packet_data = builder.build().unwrap();

    socket.send_to(&packet_data, "224.0.0.251:5353")?;

    //
    // send SSDP M-SEARCH
    //
    let m_search =
        "M-SEARCH * HTTP/1.1\rHost:239.255.255.250:1900\rMan:\"ssdp:discover\"\rST: ssdp:all\rMX: 1\r\n\r\n";

    socket.send_to(m_search.as_bytes(), "239.255.255.250:1900")?;

    // Everything fine
    Ok(())
}

fn parse_discovery_responses(receiver: sync::mpsc::Receiver<DiscoveryResponse>) {
    // Store discovered addresses so we can skip them.
    let mut address_store = collections::HashSet::<String>::new();

    for (ip, data) in receiver.into_iter() {
        // Ignore already discovered IPs.
        if address_store.contains(&ip) {
            continue;
        }

        if &data[0..4] == "HTTP".as_bytes() {
            // Assume it's an SSDP response.
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut response = httparse::Response::new(&mut headers);
            if let Ok(_) = response.parse(&data) {
                for header in response.headers {
                    if header.name.to_ascii_lowercase() == "server" {
                        println!("{} {}", ip, std::str::from_utf8(header.value).unwrap());
                    }
                }
            }
        } else {
            // Assume it's a mDNS response.
            if let Ok(packet) = dns_parser::Packet::parse(&data) {
                for answer in packet.answers {
                    if let dns_parser::rdata::RData::PTR(dns_parser::rdata::Ptr(name)) = answer.data
                    {
                        println!("{} {}", ip, name.to_string());
                    }
                }
            };
        }

        // Remember so we can skip it next time.
        address_store.insert(ip);
    }
}

/// Print list of IP, name of discovered mDNS/SSDP services.
fn main() {
    let interfaces = pnet::datalink::interfaces();

    let (sender, receiver) = sync::mpsc::channel::<DiscoveryResponse>();

    let mut scanner_thread_handles = Vec::<thread::JoinHandle<()>>::new();
    let mut success = Vec::new();
    let mut failure = Vec::new();
    for interface in interfaces {
        for ip in interface.ips {
            match start_scanner_thread(ip, sender.clone()) {
                Ok(handle) => {
                    scanner_thread_handles.push(handle);
                    success.push(format!("  {} @ {}", interface.name, ip.to_string()))
                }
                Err(msg) => failure.push(format!(
                    "  {} @ {} ({})",
                    interface.name,
                    ip.to_string(),
                    msg
                )),
            };
        }
    }

    println!("Started scanning on:");
    for msg in success {
        println!("{}", msg);
    }

    println!("Failed to start scanning on:");
    for msg in failure {
        println!("{}", msg);
    }

    println!("\nlistening for mDNS/SSDP replies...");
    parse_discovery_responses(receiver);

    for handle in scanner_thread_handles {
        handle.join().unwrap();
    }

    return;
}
