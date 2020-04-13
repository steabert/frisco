extern crate dns_parser;
extern crate httparse;

use std::collections;
use std::net;

/// Print list of IP, name of discovered mDNS/SSDP services.
fn main() {
    // Store discovered addresses so we can skip them.
    let mut address_store = collections::HashSet::new();

    // Set up sending an receiving sockets.
    let host_addr = net::Ipv4Addr::new(0, 0, 0, 0);
    let sender = net::UdpSocket::bind(net::SocketAddrV4::new(host_addr, 0)).unwrap();
    let receiver = sender.try_clone().unwrap();

    //
    // mDNS discovery
    //

    // listen for mDNS unicast answers / SSDP responses
    let receiver_handle = std::thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match receiver.recv_from(&mut buffer) {
                Ok((n_bytes, origin)) => {
                    if address_store.contains(&origin) {
                        continue;
                    }
                    address_store.insert(origin);
                    if &buffer[0..4] == "HTTP".as_bytes() {
                        // Assume it's an SSDP response.
                        let mut headers = [httparse::EMPTY_HEADER; 32];
                        let mut response = httparse::Response::new(&mut headers);
                        if let Ok(_) = response.parse(&buffer[0..n_bytes]) {
                            for header in response.headers {
                                if header.name.to_ascii_lowercase() == "server" {
                                    println!(
                                        "{} {}",
                                        origin.ip(),
                                        std::str::from_utf8(header.value).unwrap()
                                    );
                                }
                            }
                        }
                    } else {
                        // Assume it's a mDNS response.
                        if let Ok(packet) = dns_parser::Packet::parse(&buffer[0..n_bytes]) {
                            for answer in packet.answers {
                                if let dns_parser::rdata::RData::PTR(dns_parser::rdata::Ptr(name)) =
                                    answer.data
                                {
                                    println!("{} {}", origin.ip(), name.to_string());
                                }
                            }
                        };
                    }
                }
                Err(msg) => println!("noooo! {}", msg),
            }; // blocking
        }
    });

    // send mDNS question
    let mut builder = dns_parser::Builder::new_query(0, false);
    builder.add_question(
        "_googlecast._tcp.local",
        true, // prefer unicast response
        dns_parser::QueryType::PTR,
        dns_parser::QueryClass::IN,
    );
    let packet_data = builder.build().unwrap();
    sender.send_to(&packet_data, "224.0.0.251:5353").unwrap();

    // send SSDP M-SEARCH
    let m_search =
        "M-SEARCH * HTTP/1.1\rHost:239.255.255.250:1900\rMan:\"ssdp:discover\"\rST: ssdp:all\rMX: 1\r\n\r\n";
    sender
        .send_to(m_search.as_bytes(), "239.255.255.250:1900")
        .unwrap();

    // Gather responses
    println!("listening for mDNS/SSDP replies...");
    receiver_handle.join().unwrap();
}
