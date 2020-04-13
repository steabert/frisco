extern crate dns_parser;

use std::net;

const MDNS_MULTICAST_DST: &str = "224.0.0.251:5353";
const SSDP_MULTICAST_DST: &str = "239.255.255.250:1900";

/// Create a pair of sender/receiver sockets
/// Note that we're not joining the multicast group,
/// as we'll only listen for unicast responses to our question.
fn socket_pair() -> (net::UdpSocket, net::UdpSocket) {
    let host_addr = net::Ipv4Addr::new(0, 0, 0, 0);

    let sender = net::UdpSocket::bind(net::SocketAddrV4::new(host_addr, 0)).unwrap();
    let receiver = sender.try_clone().unwrap();

    (sender, receiver)
}

fn main() {
    println!("prototype service discovery");

    //
    // mDNS discovery
    //
    let (mdns_sender, mdns_receiver) = socket_pair();

    // listen for mDNS unicast answers
    let mdns_handle = std::thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match mdns_receiver.recv_from(&mut buffer) {
                Ok((n_bytes, origin)) => {
                    let packet = dns_parser::Packet::parse(&buffer[0..n_bytes]).unwrap();
                    for answer in packet.answers {
                        if let dns_parser::rdata::RData::PTR(dns_parser::rdata::Ptr(name)) =
                            answer.data
                        {
                            println!("{} {:?}", origin.ip(), name.to_string());
                        }
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
    mdns_sender
        .send_to(&packet_data, MDNS_MULTICAST_DST)
        .unwrap();

    //
    // SSDP discovery
    //
    let (ssdp_sender, ssdp_receiver) = socket_pair();

    // listen for SDP reponses
    let ssdp_handle = std::thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match ssdp_receiver.recv_from(&mut buffer) {
                Ok((n_bytes, origin)) => {
                    println!(
                        "{} {:?}",
                        origin.ip(),
                        std::str::from_utf8(&buffer[0..n_bytes])
                    );
                }
                Err(msg) => println!("noooo! {}", msg),
            }; // blocking
        }
    });

    // send SSDP M-SEARCH
    let m_search =
        "M-SEARCH * HTTP/1.1\rHost:239.255.255.250:1900\rMan:\"ssdp:discover\"\rST: ssdp:all\rMX: 1\r\n\r\n";
    ssdp_sender
        .send_to(m_search.as_bytes(), SSDP_MULTICAST_DST)
        .unwrap();

    println!("listening...");

    mdns_handle.join().unwrap();
    ssdp_handle.join().unwrap();
}
