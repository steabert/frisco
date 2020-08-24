extern crate dns_parser;
extern crate httparse;
extern crate pnet;

use std::collections;
use std::sync;
use std::thread::JoinHandle;

mod mdns;
mod ssdp;

///
/// Loop over available interfaces and start a discovery scan
/// on each of their addresses.
///
fn main() {
    let if_inet_addresses: Vec<(std::net::IpAddr, u32)> =
        pnet::datalink::interfaces()
            .iter()
            .map(|iface| iface.ips.iter().map(move |ip| (ip.ip(), iface.index)))
            .flatten()
            .collect();
    let (sender, receiver) = sync::mpsc::channel::<String>();

    let mut scanner_thread_handles = Vec::<JoinHandle<()>>::new();

    match mdns::scan(&if_inet_addresses, sender.clone()) {
        Ok(handle) => {
            scanner_thread_handles.push(handle);
        }
        Err(msg) => eprintln!("mDNS scan failed to start: {}", msg),
    };
    match ssdp::scan(&if_inet_addresses, sender.clone()) {
        Ok(handle) => {
            scanner_thread_handles.push(handle);
        }
        Err(msg) => eprintln!("SSDP scan failed to start: {}", msg),
    };

    println!("scanning...");
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
