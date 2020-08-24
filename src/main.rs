extern crate dns_parser;
extern crate httparse;
extern crate pnet;

use std::collections;
use std::sync;

mod mdns;
mod ssdp;

///
/// Loop over available interfaces and start a discovery scan
/// on each of their addresses.
///
#[async_std::main]
async fn main() {
    let (sender, receiver) = sync::mpsc::channel::<String>();

    let mut scan_handles = Vec::new();
    for iface in pnet::datalink::interfaces() {
        for ip_network in iface.ips {
            scan_handles.push(async_std::task::spawn(mdns::scan(
                ip_network.ip(),
                iface.index,
                sender.clone(),
            )));

            scan_handles.push(async_std::task::spawn(ssdp::scan(
                ip_network.ip(),
                iface.index,
                sender.clone(),
            )));
        }
    }

    println!("scanning...");
    let mut log_set = collections::HashSet::<String>::new();
    for log_msg in receiver.into_iter() {
        if log_set.contains(&log_msg) {
            continue;
        }
        println!("{}", log_msg);
        log_set.insert(log_msg);
    }

    for handle in scan_handles {
        handle.await;
    }

    return;
}
