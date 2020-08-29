extern crate dns_parser;
extern crate httparse;
extern crate pnet;

use std::collections;
use std::{net::IpAddr, sync};

mod mdns;
mod service;
mod ssdp;

use crate::service::Service;

///
/// Loop over available interfaces and start a discovery scan
/// on each of their addresses.
///
#[async_std::main]
async fn main() {
    let (send_service, recv_service) = sync::mpsc::channel::<Service>();

    let mut scan_handles = Vec::new();
    for iface in pnet::datalink::interfaces() {
        for ip_network in iface.ips {
            scan_handles.push(async_std::task::spawn(mdns::scan(
                ip_network.ip(),
                iface.index,
                send_service.clone(),
            )));

            scan_handles.push(async_std::task::spawn(ssdp::scan(
                ip_network.ip(),
                iface.index,
                send_service.clone(),
            )));
        }
    }

    println!("scanning...");
    let mut services = collections::HashMap::<String, Service>::new();
    for service in recv_service.into_iter() {
        let key = service.key();
        if services.contains_key(&key) {
            continue;
        }
        println!("{}", service);
        services.insert(key, service);
    }

    for handle in scan_handles {
        handle.await;
    }

    return;
}
