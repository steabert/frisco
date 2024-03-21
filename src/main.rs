extern crate dns_parser;
extern crate httparse;

use std::collections;

use crate::service::Service;
use async_std::channel;
use async_std::task::spawn;
use futures::future::join_all;

mod interfaces;
mod mdns;
mod service;
mod ssdp;

///
/// Loop over available interfaces and start a discovery scan
/// on each of their addresses.
///
#[async_std::main]
async fn main() {
    let (s, r) = channel::unbounded::<Service>();

    let mut tasks = Vec::new();
    for (addr, scope) in interfaces::ifaddrs() {
        tasks.push(spawn(mdns::scan(addr, scope, s.clone())));
        tasks.push(spawn(ssdp::scan(addr, scope, s.clone())));
    }
    tasks.push(spawn(log(r.clone())));

    join_all(tasks).await;

    return;
}

async fn log(r: channel::Receiver<Service>) {
    println!("scanning...");
    let mut messages = collections::HashMap::<String, Service>::new();
    while let Ok(msg) = r.recv().await {
        let key = msg.key();
        if messages.contains_key(&key) {
            continue;
        }
        println!("{}", msg);
        messages.insert(key, msg);
    }
}
