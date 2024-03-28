extern crate dns_parser;
extern crate httparse;

use std::collections;

use crate::service::Service;
use futures::future::join_all;
use tokio::sync::mpsc;
use tokio::task::spawn;

mod interfaces;
mod mdns;
mod service;
mod ssdp;

///
/// Loop over available interfaces and start a discovery scan
/// on each of their addresses.
///
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (s, r) = mpsc::channel::<Service>(1024);

    let mut tasks = Vec::new();
    for (addr, scope) in interfaces::ifaddrs() {
        tasks.push(spawn(mdns::scan(addr, scope, s.clone())));
        tasks.push(spawn(ssdp::scan(addr, scope, s.clone())));
    }
    tasks.push(spawn(log(r)));

    join_all(tasks).await;

    return;
}

async fn log(mut r: mpsc::Receiver<Service>) {
    println!("scanning...");
    let mut messages = collections::HashMap::<String, Service>::new();
    while let Some(msg) = r.recv().await {
        let key = msg.key();
        if messages.contains_key(&key) {
            continue;
        }
        println!("{}", msg);
        messages.insert(key, msg);
    }
}
