use std::{fmt, net::IpAddr};

use crate::mdns::MDNSInfo;
use crate::ssdp::SSDPInfo;

#[derive(Debug)]
pub enum ServiceInfo {
    MDNS(MDNSInfo),
    SSDP(SSDPInfo),
}

#[derive(Debug)]
pub struct Service {
    ip: IpAddr,
    info: ServiceInfo,
}

impl Service {
    pub fn new(ip: IpAddr, info: ServiceInfo) -> Service {
        Service { ip, info }
    }

    pub fn mdns(ip: IpAddr, info: MDNSInfo) -> Service {
        Service {
            ip,
            info: ServiceInfo::MDNS(info),
        }
    }

    pub fn ssdp(ip: IpAddr, info: SSDPInfo) -> Service {
        Service {
            ip,
            info: ServiceInfo::SSDP(info),
        }
    }

    pub fn key(&self) -> String {
        match &self.info {
            ServiceInfo::SSDP(_) => {
                format!("{}:{}", "SSDP", self.ip.to_string())
            }
            ServiceInfo::MDNS(_) => {
                format!("{}:{}", "MDNS", self.ip.to_string())
            }
        }
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.info {
            ServiceInfo::SSDP(info) => {
                write!(f, "{:16} {:8} {}", self.ip, "SSDP", info)
            }
            ServiceInfo::MDNS(info) => {
                write!(f, "{:16} {:8} {}", self.ip, "mDNS", info)
            }
        }
    }
}
