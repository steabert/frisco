/// Interfaces
///
/// Alternative to using pnet just to get the interface addresses + scope_id.
/// This makes it less portable though, as we're now stuck with only linux.
///
extern crate libc;

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type InetAddr = (IpAddr, Option<u32>);

#[derive(Debug)]
pub struct Interfaces {
    ptr_ifa_head: *mut libc::ifaddrs,
    ptr_ifa: *mut libc::ifaddrs,
}

impl Interfaces {
    fn new() -> Interfaces {
        unsafe {
            let mut ptr_ifa_head: *mut libc::ifaddrs = mem::zeroed();
            if libc::getifaddrs(&mut ptr_ifa_head) != 0 {
                panic!("failed to get interface addresses");
            }
            Interfaces {
                ptr_ifa_head,
                ptr_ifa: ptr_ifa_head,
            }
        }
    }
    fn shift(&mut self) -> Option<libc::ifaddrs> {
        if self.ptr_ifa.is_null() {
            return None;
        }
        let ifa = unsafe { *self.ptr_ifa };
        self.ptr_ifa = ifa.ifa_next;
        return Some(ifa);
    }
}

impl Drop for Interfaces {
    fn drop(&mut self) -> () {
        unsafe {
            libc::freeifaddrs(self.ptr_ifa_head);
        }
    }
}

impl Iterator for Interfaces {
    type Item = InetAddr;
    fn next(&mut self) -> Option<InetAddr> {
        let next_sockaddr = loop {
            let ifa = self.shift()?;

            let ptr_sa = ifa.ifa_addr;
            if let Some(sockaddr) = sock_addr(ptr_sa) {
                break sockaddr;
            }
        };

        return Some(inet_addr(next_sockaddr));
    }
}

enum SockAddr {
    V4(libc::sockaddr_in),
    V6(libc::sockaddr_in6),
}

fn sock_addr(c_sockaddr: *const libc::sockaddr) -> Option<SockAddr> {
    if c_sockaddr.is_null() {
        return None;
    }

    let sa_family = unsafe { (*c_sockaddr).sa_family };
    match sa_family as i32 {
        libc::AF_INET => Some(SockAddr::V4(unsafe {
            *(c_sockaddr as *const libc::sockaddr_in)
        })),
        libc::AF_INET6 => Some(SockAddr::V6(unsafe {
            *(c_sockaddr as *const libc::sockaddr_in6)
        })),
        _ => None,
    }
}

fn inet_addr(addr: SockAddr) -> InetAddr {
    match addr {
        SockAddr::V4(sockaddr) => {
            let s_addr = sockaddr.sin_addr.s_addr;
            // Note that s_addr shouldn't be used as if it was "u32"
            // because the representation in memory is already network
            // byte order.
            let bytes: [u8; 4] = unsafe { mem::transmute(s_addr) };
            return (IpAddr::V4(Ipv4Addr::from(bytes)), None);
        }
        SockAddr::V6(sockaddr) => {
            let s_addr = sockaddr.sin6_addr.s6_addr;
            let scope_id = sockaddr.sin6_scope_id;
            return (IpAddr::V6(Ipv6Addr::from(s_addr)), Some(scope_id));
        }
    }
}

pub fn ifaddrs() -> Interfaces {
    return Interfaces::new();
}
