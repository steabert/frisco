/// Interfaces
///
/// Alternative to using pnet just to get the interface addresses + scope_id.
/// This makes it less portable though, as we're now stuck with only linux.
///
extern crate libc;

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type InetAddr = (IpAddr, Option<u32>);

pub fn get_if_inet_addrs() -> Vec<InetAddr> {
    let mut if_addrs: Vec<InetAddr> = Vec::new();
    unsafe {
        let mut ptr_ifa_head: *mut libc::ifaddrs =
            mem::MaybeUninit::uninit().assume_init();
        if libc::getifaddrs(&mut ptr_ifa_head) != 0 {
            return if_addrs;
        }
        // We now have a linked list in memory attached to ptr_ifa_head.
        let mut ptr_ifa = ptr_ifa_head;
        while !ptr_ifa.is_null() {
            let ptr_sa = (*ptr_ifa).ifa_addr;
            let sa_family = (*ptr_sa).sa_family;

            match sa_family as i32 {
                libc::AF_INET => {
                    let sockaddr = ptr_sa as *const libc::sockaddr_in;
                    let s_addr = (*sockaddr).sin_addr.s_addr;
                    // Note that s_addr shouldn't be used as if it was "u32"
                    // because the representation in memory is already network
                    // byte order.
                    let bytes: [u8; 4] = mem::transmute(s_addr);
                    let a = bytes[0];
                    let b = bytes[1];
                    let c = bytes[2];
                    let d = bytes[3];
                    if_addrs
                        .push((IpAddr::V4(Ipv4Addr::new(a, b, c, d)), None));
                }
                libc::AF_INET6 => {
                    let sockaddr = ptr_sa as *const libc::sockaddr_in6;
                    let scope_id = (*sockaddr).sin6_scope_id;
                    let s_addr = (*sockaddr).sin6_addr.s6_addr;
                    let a = ((s_addr[0] as u16) << 8) + s_addr[1] as u16;
                    let b = ((s_addr[2] as u16) << 8) + s_addr[3] as u16;
                    let c = ((s_addr[4] as u16) << 8) + s_addr[5] as u16;
                    let d = ((s_addr[6] as u16) << 8) + s_addr[7] as u16;
                    let e = ((s_addr[8] as u16) << 8) + s_addr[9] as u16;
                    let f = ((s_addr[10] as u16) << 8) + s_addr[11] as u16;
                    let g = ((s_addr[12] as u16) << 8) + s_addr[13] as u16;
                    let h = ((s_addr[14] as u16) << 8) + s_addr[15] as u16;
                    if_addrs.push((
                        IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h)),
                        Some(scope_id),
                    ));
                }
                _ => (),
            };

            // advance to next if address
            ptr_ifa = (*ptr_ifa).ifa_next
        }
        libc::freeifaddrs(ptr_ifa_head);
    }
    if_addrs
}
