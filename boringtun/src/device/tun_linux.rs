// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use libc::*;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

const TUNSETIFF: u64 = 0x4004_54ca;
const TUNGETIFF: u64 = 0x8004_54d2;

#[repr(C)]
union IfrIfru {
    ifru_addr: sockaddr,
    ifru_addr_v4: sockaddr_in,
    ifru_addr_v6: sockaddr_in,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_flags: c_short,
    ifru_metric: c_int,
    ifru_mtu: c_int,
    ifru_phys: c_int,
    ifru_media: c_int,
    ifru_intval: c_int,
    //ifru_data: caddr_t,
    //ifru_devmtu: ifdevmtu,
    //ifru_kpi: ifkpi,
    ifru_wake_flags: u32,
    ifru_route_refcnt: u32,
    ifru_cap: [c_int; 2],
    ifru_functional_type: u32,
}

#[repr(C)]
pub struct ifreq {
    ifr_name: [c_uchar; IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
    name: String,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl TunSocket {
    fn write(&self, buf: &[u8]) -> usize {
        match unsafe { write(self.fd, buf.as_ptr() as _, buf.len() as _) } {
            -1 => 0,
            n => n as usize,
        }
    }

    pub fn new(name: &str) -> Result<TunSocket, Error> {
        // If the provided name appears to be a FD, use that.
        let provided_fd = name.parse::<i32>();
        if let Ok(fd) = provided_fd {
            return Ok(TunSocket {
                fd,
                name: name.to_string(),
            });
        }

        let fd = match unsafe { open(b"/dev/net/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => fd,
        };
        let iface_name = name.as_bytes();
        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru {
                ifru_flags: (IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE) as _,
            },
        };

        if iface_name.len() >= ifr.ifr_name.len() {
            return Err(Error::InvalidTunnelName);
        }

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, TUNSETIFF as _, &ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        let name = name.to_string();
        Ok(TunSocket { fd, name })
    }

    pub fn set_non_blocking(self) -> Result<TunSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(io::Error::last_os_error())),
            flags => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(io::Error::last_os_error())),
                _ => Ok(self),
            },
        }
    }

    pub fn name(&self) -> Result<String, Error> {
        Ok(self.name.clone())
    }

    /// Verify that this descriptor is still attached to the interface it
    /// originally created. Looking up the name in the network namespace is
    /// insufficient: Linux can delete the link and create an unrelated link
    /// with the same name while this descriptor remains detached.
    pub fn verify_identity(&self) -> Result<(), Error> {
        if self.name.parse::<i32>().is_ok() {
            return Err(Error::InvalidTunnelName);
        }

        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru { ifru_flags: 0 },
        };
        if unsafe { ioctl(self.fd, TUNGETIFF as _, &mut ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        let actual =
            unsafe { std::ffi::CStr::from_ptr(ifr.ifr_name.as_ptr() as *const c_char) }
                .to_string_lossy();
        if actual != self.name {
            return Err(Error::IOCtl(io::Error::new(
                io::ErrorKind::NotConnected,
                format!(
                    "TUN descriptor identity changed: expected '{}', got '{}'",
                    self.name, actual
                ),
            )));
        }
        Ok(())
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, Error> {
        let provided_fd = self.name.parse::<i32>();
        if provided_fd.is_ok() {
            return Ok(1500);
        }

        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(io::Error::last_os_error())),
            fd => fd,
        };

        let name = self.name()?;
        let iface_name: &[u8] = name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, SIOCGIFMTU as _, &ifr) } < 0 {
            return Err(Error::IOCtl(io::Error::last_os_error()));
        }

        unsafe { close(fd) };

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as _)
    }

    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        match unsafe { read(self.fd, dst.as_mut_ptr() as _, dst.len()) } {
            -1 => Err(Error::IfaceRead(io::Error::last_os_error())),
            n => Ok(&mut dst[..n as usize]),
        }
    }
}


#[cfg(test)]
mod identity_tests {
    use super::*;
    use std::process::Command;

    /// Exercises the kernel lifecycle, not just name lookup: a replacement
    /// TUN with the same name must never make the old descriptor valid again.
    #[test]
    #[ignore = "requires root, /dev/net/tun and iproute2"]
    fn detached_tun_descriptor_does_not_attach_to_same_name_replacement() {
        let name = format!("btid{:x}", std::process::id());
        let original = TunSocket::new(&name).expect("create original TUN");
        original
            .verify_identity()
            .expect("original descriptor should identify its interface");

        let deleted = Command::new("ip")
            .args(["link", "delete", "dev", &name])
            .status()
            .expect("run ip link delete");
        assert!(deleted.success(), "failed to delete original TUN");

        let replacement = TunSocket::new(&name).expect("create replacement TUN");
        replacement
            .verify_identity()
            .expect("replacement descriptor should identify replacement");
        assert!(
            original.verify_identity().is_err(),
            "detached descriptor must not inherit a same-name replacement"
        );
    }
}
