// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use ip_network::IpNetwork;
use parking_lot::RwLock;
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use crate::device::Error;
use crate::noise::{Tunn, TunnResult};

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<socket2::Socket>,
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    preshared_key: Option<[u8; 32]>,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => {
                let network = IpNetwork::new_truncate(addr, cidr)
                    .map_err(|_| "Invalid IP format".to_owned())?;
                Ok(AllowedIP {
                    addr: network.network_address(),
                    cidr: network.netmask(),
                })
            }
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => {
                let network = IpNetwork::new_truncate(addr, cidr)
                    .map_err(|_| "Invalid IP format".to_owned())?;
                Ok(AllowedIP {
                    addr: network.network_address(),
                    cidr: network.netmask(),
                })
            }
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl Peer {
    /// Allowed IPs are deliberately absent: `Device::peers_by_ip` owns them.
    pub fn new(
        tunnel: Tunn,
        index: u32,
        endpoint: Option<SocketAddr>,
        preshared_key: Option<[u8; 32]>,
    ) -> Peer {
        Peer {
            tunnel,
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            preshared_key,
        }
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub(crate) fn endpoint_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Endpoint> {
        self.endpoint.write()
    }

    pub fn shutdown_endpoint(&self) {
        if let Some(conn) = self.endpoint.write().conn.take() {
            tracing::info!("Disconnecting from endpoint");
            conn.shutdown(Shutdown::Both).unwrap();
        }
    }

    pub fn set_endpoint(&mut self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr != Some(addr) {
            // A roaming peer gets a fresh UDP size estimate, as in upstream.
            self.tunnel.reset_udp_window();
            // We only need to update the endpoint if it differs from the current one
            if let Some(conn) = endpoint.conn.take() {
                conn.shutdown(Shutdown::Both).unwrap();
            }

            endpoint.addr = Some(addr);
        }
    }

    pub fn connect_endpoint(
        &self,
        port: u16,
        fwmark: Option<u32>,
    ) -> Result<socket2::Socket, Error> {
        let mut endpoint = self.endpoint.write();

        if endpoint.conn.is_some() {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let addr = endpoint
            .addr
            .expect("Attempt to connect to undefined endpoint");

        let udp_conn =
            socket2::Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        udp_conn.set_reuse_address(true)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        udp_conn.connect(&addr.into())?;
        udp_conn.set_nonblocking(true)?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(fwmark) = fwmark {
            udp_conn.set_mark(fwmark)?;
        }

        tracing::info!(
            message="Connected endpoint",
            port=port,
            endpoint=?endpoint.addr.unwrap()
        );

        endpoint.conn = Some(udp_conn.try_clone().unwrap());

        Ok(udp_conn)
    }

    /// Replace this peer's pre-shared key, discarding sessions if it changed.
    pub(crate) fn set_preshared_key(&mut self, preshared_key: Option<[u8; 32]>) {
        self.preshared_key = preshared_key;
        self.tunnel.set_preshared_key(preshared_key);
    }

    /// Replace this peer's persistent-keepalive interval range, keeping sessions.
    pub(crate) fn set_persistent_keepalive_range(&mut self, keepalive: Option<(u32, u32)>) {
        self.tunnel.set_persistent_keepalive_range(keepalive);
    }

    /// The configured persistent-keepalive range, if enabled.
    pub fn persistent_keepalive_range(&self) -> Option<(u32, u32)> {
        self.tunnel.persistent_keepalive_range()
    }

    // Deliberately no `is_allowed_ip` / `allowed_ips` here. Which prefixes
    // route to a peer is a property of `Device::peers_by_ip`, and keeping a
    // second copy on the peer is what let the two disagree: a prefix moved
    // between peers updated the trie and left the old owner's copy behind,
    // so it could still source-spoof an address it no longer held. Use
    // `Device::peer_owns` and `Device::peer_allowed_ips`.

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    pub fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::amnezia::{AmneziaConfig, DEFAULT_UDP_WINDOW};
    use crate::noise::TunnResult;
    use rand_core::OsRng;

    fn take_network_packet(result: TunnResult<'_>) -> Vec<u8> {
        match result {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected network packet, got {:?}", other),
        }
    }

    fn complete_handshake(sender: &mut crate::noise::Tunn, receiver: &mut crate::noise::Tunn) {
        let mut buffer = vec![0u8; 2048];
        let init = take_network_packet(sender.format_handshake_initiation(&mut buffer, false));

        let mut buffer = vec![0u8; 2048];
        let response = take_network_packet(receiver.decapsulate(None, &init, &mut buffer));

        let mut buffer = vec![0u8; 2048];
        let keepalive = take_network_packet(sender.decapsulate(None, &response, &mut buffer));

        let mut buffer = vec![0u8; 2048];
        assert!(matches!(
            receiver.decapsulate(None, &keepalive, &mut buffer),
            TunnResult::Done
        ));
    }

    fn ipv4_udp_packet(size: usize) -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet.resize(size, 0);
        packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        packet[24..26].copy_from_slice(&((size - 20) as u16).to_be_bytes());
        packet
    }

    #[test]
    fn endpoint_roaming_resets_learned_udp_window() {
        let cfg = AmneziaConfig::new(0, 0, 0, 0).with_random_trailers(true);
        let local_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let local_public = x25519_dalek::PublicKey::from(&local_secret);
        let remote_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let remote_public = x25519_dalek::PublicKey::from(&remote_secret);

        let mut sender = crate::noise::Tunn::new_with_amnezia(
            local_secret, remote_public, None, None, 1, None,
            0, 0, 0, 0, 0, 0, 0, 0, cfg.clone(),
        ).unwrap();
        let mut receiver = crate::noise::Tunn::new_with_amnezia(
            remote_secret, local_public, None, None, 2, None,
            0, 0, 0, 0, 0, 0, 0, 0, cfg,
        ).unwrap();
        complete_handshake(&mut sender, &mut receiver);

        let first_endpoint = "192.0.2.1:51820".parse().unwrap();
        let new_endpoint = "192.0.2.2:51820".parse().unwrap();
        let mut peer = Peer::new(sender, 1, Some(first_endpoint), None);

        // A large outbound packet raises the peer's high-water mark above the
        // default. A subsequent small packet can then receive a large trailer.
        let large = ipv4_udp_packet(600);
        let mut buffer = vec![0u8; 4096];
        let large_datagram = take_network_packet(peer.tunnel.encapsulate(&large, &mut buffer));
        assert_eq!(large_datagram.len(), 600 + 32);

        let small = ipv4_udp_packet(28);
        let mut observed_above_default = false;
        for _ in 0..256 {
            let mut buffer = vec![0u8; 4096];
            let datagram = take_network_packet(peer.tunnel.encapsulate(&small, &mut buffer));
            if datagram.len() > DEFAULT_UDP_WINDOW {
                observed_above_default = true;
                break;
            }
        }
        assert!(
            observed_above_default,
            "the learned high-water mark should permit a trailer above the default window"
        );

        peer.set_endpoint(new_endpoint);

        for _ in 0..64 {
            let mut buffer = vec![0u8; 4096];
            let datagram = take_network_packet(peer.tunnel.encapsulate(&small, &mut buffer));
            assert!(
                datagram.len() <= DEFAULT_UDP_WINDOW,
                "roaming must reset the old endpoint's learned UDP window"
            );
        }
    }
}
