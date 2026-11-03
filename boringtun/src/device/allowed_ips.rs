// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use crate::device::peer::AllowedIP;

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

use std::collections::VecDeque;
use std::iter::FromIterator;
use std::net::IpAddr;

/// A trie of IP/cidr addresses
#[derive(Default)]
pub struct AllowedIps<D> {
    ips: IpNetworkTable<D>,
}

impl<'a, D> FromIterator<(&'a AllowedIP, D)> for AllowedIps<D> {
    fn from_iter<I: IntoIterator<Item = (&'a AllowedIP, D)>>(iter: I) -> Self {
        let mut allowed_ips = AllowedIps::new();

        for (ip, data) in iter {
            allowed_ips.insert(ip.addr, ip.cidr as u32, data);
        }

        allowed_ips
    }
}

impl<D> AllowedIps<D> {
    pub fn new() -> Self {
        Self {
            ips: IpNetworkTable::new(),
        }
    }

    pub fn clear(&mut self) {
        self.ips = IpNetworkTable::new();
    }

    pub fn insert(&mut self, key: IpAddr, cidr: u32, data: D) -> Option<D> {
        // These are networks, it doesn't make sense for host bits to be set, so
        // use new_truncate().
        self.ips.insert(
            IpNetwork::new_truncate(key, cidr as u8).expect("cidr is valid length"),
            data,
        )
    }

    pub fn find(&self, key: IpAddr) -> Option<&D> {
        self.ips.longest_match(key).map(|(_net, data)| data)
    }

    pub fn remove(&mut self, predicate: &dyn Fn(&D) -> bool) {
        self.ips.retain(|_, v| !predicate(v));
    }

    /// Remove one exact prefix only when it is currently owned by data matching
    /// the supplied predicate. This mirrors amneziawg-go's AllowedIPs.Remove.
    pub fn remove_exact(
        &mut self,
        key: IpAddr,
        cidr: u32,
        predicate: &dyn Fn(&D) -> bool,
    ) {
        let target = IpNetwork::new_truncate(key, cidr as u8)
            .expect("cidr is valid length");
        self.ips.retain(|network, data| {
            !(network.network_address() == target.network_address()
                && network.netmask() == target.netmask()
                && predicate(data))
        });
    }

    pub fn iter(&self) -> Iter<D> {
        Iter(
            self.ips
                .iter()
                .map(|(ipa, d)| (d, ipa.network_address(), ipa.netmask()))
                .collect(),
        )
    }
}

pub struct Iter<'a, D: 'a>(VecDeque<(&'a D, IpAddr, u8)>);

impl<'a, D> Iterator for Iter<'a, D> {
    type Item = (&'a D, IpAddr, u8);
    fn next(&mut self) -> Option<Self::Item> {
        self.0.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_allowed_ips() -> AllowedIps<char> {
        let mut map: AllowedIps<char> = Default::default();
        map.insert(IpAddr::from([127, 0, 0, 1]), 32, '1');
        map.insert(IpAddr::from([45, 25, 15, 1]), 30, '6');
        map.insert(IpAddr::from([127, 0, 15, 1]), 16, '2');
        map.insert(IpAddr::from([127, 1, 15, 1]), 24, '3');
        map.insert(IpAddr::from([255, 1, 15, 1]), 24, '4');
        map.insert(IpAddr::from([60, 25, 15, 1]), 32, '5');
        map.insert(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128, '7');
        map
    }

    #[test]
    fn test_allowed_ips_insert_find() {
        let map = build_allowed_ips();
        assert_eq!(map.find(IpAddr::from([127, 0, 0, 1])), Some(&'1'));
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 255, 255])), None);
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(IpAddr::from([127, 0, 255, 255])), Some(&'2'));
        assert_eq!(map.find(IpAddr::from([127, 1, 15, 255])), Some(&'3'));
        assert_eq!(map.find(IpAddr::from([255, 1, 15, 2])), Some(&'4'));
        assert_eq!(map.find(IpAddr::from([60, 25, 15, 1])), Some(&'5'));
        assert_eq!(map.find(IpAddr::from([20, 0, 0, 100])), None);
        assert_eq!(
            map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0])),
            Some(&'7')
        );
        assert_eq!(map.find(IpAddr::from([553, 0, 0, 1, 0, 0, 0, 1])), None);
        assert_eq!(map.find(IpAddr::from([45, 25, 15, 1])), Some(&'6'));
    }

    #[test]
    fn remove_exact_matches_prefix_and_current_owner() {
        let prefix = IpAddr::from([192, 0, 2, 0]);
        let mut map: AllowedIps<char> = AllowedIps::new();

        map.insert(prefix, 24, 'b');
        map.remove_exact(prefix, 24, &|owner| *owner == 'a');
        assert_eq!(map.find(IpAddr::from([192, 0, 2, 1])), Some(&'b'));

        // Inserting the same prefix transfers ownership. Removing it as the
        // new owner must delete it entirely, not restore the previous owner.
        map.insert(prefix, 24, 'a');
        map.remove_exact(prefix, 24, &|owner| *owner == 'a');
        assert_eq!(map.find(IpAddr::from([192, 0, 2, 1])), None);
    }

    #[test]
    fn replace_and_add_allowed_ip_operations_are_sequential() {
        let first = IpAddr::from([192, 0, 2, 1]);
        let second = IpAddr::from([198, 51, 100, 1]);
        let third = IpAddr::from([203, 0, 113, 1]);
        let mut map: AllowedIps<char> = AllowedIps::new();

        map.insert(first, 32, 'a');
        map.insert(second, 32, 'a');

        // replace_allowed_ips removes all entries owned by this peer at the
        // point where the UAPI line appears; a later add survives.
        map.remove(&|owner| *owner == 'a');
        map.insert(third, 32, 'a');

        assert_eq!(map.find(first), None);
        assert_eq!(map.find(second), None);
        assert_eq!(map.find(third), Some(&'a'));
    }

    #[test]
    fn test_allowed_ips_remove() {
        let mut map = build_allowed_ips();
        map.remove(&|c| *c == '5' || *c == '1' || *c == '7');

        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'6', IpAddr::from([45, 25, 15, 0]), 30))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', IpAddr::from([127, 0, 0, 0]), 16))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', IpAddr::from([127, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'4', IpAddr::from([255, 1, 15, 0]), 24))
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn test_allowed_ips_iter() {
        let map = build_allowed_ips();
        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'6', IpAddr::from([45, 25, 15, 0]), 30))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'5', IpAddr::from([60, 25, 15, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', IpAddr::from([127, 0, 0, 0]), 16))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'1', IpAddr::from([127, 0, 0, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', IpAddr::from([127, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'4', IpAddr::from([255, 1, 15, 0]), 24))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'7', IpAddr::from([553, 0, 0, 1, 0, 0, 0, 0]), 128))
        );
        assert_eq!(map_iter.next(), None);
    }

    #[test]
    fn test_allowed_ips_v4_kernel_compatibility() {
        // Test case from wireguard-go
        let mut map: AllowedIps<char> = Default::default();

        map.insert(IpAddr::from([192, 168, 4, 0]), 24, 'a');
        map.insert(IpAddr::from([192, 168, 4, 4]), 32, 'b');
        map.insert(IpAddr::from([192, 168, 0, 0]), 16, 'c');
        map.insert(IpAddr::from([192, 95, 5, 64]), 27, 'd');
        map.insert(IpAddr::from([192, 95, 5, 65]), 27, 'c');
        map.insert(IpAddr::from([0, 0, 0, 0]), 0, 'e');
        map.insert(IpAddr::from([64, 15, 112, 0]), 20, 'g');
        map.insert(IpAddr::from([64, 15, 123, 211]), 25, 'h');
        map.insert(IpAddr::from([10, 0, 0, 0]), 25, 'a');
        map.insert(IpAddr::from([10, 0, 0, 128]), 25, 'b');
        map.insert(IpAddr::from([10, 1, 0, 0]), 30, 'a');
        map.insert(IpAddr::from([10, 1, 0, 4]), 30, 'b');
        map.insert(IpAddr::from([10, 1, 0, 8]), 29, 'c');
        map.insert(IpAddr::from([10, 1, 0, 16]), 29, 'd');

        assert_eq!(Some(&'a'), map.find(IpAddr::from([192, 168, 4, 20])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([192, 168, 4, 0])));
        assert_eq!(Some(&'b'), map.find(IpAddr::from([192, 168, 4, 4])));
        assert_eq!(Some(&'c'), map.find(IpAddr::from([192, 168, 200, 182])));
        assert_eq!(Some(&'c'), map.find(IpAddr::from([192, 95, 5, 68])));
        assert_eq!(Some(&'e'), map.find(IpAddr::from([192, 95, 5, 96])));
        assert_eq!(Some(&'g'), map.find(IpAddr::from([64, 15, 116, 26])));
        assert_eq!(Some(&'g'), map.find(IpAddr::from([64, 15, 127, 3])));

        map.insert(IpAddr::from([1, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([64, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([128, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([192, 0, 0, 0]), 32, 'a');
        map.insert(IpAddr::from([255, 0, 0, 0]), 32, 'a');

        assert_eq!(Some(&'a'), map.find(IpAddr::from([1, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([64, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([128, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([192, 0, 0, 0])));
        assert_eq!(Some(&'a'), map.find(IpAddr::from([255, 0, 0, 0])));

        map.remove(&|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(IpAddr::from([1, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([64, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([128, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([192, 0, 0, 0])));
        assert_ne!(Some(&'a'), map.find(IpAddr::from([255, 0, 0, 0])));

        map.clear();

        map.insert(IpAddr::from([192, 168, 0, 0]), 16, 'a');
        map.insert(IpAddr::from([192, 168, 0, 0]), 24, 'a');

        map.remove(&|c| *c == 'a');

        assert_ne!(Some(&'a'), map.find(IpAddr::from([192, 168, 0, 1])));
    }

    #[test]
    fn test_allowed_ips_v6_kernel_compatibility() {
        // Test case from wireguard-go
        let mut map: AllowedIps<char> = Default::default();

        map.insert(
            IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0xc05f, 0x0543,
            ]),
            128,
            'd',
        );
        map.insert(
            IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            64,
            'c',
        );
        map.insert(
            IpAddr::from([
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            0,
            'e',
        );
        map.insert(
            IpAddr::from([
                0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            0,
            'f',
        );
        map.insert(
            IpAddr::from([
                0x2404, 0x6800, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            ]),
            32,
            'g',
        );
        map.insert(
            IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef,
            ]),
            64,
            'h',
        );
        map.insert(
            IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef,
            ]),
            128,
            'a',
        );
        map.insert(
            IpAddr::from([
                0x2444, 0x6800, 0x40e4, 0x0800, 0xdeae, 0xbeef, 0x0def, 0xbeef,
            ]),
            128,
            'c',
        );
        map.insert(
            IpAddr::from([
                0x2444, 0x6800, 0xf0e4, 0x0800, 0xeeae, 0xbeef, 0x0000, 0x0000,
            ]),
            98,
            'b',
        );

        assert_eq!(
            Some(&'d'),
            map.find(IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0x0000, 0x0000, 0xc05f, 0x0543
            ]))
        );
        assert_eq!(
            Some(&'c'),
            map.find(IpAddr::from([
                0x2607, 0x5300, 0x6000, 0x6b00, 0, 0, 0xc02e, 0x01ee
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(IpAddr::from([0x2607, 0x5300, 0x6000, 0x6b01, 0, 0, 0, 0]))
        );
        assert_eq!(
            Some(&'g'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0806, 0, 0, 0, 0x1006
            ]))
        );
        assert_eq!(
            Some(&'g'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(IpAddr::from([
                0x2404, 0x67ff, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'f'),
            map.find(IpAddr::from([
                0x2404, 0x6801, 0x4004, 0x0806, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0, 0x1234, 0, 0x5678
            ]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(IpAddr::from([0x2404, 0x6800, 0x4004, 0x0800, 0, 0, 0, 0]))
        );
        assert_eq!(
            Some(&'h'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0x1010, 0x1010, 0x1010, 0x1010
            ]))
        );
        assert_eq!(
            Some(&'a'),
            map.find(IpAddr::from([
                0x2404, 0x6800, 0x4004, 0x0800, 0xdead, 0xbeef, 0xdead, 0xbeef
            ]))
        );
    }

    #[test]
    fn test_allowed_ips_iter_zero_leaf_bits() {
        let mut map: AllowedIps<char> = Default::default();
        map.insert(IpAddr::from([10, 111, 0, 1]), 32, '1');
        map.insert(IpAddr::from([10, 111, 0, 2]), 32, '2');
        map.insert(IpAddr::from([10, 111, 0, 3]), 32, '3');

        let mut map_iter = map.iter();
        assert_eq!(
            map_iter.next(),
            Some((&'1', IpAddr::from([10, 111, 0, 1]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'2', IpAddr::from([10, 111, 0, 2]), 32))
        );
        assert_eq!(
            map_iter.next(),
            Some((&'3', IpAddr::from([10, 111, 0, 3]), 32))
        );
        assert_eq!(map_iter.next(), None);
    }
}
