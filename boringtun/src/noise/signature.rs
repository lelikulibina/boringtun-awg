// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! AmneziaWG I1-I5 pre-handshake signature packet chains.
//!
//! This implements the subset of upstream's obfuscation chain that is used to
//! construct standalone I1-I5 datagrams. The chain source is empty in this
//! callsite, exactly as in amneziawg-go's `ipacket.Obfuscate(buf, nil)`.

use rand_core::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SIGNATURE_DATAGRAM: usize = 65_507;
const LETTERS: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8; 10] = b"0123456789";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignatureChain {
    spec: String,
    operations: Vec<SignatureOperation>,
    wire_len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SignatureOperation {
    Bytes(Vec<u8>),
    Timestamp,
    RandomBytes(usize),
    RandomLetters(usize),
    RandomDigits(usize),
    ZeroLength(usize),
}

impl SignatureChain {
    /// Parse the upstream `<tag value>` grammar. Text outside tags is ignored,
    /// matching newObfChain; an empty/no-tag value clears the corresponding I.
    pub(crate) fn parse(spec: &str) -> Result<Option<Self>, String> {
        let mut remaining = spec;
        let mut operations = Vec::new();
        let mut wire_len = 0usize;

        while let Some(start) = remaining.find('<') {
            remaining = &remaining[start + 1..];
            let end = remaining
                .find('>')
                .ok_or_else(|| "signature chain has an unterminated tag".to_owned())?;
            let tag = &remaining[..end];
            remaining = &remaining[end + 1..];

            let mut parts = tag.split_whitespace();
            let name = parts
                .next()
                .ok_or_else(|| "signature chain contains an empty tag".to_owned())?;
            let value = parts.next().unwrap_or("");

            let operation = match name {
                "b" => {
                    let hex = value.strip_prefix("0x").unwrap_or(value);
                    if hex.is_empty() || hex.len() % 2 != 0 {
                        return Err("signature <b> requires a non-empty even-length hex value".into());
                    }
                    let mut bytes = Vec::with_capacity(hex.len() / 2);
                    for pair in hex.as_bytes().chunks_exact(2) {
                        let digit = |b: u8| -> Option<u8> {
                            match b {
                                b'0'..=b'9' => Some(b - b'0'),
                                b'a'..=b'f' => Some(b - b'a' + 10),
                                b'A'..=b'F' => Some(b - b'A' + 10),
                                _ => None,
                            }
                        };
                        let high = digit(pair[0])
                            .ok_or_else(|| "signature <b> contains non-hex characters".to_owned())?;
                        let low = digit(pair[1])
                            .ok_or_else(|| "signature <b> contains non-hex characters".to_owned())?;
                        bytes.push((high << 4) | low);
                    }
                    SignatureOperation::Bytes(bytes)
                }
                "t" => SignatureOperation::Timestamp,
                "r" => SignatureOperation::RandomBytes(parse_length(value, name)?),
                "rc" => SignatureOperation::RandomLetters(parse_length(value, name)?),
                "rd" => SignatureOperation::RandomDigits(parse_length(value, name)?),
                // In the upstream sender the source is nil, so <d> and <ds>
                // contribute zero bytes. <dz N> writes the big-endian source
                // length, which is therefore N zero bytes.
                "d" | "ds" => SignatureOperation::ZeroLength(0),
                "dz" => SignatureOperation::ZeroLength(parse_length(value, name)?),
                _ => return Err(format!("signature chain contains unknown tag <{}>", name)),
            };

            let operation_len = match &operation {
                SignatureOperation::Bytes(bytes) => bytes.len(),
                SignatureOperation::Timestamp => 4,
                SignatureOperation::RandomBytes(len)
                | SignatureOperation::RandomLetters(len)
                | SignatureOperation::RandomDigits(len)
                | SignatureOperation::ZeroLength(len) => *len,
            };
            wire_len = wire_len
                .checked_add(operation_len)
                .filter(|len| *len <= MAX_SIGNATURE_DATAGRAM)
                .ok_or_else(|| "signature chain exceeds the maximum UDP datagram size".to_owned())?;
            operations.push(operation);
        }

        if operations.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self {
            spec: spec.to_owned(),
            operations,
            wire_len,
        }))
    }

    pub(crate) fn spec(&self) -> &str {
        &self.spec
    }

    pub(crate) fn emit(&self, rng: &mut impl RngCore) -> Vec<u8> {
        let mut packet = Vec::with_capacity(self.wire_len);
        for operation in &self.operations {
            match operation {
                SignatureOperation::Bytes(bytes) => packet.extend_from_slice(bytes),
                SignatureOperation::Timestamp => {
                    let seconds = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32;
                    packet.extend_from_slice(&seconds.to_be_bytes());
                }
                SignatureOperation::RandomBytes(len) => {
                    let start = packet.len();
                    packet.resize(start + len, 0);
                    rng.fill_bytes(&mut packet[start..]);
                }
                SignatureOperation::RandomLetters(len) => {
                    let start = packet.len();
                    packet.resize(start + len, 0);
                    rng.fill_bytes(&mut packet[start..]);
                    for byte in &mut packet[start..] {
                        *byte = LETTERS[(*byte as usize) % LETTERS.len()];
                    }
                }
                SignatureOperation::RandomDigits(len) => {
                    let start = packet.len();
                    packet.resize(start + len, 0);
                    rng.fill_bytes(&mut packet[start..]);
                    for byte in &mut packet[start..] {
                        *byte = DIGITS[(*byte as usize) % DIGITS.len()];
                    }
                }
                SignatureOperation::ZeroLength(len) => {
                    packet.resize(packet.len() + len, 0);
                }
            }
        }
        packet
    }
}

fn parse_length(value: &str, tag: &str) -> Result<usize, String> {
    let len = value
        .parse::<usize>()
        .map_err(|_| format!("signature <{}> requires a non-negative length", tag))?;
    if len > MAX_SIGNATURE_DATAGRAM {
        return Err(format!("signature <{}> length exceeds the UDP datagram limit", tag));
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};

    #[test]
    fn parses_and_emits_upstream_signature_chain_operations() {
        let chain = SignatureChain::parse(
            "<b 0x4142><dz 2><r 4><rc 3><rd 2><t><d><ds>",
        )
        .unwrap()
        .expect("non-empty chain");
        let mut rng = ChaCha8Rng::seed_from_u64(0x1_1_5);
        let packet = chain.emit(&mut rng);

        assert_eq!(&packet[..4], b"AB\0\0");
        assert_eq!(packet.len(), 17);
        assert!(packet[8..11].iter().all(|b| LETTERS.contains(b)));
        assert!(packet[11..13].iter().all(|b| DIGITS.contains(b)));
    }

    #[test]
    fn empty_chains_clear_and_invalid_chains_are_rejected() {
        assert!(SignatureChain::parse("").unwrap().is_none());
        assert!(SignatureChain::parse("plain text").unwrap().is_none());
        assert!(SignatureChain::parse("<b 0>").is_err());
        assert!(SignatureChain::parse("<b abc>").is_err());
        assert!(SignatureChain::parse("<r -1>").is_err());
        assert!(SignatureChain::parse("<unknown 1>").is_err());
        assert!(SignatureChain::parse("<r 1").is_err());
    }

    #[test]
    fn signature_chain_rejects_datagrams_over_udp_limit() {
        assert!(SignatureChain::parse("<r 65508>").is_err());
        assert!(SignatureChain::parse("<b 00><r 65507>").is_err());
    }
}
