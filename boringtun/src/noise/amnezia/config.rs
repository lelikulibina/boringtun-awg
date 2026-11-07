// Copyright (c) 2026 BoringTun contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::super::handshake::ObfuscationRanges;
use super::{AmneziaConfig, AmneziaWgVersion};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Complete AmneziaWG protocol configuration before normalization.
///
/// Optional fields preserve whether a parameter was omitted or explicitly
/// configured with its default value. This distinction is used to identify
/// the protocol generation without guessing in downstream applications.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AmneziaWgConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jc: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jmin: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jmax: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s1: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s2: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s4: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_cookies: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_trailers: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i2: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_protection_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_padding_addition: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey_after_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey_timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_after_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive_timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_handshake_attempts: Option<String>,
}

/// Invalid AmneziaWG configuration or incompatible parameter combination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmneziaWgConfigError(String);

impl fmt::Display for AmneziaWgConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AmneziaWgConfigError {}

impl AmneziaWgConfig {
    /// Validate, identify the generation and normalize this configuration
    /// into the packet-processing configuration used by BoringTun.
    pub fn build(&self) -> Result<(ObfuscationRanges, AmneziaConfig), AmneziaWgConfigError> {
        let values = [
            self.h1.as_deref().unwrap_or("1"),
            self.h2.as_deref().unwrap_or("2"),
            self.h3.as_deref().unwrap_or("3"),
            self.h4.as_deref().unwrap_or("4"),
        ];
        let mut headers = [(0, 0); 4];
        for (index, value) in values.iter().enumerate() {
            headers[index] = parse_u32_range(value).ok_or_else(|| {
                error(format!(
                    "h{} must be a uint32 tag or inclusive range",
                    index + 1
                ))
            })?;
        }
        let obfuscation = ObfuscationRanges::from_explicit_ranges(headers)
            .map_err(|cause| error(format!("invalid H1-H4 ranges: {cause}")))?;

        match (self.jmin, self.jmax) {
            (Some(min), Some(max)) if min <= max => {}
            (Some(_), Some(_)) => return Err(error("jmin must not exceed jmax")),
            (Some(_), None) | (None, Some(_)) => {
                return Err(error("jmin and jmax must be configured together"))
            }
            _ => {}
        }

        let mut config = AmneziaConfig::new(
            self.s1.unwrap_or(0),
            self.s2.unwrap_or(0),
            self.s3.unwrap_or(0),
            self.s4.unwrap_or(0),
        )
        .try_with_pre_handshake_junk(
            self.jc.unwrap_or(0),
            self.jmin.unwrap_or(0),
            self.jmax.unwrap_or(0),
            0,
        )
        .map_err(|cause| error(format!("invalid junk settings: {cause}")))?
        .with_disable_cookies(self.disable_cookies.unwrap_or(false))
        .with_random_trailers(self.random_trailers.unwrap_or(false));

        if let Some(value) = &self.header_protection_key {
            let key = decode_hex_key(value)
                .ok_or_else(|| error("header_protection_key must be 64 hexadecimal characters"))?;
            config = config.with_header_protection_key(key);
        }
        if let Some(value) = &self.content_padding_addition {
            let (min, max) = parse_u32_range(value)
                .ok_or_else(|| error("content_padding_addition must be uint32 or min-max"))?;
            config = config.with_content_padding_addition_range(min, max);
        }

        let mut parameters = Vec::new();
        macro_rules! present {
            ($name:literal, $field:expr) => {
                if let Some(value) = $field {
                    parameters.push(($name, value));
                }
            };
        }
        if self.jc.is_some() {
            parameters.push(("jc", ""));
        }
        if self.jmin.is_some() {
            parameters.push(("jmin", ""));
        }
        if self.jmax.is_some() {
            parameters.push(("jmax", ""));
        }
        if self.s1.is_some() {
            parameters.push(("s1", ""));
        }
        if self.s2.is_some() {
            parameters.push(("s2", ""));
        }
        if self.s3.is_some() {
            parameters.push(("s3", ""));
        }
        if self.s4.is_some() {
            parameters.push(("s4", ""));
        }
        present!("h1", self.h1.as_deref());
        present!("h2", self.h2.as_deref());
        present!("h3", self.h3.as_deref());
        present!("h4", self.h4.as_deref());
        present!("i1", self.i1.as_deref());
        present!("i2", self.i2.as_deref());
        present!("i3", self.i3.as_deref());
        present!("i4", self.i4.as_deref());
        present!("i5", self.i5.as_deref());
        present!("headerprotectionkey", self.header_protection_key.as_deref());
        present!(
            "contentpaddingaddition",
            self.content_padding_addition.as_deref()
        );
        present!("rekeyaftertime", self.rekey_after_time.as_deref());
        present!("rekeytimeout", self.rekey_timeout.as_deref());
        present!("rejectaftertime", self.reject_after_time.as_deref());
        present!("keepalivetimeout", self.keepalive_timeout.as_deref());
        present!(
            "maxhandshakeattempts",
            self.max_handshake_attempts.as_deref()
        );
        if self.random_trailers.is_some() {
            parameters.push(("randomtrailers", ""));
        }
        if self.disable_cookies.is_some() {
            parameters.push(("disablecookies", ""));
        }
        if let Some(detected_version) = AmneziaWgVersion::detect_from_parameters(&parameters) {
            config = config.with_protocol_version(detected_version);
        }

        for (name, value, slot) in [
            ("rekey_after_time", self.rekey_after_time.as_deref(), 0u8),
            ("rekey_timeout", self.rekey_timeout.as_deref(), 1u8),
            ("reject_after_time", self.reject_after_time.as_deref(), 2u8),
            ("keepalive_timeout", self.keepalive_timeout.as_deref(), 3u8),
            (
                "max_handshake_attempts",
                self.max_handshake_attempts.as_deref(),
                4u8,
            ),
        ] {
            if let Some(value) = value {
                let (min, max) = parse_u32_range(value)
                    .ok_or_else(|| error(format!("{name} must be uint32 or min-max")))?;
                config = match slot {
                    0 => config.with_rekey_after_time(min, max),
                    1 => config.with_rekey_timeout(min, max),
                    2 => config.with_reject_after_time(min, max),
                    3 => config.with_keepalive_timeout(min, max),
                    _ => config.with_max_handshake_attempts(min, max),
                };
            }
        }

        for (index, value) in [
            self.i1.as_deref(),
            self.i2.as_deref(),
            self.i3.as_deref(),
            self.i4.as_deref(),
            self.i5.as_deref(),
        ]
        .iter()
        .enumerate()
        {
            if let Some(specification) = value {
                config = config
                    .with_signature_packet(index, specification)
                    .map_err(|cause| error(format!("i{} is invalid: {cause}", index + 1)))?;
            }
        }

        config
            .validate()
            .map_err(|cause| error(format!("invalid AmneziaWG settings: {cause}")))?;
        config
            .validate_random_trailers(obfuscation)
            .map_err(|cause| error(format!("invalid RandomTrailers settings: {cause}")))?;

        Ok((obfuscation, config))
    }
}

fn error(message: impl Into<String>) -> AmneziaWgConfigError {
    AmneziaWgConfigError(message.into())
}

fn parse_u32_range(value: &str) -> Option<(u32, u32)> {
    let (min, max) = match value.split_once('-') {
        Some((min, max)) => (min.trim().parse().ok()?, max.trim().parse().ok()?),
        None => {
            let value = value.trim().parse().ok()?;
            (value, value)
        }
    };
    (min <= max).then_some((min, max))
}

fn decode_hex_key(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        return None;
    }
    let mut key = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        key[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::{AmneziaWgConfig, AmneziaWgVersion};

    #[test]
    fn detects_all_supported_generations_from_their_parameters() {
        let cases = [
            (
                AmneziaWgConfig {
                    jc: Some(4),
                    ..Default::default()
                },
                AmneziaWgVersion::V1,
            ),
            (
                AmneziaWgConfig {
                    i1: Some("<t>".into()),
                    ..Default::default()
                },
                AmneziaWgVersion::V1_5,
            ),
            (
                AmneziaWgConfig {
                    s3: Some(0),
                    ..Default::default()
                },
                AmneziaWgVersion::V2,
            ),
            (
                AmneziaWgConfig {
                    header_protection_key: Some("00".repeat(32)),
                    ..Default::default()
                },
                AmneziaWgVersion::V3,
            ),
            (
                AmneziaWgConfig {
                    random_trailers: Some(true),
                    ..Default::default()
                },
                AmneziaWgVersion::V3_1,
            ),
            (
                AmneziaWgConfig {
                    disable_cookies: Some(true),
                    ..Default::default()
                },
                AmneziaWgVersion::V3_1,
            ),
        ];
        for (input, expected) in cases {
            let (_, normalized) = input.build().unwrap();
            assert_eq!(normalized.protocol_version(), Some(expected));
        }
    }

    #[test]
    fn supported_generation_list_is_complete_and_stable() {
        assert_eq!(
            AmneziaWgVersion::ALL.map(|version| version.as_str()),
            ["1.0", "1.5", "2.0", "3.0", "3.1"]
        );
    }

    #[test]
    fn newer_generation_parameters_extend_earlier_profiles() {
        let input = AmneziaWgConfig {
            i1: Some("<t>".into()),
            s3: Some(0),
            header_protection_key: Some("00".repeat(32)),
            random_trailers: Some(true),
            ..Default::default()
        };
        let (_, normalized) = input.build().unwrap();
        assert_eq!(normalized.protocol_version(), Some(AmneziaWgVersion::V3_1));
    }

    #[test]
    fn explicit_disabled_31_parameters_still_identify_generation_31() {
        let (_, config) = AmneziaWgConfig {
            random_trailers: Some(false),
            disable_cookies: Some(false),
            content_padding_addition: Some("10-20".into()),
            ..Default::default()
        }
        .build()
        .unwrap();
        assert_eq!(config.protocol_version(), Some(AmneziaWgVersion::V3_1));
        assert!(!config.content_padding_uses_mtu);

        let (_, config) = AmneziaWgConfig {
            random_trailers: Some(false),
            disable_cookies: Some(false),
            ..Default::default()
        }
        .build()
        .unwrap();
        assert_eq!(config.protocol_version(), Some(AmneziaWgVersion::V3_1));
    }

    #[test]
    fn rejects_invalid_parameter_combinations() {
        assert!(AmneziaWgConfig {
            jmin: Some(10),
            ..Default::default()
        }
        .build()
        .is_err());
        assert!(AmneziaWgConfig {
            jmin: Some(20),
            jmax: Some(10),
            ..Default::default()
        }
        .build()
        .is_err());
        assert!(AmneziaWgConfig {
            header_protection_key: Some("bad".into()),
            ..Default::default()
        }
        .build()
        .is_err());
        assert!(AmneziaWgConfig {
            content_padding_addition: Some("100-10".into()),
            ..Default::default()
        }
        .build()
        .is_err());
    }
}
