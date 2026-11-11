//! Import standard WireGuard and AmneziaWG INI configurations.
use crate::config::{Config, InterfaceConfig, PeerConfig, PeerEndpoint, PersistentKeepaliveConfig, TunnelType};
use boringtun::noise::amnezia::AmneziaWgConfig;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("failed to read source configuration: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid source configuration: {0}")]
    Parse(String),
    #[error("interface '{0}' already exists; pass --yes to replace it")]
    Exists(String),
    #[error("invalid resulting daemon configuration: {0}")]
    Config(String),
    #[error("cannot update daemon configuration: {0}")]
    Write(String),
}

#[derive(Debug)]
pub struct ImportReport {
    pub tunnel_type: TunnelType,
    pub warnings: Vec<String>,
    pub replaced: bool,
}

#[derive(Clone, Copy)]
enum Section {
    Interface,
    Peer(usize),
}

pub fn interface_exists(config_path: &Path, name: &str) -> Result<bool, ImportError> {
    if !config_path.exists() {
        return Ok(false);
    }
    let source = fs::read_to_string(config_path)?;
    let value: toml::Value = source
        .parse()
        .map_err(|e: toml::de::Error| ImportError::Config(e.to_string()))?;
    Ok(value.get("interfaces").and_then(|v| v.get(name)).is_some())
}

pub fn import_file(
    source_path: &Path,
    config_path: &Path,
    name: &str,
    replace: bool,
) -> Result<ImportReport, ImportError> {
    let source = fs::read_to_string(source_path)?;
    let (interface, warnings) = parse_interface(&source)?;
    if config_path.exists() {
        let current = fs::read_to_string(config_path)?;
        let mut root: toml::Value = current
            .parse()
            .map_err(|e: toml::de::Error| ImportError::Config(e.to_string()))?;
        let interfaces = root
            .as_table_mut()
            .and_then(|t| t.get_mut("interfaces"))
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| {
                ImportError::Config("existing configuration has no [interfaces] table".into())
            })?;
        let replaced = interfaces.contains_key(name);
        if replaced && !replace {
            return Err(ImportError::Exists(name.into()));
        }
        let value =
            toml::Value::try_from(&interface).map_err(|e| ImportError::Config(e.to_string()))?;
        interfaces.insert(name.to_owned(), value);
        let rendered =
            toml::to_string_pretty(&root).map_err(|e| ImportError::Config(e.to_string()))?;
        validate_rendered_config(&rendered)?;
        atomic_write(config_path, rendered.as_bytes())?;
        Ok(ImportReport {
            tunnel_type: interface.tunnel_type,
            warnings,
            replaced,
        })
    } else {
        let mut root = toml::map::Map::new();
        root.insert(
            "interfaces".into(),
            toml::Value::Table(toml::map::Map::new()),
        );
        let mut value = toml::Value::Table(root);
        let interfaces = value
            .get_mut("interfaces")
            .and_then(toml::Value::as_table_mut)
            .unwrap();
        interfaces.insert(
            name.to_owned(),
            toml::Value::try_from(&interface).map_err(|e| ImportError::Config(e.to_string()))?,
        );
        let rendered =
            toml::to_string_pretty(&value).map_err(|e| ImportError::Config(e.to_string()))?;
        validate_rendered_config(&rendered)?;
        atomic_write(config_path, rendered.as_bytes())?;
        Ok(ImportReport {
            tunnel_type: interface.tunnel_type,
            warnings,
            replaced: false,
        })
    }
}

fn validate_rendered_config(rendered: &str) -> Result<(), ImportError> {
    let config =
        Config::parse_toml(rendered).map_err(|error| ImportError::Config(error.to_string()))?;
    #[cfg(target_os = "linux")]
    crate::backend::BackendRegistry::default()
        .validate_config(&config)
        .map_err(|error| ImportError::Config(error.to_string()))?;
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), ImportError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    if let Err(error) = file.write_all(contents).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(ImportError::Write(error.to_string()));
    }
    Ok(())
}

fn parse_interface(source: &str) -> Result<(InterfaceConfig, Vec<String>), ImportError> {
    let mut section = None;
    let mut interface = HashMap::<String, String>::new();
    let mut peers = Vec::<HashMap<String, String>>::new();
    for (line_index, raw) in source.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            match line[1..line.len() - 1].trim().to_ascii_lowercase().as_str() {
                "interface" => {
                    if section.is_some() {
                        return Err(parse_error(line_index, "duplicate [Interface] section"));
                    }
                    section = Some(Section::Interface);
                }
                "peer" => {
                    peers.push(HashMap::new());
                    section = Some(Section::Peer(peers.len() - 1));
                }
                other => {
                    return Err(parse_error(
                        line_index,
                        &format!("unsupported section [{other}]"),
                    ))
                }
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(parse_error(line_index, "expected Key = Value"));
        };
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(parse_error(line_index, "empty key"));
        }
        let value = unquote(value.trim());
        let target = match section {
            Some(Section::Interface) => &mut interface,
            Some(Section::Peer(index)) => &mut peers[index],
            None => return Err(parse_error(line_index, "key appears before a section")),
        };
        if target.insert(key.clone(), value).is_some() {
            return Err(parse_error(line_index, &format!("duplicate key '{key}'")));
        }
    }
    if !interface.contains_key("privatekey") {
        return Err(ImportError::Parse("[Interface] requires PrivateKey".into()));
    }
    let address = list_required(&interface, "address", "[Interface] Address")?;
    let private_key = required(&interface, "privatekey", "[Interface] PrivateKey")?.to_owned();
    let listen_port = interface
        .get("listenport")
        .map(|v| parse_number::<u16>(v, "ListenPort"))
        .transpose()?;
    let mtu = interface
        .get("mtu")
        .map(|v| parse_number::<u16>(v, "MTU"))
        .transpose()?
        .unwrap_or(1380);
    let socket_fwmark = interface
        .get("fwmark")
        .map(|v| parse_fwmark(v))
        .transpose()?;
    let mut warnings = Vec::new();
    for key in interface.keys() {
        if !matches!(
            key.as_str(),
            "privatekey"
                | "address"
                | "listenport"
                | "mtu"
                | "fwmark"
                | "dns"
                | "table"
                | "preup"
                | "postup"
                | "predown"
                | "postdown"
                | "saveconfig"
                | "jc"
                | "jmin"
                | "jmax"
                | "s1"
                | "s2"
                | "s3"
                | "s4"
                | "h1"
                | "h2"
                | "h3"
                | "h4"
                | "i1"
                | "i2"
                | "i3"
                | "i4"
                | "i5"
                | "headerprotectionkey"
                | "contentpaddingaddition"
                | "rekeyaftertime"
                | "rekeytimeout"
                | "rejectaftertime"
                | "keepalivetimeout"
                | "maxhandshakeattempts"
                | "randomtrailers"
                | "disablecookies"
        ) {
            warnings.push(format!(
                "[Interface] {key} is not supported and was not imported"
            ));
        }
    }
    for key in [
        "dns",
        "table",
        "preup",
        "postup",
        "predown",
        "postdown",
        "saveconfig",
    ] {
        if interface.contains_key(key) {
            warnings.push(format!(
                "[Interface] {} is not applied by vpn-relay",
                display_key(key)
            ));
        }
    }

    let mut parsed_peers = Vec::new();
    if address.iter().any(|a| a.contains(':')) {
        return Err(ImportError::Parse("IPv6 interface addresses are not supported by vpn-relay".into()));
    }
    for (index, values) in peers.iter().enumerate() {
        let public_key = required(
            values,
            "publickey",
            &format!("[Peer {}] PublicKey", index + 1),
        )?
        .to_owned();
        let allowed_ips = list_optional(values, "allowedips");
        if allowed_ips.iter().any(|a| a.contains(':')) {
            return Err(ImportError::Parse(format!(
                "[Peer {}] IPv6 AllowedIPs are not supported by vpn-relay", index + 1
            )));
        }
        let endpoint = values.get("endpoint").cloned();
        if let Some(endpoint) = &endpoint {
            PeerEndpoint::parse(endpoint).map_err(|error| {
                ImportError::Parse(format!("[Peer {}] invalid Endpoint: {error}", index + 1))
            })?;
        }
        let persistent_keepalive_secs = values
            .get("persistentkeepalive")
            .map(|value| parse_persistent_keepalive(value))
            .transpose()?
            .flatten();
        parsed_peers.push(PeerConfig {
            public_key,
            preshared_key: values.get("presharedkey").cloned(),
            endpoint,
            allowed_ips,
            persistent_keepalive_secs,
            persistent_keepalive_range: None,
        });
        for key in values.keys() {
            if !matches!(
                key.as_str(),
                "publickey" | "presharedkey" | "endpoint" | "allowedips" | "persistentkeepalive"
            ) {
                warnings.push(format!(
                    "[Peer {}] {key} is not supported and was not imported",
                    index + 1
                ));
            }
        }
    }
    let awg = parse_awg(&interface)?;
    let tunnel_type = if awg.is_some() {
        TunnelType::AmneziaWg
    } else {
        TunnelType::WireGuard
    };
    let config = InterfaceConfig {
        tunnel_type,
        address,
        mtu,
        listen_port,
        private_key,
        socket_fwmark,
        peers: parsed_peers,
        awg,
    };
    Ok((config, warnings))
}

fn parse_awg(values: &HashMap<String, String>) -> Result<Option<AmneziaWgConfig>, ImportError> {
    let mut a = AmneziaWgConfig::default();
    macro_rules! num {
        ($key:literal,$field:ident) => {
            if let Some(v) = values.get($key) {
                a.$field = Some(parse_number::<u16>(v, $key)?);
            }
        };
    }
    macro_rules! string {
        ($key:literal,$field:ident) => {
            if let Some(v) = values.get($key) {
                a.$field = Some(v.clone());
            }
        };
    }
    macro_rules! boolean {
        ($key:literal,$field:ident) => {
            if let Some(v) = values.get($key) {
                a.$field = Some(parse_bool(v, $key)?);
            }
        };
    }
    num!("jc", jc);
    num!("jmin", jmin);
    num!("jmax", jmax);
    num!("s1", s1);
    num!("s2", s2);
    num!("s3", s3);
    num!("s4", s4);
    string!("h1", h1);
    string!("h2", h2);
    string!("h3", h3);
    string!("h4", h4);
    string!("i1", i1);
    string!("i2", i2);
    string!("i3", i3);
    string!("i4", i4);
    string!("i5", i5);
    string!("headerprotectionkey", header_protection_key);
    string!("contentpaddingaddition", content_padding_addition);
    string!("rekeyaftertime", rekey_after_time);
    string!("rekeytimeout", rekey_timeout);
    string!("rejectaftertime", reject_after_time);
    string!("keepalivetimeout", keepalive_timeout);
    string!("maxhandshakeattempts", max_handshake_attempts);
    boolean!("randomtrailers", random_trailers);
    boolean!("disablecookies", disable_cookies);
    let any = [
        "jc",
        "jmin",
        "jmax",
        "s1",
        "s2",
        "s3",
        "s4",
        "h1",
        "h2",
        "h3",
        "h4",
        "i1",
        "i2",
        "i3",
        "i4",
        "i5",
        "headerprotectionkey",
        "contentpaddingaddition",
        "rekeyaftertime",
        "rekeytimeout",
        "rejectaftertime",
        "keepalivetimeout",
        "maxhandshakeattempts",
        "randomtrailers",
        "disablecookies",
    ]
    .iter()
    .any(|k| values.contains_key(*k));
    Ok(any.then_some(a))
}

fn required<'a>(
    v: &'a HashMap<String, String>,
    key: &str,
    label: &str,
) -> Result<&'a str, ImportError> {
    v.get(key)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ImportError::Parse(format!("{label} is required")))
}
fn list_required(
    v: &HashMap<String, String>,
    key: &str,
    label: &str,
) -> Result<Vec<String>, ImportError> {
    let raw = required(v, key, label)?;
    let items: Vec<_> = raw
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if items.is_empty() {
        return Err(ImportError::Parse(format!("{label} must not be empty")));
    }
    Ok(items)
}
fn list_optional(v: &HashMap<String, String>, key: &str) -> Vec<String> {
    v.get(key)
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}
fn parse_persistent_keepalive(
    value: &str,
) -> Result<Option<PersistentKeepaliveConfig>, ImportError> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("off") || value == "0" || value == "0-0" {
        return Ok(None);
    }
    if let Some((min, max)) = value.split_once('-') {
        if max.contains('-') {
            return Err(ImportError::Parse(format!(
                "invalid PersistentKeepalive range '{value}'"
            )));
        }
        let min = parse_number::<u32>(min, "PersistentKeepalive range minimum")?;
        let max = parse_number::<u32>(max, "PersistentKeepalive range maximum")?;
        if min == 0 || max == 0 || min > max {
            return Err(ImportError::Parse(format!(
                "invalid PersistentKeepalive range '{value}': expected 1 <= min <= max"
            )));
        }
        return Ok(Some(PersistentKeepaliveConfig::Range(format!(
            "{min}-{max}"
        ))));
    }
    let seconds = parse_number::<u16>(value, "PersistentKeepalive")?;
    if seconds == 0 {
        Ok(None)
    } else {
        Ok(Some(PersistentKeepaliveConfig::Seconds(seconds)))
    }
}

fn parse_number<T: std::str::FromStr>(v: &str, key: &str) -> Result<T, ImportError> {
    v.parse()
        .map_err(|_| ImportError::Parse(format!("invalid {key} value '{v}'")))
}
fn parse_fwmark(v: &str) -> Result<u32, ImportError> {
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
            .map_err(|_| ImportError::Parse(format!("invalid FwMark '{v}'")))
    } else {
        parse_number(v, "FwMark")
    }
}
fn parse_bool(v: &str, key: &str) -> Result<bool, ImportError> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(ImportError::Parse(format!("invalid {key} boolean '{v}'"))),
    }
}
fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
        v[1..v.len() - 1].to_owned()
    } else {
        v.to_owned()
    }
}
fn strip_comment(v: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in v.char_indices() {
        if c == '"' && !escaped {
            quoted = !quoted;
        }
        if !quoted && (c == '#' || c == ';') {
            return &v[..i];
        }
        escaped = c == '\\' && !escaped;
        if c != '\\' {
            escaped = false;
        }
    }
    v
}
fn parse_error(line: usize, message: &str) -> ImportError {
    ImportError::Parse(format!("line {}: {message}", line + 1))
}
fn display_key(key: &str) -> &str {
    match key {
        "dns" => "DNS",
        "table" => "Table",
        "preup" => "PreUp",
        "postup" => "PostUp",
        "predown" => "PreDown",
        "postdown" => "PostDown",
        "saveconfig" => "SaveConfig",
        _ => key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = r#"[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#;

    #[test]
    fn rejects_ipv6_source_profiles() {
        for source in [
            CLIENT.replace("Address = 10.0.0.2/32", "Address = fd00::2/128"),
            CLIENT.replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0"),
            CLIENT.replace("Endpoint = vpn.example.com:51820", "Endpoint = [2001:db8::1]:51820"),
        ] {
            assert!(parse_interface(&source).is_err());
        }
    }

    #[test]
    fn imports_ipv4_wireguard_profiles_without_inferring_router_roles() {
        let (cfg, warnings) = parse_interface(CLIENT).unwrap();
        assert_eq!(cfg.tunnel_type, TunnelType::WireGuard);
        assert_eq!(cfg.address, vec!["10.0.0.2/32"]);
        assert_eq!(cfg.listen_port, None);
        assert_eq!(
            cfg.peers[0].persistent_keepalive_secs,
            Some(PersistentKeepaliveConfig::Seconds(25))
        );
        assert_eq!(cfg.peers[0].persistent_keepalive_range, None);
        assert!(warnings.iter().any(|w| w.contains("DNS")));
    }

    #[test]
    fn imports_ipv4_amnezia_persistent_keepalive_ranges_and_disable_values() {
        let range = CLIENT.replace("PersistentKeepalive = 25", "PersistentKeepalive = 25-35");
        let (cfg, _) = parse_interface(&range).unwrap();
        assert_eq!(
            cfg.peers[0].persistent_keepalive_secs,
            Some(PersistentKeepaliveConfig::Range("25-35".to_owned()))
        );
        assert_eq!(cfg.peers[0].persistent_keepalive_range, None);

        for value in ["off", "0", "0-0"] {
            let input = CLIENT.replace(
                "PersistentKeepalive = 25",
                &format!("PersistentKeepalive = {value}"),
            );
            let (cfg, _) = parse_interface(&input).unwrap();
            assert_eq!(cfg.peers[0].persistent_keepalive_secs, None);
            assert_eq!(cfg.peers[0].persistent_keepalive_range, None);
        }
    }

    #[test]
    fn rejects_invalid_persistent_keepalive_ranges() {
        for value in ["35-25", "0-25", "25-0", "1-2-3", "4294967296-4294967297"] {
            let input = CLIENT.replace(
                "PersistentKeepalive = 25",
                &format!("PersistentKeepalive = {value}"),
            );
            assert!(
                parse_interface(&input).is_err(),
                "accepted invalid range {value}"
            );
        }
    }

    #[test]
    fn importing_and_replacing_an_interface_preserves_other_interfaces() {
        let directory =
            std::env::temp_dir().join(format!("vpn-relay-import-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let source_path = directory.join("wg.conf");
        let config_path = directory.join("config.toml");
        fs::write(&source_path, CLIENT).unwrap();

        import_file(&source_path, &config_path, "wg-client", false).unwrap();
        import_file(&source_path, &config_path, "wg-backup", false).unwrap();

        let before_declined_replace = fs::read_to_string(&config_path).unwrap();
        assert!(matches!(
            import_file(&source_path, &config_path, "wg-client", false),
            Err(ImportError::Exists(_))
        ));
        assert_eq!(
            fs::read_to_string(&config_path).unwrap(),
            before_declined_replace
        );

        let report = import_file(&source_path, &config_path, "wg-client", true).unwrap();
        assert!(report.replaced);
        let config = Config::load(&config_path).unwrap();
        assert_eq!(config.interfaces.len(), 2);
        assert_eq!(
            config.interfaces["wg-client"].address,
            vec!["10.0.0.2/32", "fd00::2/128"]
        );
        assert_eq!(config.interfaces["wg-client"].listen_port, None);
        assert_eq!(config.interfaces["wg-backup"].listen_port, None);

        let rendered = fs::read_to_string(&config_path).unwrap();
        assert!(rendered.contains("address ="));
        assert!(!rendered.contains("addresses ="));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn imports_awg_parameter_profiles_as_awg_tunnel() {
        let base = CLIENT
            .replace("DNS = 1.1.1.1\n", "")
            .replace("fd00::2/128", "10.0.0.2/32")
            .replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 0.0.0.0/0");
        let profiles = [
            ("Jc = 4\nS1 = 16", TunnelType::AmneziaWg),
            ("I1 = <t>", TunnelType::AmneziaWg),
            ("S3 = 16\nH1 = 1-100", TunnelType::AmneziaWg),
            ("S3 = 0\nS4 = 0\nI1 = <t>", TunnelType::AmneziaWg),
            (
                "HeaderProtectionKey = 0000000000000000000000000000000000000000000000000000000000000000",
                TunnelType::AmneziaWg,
            ),
            ("RandomTrailers = true", TunnelType::AmneziaWg),
        ];

        for (parameters, expected) in profiles {
            let input = base.replace("MTU = 1380", &format!("MTU = 1380\n{parameters}"));
            assert_eq!(parse_interface(&input).unwrap().0.tunnel_type, expected);
        }
    }

    #[test]
    fn imports_mixed_peer_endpoint_configuration_without_guessing_a_role() {
        let input = format!(
            "{}\n[Peer]\nPublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\nAllowedIPs = 10.0.0.3/32\n",
            CLIENT
        );
        assert!(parse_interface(&input).is_ok());
    }
}
