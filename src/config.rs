use std::{net::{IpAddr, SocketAddr}, path::Path, str::FromStr};

use ipnet::IpNet;
use iroh::{KeyParsingError, PublicKey, SecretKey, dns::{DnsProtocol, NameserverConfig}};
use serde::{Deserialize, Deserializer, de::{Error, Unexpected}};

#[derive(Debug, Deserialize)]
pub struct TunnelConfig {
    #[serde(rename = "Interface")]
    pub interface: InterfaceConfig,
    #[serde(rename = "Peer")]
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Deserialize)]
pub struct InterfaceConfig {
    #[serde(rename = "PrivateKey", deserialize_with = "deserialize_irohkey")]
    pub priv_key: SecretKey,
    #[serde(rename = "Addresses")]
    pub addresses: Vec<IpNet>,
    #[serde(rename = "BootstrapDNS", default = "Default::default")]
    pub dns_bootstrap: Vec<NameserverConfigWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct PeerConfig {
    #[serde(rename = "PublicKey", deserialize_with = "deserialize_irohkey")]
    pub pub_key: PublicKey,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: Vec<IpNet>,
}

fn deserialize_irohkey<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: std::str::FromStr<Err = KeyParsingError>,
{
    let value = <&str>::deserialize(deserializer)?;
    let attempt = value
        .parse::<T>()
        .map_err(|e| parse_error_to_serde::<D>(value, e));
    match attempt {
        Ok(v) => Ok(v),
        Err(e) => {
            let path = Path::new(value);
            if path.is_file() {
                let contents = std::fs::read_to_string(path)
                    .map_err(|e| D::Error::custom(format!("could not read key file due to {e}")))?;
                contents.trim().parse::<T>()
                    .map_err(|e| parse_error_to_serde::<D>(value, e))
            } else {
                Err(e)
            }
        },
    }
}

fn parse_error_to_serde<'de, D>(value: &str, error: KeyParsingError) -> D::Error
where
    D: Deserializer<'de>,
{
    match error {
        KeyParsingError::FailedToDecodeHex { .. } | KeyParsingError::FailedToDecodeBase32 { .. } => {
            D::Error::invalid_value(serde::de::Unexpected::Str(value), &"a hex or base32 encoded key")
        },
        KeyParsingError::InvalidKeyData { .. } => {
            D::Error::invalid_type(serde::de::Unexpected::Str(value), &"a proper ed25519 key")
        }
        KeyParsingError::InvalidLength { .. } => D::Error::invalid_length(value.len(), &"a proper ed25519 key"),
        _ => D::Error::custom("a proper ed25519 key as either hex or base32"),
    }
}

#[derive(Debug)]
pub struct NameserverConfigWrapper(pub NameserverConfig);

impl<'de> Deserialize<'de> for NameserverConfigWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>
    {
        let input = <&str>::deserialize(deserializer)?.trim();
        if input.is_empty() {
            return Err(D::Error::invalid_value(Unexpected::Str(input), &"a valid DNS format"));
        }

        let (scheme, rest) = match input.split_once("://") {
            Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
            _ => ("udp".to_string(), input),
        };

        let (protocol, default_port) = match scheme.as_str() {
            "udp" => (DnsProtocol::Udp, 53),
            "tcp" => (DnsProtocol::Tcp, 53),
            "dot" | "tls" => (DnsProtocol::Tls, 853),
            "doh" | "https" => (DnsProtocol::Https, 443),
            other => return Err(D::Error::invalid_value(Unexpected::Str(other), &"a valid scheme (udp, tcp, tls or https)")),
        };

        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "")
        };

        if let DnsProtocol::Https = protocol {
            if !matches!(path, "" | "/" | "/dns-query") {
                return Err(D::Error::invalid_value(Unexpected::Str(path), &"the default /dns-query path (or empty)"));
            }
        } else if !path.is_empty() {
            return Err(D::Error::invalid_type(Unexpected::Str(path), &"path info is only for https"));
        }

        let (dns_name, ip) = match authority.split_once('@') {
            Some(("", ip)) => (None, ip),
            Some((name, ip)) => (Some(name), ip),
            None => (None, authority),
        };

        let addr = parse_ip::<D>(ip, default_port)?;

        let config = match protocol {
            DnsProtocol::Udp => NameserverConfig::udp(addr.ip()),
            DnsProtocol::Tcp => NameserverConfig::tcp(addr.ip()),
            DnsProtocol::Tls => NameserverConfig::tls(addr.ip()),
            DnsProtocol::Https => NameserverConfig::https(addr.ip()),
            _ => unreachable!(),
        };
        let mut config = config.with_port(addr.port());
        if let Some(dns_name) = dns_name {
            config = config.with_tls_server_name(dns_name);
        }
        Ok(NameserverConfigWrapper(config))
    }
}

fn parse_ip<'de, D>(ip: &str, default_port: u16) -> Result<SocketAddr, D::Error>
where
    D: Deserializer<'de>,
{
    if let Ok(sa) = SocketAddr::from_str(ip) {
        return Ok(sa);
    }

    if let Ok(ip) = IpAddr::from_str(ip) {
        return Ok(SocketAddr::new(ip, default_port));
    }

    if let Some(Ok(ip)) = ip.strip_prefix('[').and_then(|s| s.strip_suffix(']')).map(IpAddr::from_str) {
        return Ok(SocketAddr::new(ip, default_port));
    }

    Err(D::Error::invalid_value(Unexpected::Str(ip), &"a valid socket addr (ip with optional port)"))
}
