use std::path::Path;

use ipnet::IpNet;
use iroh::{KeyParsingError, PublicKey, SecretKey};
use serde::{Deserialize, Deserializer, de::Error};

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
