use std::{net::IpAddr, path::PathBuf};

use anyhow::Context;
use ipnet::IpNet;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use iroh_static_mesh::{GATED_CHANNEL_BUFFER, PubkeyToId, config::TunnelConfig, sync::gated_channel, tunnel::start_tunnel};
use lexopt::{Arg, ValueExt};
use prefix_trie::PrefixMap;
use sd_notify::NotifyState;

use crate::{connection::{connect_loop, run_connection}, hook::AcceptHook, protocol::ALPN};

pub mod connection;
pub mod hook;
pub mod protocol;

enum Args {
    Serve {
        config: PathBuf,
        name: Option<String>,
    },
    Generate,
    PubKey,
}

fn parse_args() -> Result<Args, lexopt::Error> {
    let mut flavor = None;
    let mut config = None;
    let mut name = None;
    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Arg::Value(val) if flavor.is_none() => {
                let val: String = val.parse()?;
                flavor = Some(match val.as_str() {
                    "serve" => Args::Serve { config: PathBuf::new(), name: None },
                    "genkey" => Args::Generate,
                    "pubkey" => Args::PubKey,
                    _ => return Err("Usage: wiresneakd <serve|genkey|pubkey> [CONFIG [NAME]]".into()),
                });
            }
            Arg::Value(val) if config.is_none() && matches!(flavor, Some(Args::Serve { .. })) => {
                config = Some(val.parse()?);
            }
            Arg::Value(val) if name.is_none() && matches!(flavor, Some(Args::Serve { .. })) => {
                name = Some(val.parse()?);
            }
            Arg::Long("help") | Arg::Short('h') => {
                println!("Usage: wiresneakd <serve|genkey|pubkey> [CONFIG [NAME]]");
                std::process::exit(0);
            }
            _ => return Err(arg.unexpected()),
        }
    }

    Ok(match flavor.ok_or("Usage: wiresneakd <serve|genkey|pubkey| [CONFIG [NAME]]")? {
        Args::Serve { .. } => Args::Serve { config: config.ok_or("missing argument CONFIG")?, name },
        x => x,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Fetch config
    let args = parse_args()?;

    let (config, name) = match args {
        Args::Serve { config, name } => (config, name),
        Args::Generate => {
            genkey()?;
            return Ok(())
        }
        Args::PubKey => {
            pubkey()?;
            return Ok(())
        },
    };

    let tunnel_name = name
        .unwrap_or(config.file_stem()
            .map(|s| s.to_os_string())
            .map(|s| s.string())
            .transpose()?
            .ok_or(anyhow::anyhow!("Invalid tunnel name"))?);
    let config: TunnelConfig = toml::from_str(&std::fs::read_to_string(&config).context("Could not read config")?).context("Could not parse config file")?;
    let self_id = config.interface.priv_key.public();

    println!("{config:?}");

    // Build prefix tree and create endoint
    let mut keymap = PubkeyToId::new();

    let mut peers_v4 = PrefixMap::new();
    let mut peers_v6 = PrefixMap::new();
    for peer in &config.peers {
        let pubkey = peer.pub_key;
        let (id, state) = keymap.insert(pubkey);
        for &net in &peer.allowed_ips {
            match net {
                IpNet::V4(ip_net) => {
                    peers_v4.insert(ip_net, id);
                    state.subnets.push(ip_net.into());
                },
                IpNet::V6(ip_net) => {
                    peers_v6.insert(ip_net, id);
                    state.subnets.push(ip_net.into());
                },
            }
        }
    }

    println!("Computed prefix trie: {peers_v4:?}");
    println!("Computed prefix trie: {peers_v6:?}");

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(config.interface.priv_key)
        .alpns([ALPN.into()].into())
        .portmapper_config(iroh::endpoint::PortmapperConfig::Disabled)
        .hooks(AcceptHook::new(keymap.keys().to_vec()))
        .bind().await?;

    endpoint.online().await;
    println!("Endpoint up!");

    // Read packets from synchronous tunnel
    let (mut rx, tx) = start_tunnel(tunnel_name);

    let _ = sd_notify::notify(&[NotifyState::Ready]);

    // Start connect loop
    for id in keymap.keys().to_vec() {
        if let (true, Some(peer)) = (id < self_id, keymap.get_peer(id)) {
            tokio::spawn(connect_loop(endpoint.clone(), id, keymap.take_recv(peer).unwrap(), tx.clone(), keymap.get(peer).subnets.clone()));
        }
    }

    // Start accept loop
    loop {
        tokio::select! {
            Some(attempt) = endpoint.accept() => {
                if let Ok(connection) = attempt.await
                    && connection.remote_id() > self_id
                    && let Some(peer) = keymap.get_peer(connection.remote_id()) {
                        if let Some(gated_rx) = keymap.take_recv(peer) {
                            tokio::spawn(run_connection(connection, gated_rx, tx.clone(), keymap.get(peer).subnets.clone()));
                        } else if keymap.get(peer).sender.inner().is_closed() {
                            let (gated_tx, gated_rx) = gated_channel(GATED_CHANNEL_BUFFER);
                            keymap.get_mut(peer).sender = gated_tx;
                            tokio::spawn(run_connection(connection, gated_rx, tx.clone(), keymap.get(peer).subnets.clone()));
                        }
                    }
            },
            Some(packet) = rx.recv() => {
                match packet.dest {
                    IpAddr::V4(addr) => if let Some((_, &id)) = peers_v4.get_lpm(&addr.into()) {
                        keymap.get(id).sender.guard(async |sender| sender.send(packet).await).await;
                    },
                    IpAddr::V6(addr) => if let Some((_, &id)) = peers_v6.get_lpm(&addr.into()) {
                        keymap.get(id).sender.guard(async |sender| sender.send(packet).await).await;
                    }
                }
            },
            else => {
                break
            }
        }
    }

    Ok(())
}

pub fn genkey() -> anyhow::Result<()> {
    let secret = SecretKey::generate();
    println!("{}", hex::encode(secret.to_bytes()));

    Ok(())
}

pub fn pubkey() -> anyhow::Result<()> {
    let mut secret = String::new();
    std::io::stdin().read_line(&mut secret)?;
    let secret = secret.trim().parse::<SecretKey>()?;
    let public = secret.public();

    println!("{}", hex::encode(public.as_bytes()));

    Ok(())
}
