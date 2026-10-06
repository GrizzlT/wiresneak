use std::time::Duration;

use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use ipnet::IpNet;
use iroh::{Endpoint, PublicKey, endpoint::Connection};
use iroh_static_mesh::{ip::{IpPacket, parse_packet_addrs}, sync::GatedReceiver};
use tokio::sync::mpsc::Sender;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tun_rs::VIRTIO_NET_HDR_LEN;

use crate::protocol::ALPN;

pub async fn connect_loop(ep: Endpoint, peer: PublicKey, mut rx: GatedReceiver<IpPacket>, tx: Sender<BytesMut>, subnets: Vec<IpNet>) {
    loop {
        if let Ok(connection) = ep.connect(peer, ALPN).await {
            rx = run_connection(connection, rx, tx.clone(), subnets.clone()).await;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn run_connection(connection: Connection, mut rx: GatedReceiver<IpPacket>, tx: Sender<BytesMut>, subnets: Vec<IpNet>) -> GatedReceiver<IpPacket> {
    rx.set_enabled(true);

    let send = async {
        let mut tx = connection.open_uni().await?;
        tx.write_all(b"hello").await?;
        anyhow::Ok(tx)
    };
    let recv = async {
        let mut rx = connection.accept_uni().await?;
        let mut buf = [0; 5]; // enough for hello
        rx.read_exact(&mut buf).await?;
        anyhow::Ok(rx)
    };

    let _: anyhow::Result<()> = async {
        let (conn_tx, conn_rx) = tokio::try_join!(send, recv)?;
        let codec = LengthDelimitedCodec::builder()
            .length_field_type::<u16>()
            .length_field_length(2)
            .new_codec();
        let mut conn_tx = FramedWrite::new(conn_tx, codec.clone());
        let mut conn_rx = FramedRead::new(conn_rx, codec.clone());

        loop {
            tokio::select! {
                Some(packet) = conn_rx.next() => {
                    match packet {
                        Ok(packet) => if let Some((source, _)) = parse_packet_addrs(packet.as_ref()) {
                            let mut found = false;
                            for subnet in &subnets {
                                if subnet.contains(&source) {
                                    found = true;
                                    break;
                                }
                            }
                            if found {
                                let mut buf = BytesMut::zeroed(VIRTIO_NET_HDR_LEN);
                                buf.extend_from_slice(packet.as_ref());
                                tx.send(buf).await?;
                            }
                        }
                        _ => break,
                    }
                },
                Some(packet) = rx.recv() => {
                    conn_tx.send(packet.content).await?;
                },
                else => break,
            }
        }

        conn_tx.flush().await?;

        Ok(())
    }.await;

    rx.set_enabled(false);
    rx
}
