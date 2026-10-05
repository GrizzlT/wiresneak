use std::{array, sync::Arc};

use bytes::{Buf, BufMut, BytesMut};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tun_rs::{AsyncDevice, DeviceBuilder, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

use crate::ip::{IpPacket, parse_packet_addrs};

pub fn start_tunnel(name: String) -> (Receiver<IpPacket>, Sender<BytesMut>) {
    let (sender, receiver) = mpsc::channel(1024);
    let (tx, rx) = mpsc::channel(1024);
    tokio::spawn(tunnel_loop(sender, rx, name));
    (receiver, tx)
}

async fn tunnel_loop(sender: Sender<IpPacket>, receiver: Receiver<BytesMut>, name: String) -> anyhow::Result<()> {
    let dev = Arc::new(DeviceBuilder::new()
        .name(name)
        .layer(tun_rs::Layer::L3)
        .mtu(1420)
        .enable(false)
        .offload(true)
        .build_async().unwrap());

    tokio::try_join!(
        tunnel_recv(Arc::clone(&dev), sender),
        tunnel_send(dev, receiver),
    )?;
    Ok(())
}

async fn tunnel_recv(dev: Arc<AsyncDevice>, tx: Sender<IpPacket>) -> anyhow::Result<()> {
    let mut original_buffer = [0u8; VIRTIO_NET_HDR_LEN + 65535];
    let mut bufs: [BytesMut; IDEAL_BATCH_SIZE] = array::from_fn(|_| BytesMut::zeroed(65535));
    let mut sizes = [0usize; IDEAL_BATCH_SIZE];

    loop {
        let num = dev.recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0).await.unwrap();
        for i in 0..num {
            let packet = bufs[i].copy_to_bytes(sizes[i]);
            bufs[i].put_bytes(0, sizes[i]);

            if let Some((source, dest)) = parse_packet_addrs(packet.as_ref()) {
                let packet = IpPacket {
                    source,
                    dest,
                    content: packet,
                };
                tx.send(packet).await?;
            }
        }
    }
}

async fn tunnel_send(dev: Arc<AsyncDevice>, mut rx: Receiver<BytesMut>) -> anyhow::Result<()> {
    let mut gro_table = GROTable::default();
    let mut batch: Vec<BytesMut> = Vec::with_capacity(IDEAL_BATCH_SIZE);

    loop {
        batch.clear();
        if rx.recv_many(&mut batch, IDEAL_BATCH_SIZE).await == 0 {
            break;
        };

        // NOTE: Each packet needs VIRTIO_NET_HDR_LEN empty bytes at the front!
        dev.send_multiple(&mut gro_table, &mut batch, VIRTIO_NET_HDR_LEN).await?;
    }

    Ok(())
}
