use std::net::SocketAddrV4;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub mod tcp;
pub mod udp;

pub struct SocksData {
    pub key: String,
    pub data: Vec<u8>,
    pub addr: SocketAddrV4,
}

pub struct SocksChannel {
    pub tx: UnboundedSender<SocksData>,
    pub rx: UnboundedReceiver<SocksData>,
}

pub fn socks_channel() -> (SocksChannel, SocksChannel) {
    let (tx1, rx1) = unbounded_channel();
    let (tx2, rx2) = unbounded_channel();
    (
        SocksChannel { tx: tx1, rx: rx2 },
        SocksChannel { tx: tx2, rx: rx1 },
    )
}
