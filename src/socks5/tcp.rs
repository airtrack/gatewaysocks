use std::net::{SocketAddr, SocketAddrV4};

use super::Socks5Channel;

pub enum TcpSocks5Data {
    Connect((String, SocketAddrV4)),
    Push((String, Vec<u8>)),
    Shutdown(String),
    Close(String),
}

pub struct TcpSocks5 {
    _socks5_addr: SocketAddr,
    channel: Socks5Channel<TcpSocks5Data>,
}

impl TcpSocks5 {
    pub fn new(socks5_addr: SocketAddr, channel: Socks5Channel<TcpSocks5Data>) -> Self {
        Self {
            _socks5_addr: socks5_addr,
            channel,
        }
    }

    pub async fn run(&mut self) {
        loop {
            self.channel.rx.recv().await;
        }
    }
}
