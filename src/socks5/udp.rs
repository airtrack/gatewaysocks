use std::collections::HashMap;
use std::io::Result;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{error::SendError, unbounded_channel, UnboundedReceiver, UnboundedSender};

use super::{Handshaker, SocksChannel, SocksData};

pub struct UdpSocks5 {
    server_addr: SocketAddr,
    channel: SocksChannel,
    clients: HashMap<String, Client>,
}

struct Client {
    tx: UnboundedSender<SocksData>,
}

impl UdpSocks5 {
    pub fn new(server_addr: SocketAddr, channel: SocksChannel) -> Self {
        Self {
            server_addr,
            channel,
            clients: HashMap::new(),
        }
    }

    pub async fn run(&mut self) {
        loop {
            if let Some(packet) = self.channel.rx.recv().await {
                if !self.clients.contains_key(&packet.key) {
                    let client = Client::new(
                        packet.key.clone(),
                        self.server_addr,
                        self.channel.tx.clone(),
                    );
                    self.clients.insert(packet.key.clone(), client);
                }

                if let Some(client) = self.clients.get(&packet.key) {
                    let _ = client.send_to(packet);
                }
            }
        }
    }
}

impl Client {
    fn new(key: String, server_addr: SocketAddr, output_tx: UnboundedSender<SocksData>) -> Self {
        let (tx, rx) = unbounded_channel();

        tokio::spawn(async move {
            let _ = Self::connect_socks5(key, server_addr, output_tx, rx).await;
        });

        Self { tx }
    }

    fn send_to(&self, packet: SocksData) -> core::result::Result<(), SendError<SocksData>> {
        self.tx.send(packet)
    }

    async fn connect_socks5(
        key: String,
        server_addr: SocketAddr,
        output_tx: UnboundedSender<SocksData>,
        input_rx: UnboundedReceiver<SocksData>,
    ) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = socket.local_addr()?;
        let mut handshaker = Handshaker::new(server_addr).await?;
        let relay_addr = handshaker.udp_associate(local_addr).await?;
        let mut stream = handshaker.into_tcp_stream();

        let ssocket = Arc::new(socket);
        let rsocket = ssocket.clone();

        tokio::spawn(async move {
            Self::send_to_socks5(input_rx, ssocket, relay_addr).await;
        });
        tokio::spawn(async move {
            Self::receive_from_socks5(output_tx, rsocket, key).await;
        });

        loop {
            let mut buffer = [0u8; 1024];
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }

        Ok(())
    }

    async fn send_to_socks5(
        mut input_rx: UnboundedReceiver<SocksData>,
        udp_socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
    ) {
        loop {
            if let Some(input) = input_rx.recv().await {
                let mut data = [0u8; 1500];
                data[0] = 0;
                data[1] = 0;
                data[2] = 0;
                data[3] = super::ATYP_IPV4;
                data[4..8].copy_from_slice(&input.addr.ip().octets());
                data[8..10].copy_from_slice(&input.addr.port().to_be_bytes());

                let len = std::cmp::min(input.data.len(), 1490);
                data[10..10 + len].copy_from_slice(&input.data[0..len]);

                let _ = udp_socket.send_to(&data[0..10 + len], relay_addr).await;
            }
        }
    }

    async fn receive_from_socks5(
        output_tx: UnboundedSender<SocksData>,
        udp_socket: Arc<UdpSocket>,
        key: String,
    ) {
        loop {
            let mut buffer = [0u8; 1500];
            match udp_socket.recv_from(&mut buffer).await {
                Ok((n, _)) => {
                    if n <= 10 || buffer[3] != super::ATYP_IPV4 {
                        continue;
                    }

                    let ip = Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
                    let port = u16::from_be_bytes(buffer[8..10].try_into().unwrap());
                    let mut data = Vec::with_capacity(n - 10);
                    data.extend_from_slice(&buffer[10..n]);

                    let _ = output_tx.send(SocksData {
                        key: key.clone(),
                        data,
                        addr: SocketAddrV4::new(ip, port),
                    });
                }
                Err(_) => {}
            }
        }
    }
}
