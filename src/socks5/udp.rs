use std::collections::HashMap;
use std::io::Result;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::info;

use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{error::SendError, unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::watch::{self, Receiver, Sender};
use tokio::time::{interval, Interval};

use super::{Handshaker, Socks5Channel};

pub struct UdpSocks5Data {
    pub key: String,
    pub data: Vec<u8>,
    pub addr: SocketAddrV4,
}

pub struct UdpSocks5 {
    server_addr: SocketAddr,
    channel: Socks5Channel<UdpSocks5Data>,
    exited_tx: UnboundedSender<String>,
    exited_rx: UnboundedReceiver<String>,
    timer: Interval,
    clients: HashMap<String, Client>,
}

struct Client {
    tx: UnboundedSender<UdpSocks5Data>,
    alive_time: Instant,
    shutdown: Sender<()>,
}

impl UdpSocks5 {
    pub fn new(server_addr: SocketAddr, channel: Socks5Channel<UdpSocks5Data>) -> Self {
        let (exited_tx, exited_rx) = unbounded_channel();
        Self {
            server_addr,
            channel,
            exited_tx,
            exited_rx,
            timer: interval(Duration::from_millis(100)),
            clients: HashMap::new(),
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                _ = self.timer.tick() => {
                    self.clients.retain(|key, client| {
                        let timeout = client.is_timeout();
                        if timeout {
                            info!("timeout to stop UDP socks5 {}", key);
                            client.shutdown();
                        }
                        !timeout
                    });
                }
                key = self.exited_rx.recv() => {
                    if let Some(key) = key {
                        if let Some(client) = self.clients.get(&key) {
                            client.shutdown();
                        }
                        self.clients.remove(&key);
                    }
                }
                result = self.channel.rx.recv() => {
                    if let Some(packet) = result {
                        if !self.clients.contains_key(&packet.key) {
                            let client = Client::new(
                                packet.key.clone(),
                                self.server_addr,
                                self.channel.tx.clone(),
                                self.exited_tx.clone(),
                            );
                            self.clients.insert(packet.key.clone(), client);
                        }

                        if let Some(client) = self.clients.get_mut(&packet.key) {
                            let _ = client.send_to(packet);
                        }
                    }
                }
            }
        }
    }
}

impl Client {
    fn new(
        key: String,
        server_addr: SocketAddr,
        output_tx: UnboundedSender<UdpSocks5Data>,
        exited_tx: UnboundedSender<String>,
    ) -> Self {
        let (tx, rx) = unbounded_channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        tokio::spawn(async move {
            info!("start UDP socks5 {}", key);
            let _ = Self::socks5_task(&key, shutdown_rx, server_addr, output_tx, rx).await;
            info!("stop UDP socks5 {}", key);
            let _ = exited_tx.send(key);
        });

        Self {
            tx,
            alive_time: Instant::now(),
            shutdown: shutdown_tx,
        }
    }

    fn is_timeout(&self) -> bool {
        (Instant::now() - self.alive_time) > Duration::new(300, 0)
    }

    fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    fn send_to(
        &mut self,
        packet: UdpSocks5Data,
    ) -> core::result::Result<(), SendError<UdpSocks5Data>> {
        self.alive_time = Instant::now();
        self.tx.send(packet)
    }

    async fn socks5_task(
        key: &String,
        mut shutdown: Receiver<()>,
        server_addr: SocketAddr,
        output_tx: UnboundedSender<UdpSocks5Data>,
        input_rx: UnboundedReceiver<UdpSocks5Data>,
    ) -> Result<()> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = socket.local_addr()?;
        let mut handshaker = Handshaker::new(server_addr).await?;
        let relay_addr = handshaker.udp_associate(local_addr).await?;
        let mut stream = handshaker.into_tcp_stream();

        let ssocket = Arc::new(socket);
        let rsocket = ssocket.clone();

        let k = key.clone();
        let shutdown_rx = shutdown.clone();
        tokio::spawn(async move {
            Self::send_to_socks5(k, shutdown_rx, input_rx, ssocket, relay_addr).await;
        });

        let k = key.clone();
        let shutdown_rx = shutdown.clone();
        tokio::spawn(async move {
            Self::receive_from_socks5(k, shutdown_rx, output_tx, rsocket).await;
        });

        loop {
            let mut buffer = [0u8; 1024];
            tokio::select! {
                result = stream.read(&mut buffer) => {
                    match result {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                _ = shutdown.changed() => break,
            }
        }

        Ok(())
    }

    async fn send_to_socks5(
        key: String,
        mut shutdown: Receiver<()>,
        mut input_rx: UnboundedReceiver<UdpSocks5Data>,
        udp_socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
    ) {
        info!("start UDP socks5 send task {} -> {}", key, relay_addr);

        loop {
            tokio::select! {
                result = input_rx.recv() => {
                    if let Some(input) = result {
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
                _ = shutdown.changed() => break,
            }
        }

        info!("stop UDP socks5 send task {} -> {}", key, relay_addr);
    }

    async fn receive_from_socks5(
        key: String,
        mut shutdown: Receiver<()>,
        output_tx: UnboundedSender<UdpSocks5Data>,
        udp_socket: Arc<UdpSocket>,
    ) {
        info!("start UDP socks5 recv task {}", key);

        loop {
            let mut buffer = [0u8; 1500];
            tokio::select! {
                result = udp_socket.recv_from(&mut buffer) => {
                    match result {
                        Ok((n, _)) => {
                            if n <= 10 || buffer[3] != super::ATYP_IPV4 {
                                continue;
                            }

                            let ip = Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
                            let port = u16::from_be_bytes(buffer[8..10].try_into().unwrap());
                            let mut data = Vec::with_capacity(n - 10);
                            data.extend_from_slice(&buffer[10..n]);

                            let _ = output_tx.send(UdpSocks5Data {
                                key: key.clone(),
                                data,
                                addr: SocketAddrV4::new(ip, port),
                            });
                        }
                        Err(_) => {}
                    }
                }
                _ = shutdown.changed() => break,
            }
        }

        info!("stop UDP socks5 recv task {}", key);
    }
}
