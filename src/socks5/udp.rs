use std::collections::HashMap;
use std::io::Result;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{info, trace};
use pnet::util::MacAddr;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{error::SendError, unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::watch::{self, Receiver, Sender};
use tokio::time::{interval, Interval};

use super::{Handshaker, Socks5Channel};

pub struct UdpSocks5Data {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub mac: MacAddr,
    pub data: Vec<u8>,
}

pub struct UdpSocks5 {
    server_addr: SocketAddr,
    channel: Socks5Channel<UdpSocks5Data>,
    exited_tx: UnboundedSender<SocketAddrV4>,
    exited_rx: UnboundedReceiver<SocketAddrV4>,
    timer: Interval,
    clients: HashMap<SocketAddrV4, Client>,
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
                    self.clients.retain(|src, client| {
                        let timeout = client.is_timeout();
                        if timeout {
                            trace!("{}: timeout to stop udp socks5", src);
                            client.shutdown();
                        }
                        !timeout
                    });
                }
                src = self.exited_rx.recv() => {
                    if let Some(src) = src {
                        if let Some(client) = self.clients.get(&src) {
                            client.shutdown();
                        }
                        self.clients.remove(&src);
                    }
                }
                result = self.channel.rx.recv() => {
                    if let Some(packet) = result {
                        if !self.clients.contains_key(&packet.src) {
                            let client = Client::new(
                                packet.src,
                                packet.mac,
                                self.server_addr,
                                self.channel.tx.clone(),
                                self.exited_tx.clone(),
                            );
                            self.clients.insert(packet.src, client);
                        }

                        if let Some(client) = self.clients.get_mut(&packet.src) {
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
        src: SocketAddrV4,
        mac: MacAddr,
        server_addr: SocketAddr,
        output_tx: UnboundedSender<UdpSocks5Data>,
        exited_tx: UnboundedSender<SocketAddrV4>,
    ) -> Self {
        let (tx, rx) = unbounded_channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        tokio::spawn(async move {
            info!("{}: start udp socks5", src);
            let _ = Self::socks5_task(src, mac, shutdown_rx, server_addr, output_tx, rx).await;
            info!("{}: stop udp socks5", src);
            let _ = exited_tx.send(src);
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
        src: SocketAddrV4,
        mac: MacAddr,
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

        let shutdown_rx = shutdown.clone();
        let send_task = Self::send_to_socks5(shutdown_rx, input_rx, ssocket, relay_addr);

        let shutdown_rx = shutdown.clone();
        let recv_task = Self::receive_from_socks5(shutdown_rx, output_tx, rsocket, src, mac);

        let hold_task = async move {
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
        };

        futures::join!(send_task, recv_task, hold_task);
        Ok(())
    }

    async fn send_to_socks5(
        mut shutdown: Receiver<()>,
        mut input_rx: UnboundedReceiver<UdpSocks5Data>,
        udp_socket: Arc<UdpSocket>,
        relay_addr: SocketAddr,
    ) {
        loop {
            tokio::select! {
                result = input_rx.recv() => {
                    if let Some(input) = result {
                        let mut data = [0u8; 1500];
                        data[0] = 0;
                        data[1] = 0;
                        data[2] = 0;
                        data[3] = super::ATYP_IPV4;
                        data[4..8].copy_from_slice(&input.dst.ip().octets());
                        data[8..10].copy_from_slice(&input.dst.port().to_be_bytes());

                        let len = std::cmp::min(input.data.len(), 1490);
                        data[10..10 + len].copy_from_slice(&input.data[0..len]);

                        let _ = udp_socket.send_to(&data[0..10 + len], relay_addr).await;
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
    }

    async fn receive_from_socks5(
        mut shutdown: Receiver<()>,
        output_tx: UnboundedSender<UdpSocks5Data>,
        udp_socket: Arc<UdpSocket>,
        src: SocketAddrV4,
        mac: MacAddr,
    ) {
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
                                src: SocketAddrV4::new(ip, port),
                                dst: src,
                                mac,
                                data,
                            });
                        }
                        Err(_) => {}
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
    }
}
