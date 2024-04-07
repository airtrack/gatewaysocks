use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{info, trace};
use pnet::util::MacAddr;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{error::SendError, unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::{interval, Interval};

use super::{Handshaker, Socks5Channel};

const TIMER_INTERVAL_MS: u64 = 100;
const CLIENT_TIMEOUT_SECS: u64 = 300;

pub struct UdpSocks5Data {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub mac: MacAddr,
    pub data: Vec<u8>,
}

pub struct UdpSocks5 {
    socks5_addr: SocketAddr,
    timer: Interval,
    exited: Exited,
    channel: Socks5Channel<UdpSocks5Data>,
    clients: HashMap<SocketAddrV4, Client>,
}

struct Exited {
    tx: UnboundedSender<SocketAddrV4>,
    rx: UnboundedReceiver<SocketAddrV4>,
}

struct Client {
    input: UnboundedSender<UdpSocks5Data>,
    alive_time: Instant,
}

impl UdpSocks5 {
    pub fn new(socks5_addr: SocketAddr, channel: Socks5Channel<UdpSocks5Data>) -> Self {
        let timer = interval(Duration::from_millis(TIMER_INTERVAL_MS));
        let (tx, rx) = unbounded_channel();
        let exited = Exited { tx, rx };
        let clients = HashMap::new();

        Self {
            socks5_addr,
            timer,
            exited,
            channel,
            clients,
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                _ = self.timer.tick() => {
                    self.clients.retain(|src, client| {
                        let timeout = client.is_timeout();
                        if timeout {
                            trace!("{} timeout to stop udp socks5", src);
                        }
                        !timeout
                    });
                }
                src = self.exited.rx.recv() => {
                    if let Some(src) = src {
                        self.clients.remove(&src);
                    }
                }
                result = self.channel.rx.recv() => {
                    if let Some(packet) = result {
                        if !self.clients.contains_key(&packet.src) {
                            let client = Client::new(
                                packet.src,
                                packet.mac,
                                self.socks5_addr,
                                self.channel.tx.clone(),
                                self.exited.tx.clone(),
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
        socks5_addr: SocketAddr,
        outbound: UnboundedSender<UdpSocks5Data>,
        exit: UnboundedSender<SocketAddrV4>,
    ) -> Self {
        let (input, inbound) = unbounded_channel();

        tokio::spawn(async move {
            info!("{} start udp socks5", src);
            let result = Self::run_udp_socks5(src, mac, socks5_addr, outbound, inbound).await;
            let _ = exit.send(src);
            info!("{} stop udp socks5: {:?}", src, result);
        });

        Self {
            input,
            alive_time: Instant::now(),
        }
    }

    fn is_timeout(&self) -> bool {
        (Instant::now() - self.alive_time) > Duration::new(CLIENT_TIMEOUT_SECS, 0)
    }

    fn send_to(
        &mut self,
        packet: UdpSocks5Data,
    ) -> core::result::Result<(), SendError<UdpSocks5Data>> {
        self.alive_time = Instant::now();
        self.input.send(packet)
    }

    async fn run_udp_socks5(
        src: SocketAddrV4,
        mac: MacAddr,
        socks5_addr: SocketAddr,
        outbound: UnboundedSender<UdpSocks5Data>,
        inbound: UnboundedReceiver<UdpSocks5Data>,
    ) -> Result<()> {
        let mut handshaker = Handshaker::new(socks5_addr).await?;
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let destination = handshaker.udp_associate(socket.local_addr()?).await?;
        let stream = handshaker.into_tcp_stream();

        let sender = Arc::new(socket);
        let receiver = sender.clone();

        let send_task = Self::send_to_socks5(inbound, sender, destination);
        let recv_task = Self::receive_from_socks5(outbound, receiver, src, mac);
        let hold_task = Self::holding_socks5(stream);

        futures::try_join!(send_task, recv_task, hold_task)?;
        Ok(())
    }

    async fn send_to_socks5(
        mut inbound: UnboundedReceiver<UdpSocks5Data>,
        sender: Arc<UdpSocket>,
        destination: SocketAddr,
    ) -> Result<()> {
        loop {
            let packet = inbound
                .recv()
                .await
                .ok_or(Error::new(ErrorKind::Other, "inbound dropped"))?;

            let mut data = [0u8; 1500];
            data[0] = 0;
            data[1] = 0;
            data[2] = 0;
            data[3] = super::ATYP_IPV4;
            data[4..8].copy_from_slice(&packet.dst.ip().octets());
            data[8..10].copy_from_slice(&packet.dst.port().to_be_bytes());

            let len = std::cmp::min(packet.data.len(), 1490);
            data[10..10 + len].copy_from_slice(&packet.data[0..len]);

            sender.send_to(&data[0..10 + len], destination).await?;
        }
    }

    async fn receive_from_socks5(
        outbound: UnboundedSender<UdpSocks5Data>,
        receiver: Arc<UdpSocket>,
        src: SocketAddrV4,
        mac: MacAddr,
    ) -> Result<()> {
        loop {
            let mut buffer = [0u8; 1500];
            let (n, _) = receiver.recv_from(&mut buffer).await?;
            if n <= 10 || buffer[3] != super::ATYP_IPV4 {
                continue;
            }

            let ip = Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]);
            let port = u16::from_be_bytes(buffer[8..10].try_into().unwrap());
            let mut data = Vec::with_capacity(n - 10);
            data.extend_from_slice(&buffer[10..n]);

            let message = UdpSocks5Data {
                src: SocketAddrV4::new(ip, port),
                dst: src,
                mac,
                data,
            };

            outbound
                .send(message)
                .map_err(|_| Error::new(ErrorKind::Other, "send message error"))?;
        }
    }

    async fn holding_socks5(mut stream: TcpStream) -> Result<()> {
        loop {
            let mut buffer = [0u8; 1024];
            let size = stream.read(&mut buffer).await?;
            if size == 0 {
                return Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "holding tcp closed",
                ));
            }
        }
    }
}
