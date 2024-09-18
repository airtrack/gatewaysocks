use std::collections::HashMap;
use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::{error, info, trace};
use pnet::util::MacAddr;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{error::SendError, unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::interval;

use super::Handshaker;

const TIMER_INTERVAL_MS: u64 = 100;
const CLIENT_TIMEOUT_SECS: u64 = 300;

pub struct UdpSocks5Message {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub mac: MacAddr,
    pub data: Vec<u8>,
}

pub fn udp_socks5(socks5_addr: SocketAddr) -> (UdpSocks5Handle, UdpSocks5Service) {
    let (input, inbound) = unbounded_channel();
    let (outbound, output) = unbounded_channel();
    let handle = UdpSocks5Handle::new(input, output);
    let service = UdpSocks5Service::new(socks5_addr, inbound, outbound);
    (handle, service)
}

pub struct UdpSocks5Handle {
    input: UnboundedSender<UdpSocks5Message>,
    output: UnboundedReceiver<UdpSocks5Message>,
}

impl UdpSocks5Handle {
    fn new(
        input: UnboundedSender<UdpSocks5Message>,
        output: UnboundedReceiver<UdpSocks5Message>,
    ) -> Self {
        Self { input, output }
    }
}

impl UdpSocks5Handle {
    pub fn send_udp_message(&self, message: UdpSocks5Message) {
        self.input.send(message).unwrap_or_else(|e| {
            error!("send udp socks5 message error: {:?}", e);
        });
    }

    pub fn recv_udp_message(&mut self) -> Option<UdpSocks5Message> {
        match self.output.try_recv() {
            Ok(message) => return Some(message),
            Err(_) => return None,
        }
    }
}

pub struct UdpSocks5Service {
    socks5_addr: SocketAddr,
    inbound: UnboundedReceiver<UdpSocks5Message>,
    outbound: UnboundedSender<UdpSocks5Message>,
    clients: HashMap<SocketAddrV4, UdpSocks5Client>,
    futs: FuturesUnordered<Pin<Box<dyn Future<Output = SocketAddrV4> + Send>>>,
}

impl UdpSocks5Service {
    fn new(
        socks5_addr: SocketAddr,
        inbound: UnboundedReceiver<UdpSocks5Message>,
        outbound: UnboundedSender<UdpSocks5Message>,
    ) -> Self {
        let clients = HashMap::new();
        let futs = FuturesUnordered::new();

        Self {
            socks5_addr,
            inbound,
            outbound,
            clients,
            futs,
        }
    }

    pub async fn run(&mut self) {
        let mut timer = interval(Duration::from_millis(TIMER_INTERVAL_MS));

        loop {
            tokio::select! {
                _ = timer.tick() => {
                    self.clients.retain(|src, client| {
                        let timeout = client.is_timeout();
                        if timeout {
                            trace!("{} timeout to stop udp socks5", src);
                        }
                        !timeout
                    });
                }
                Some(src) = self.futs.next() => {
                    self.clients.remove(&src);
                }
                Some(packet) = self.inbound.recv() => {
                    if !self.clients.contains_key(&packet.src) {
                        let (client, fut) = UdpSocks5Client::new(
                            packet.src,
                            packet.mac,
                            self.socks5_addr,
                            self.outbound.clone(),
                        );
                        self.clients.insert(packet.src, client);
                        self.futs.push(Box::pin(fut));
                    }

                    if let Some(client) = self.clients.get_mut(&packet.src) {
                        match client.send_to(packet) {
                            Ok(_) => {},
                            Err(SendError(packet)) => {
                                self.clients.remove(&packet.src);
                                error!("{} udp socks5 ended, send message error", packet.src);
                            }
                        }
                    }
                }
            }
        }
    }
}

struct UdpSocks5Client {
    input: UnboundedSender<UdpSocks5Message>,
    alive_time: Instant,
}

impl UdpSocks5Client {
    fn new(
        src: SocketAddrV4,
        mac: MacAddr,
        socks5_addr: SocketAddr,
        outbound: UnboundedSender<UdpSocks5Message>,
    ) -> (Self, impl Future<Output = SocketAddrV4>) {
        let (input, inbound) = unbounded_channel();
        let alive_time = Instant::now();

        let fut = async move {
            info!("{} start udp socks5", src);
            let result = Self::run_udp_socks5(src, mac, socks5_addr, outbound, inbound).await;
            info!("{} stop udp socks5: {:?}", src, result);
            src
        };

        (Self { input, alive_time }, fut)
    }

    fn is_timeout(&self) -> bool {
        (Instant::now() - self.alive_time) > Duration::new(CLIENT_TIMEOUT_SECS, 0)
    }

    fn send_to(
        &mut self,
        packet: UdpSocks5Message,
    ) -> core::result::Result<(), SendError<UdpSocks5Message>> {
        self.alive_time = Instant::now();
        self.input.send(packet)
    }

    async fn run_udp_socks5(
        src: SocketAddrV4,
        mac: MacAddr,
        socks5_addr: SocketAddr,
        outbound: UnboundedSender<UdpSocks5Message>,
        inbound: UnboundedReceiver<UdpSocks5Message>,
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
        mut inbound: UnboundedReceiver<UdpSocks5Message>,
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
        outbound: UnboundedSender<UdpSocks5Message>,
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

            let message = UdpSocks5Message {
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
