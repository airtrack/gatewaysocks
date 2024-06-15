use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::net::{SocketAddr, SocketAddrV4};
use std::pin::Pin;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::{
    channel, unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender,
};

use super::Handshaker;

pub enum TcpSocks5Message {
    Connect((String, SocketAddrV4)),
    Established(String),
    Push((String, Vec<u8>)),
    Shutdown(String),
    Close(String),
}

pub fn tcp_socks5(socks5_addr: SocketAddr) -> (TcpSocks5Handle, TcpSocks5Service) {
    let (futs_tx, futs_rx) = unbounded_channel();
    let handle = TcpSocks5Handle::new(socks5_addr, futs_tx);
    let service = TcpSocks5Service::new(futs_rx);
    (handle, service)
}

pub struct TcpSocks5Handle {
    socks5_addr: SocketAddr,
    futs_tx: UnboundedSender<Box<dyn Future<Output = ()> + Send>>,
}

impl TcpSocks5Handle {
    fn new(
        socks5_addr: SocketAddr,
        futs_tx: UnboundedSender<Box<dyn Future<Output = ()> + Send>>,
    ) -> Self {
        Self {
            socks5_addr,
            futs_tx,
        }
    }

    pub fn start_connection(&mut self, key: &str, destination: SocketAddrV4) -> TcpSocks5Client {
        let (client, fut) =
            TcpSocks5Client::new(key, self.socks5_addr, SocketAddr::V4(destination));

        let _ = self.futs_tx.send(Box::new(fut));
        client
    }
}

pub struct TcpSocks5Service {
    futs: FuturesUnordered<Pin<Box<dyn Future<Output = ()> + Send>>>,
    futs_rx: UnboundedReceiver<Box<dyn Future<Output = ()> + Send>>,
}

impl TcpSocks5Service {
    fn new(futs_rx: UnboundedReceiver<Box<dyn Future<Output = ()> + Send>>) -> Self {
        let futs = FuturesUnordered::new();
        Self { futs, futs_rx }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(_) = self.futs.next() => {}
                Some(fut) = self.futs_rx.recv() => {
                    self.futs.push(Pin::from(fut));
                }
            }
        }
    }
}

pub struct TcpSocks5Client {
    input: UnboundedSender<TcpSocks5Message>,
    output: Receiver<TcpSocks5Message>,
}

impl TcpSocks5Client {
    fn new(
        key: &str,
        socks5_addr: SocketAddr,
        destination: SocketAddr,
    ) -> (Self, impl Future<Output = ()>) {
        let (input, inbound) = unbounded_channel();
        let (outbound, output) = channel(32);

        let key = key.to_string();
        let fut = async move {
            let sender = outbound.clone();
            info!("{} start tcp socks5", key);
            let result =
                Self::run_tcp_socks5(&key, socks5_addr, destination, outbound, inbound).await;
            info!("{} stop tcp socks5: {:?}", key, result);
            let _ = sender.send(TcpSocks5Message::Close(key));
        };

        (Self { input, output }, fut)
    }

    pub fn send_socks5_message(&self, message: TcpSocks5Message) {
        let _ = self.input.send(message);
    }

    pub fn recv_socks5_messages(&mut self) -> Option<Vec<TcpSocks5Message>> {
        let size = self.output.len();
        if size == 0 {
            return None;
        }

        let mut messages = Vec::new();
        messages.reserve(size);

        loop {
            match self.output.try_recv() {
                Ok(message) => {
                    messages.push(message);
                }
                Err(_) => break,
            }
        }

        Some(messages)
    }

    async fn run_tcp_socks5(
        key: &str,
        socks5_addr: SocketAddr,
        destination: SocketAddr,
        outbound: Sender<TcpSocks5Message>,
        inbound: UnboundedReceiver<TcpSocks5Message>,
    ) -> Result<()> {
        let mut handshaker = Handshaker::new(socks5_addr).await?;
        handshaker.connect(destination).await?;

        outbound
            .send(TcpSocks5Message::Established(key.to_string()))
            .await
            .map_err(|_| Error::new(ErrorKind::Other, "send established error"))?;

        let (reader, writer) = handshaker.into_tcp_stream().into_split();
        let send_task = Self::send_to_socks5(inbound, writer);
        let recv_task = Self::receive_from_socks5(key, outbound, reader);

        futures::try_join!(send_task, recv_task)?;
        Ok(())
    }

    async fn send_to_socks5(
        mut inbound: UnboundedReceiver<TcpSocks5Message>,
        mut writer: OwnedWriteHalf,
    ) -> Result<()> {
        loop {
            let packet = inbound
                .recv()
                .await
                .ok_or(Error::new(ErrorKind::Other, "inbound dropped"))?;

            match packet {
                TcpSocks5Message::Push((_, data)) => {
                    writer.write(&data).await?;
                }
                TcpSocks5Message::Shutdown(_) => {
                    writer.shutdown().await?;
                    break;
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn receive_from_socks5(
        key: &str,
        outbound: Sender<TcpSocks5Message>,
        mut reader: OwnedReadHalf,
    ) -> Result<()> {
        loop {
            let mut buffer = vec![0u8; 2048];
            let len = reader.read(&mut buffer).await?;

            if len == 0 {
                outbound
                    .send(TcpSocks5Message::Shutdown(key.to_string()))
                    .await
                    .map_err(|_| Error::new(ErrorKind::Other, "send shutdown error"))?;
                break;
            }

            buffer.truncate(len);
            outbound
                .send(TcpSocks5Message::Push((key.to_string(), buffer)))
                .await
                .map_err(|_| Error::new(ErrorKind::Other, "send message error"))?;
        }

        Ok(())
    }
}
