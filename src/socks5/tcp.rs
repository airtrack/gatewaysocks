use std::collections::HashMap;
use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::net::{SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::error::{SendError, TryRecvError};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use super::Handshaker;

pub enum TcpSocks5Message {
    Connect((String, SocketAddrV4)),
    Established(String),
    Push((String, Vec<u8>)),
    Shutdown(String),
    Close(String),
}

pub fn tcp_socks5(socks5_addr: SocketAddr) -> (TcpSocks5Handle, TcpSocks5Service) {
    let clients = Arc::new(Mutex::new(HashMap::new()));
    let (futs_tx, futs_rx) = unbounded_channel();
    let (message_tx, message_rx) = unbounded_channel();
    let handle = TcpSocks5Handle::new(
        socks5_addr,
        clients.clone(),
        futs_tx,
        message_tx.clone(),
        message_rx,
    );
    let service = TcpSocks5Service::new(clients, futs_rx, message_tx);
    (handle, service)
}

pub struct TcpSocks5Handle {
    socks5_addr: SocketAddr,
    clients: Arc<Mutex<HashMap<String, TcpSocks5Client>>>,
    futs_tx: UnboundedSender<Box<dyn Future<Output = String> + Send>>,
    message_tx: UnboundedSender<TcpSocks5Message>,
    message_rx: UnboundedReceiver<TcpSocks5Message>,
}

impl TcpSocks5Handle {
    fn new(
        socks5_addr: SocketAddr,
        clients: Arc<Mutex<HashMap<String, TcpSocks5Client>>>,
        futs_tx: UnboundedSender<Box<dyn Future<Output = String> + Send>>,
        message_tx: UnboundedSender<TcpSocks5Message>,
        message_rx: UnboundedReceiver<TcpSocks5Message>,
    ) -> Self {
        Self {
            socks5_addr,
            clients,
            futs_tx,
            message_tx,
            message_rx,
        }
    }

    pub fn start_connection(&mut self, key: &str, destination: SocketAddrV4) {
        let (client, fut) = TcpSocks5Client::new(
            key,
            self.socks5_addr,
            SocketAddr::V4(destination),
            self.message_tx.clone(),
        );

        let _ = self.futs_tx.send(Box::new(fut));
        self.clients.lock().unwrap().insert(key.to_string(), client);
    }

    pub fn close_connection(&mut self, key: &str) {
        self.clients.lock().unwrap().remove(key);
    }

    pub fn send_socks5_message(&mut self, message: TcpSocks5Message) {
        match message {
            TcpSocks5Message::Push((ref key, _)) => {
                if let Some(client) = self.clients.lock().unwrap().get(key) {
                    let _ = client.send_to(message);
                }
            }
            TcpSocks5Message::Shutdown(ref key) => {
                if let Some(client) = self.clients.lock().unwrap().get(key) {
                    let _ = client.send_to(message);
                }
            }
            _ => {}
        }
    }

    pub fn try_recv_socks5_message(
        &mut self,
    ) -> core::result::Result<TcpSocks5Message, TryRecvError> {
        self.message_rx.try_recv()
    }
}

pub struct TcpSocks5Service {
    clients: Arc<Mutex<HashMap<String, TcpSocks5Client>>>,
    futs: FuturesUnordered<Pin<Box<dyn Future<Output = String> + Send>>>,
    futs_rx: UnboundedReceiver<Box<dyn Future<Output = String> + Send>>,
    message_tx: UnboundedSender<TcpSocks5Message>,
}

impl TcpSocks5Service {
    fn new(
        clients: Arc<Mutex<HashMap<String, TcpSocks5Client>>>,
        futs_rx: UnboundedReceiver<Box<dyn Future<Output = String> + Send>>,
        message_tx: UnboundedSender<TcpSocks5Message>,
    ) -> Self {
        let futs = FuturesUnordered::new();

        Self {
            clients,
            futs,
            futs_rx,
            message_tx,
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(key) = self.futs.next() => {
                    self.clients.lock().unwrap().remove(&key);
                    let _ = self.message_tx.send(TcpSocks5Message::Close(key));
                }
                Some(fut) = self.futs_rx.recv() => {
                    self.futs.push(Pin::from(fut));
                }
            }
        }
    }
}

struct TcpSocks5Client {
    input: UnboundedSender<TcpSocks5Message>,
}

impl TcpSocks5Client {
    fn new(
        key: &str,
        socks5_addr: SocketAddr,
        destination: SocketAddr,
        outbound: UnboundedSender<TcpSocks5Message>,
    ) -> (Self, impl Future<Output = String>) {
        let (input, inbound) = unbounded_channel();

        let key = key.to_string();
        let fut = async move {
            info!("{} start tcp socks5", key);
            let result =
                Self::run_tcp_socks5(&key, socks5_addr, destination, outbound, inbound).await;
            info!("{} stop tcp socks5: {:?}", key, result);
            key
        };

        (Self { input }, fut)
    }

    fn send_to(
        &self,
        message: TcpSocks5Message,
    ) -> core::result::Result<(), SendError<TcpSocks5Message>> {
        self.input.send(message)
    }

    async fn run_tcp_socks5(
        key: &str,
        socks5_addr: SocketAddr,
        destination: SocketAddr,
        outbound: UnboundedSender<TcpSocks5Message>,
        inbound: UnboundedReceiver<TcpSocks5Message>,
    ) -> Result<()> {
        let mut handshaker = Handshaker::new(socks5_addr).await?;
        handshaker.connect(destination).await?;

        outbound
            .send(TcpSocks5Message::Established(key.to_string()))
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
        outbound: UnboundedSender<TcpSocks5Message>,
        mut reader: OwnedReadHalf,
    ) -> Result<()> {
        loop {
            let mut buffer = vec![0u8; 2048];
            let len = reader.read(&mut buffer).await?;

            if len == 0 {
                outbound
                    .send(TcpSocks5Message::Shutdown(key.to_string()))
                    .map_err(|_| Error::new(ErrorKind::Other, "send shutdown error"))?;
                break;
            }

            buffer.truncate(len);
            outbound
                .send(TcpSocks5Message::Push((key.to_string(), buffer)))
                .map_err(|_| Error::new(ErrorKind::Other, "send message error"))?;
        }

        Ok(())
    }
}
