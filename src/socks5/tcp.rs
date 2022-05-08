use std::collections::HashMap;
use std::io::Result;
use std::net::{SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::watch::{self, Receiver, Sender};

use super::{Handshaker, Socks5Channel};

pub enum TcpSocks5Data {
    Connect((String, SocketAddrV4)),
    Established(String),
    Push((String, Vec<u8>)),
    Shutdown(String),
    Close(String),
}

pub struct TcpSocks5 {
    socks5_addr: SocketAddr,
    channel: Socks5Channel<TcpSocks5Data>,
    exited_tx: UnboundedSender<String>,
    exited_rx: UnboundedReceiver<String>,
    clients: HashMap<String, Client>,
}

struct Client {
    tx: UnboundedSender<TcpSocks5Data>,
    shutdown: Sender<()>,
}

impl TcpSocks5 {
    pub fn new(socks5_addr: SocketAddr, channel: Socks5Channel<TcpSocks5Data>) -> Self {
        let (exited_tx, exited_rx) = unbounded_channel();

        Self {
            socks5_addr,
            channel,
            exited_tx,
            exited_rx,
            clients: HashMap::new(),
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                key = self.exited_rx.recv() => {
                    if let Some(key) = key {
                        if let Some(client) = self.clients.get(&key) {
                            client.shutdown();
                            self.clients.remove(&key);
                            let _ = self.channel.tx.send(TcpSocks5Data::Close(key));
                        }
                    }
                }
                result = self.channel.rx.recv() => {
                    if let Some(data) = result {
                        match data {
                            TcpSocks5Data::Connect((key, destination)) => {
                                let client = Client::new(
                                    key.clone(),
                                    self.socks5_addr,
                                    SocketAddr::V4(destination),
                                    self.channel.tx.clone(),
                                    self.exited_tx.clone()
                                );
                                self.clients.insert(key, client);
                            }
                            TcpSocks5Data::Push((key, buffer)) => {
                                if let Some(client) = self.clients.get(&key) {
                                    client.send_to(TcpSocks5Data::Push((key, buffer)));
                                }
                            }
                            TcpSocks5Data::Shutdown(key) => {
                                if let Some(client) = self.clients.get(&key) {
                                    client.send_to(TcpSocks5Data::Shutdown(key));
                                }
                            }
                            TcpSocks5Data::Close(key) => {
                                if let Some(client) = self.clients.get(&key) {
                                    client.shutdown();
                                    self.clients.remove(&key);
                                }
                            }
                            _ => {}
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
        destination: SocketAddr,
        output_tx: UnboundedSender<TcpSocks5Data>,
        exited_tx: UnboundedSender<String>,
    ) -> Self {
        let (tx, rx) = unbounded_channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        tokio::spawn(async move {
            let result = Self::socks5_task(
                key.clone(),
                shutdown_rx,
                server_addr,
                destination,
                exited_tx.clone(),
                output_tx,
                rx,
            )
            .await;

            if result.is_err() {
                let _ = exited_tx.send(key);
            }
        });

        Self {
            tx,
            shutdown: shutdown_tx,
        }
    }

    fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    fn send_to(&self, message: TcpSocks5Data) {
        let _ = self.tx.send(message);
    }

    async fn socks5_task(
        key: String,
        shutdown: Receiver<()>,
        server_addr: SocketAddr,
        destination: SocketAddr,
        exited_tx: UnboundedSender<String>,
        output_tx: UnboundedSender<TcpSocks5Data>,
        input_rx: UnboundedReceiver<TcpSocks5Data>,
    ) -> Result<()> {
        let mut handshaker = Handshaker::new(server_addr).await?;
        handshaker.connect(destination).await?;
        let _ = output_tx.send(TcpSocks5Data::Established(key.clone()));

        let (reader, writer) = handshaker.into_tcp_stream().into_split();

        let k = key.clone();
        let s = shutdown.clone();
        let e = exited_tx.clone();
        tokio::spawn(async move {
            Self::send_to_socks5(k, s, e, input_rx, writer).await;
        });

        let k = key;
        let s = shutdown;
        let e = exited_tx;
        tokio::spawn(async move {
            Self::receive_from_socks5(k, s, e, output_tx, reader).await;
        });

        Ok(())
    }

    async fn send_to_socks5(
        key: String,
        mut shutdown: Receiver<()>,
        exited_tx: UnboundedSender<String>,
        mut input_rx: UnboundedReceiver<TcpSocks5Data>,
        mut writer: OwnedWriteHalf,
    ) {
        loop {
            tokio::select! {
                result = input_rx.recv() => {
                    if let Some(input) = result {
                        match input {
                            TcpSocks5Data::Push((_, data)) => {
                                if writer.write(&data).await.is_err() {
                                    let _ = exited_tx.send(key);
                                    break;
                                }
                            }
                            TcpSocks5Data::Shutdown(_) => {
                                if writer.shutdown().await.is_err() {
                                    let _ = exited_tx.send(key);
                                }
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
    }

    async fn receive_from_socks5(
        key: String,
        mut shutdown: Receiver<()>,
        exited_tx: UnboundedSender<String>,
        output_tx: UnboundedSender<TcpSocks5Data>,
        mut reader: OwnedReadHalf,
    ) {
        loop {
            let mut buffer = vec![0u8; 2048];
            tokio::select! {
                result = reader.read(&mut buffer) => {
                    match result {
                        Ok(0) => {
                            let _ = output_tx.send(TcpSocks5Data::Shutdown(key.clone()));
                            break;
                        }
                        Ok(n) => {
                            buffer.truncate(n);
                            let _ = output_tx.send(TcpSocks5Data::Push((key.clone(), buffer)));
                        }
                        Err(_) => {
                            let _ = exited_tx.send(key);
                            break;
                        }
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
    }
}
