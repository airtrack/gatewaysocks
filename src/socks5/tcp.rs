use std::collections::HashMap;
use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::net::{SocketAddr, SocketAddrV4};
use std::pin::Pin;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::{error, info};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::{error::SendError, unbounded_channel, UnboundedReceiver, UnboundedSender};

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
    clients: HashMap<String, Client>,
    futs: FuturesUnordered<Pin<Box<dyn Future<Output = String>>>>,
}

struct Client {
    input: UnboundedSender<TcpSocks5Data>,
}

impl TcpSocks5 {
    pub fn new(socks5_addr: SocketAddr, channel: Socks5Channel<TcpSocks5Data>) -> Self {
        let clients = HashMap::new();
        let futs = FuturesUnordered::new();

        Self {
            socks5_addr,
            channel,
            clients,
            futs,
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(key) = self.futs.next() => {
                    self.clients.remove(&key);
                    let _ = self.channel.tx.send(TcpSocks5Data::Close(key));
                }
                Some(data) = self.channel.rx.recv() => {
                    match data {
                        TcpSocks5Data::Connect((key, destination)) => {
                            let (client, fut) = Client::new(
                                &key,
                                self.socks5_addr,
                                SocketAddr::V4(destination),
                                self.channel.tx.clone(),
                            );
                            self.clients.insert(key, client);
                            self.futs.push(Box::pin(fut));
                        }
                        TcpSocks5Data::Push((key, buffer)) => {
                            if let Some(client) = self.clients.get(&key) {
                                match client.send_to(TcpSocks5Data::Push((key, buffer))) {
                                    Err(SendError(TcpSocks5Data::Push((key, _)))) => {
                                        error!("{} tcp socks5 ended, send message error", key);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        TcpSocks5Data::Shutdown(key) => {
                            if let Some(client) = self.clients.get(&key) {
                                match client.send_to(TcpSocks5Data::Shutdown(key)) {
                                    Err(SendError(TcpSocks5Data::Shutdown(key))) => {
                                        error!("{} tcp socks5 ended, send shutdown error", key);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        TcpSocks5Data::Close(key) => {
                            self.clients.remove(&key);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

impl Client {
    fn new(
        key: &str,
        socks5_addr: SocketAddr,
        destination: SocketAddr,
        outbound: UnboundedSender<TcpSocks5Data>,
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
        message: TcpSocks5Data,
    ) -> core::result::Result<(), SendError<TcpSocks5Data>> {
        self.input.send(message)
    }

    async fn run_tcp_socks5(
        key: &str,
        socks5_addr: SocketAddr,
        destination: SocketAddr,
        outbound: UnboundedSender<TcpSocks5Data>,
        inbound: UnboundedReceiver<TcpSocks5Data>,
    ) -> Result<()> {
        let mut handshaker = Handshaker::new(socks5_addr).await?;
        handshaker.connect(destination).await?;

        outbound
            .send(TcpSocks5Data::Established(key.to_string()))
            .map_err(|_| Error::new(ErrorKind::Other, "send established error"))?;

        let (reader, writer) = handshaker.into_tcp_stream().into_split();
        let send_task = Self::send_to_socks5(inbound, writer);
        let recv_task = Self::receive_from_socks5(key, outbound, reader);

        futures::try_join!(send_task, recv_task)?;
        Ok(())
    }

    async fn send_to_socks5(
        mut inbound: UnboundedReceiver<TcpSocks5Data>,
        mut writer: OwnedWriteHalf,
    ) -> Result<()> {
        loop {
            let packet = inbound
                .recv()
                .await
                .ok_or(Error::new(ErrorKind::Other, "inbound dropped"))?;

            match packet {
                TcpSocks5Data::Push((_, data)) => {
                    writer.write(&data).await?;
                }
                TcpSocks5Data::Shutdown(_) => {
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
        outbound: UnboundedSender<TcpSocks5Data>,
        mut reader: OwnedReadHalf,
    ) -> Result<()> {
        loop {
            let mut buffer = vec![0u8; 2048];
            let len = reader.read(&mut buffer).await?;

            if len == 0 {
                outbound
                    .send(TcpSocks5Data::Shutdown(key.to_string()))
                    .map_err(|_| Error::new(ErrorKind::Other, "send shutdown error"))?;
                break;
            }

            buffer.truncate(len);
            outbound
                .send(TcpSocks5Data::Push((key.to_string(), buffer)))
                .map_err(|_| Error::new(ErrorKind::Other, "send message error"))?;
        }

        Ok(())
    }
}
