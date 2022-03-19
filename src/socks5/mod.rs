use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

pub mod tcp;
pub mod udp;

const ATYP_IPV4: u8 = 1;
const VER: u8 = 5;
const NO_AUTH: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

pub struct Socks5Channel<T> {
    pub tx: UnboundedSender<T>,
    pub rx: UnboundedReceiver<T>,
}

pub fn socks5_channel<T>() -> (Socks5Channel<T>, Socks5Channel<T>) {
    let (tx1, rx1) = unbounded_channel();
    let (tx2, rx2) = unbounded_channel();
    (
        Socks5Channel { tx: tx1, rx: rx2 },
        Socks5Channel { tx: tx2, rx: rx1 },
    )
}

struct Handshaker {
    server: SocketAddr,
    stream: TcpStream,
}

impl Handshaker {
    async fn new(server: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(server).await?;
        let mut handshaker = Self { server, stream };

        handshaker.select_method().await?;
        Ok(handshaker)
    }

    fn into_tcp_stream(self) -> TcpStream {
        self.stream
    }

    async fn connect(&mut self, destination: SocketAddr) -> Result<SocketAddr> {
        self.handshake(destination, CMD_CONNECT).await
    }

    async fn udp_associate(&mut self, local_addr: SocketAddr) -> Result<SocketAddr> {
        let addr = self.handshake(local_addr, CMD_UDP_ASSOCIATE).await?;
        Ok(SocketAddr::new(self.server.ip(), addr.port()))
    }

    async fn select_method(&mut self) -> Result<()> {
        let request = [VER, 1, NO_AUTH];
        self.stream.write_all(&request).await?;

        let mut response = [0u8; 2];
        self.stream.read_exact(&mut response).await?;

        if response[0] != VER || response[1] != NO_AUTH {
            return Err(Error::new(ErrorKind::Other, "socks5: select method error"));
        }

        Ok(())
    }

    async fn handshake(&mut self, address: SocketAddr, cmd: u8) -> Result<SocketAddr> {
        let mut request = [0u8; 10];
        request[0] = VER;
        request[1] = cmd;
        request[2] = 0;
        request[3] = ATYP_IPV4;

        match address {
            SocketAddr::V4(addr) => {
                request[4..8].copy_from_slice(&addr.ip().octets());
                request[8..10].copy_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(_) => panic!("socks5: unsupport ipv6"),
        }

        self.stream.write_all(&request).await?;

        let mut response = [0u8; 10];
        self.stream.read_exact(&mut response).await?;

        if response[0] != VER || response[1] != 0 || response[3] != ATYP_IPV4 {
            return Err(Error::new(ErrorKind::Other, "socks5: handshake error"));
        }

        let ip = Ipv4Addr::new(response[4], response[5], response[6], response[7]);
        let port = u16::from_be_bytes(response[8..10].try_into().unwrap());

        Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    }
}
