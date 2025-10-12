use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ATYP_IPV4: u8 = 1;
const VER: u8 = 5;
const NO_AUTH: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

pub struct Handshaker {
    stream: TcpStream,
}

impl Handshaker {
    async fn new(addr: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let mut handshaker = Self { stream };

        handshaker.select_method().await?;
        Ok(handshaker)
    }

    pub async fn connect(socks5: SocketAddr, destination: SocketAddr) -> Result<TcpStream> {
        let mut handshaker = Self::new(socks5).await?;
        handshaker.handshake(destination, CMD_CONNECT).await?;
        Ok(handshaker.stream)
    }

    pub async fn udp_associate(
        socks5: SocketAddr,
        local_addr: SocketAddr,
    ) -> Result<(SocketAddr, TcpStream)> {
        let mut handshaker = Self::new(socks5).await?;
        let mut addr = handshaker.handshake(local_addr, CMD_UDP_ASSOCIATE).await?;

        if addr.ip().is_unspecified() {
            addr = SocketAddr::new(socks5.ip(), addr.port());
        }

        Ok((addr, handshaker.stream))
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

pub struct UdpSocketBuf {
    buf: [u8; 1500],
    data_len: usize,
}

impl UdpSocketBuf {
    pub fn new() -> Self {
        Self {
            buf: [0u8; _],
            data_len: 0,
        }
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[10..]
    }

    pub fn set_len(&mut self, len: usize) {
        self.data_len = len;
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.buf[10..10 + self.data_len]
    }
}

pub struct UdpSocket {
    socket: tokio::net::UdpSocket,
}

impl UdpSocket {
    pub fn from(socket: tokio::net::UdpSocket) -> Self {
        Self { socket }
    }

    pub async fn send_to(
        &self,
        buf: &mut UdpSocketBuf,
        addr: SocketAddrV4,
        proxy_addr: SocketAddr,
    ) -> Result<()> {
        let len = buf.data_len;
        let buf = &mut buf.buf;

        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = ATYP_IPV4;
        buf[4..8].copy_from_slice(&addr.ip().octets());
        buf[8..10].copy_from_slice(&addr.port().to_be_bytes());

        self.socket.send_to(&buf[..10 + len], proxy_addr).await?;
        Ok(())
    }

    pub async fn recv_from(&self, buf: &mut UdpSocketBuf) -> Result<SocketAddrV4> {
        loop {
            let (n, _) = self.socket.recv_from(&mut buf.buf).await?;
            if n <= 10 || buf.buf[3] != ATYP_IPV4 {
                continue;
            }

            buf.set_len(n - 10);

            let buf = &mut buf.buf;
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes(buf[8..10].try_into().unwrap());

            return Ok(SocketAddrV4::new(ip, port));
        }
    }
}

pub async fn udp_holder(stream: &mut TcpStream) -> Result<()> {
    loop {
        let mut buffer = [0u8; 1024];
        let size = stream.read(&mut buffer).await?;
        if size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "holding tcp closed",
            ));
        }
    }
}
