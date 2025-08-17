use std::env;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atomic_time::AtomicInstant;
use gatewaysocks::gateway::new_gateway;
use gatewaysocks::{gateway, socks5};
use getopts::Options;
use log::info;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::runtime::Runtime;
use tokio::time::sleep_until;

async fn gateway_udp_send(
    socket: &gateway::UdpSocket,
    osocket: &UdpSocket,
    proxy_addr: SocketAddr,
    t: Arc<AtomicInstant>,
) -> std::io::Result<()> {
    loop {
        let mut buf = [0u8; 1500];
        let (size, dst) = socket.recv(&mut buf[10..]).await?;

        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = socks5::ATYP_IPV4;
        buf[4..8].copy_from_slice(&dst.ip().octets());
        buf[8..10].copy_from_slice(&dst.port().to_be_bytes());

        osocket.send_to(&buf[..10 + size], proxy_addr).await?;
        t.store(Instant::now(), Ordering::Relaxed);
    }
}

async fn gateway_udp_recv(
    socket: &gateway::UdpSocket,
    osocket: &UdpSocket,
    t: Arc<AtomicInstant>,
) -> std::io::Result<()> {
    loop {
        let mut buf = [0u8; 1500];
        let (n, _) = osocket.recv_from(&mut buf).await?;
        if n <= 10 || buf[3] != socks5::ATYP_IPV4 {
            continue;
        }

        let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        let port = u16::from_be_bytes(buf[8..10].try_into().unwrap());
        let from = SocketAddrV4::new(ip, port);
        socket.try_send(&buf[10..n], from)?;
        t.store(Instant::now(), Ordering::Relaxed);
    }
}

async fn gateway_udp_timeout(t: Arc<AtomicInstant>, timeout: Duration) -> std::io::Result<()> {
    loop {
        let deadline = t.load(Ordering::Relaxed) + timeout;
        if deadline <= Instant::now() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        }

        sleep_until(deadline.into()).await;
    }
}

async fn gateway_udp_holder(mut holder: TcpStream) -> std::io::Result<()> {
    loop {
        let mut buffer = [0u8; 1024];
        let size = holder.read(&mut buffer).await?;
        if size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "holding tcp closed",
            ));
        }
    }
}

async fn gateway_udp_socket(socket: gateway::UdpSocket, socks5: SocketAddr) -> std::io::Result<()> {
    let mut handshaker = socks5::Handshaker::new(socks5).await?;
    let osocket = UdpSocket::bind("0.0.0.0:0").await?;
    let proxy_addr = handshaker.udp_associate(osocket.local_addr()?).await?;
    let holder = handshaker.into_tcp_stream();
    let t = Arc::new(AtomicInstant::now());
    let timeout = Duration::from_secs(60);

    futures::try_join!(
        gateway_udp_send(&socket, &osocket, proxy_addr, t.clone()),
        gateway_udp_recv(&socket, &osocket, t.clone()),
        gateway_udp_timeout(t, timeout),
        gateway_udp_holder(holder),
    )?;

    Ok(())
}

async fn gateway_tcp_stream(stream: gateway::TcpStream, socks5: SocketAddr) -> std::io::Result<()> {
    let mut handshaker = socks5::Handshaker::new(socks5).await?;
    handshaker.connect(stream.remote_addr()).await?;

    let mut stream = stream;
    let (mut reader, mut writer) = stream.split();

    let mut ostream = handshaker.into_tcp_stream();
    let (mut oreader, mut owriter) = ostream.split();

    let _ = futures::join!(
        tokio::io::copy(&mut reader, &mut owriter),
        tokio::io::copy(&mut oreader, &mut writer),
    );

    Ok(())
}

fn gateway_async_main(
    gateway: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    iface_name: &str,
    socks5: SocketAddr,
) {
    info!(
        "start gatewaysocks on {}: {}({}), relay to socks5://{} ...",
        iface_name, gateway, subnet_mask, socks5
    );

    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        let (mut udp_binder, mut tcp_listener) =
            new_gateway(gateway, subnet_mask, iface_name).unwrap();
        let fut_udp = async {
            loop {
                let socket = udp_binder.accept().await.unwrap();
                info!("UDP socket going out: {}", socket.local_addr());
                tokio::spawn(gateway_udp_socket(socket, socks5));
            }
        };
        let fut_tcp = async {
            loop {
                let stream = tcp_listener.accept().await.unwrap();
                info!(
                    "TCP stream going out: {} -> {}",
                    stream.local_addr(),
                    stream.remote_addr()
                );
                tokio::spawn(gateway_tcp_stream(stream, socks5));
            }
        };

        futures::join!(fut_udp, fut_tcp);
    });
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();

    opts.optopt("i", "interface", "ether interface", "interface");
    opts.optopt("s", "socks5", "socks5 address", "socks5");
    opts.optopt("", "gateway-ip", "gateway ip", "gateway");
    opts.optopt("", "subnet-mask", "subnet mask", "subnet");
    opts.optopt("", "prometheus", "prometheus exporter", "prometheus");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => return println!("{}", opts.short_usage(&args[0])),
    };

    let iface_name = matches.opt_str("i").unwrap_or("".to_string());
    let socks5_addr = matches.opt_str("s").unwrap_or("127.0.0.1:1080".to_string());
    let gateway_addr = matches
        .opt_str("gateway-ip")
        .unwrap_or("10.6.0.1".to_string());
    let subnet_addr = matches
        .opt_str("subnet-mask")
        .unwrap_or("255.255.255.0".to_string());

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let socks5 = socks5_addr.parse::<SocketAddr>().unwrap();
    let gateway = gateway_addr.parse::<Ipv4Addr>().unwrap();
    let subnet_mask = subnet_addr.parse::<Ipv4Addr>().unwrap();

    gateway_async_main(gateway, subnet_mask, &iface_name, socks5);
}
