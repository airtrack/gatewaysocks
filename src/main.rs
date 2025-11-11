use std::env;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use atomic_time::AtomicInstant;
use axum::response::IntoResponse;
use axum::{Router, routing};
use gatewaysocks::gateway::{self, tcp, udp};
use getopts::Options;
use log::info;
use tabled::settings::Style;
use tabled::{Table, Tabled};
use tokio::net::{TcpListener, UdpSocket};
use tokio::runtime::Runtime;
use tokio::time::sleep_until;

async fn gateway_udp_send(
    socket: &gateway::UdpSocket,
    osocket: &socks5::UdpSocket,
    t: Arc<AtomicInstant>,
) -> std::io::Result<()> {
    let mut buf = socks5::UdpSocketBuf::new();

    loop {
        let (size, dst) = socket.recv(buf.as_mut()).await?;
        buf.set_len(size);

        osocket.send(&mut buf, SocketAddr::V4(dst)).await?;
        t.store(Instant::now(), Ordering::Relaxed);
    }
}

async fn gateway_udp_recv(
    socket: &gateway::UdpSocket,
    osocket: &socks5::UdpSocket,
    t: Arc<AtomicInstant>,
) -> std::io::Result<()> {
    let mut buf = socks5::UdpSocketBuf::new();

    loop {
        if let SocketAddr::V4(from) = osocket.recv(&mut buf).await? {
            socket.try_send(buf.as_ref(), from)?;
            t.store(Instant::now(), Ordering::Relaxed);
        }
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

async fn gateway_udp_holder(mut holder: socks5::UdpSocketHolder) -> std::io::Result<()> {
    holder.wait().await
}

async fn gateway_udp_socket(socket: gateway::UdpSocket, socks5: SocketAddr) -> std::io::Result<()> {
    let osocket = UdpSocket::bind("0.0.0.0:0").await?;
    let (osocket, holder) = socks5::udp_associate(socks5, osocket).await?;

    let t = Arc::new(AtomicInstant::now());
    let timeout = Duration::from_secs(60);

    futures::try_join!(
        gateway_udp_send(&socket, &osocket, t.clone()),
        gateway_udp_recv(&socket, &osocket, t.clone()),
        gateway_udp_timeout(t, timeout),
        gateway_udp_holder(holder),
    )?;

    Ok(())
}

async fn gateway_tcp_stream(stream: gateway::TcpStream, socks5: SocketAddr) -> std::io::Result<()> {
    let destination = socks5::Address::Ip(stream.destination_addr());
    let mut ostream = socks5::connect(socks5, destination).await?;
    let mut stream = stream;

    tokio::io::copy_bidirectional(&mut stream, &mut ostream).await?;
    Ok(())
}

async fn gateway_stats(listen: &str, tcp_stats: tcp::StatsMap, udp_stats: udp::StatsSet) {
    #[derive(Tabled)]
    struct SocketEntry {
        #[tabled(rename = "Proto")]
        proto: &'static str,
        #[tabled(rename = "Recv-Q")]
        recv_queue: usize,
        #[tabled(rename = "Send-Q")]
        send_queue: usize,
        #[tabled(rename = "Source Address")]
        source: SocketAddrV4,
        #[tabled(rename = "Destination Address")]
        destination: SocketAddrV4,
        #[tabled(rename = "State")]
        state: &'static str,
    }

    #[derive(Tabled)]
    struct TcpSocketEntry {
        #[tabled(inline)]
        socket: SocketEntry,
        #[tabled(rename = "Congestion On")]
        limited: bool,
        #[tabled(rename = "Congestion State")]
        state: &'static str,
        #[tabled(rename = "Congestion Window")]
        cwnd: usize,
        #[tabled(rename = "Congestion Times")]
        times: usize,
        #[tabled(rename = "Min-RTT")]
        min_rtt: usize,
        #[tabled(rename = "SRTT")]
        srtt: usize,
        #[tabled(rename = "Remote Window")]
        rwnd: usize,
        #[tabled(rename = "TX Bytes")]
        tx_bytes: usize,
        #[tabled(rename = "RX Bytes")]
        rx_bytes: usize,
    }

    struct StatsState {
        tcp: tcp::StatsMap,
        udp: udp::StatsSet,
    }

    async fn netstat(
        axum::extract::State(stats): axum::extract::State<Arc<StatsState>>,
    ) -> impl IntoResponse {
        let mut entries = Vec::new();

        stats.tcp.for_each(|k, v| {
            let entry = SocketEntry {
                proto: "tcp4",
                recv_queue: v.get_recv_queue(),
                send_queue: v.get_send_queue(),
                source: k.source,
                destination: k.destination,
                state: v.get_state().to_str(),
            };
            entries.push(entry);
        });

        stats.udp.for_each(|k| {
            let entry = SocketEntry {
                proto: "udp4",
                recv_queue: 0,
                send_queue: 0,
                source: *k,
                destination: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                state: "",
            };
            entries.push(entry);
        });

        let mut table = Table::new(entries);
        table.with(Style::empty());
        table.to_string()
    }

    async fn netstat_tcp(
        axum::extract::State(stats): axum::extract::State<Arc<StatsState>>,
    ) -> impl IntoResponse {
        let mut entries = Vec::new();

        stats.tcp.for_each(|k, v| {
            let entry = TcpSocketEntry {
                socket: SocketEntry {
                    proto: "tcp4",
                    recv_queue: v.get_recv_queue(),
                    send_queue: v.get_send_queue(),
                    source: k.source,
                    destination: k.destination,
                    state: v.get_state().to_str(),
                },
                limited: v.get_congestion_limited(),
                state: v.get_congestion_state().to_str(),
                cwnd: v.get_congestion_window(),
                times: v.get_congestion_times(),
                min_rtt: v.get_min_rtt(),
                srtt: v.get_srtt(),
                rwnd: v.get_remote_window(),
                tx_bytes: v.get_tx_bytes(),
                rx_bytes: v.get_rx_bytes(),
            };
            entries.push(entry);
        });

        let mut table = Table::new(entries);
        table.with(Style::empty());
        table.to_string()
    }

    let stats_state = Arc::new(StatsState {
        tcp: tcp_stats,
        udp: udp_stats,
    });

    let app = Router::new()
        .route("/netstat", routing::get(netstat))
        .route("/netstat/tcp", routing::get(netstat_tcp))
        .with_state(stats_state);

    let listener = TcpListener::bind(listen).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn gateway_serve(
    stats: &str,
    iface_name: &str,
    gateway: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    socks5: SocketAddr,
) {
    info!(
        "start gatewaysocks on {}: {}({}), relay to socks5://{} ...",
        iface_name, gateway, subnet_mask, socks5
    );

    let (mut udp, mut tcp) = gateway::new(gateway, subnet_mask, iface_name).unwrap();
    let udp_stats = udp.get_stats();
    let tcp_stats = tcp.get_stats();

    let fut_udp = async {
        loop {
            let socket = udp.accept().await.unwrap();
            info!("UDP socket going out: {}", socket.source_addr());
            tokio::spawn(gateway_udp_socket(socket, socks5));
        }
    };
    let fut_tcp = async {
        loop {
            let stream = tcp.accept().await.unwrap();
            info!(
                "TCP stream going out: {} -> {}",
                stream.source_addr(),
                stream.destination_addr()
            );
            tokio::spawn(gateway_tcp_stream(stream, socks5));
        }
    };
    let fut_stats = gateway_stats(stats, tcp_stats, udp_stats);

    futures::join!(fut_udp, fut_tcp, fut_stats);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();

    opts.optopt("i", "interface", "ether interface", "interface");
    opts.optopt("s", "socks5", "socks5 address", "socks5");
    opts.optopt("", "gateway-ip", "gateway ip", "gateway");
    opts.optopt("", "subnet-mask", "subnet mask", "subnet");
    opts.optopt("", "stats", "query statistics", "ip:port");

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
    let stats = matches
        .opt_str("stats")
        .unwrap_or("127.0.0.1:3080".to_string());

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let socks5 = socks5_addr.parse::<SocketAddr>().unwrap();
    let gateway = gateway_addr.parse::<Ipv4Addr>().unwrap();
    let subnet_mask = subnet_addr.parse::<Ipv4Addr>().unwrap();

    let rt = Runtime::new().unwrap();
    rt.block_on(async move {
        gateway_serve(&stats, &iface_name, gateway, subnet_mask, socks5).await;
    });
}
