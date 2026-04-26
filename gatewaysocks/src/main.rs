use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use atomic_time::AtomicInstant;
use axum::response::IntoResponse;
use axum::{Router, routing};
use clap::Parser;
use gateway::{tcp, udp};
use log::info;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{MetricExporter, Protocol, WithExportConfig};
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use shadow_rs::shadow;
use tabled::settings::Style;
use tabled::{Table, Tabled};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot::{self, Receiver, Sender};
use tokio::time::sleep_until;

shadow!(build);

#[derive(Parser)]
#[command(name = "gatewaysocks", disable_version_flag = true)]
struct Args {
    #[arg(
        short = 'i',
        long = "interface",
        value_name = "interface",
        help = "ether interface"
    )]
    interface: Option<String>,

    #[arg(
        short = 's',
        long = "socks5",
        value_name = "socks5",
        default_value = "127.0.0.1:1080",
        help = "socks5 address"
    )]
    socks5: SocketAddr,

    #[arg(
        long = "gateway-ip",
        value_name = "gateway",
        default_value = "10.6.0.1",
        help = "gateway ip"
    )]
    gateway_ip: Ipv4Addr,

    #[arg(
        long = "subnet-mask",
        value_name = "subnet",
        default_value = "255.255.255.0",
        help = "subnet mask"
    )]
    subnet_mask: Ipv4Addr,

    #[arg(
        long = "netstat",
        value_name = "ip:port",
        default_value = "127.0.0.1:3080",
        help = "netstat listen address"
    )]
    netstat: String,

    #[arg(
        long = "opentel",
        value_name = "http://ip:port",
        help = "opentel address"
    )]
    opentel: Option<String>,

    #[arg(
        long = "upstream-dns",
        value_name = "ip:port",
        value_parser = parse_upstream_dns,
        help = "upstream dns address"
    )]
    upstream_dns: Option<SocketAddr>,

    #[arg(long = "version", help = "print version information")]
    version: bool,
}

fn parse_upstream_dns(s: &str) -> Result<SocketAddr, String> {
    s.parse::<SocketAddr>().or_else(|_| {
        let ip = s
            .parse::<std::net::IpAddr>()
            .map_err(|_| "invalid upstream-dns address".to_string())?;
        Ok(SocketAddr::new(ip, 53))
    })
}

fn version() -> String {
    let git_dirty = if build::GIT_CLEAN { "" } else { "*" };
    let build_time = build::BUILD_TIME
        .rsplit_once(' ')
        .map(|(date, _)| date)
        .unwrap_or(build::BUILD_TIME);

    format!(
        "{} {} ({}{} {})",
        build::PROJECT_NAME,
        build::PKG_VERSION,
        build::SHORT_COMMIT,
        git_dirty,
        build_time
    )
}

async fn gateway_udp_send(
    socket: &gateway::UdpSocket,
    osocket: &socks5::UdpSocket,
    t: Arc<AtomicInstant>,
    gateway_ip: Ipv4Addr,
    dns_tx: Option<(Sender<Arc<UdpSocket>>, SocketAddr)>,
) -> std::io::Result<()> {
    let mut buf = socks5::UdpSocketBuf::new();

    if let Some((tx, upstream_dns)) = dns_tx {
        let gateway = SocketAddrV4::new(gateway_ip, 53);
        let mut dns_socket: Option<Arc<UdpSocket>> = None;
        let mut tx = Some(tx);

        loop {
            let (size, dst) = socket.recv(buf.as_mut()).await?;
            buf.set_len(size);

            if dst == gateway {
                if dns_socket.is_none() {
                    let s = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                    dns_socket = Some(s.clone());
                    tx.take().map(|tx| tx.send(s).ok());
                }

                dns_socket
                    .as_ref()
                    .unwrap()
                    .send_to(buf.as_ref(), upstream_dns)
                    .await?;

                t.store(Instant::now(), Ordering::Relaxed);
            } else {
                osocket.send(&mut buf, SocketAddr::V4(dst)).await?;
                t.store(Instant::now(), Ordering::Relaxed);
            }
        }
    } else {
        loop {
            let (size, dst) = socket.recv(buf.as_mut()).await?;
            buf.set_len(size);

            osocket.send(&mut buf, SocketAddr::V4(dst)).await?;
            t.store(Instant::now(), Ordering::Relaxed);
        }
    }
}

async fn gateway_udp_recv(
    socket: &gateway::UdpSocket,
    osocket: &socks5::UdpSocket,
    t: Arc<AtomicInstant>,
    gateway_ip: Ipv4Addr,
    dns_rx: Option<Receiver<Arc<UdpSocket>>>,
) -> std::io::Result<()> {
    let socks5_recv = async || -> std::io::Result<()> {
        let mut buf = socks5::UdpSocketBuf::new();

        loop {
            if let SocketAddr::V4(from) = osocket.recv(&mut buf).await? {
                socket.try_send(buf.as_ref(), from)?;
                t.store(Instant::now(), Ordering::Relaxed);
            }
        }
    };

    let dns_recv = async || -> std::io::Result<()> {
        if let Some(rx) = dns_rx {
            let dns_socket = match rx.await {
                Ok(s) => s,
                Err(_) => futures::future::pending::<Arc<UdpSocket>>().await,
            };

            let mut buf = [0u8; 2048];
            let from = SocketAddrV4::new(gateway_ip, 53);

            loop {
                let (size, _) = dns_socket.recv_from(&mut buf).await?;
                socket.try_send(&buf[..size], from)?;
                t.store(Instant::now(), Ordering::Relaxed);
            }
        } else {
            futures::future::pending::<std::io::Result<()>>().await
        }
    };

    futures::try_join!(socks5_recv(), dns_recv())?;
    Ok(())
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

async fn gateway_udp_socket(
    socket: gateway::UdpSocket,
    socks5: SocketAddr,
    gateway_ip: Ipv4Addr,
    upstream_dns: Option<SocketAddr>,
) -> std::io::Result<()> {
    let osocket = UdpSocket::bind("0.0.0.0:0").await?;
    let (osocket, holder) = socks5::udp_associate(socks5, osocket).await?;

    let t = Arc::new(AtomicInstant::now());
    let timeout = Duration::from_secs(60);

    let (dns_tx, dns_rx) = match upstream_dns {
        Some(upstream) => {
            let (tx, rx) = oneshot::channel();
            (Some((tx, upstream)), Some(rx))
        }
        None => (None, None),
    };

    futures::try_join!(
        gateway_udp_send(&socket, &osocket, t.clone(), gateway_ip, dns_tx),
        gateway_udp_recv(&socket, &osocket, t.clone(), gateway_ip, dns_rx),
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

async fn gateway_netstat(listen: &str, tcp_stats: tcp::StatsMap, udp_stats: udp::StatsMap) {
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

    #[derive(Tabled)]
    struct UdpSocketEntry {
        #[tabled(rename = "Source Address")]
        source: SocketAddrV4,
        #[tabled(rename = "TX Packets")]
        tx_packets: usize,
        #[tabled(rename = "RX Packets")]
        rx_packets: usize,
        #[tabled(rename = "TX Bytes")]
        tx_bytes: usize,
        #[tabled(rename = "RX Bytes")]
        rx_bytes: usize,
    }

    struct StatsState {
        tcp: tcp::StatsMap,
        udp: udp::StatsMap,
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

        stats.udp.for_each(|k, _| {
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

    async fn netstat_udp(
        axum::extract::State(stats): axum::extract::State<Arc<StatsState>>,
    ) -> impl IntoResponse {
        let mut entries = Vec::new();

        stats.udp.for_each(|k, v| {
            let entry = UdpSocketEntry {
                source: *k,
                tx_packets: v.get_tx_packets(),
                rx_packets: v.get_rx_packets(),
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
        .route("/netstat/udp", routing::get(netstat_udp))
        .with_state(stats_state);

    let listener = TcpListener::bind(listen).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn gateway_metrics(opentel: &str, tcp_stats: tcp::StatsMap, udp_stats: udp::StatsMap) {
    let exporter = MetricExporter::builder()
        .with_http()
        .with_endpoint(opentel.to_string() + "/v1/metrics")
        .with_protocol(Protocol::HttpBinary)
        .build()
        .unwrap();

    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(1))
        .build();
    let meter_provider = SdkMeterProvider::builder().with_reader(reader).build();

    global::set_meter_provider(meter_provider);

    let meter = global::meter("gatewaysocks");

    macro_rules! metric_u64 {
        ($meter:ident, $label:expr, $name:expr, $iter:ident, $get_fn:ident) => {
            let m = $iter.clone();
            $meter
                .u64_observable_gauge($name)
                .with_callback(move |observer| {
                    m.for_each(|k, v| {
                        observer
                            .observe(v.$get_fn() as u64, &[KeyValue::new($label, k.to_string())]);
                    });
                })
                .build();
        };
    }

    macro_rules! metric_u64_tcp {
        ($meter:ident, $name:expr, $iter:ident, $get_fn:ident) => {
            metric_u64!($meter, "socket_pair", $name, $iter, $get_fn);
        };
    }

    macro_rules! metric_u64_udp {
        ($meter:ident, $name:expr, $iter:ident, $get_fn:ident) => {
            metric_u64!($meter, "socket", $name, $iter, $get_fn);
        };
    }

    metric_u64_tcp!(meter, "tcp_state", tcp_stats, get_state);
    metric_u64_tcp!(meter, "tcp_send_queue", tcp_stats, get_send_queue);
    metric_u64_tcp!(meter, "tcp_recv_queue", tcp_stats, get_recv_queue);
    metric_u64_tcp!(meter, "tcp_climited", tcp_stats, get_congestion_limited);
    metric_u64_tcp!(meter, "tcp_cstate", tcp_stats, get_congestion_state);
    metric_u64_tcp!(meter, "tcp_cwnd", tcp_stats, get_congestion_window);
    metric_u64_tcp!(meter, "tcp_ctimes", tcp_stats, get_congestion_times);
    metric_u64_tcp!(meter, "tcp_min_rtt", tcp_stats, get_min_rtt);
    metric_u64_tcp!(meter, "tcp_srtt", tcp_stats, get_srtt);
    metric_u64_tcp!(meter, "tcp_rwnd", tcp_stats, get_remote_window);
    metric_u64_tcp!(meter, "tcp_tx_bytes", tcp_stats, get_tx_bytes);
    metric_u64_tcp!(meter, "tcp_rx_bytes", tcp_stats, get_rx_bytes);

    metric_u64_udp!(meter, "udp_tx_packets", udp_stats, get_tx_packets);
    metric_u64_udp!(meter, "udp_rx_packets", udp_stats, get_rx_packets);
    metric_u64_udp!(meter, "udp_tx_bytes", udp_stats, get_tx_bytes);
    metric_u64_udp!(meter, "udp_rx_bytes", udp_stats, get_rx_bytes);
}

async fn gateway_serve(
    netstat: &str,
    iface_name: &str,
    gateway: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    socks5: SocketAddr,
    opentel: Option<&str>,
    upstream_dns: Option<SocketAddr>,
) {
    info!(
        "start gatewaysocks on {}: {}({}), relay to socks5://{} ...",
        iface_name, gateway, subnet_mask, socks5
    );

    let (mut udp, mut tcp) = gateway::new(gateway, subnet_mask, iface_name).unwrap();
    let udp_stats = udp.get_stats();
    let tcp_stats = tcp.get_stats();

    if let Some(opentel) = opentel {
        gateway_metrics(opentel, tcp_stats.clone(), udp_stats.clone());
    }

    let fut_udp = async {
        loop {
            let socket = udp.accept().await.unwrap();
            info!("UDP socket going out: {}", socket.source_addr());
            tokio::spawn(gateway_udp_socket(socket, socks5, gateway, upstream_dns));
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
    let fut_stats = gateway_netstat(netstat, tcp_stats, udp_stats);

    futures::join!(fut_udp, fut_tcp, fut_stats);
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.version {
        println!("{}", version());
        return;
    }

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let iface_name = args.interface.unwrap_or_default();

    gateway_serve(
        &args.netstat,
        &iface_name,
        args.gateway_ip,
        args.subnet_mask,
        args.socks5,
        args.opentel.as_deref(),
        args.upstream_dns,
    )
    .await;
}
