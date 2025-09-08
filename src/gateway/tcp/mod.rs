//! TCP gateway module providing full TCP connection handling.
//!
//! This module implements a complete TCP stack for the gateway, handling
//! connection establishment, data transfer, and connection teardown.
//! It provides async-compatible TCP streams that integrate with Tokio's
//! async I/O ecosystem.
//!
//! # Architecture
//!
//! - `TcpHandler`: Processes incoming TCP packets and manages stream lifecycle
//! - `TcpListener`: Accepts new TCP connections for applications
//! - `TcpStream`: Async TCP stream implementing AsyncRead/AsyncWrite traits
//! - `TcpStreamDriver`: Background task driving individual TCP connections

use std::collections::HashMap;
use std::future::Future;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::usize;

use bytes::Bytes;
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{
    Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
};

use crate::gateway::GatewaySender;
use crate::gateway::tcp::stream::{TcpStreamInner, is_syn_packet};

mod congestion;
mod pacing;
mod recv_buffer;
mod rtt;
mod send_buffer;
mod stats;
mod stream;
mod time;
mod types;

pub use stats::StatsMap;
pub use stats::StreamStats;
pub use types::AddrPair;
pub use types::State;

/// Creates a new TCP handler and listener pair.
///
/// The handler processes incoming TCP packets and manages connection lifecycle,
/// while the listener provides an interface for accepting new connections.
///
/// # Arguments
///
/// * `channel` - Receiver for incoming TCP packets from the gateway
/// * `gw_sender` - Gateway sender for outgoing packets
///
/// # Returns
///
/// A tuple containing (TcpHandler, TcpListener)
pub(super) fn new(
    channel: UnboundedReceiver<Bytes>,
    gw_sender: GatewaySender,
) -> (TcpHandler, TcpListener) {
    let (stream_starter, stream_receiver) = stream_starter();
    let (stream_closer, closed_stream) = stream_closer();

    let handler = TcpHandler {
        channel,
        gw_sender,
        stream_starter,
        stream_closer,
        closed_stream,
        stats: StatsMap::new(),
        streams: HashMap::new(),
    };

    let listener = TcpListener {
        stats: handler.stats.clone(),
        stream_receiver,
    };

    (handler, listener)
}

/// Internal channel for notifying the listener of new TCP connections.
struct StreamStarter(UnboundedSender<TcpStream>);

impl StreamStarter {
    /// Notifies the listener of a new TCP connection.
    fn start(&self, stream: TcpStream) -> std::io::Result<()> {
        self.0.send(stream).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "stream receiver dropped")
        })
    }
}

/// Internal channel for receiving new TCP connections.
struct StreamReceiver(UnboundedReceiver<TcpStream>);

impl StreamReceiver {
    /// Receives the next new TCP connection.
    async fn recv(&mut self) -> std::io::Result<TcpStream> {
        self.0.recv().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "TCP handler broken",
        ))
    }
}

/// Creates a channel pair for stream startup notifications.
fn stream_starter() -> (StreamStarter, StreamReceiver) {
    let (starter, receiver) = unbounded_channel();
    (StreamStarter(starter), StreamReceiver(receiver))
}

/// Channel for notifying when TCP streams are closed.
#[derive(Clone)]
struct StreamCloser(UnboundedSender<AddrPair>);

impl StreamCloser {
    /// Notifies that a TCP stream with the given address pair has closed.
    fn close(&self, addr_pair: AddrPair) {
        self.0.send(addr_pair).ok();
    }
}

/// Channel for receiving notifications of closed TCP streams.
struct ClosedStream(UnboundedReceiver<AddrPair>);

impl ClosedStream {
    /// Receives the next closed stream notification.
    async fn recv(&mut self) -> Option<AddrPair> {
        self.0.recv().await
    }
}

/// Creates a channel pair for stream closure notifications.
fn stream_closer() -> (StreamCloser, ClosedStream) {
    let (send, recv) = unbounded_channel();
    (StreamCloser(send), ClosedStream(recv))
}

/// Main TCP packet handler that processes incoming packets and manages streams.
///
/// The handler maintains a map of active TCP streams and routes packets to
/// the appropriate stream. It also handles connection establishment by
/// creating new streams when SYN packets arrive.
pub(super) struct TcpHandler {
    channel: UnboundedReceiver<Bytes>,
    gw_sender: GatewaySender,
    stream_starter: StreamStarter,
    stream_closer: StreamCloser,
    closed_stream: ClosedStream,
    stats: StatsMap,
    streams: HashMap<AddrPair, Sender<Bytes>>,
}

impl TcpHandler {
    /// Starts the TCP handler in a background task.
    pub(super) fn start(mut self) {
        tokio::spawn(async move {
            self.handle_loop().await;
        });
    }

    /// Main event loop that processes packets and stream events.
    async fn handle_loop(&mut self) -> Option<()> {
        loop {
            tokio::select! {
                Some(addr_pair) = self.closed_stream.recv() => {
                    self.remove_stream(addr_pair);
                }
                Some(packet) = self.channel.recv() => {
                    self.handle_packet(packet);
                }
            }
        }
    }

    /// Removes a closed stream from the active streams map.
    fn remove_stream(&mut self, addr_pair: AddrPair) {
        self.streams.remove(&addr_pair);
        self.stats.map.remove(&addr_pair);
    }

    /// Processes an incoming TCP packet.
    ///
    /// Routes the packet to existing streams or creates new streams for SYN packets.
    fn handle_packet(&mut self, packet: Bytes) -> Option<()> {
        let ethernet_packet = EthernetPacket::new(&packet)?;
        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload())?;
        let tcp_request = TcpPacket::new(ipv4_packet.payload())?;

        let mac = ethernet_packet.get_source();
        let src = SocketAddrV4::new(ipv4_packet.get_source(), tcp_request.get_source());
        let dst = SocketAddrV4::new(ipv4_packet.get_destination(), tcp_request.get_destination());

        let pair = AddrPair {
            source: src,
            destination: dst,
        };
        let data = packet.slice_ref(ipv4_packet.payload());

        match self.streams.get(&pair) {
            Some(sender) => sender.try_send(data).ok()?,
            None => {
                if is_syn_packet(&tcp_request) {
                    let (packets_tx, packets_rx) = channel(32);
                    let stream_closer = self.stream_closer.clone();
                    let gw_sender = self.gw_sender.clone();
                    let stats = StreamStats::new();

                    let inner = Arc::new(TcpStreamInner::new(
                        mac,
                        pair,
                        stream_closer,
                        gw_sender,
                        stats.clone(),
                    ));

                    let driver = TcpStreamDriver {
                        packets: packets_rx,
                        inner: inner.clone(),
                    };

                    let stream = TcpStream { inner };

                    packets_tx.try_send(data).ok()?;
                    self.streams.insert(pair, packets_tx);
                    self.stats.map.insert(pair, stats);
                    self.stream_starter.start(stream).ok()?;
                    driver.start();
                }
            }
        }

        Some(())
    }
}

/// TCP listener for accepting incoming TCP connections.
///
/// Provides an async interface for applications to accept new TCP streams
/// and access connection statistics.
pub struct TcpListener {
    stats: StatsMap,
    stream_receiver: StreamReceiver,
}

impl TcpListener {
    /// Accepts the next incoming TCP connection.
    ///
    /// This method waits for a new TCP connection to be established
    /// and returns the corresponding TcpStream.
    pub async fn accept(&mut self) -> std::io::Result<TcpStream> {
        self.stream_receiver.recv().await
    }

    /// Returns a clone of the current connection statistics map.
    pub fn get_stats(&self) -> StatsMap {
        self.stats.clone()
    }
}

/// An async TCP stream that implements AsyncRead and AsyncWrite.
///
/// This stream represents a single TCP connection and provides
/// async I/O operations compatible with Tokio's async ecosystem.
pub struct TcpStream {
    inner: Arc<TcpStreamInner>,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.inner.close();
    }
}

impl TcpStream {
    /// Returns the source (local) address of this TCP connection.
    pub fn source_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.inner.source_addr())
    }

    /// Returns the destination (remote) address of this TCP connection.
    pub fn destination_addr(&self) -> SocketAddr {
        SocketAddr::V4(self.inner.destination_addr())
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.inner.poll_shutdown(cx)
    }
}

/// Background driver task for individual TCP streams.
///
/// Handles packet processing and state management for a single TCP connection.
/// Runs as a separate task to avoid blocking the main TCP handler.
struct TcpStreamDriver {
    packets: Receiver<Bytes>,
    inner: Arc<TcpStreamInner>,
}

impl TcpStreamDriver {
    /// Starts the stream driver in a background task.
    fn start(self) {
        tokio::spawn(async move {
            self.await;
        });
    }
}

impl Future for TcpStreamDriver {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        loop {
            match self.packets.poll_recv(cx) {
                std::task::Poll::Ready(Some(packet)) => {
                    self.inner.handle_tcp_packet(packet);
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                std::task::Poll::Pending => return self.inner.poll_state(cx),
            }
        }
    }
}
