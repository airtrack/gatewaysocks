use lazy_static::lazy_static;
use prometheus::{
    IntCounter, IntCounterVec, IntGauge, register_int_counter, register_int_counter_vec,
    register_int_gauge,
};

lazy_static! {
    pub static ref METRICS_COUNTER: IntCounter =
        register_int_counter!("metrics_counter", "metrics pull counter").unwrap();
    pub static ref UDP_TX_PACKETS: IntCounter =
        register_int_counter!("udp_tx_packets", "udp send packets").unwrap();
    pub static ref UDP_RX_PACKETS: IntCounter =
        register_int_counter!("udp_rx_packets", "udp recv packets").unwrap();
    pub static ref UDP_TX_BYTES: IntCounter =
        register_int_counter!("udp_tx_bytes", "udp send bytes").unwrap();
    pub static ref UDP_RX_BYTES: IntCounter =
        register_int_counter!("udp_rx_bytes", "udp recv bytes").unwrap();
    pub static ref TCP_CONNS: IntGauge =
        register_int_gauge!("tcp_conns", "tcp connections").unwrap();
    pub static ref TCP_TX_BYTES: IntCounterVec =
        register_int_counter_vec!("tcp_tx_bytes", "tcp send bytes", &["socket"]).unwrap();
    pub static ref TCP_RX_BYTES: IntCounterVec =
        register_int_counter_vec!("tcp_rx_bytes", "tcp recv bytes", &["socket"]).unwrap();
}
