use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use lazy_static::lazy_static;
use prometheus::{register_int_counter, Encoder, IntCounter, TextEncoder};
use tokio::net::TcpListener;

lazy_static! {
    static ref METRICS_COUNTER: IntCounter =
        register_int_counter!("metrics_counter", "metrics pull counter").unwrap();
}

pub struct Exporter {
    listen: String,
}

impl Exporter {
    pub fn new(listen: &str) -> Self {
        Self {
            listen: listen.to_string(),
        }
    }

    pub async fn run(&self) {
        let app = Router::new().route("/metrics", get(Exporter::metrics));
        let listener = TcpListener::bind(&self.listen).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }

    async fn metrics() -> impl IntoResponse {
        METRICS_COUNTER.inc();

        let mut buffer = Vec::new();
        let metric_families = prometheus::gather();
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        Response::builder()
            .status(StatusCode::OK)
            .header(
                CONTENT_TYPE,
                "application/openmetrics-text; version=1.0.0; charset=utf-8",
            )
            .body(Body::from(buffer))
            .unwrap()
    }
}
