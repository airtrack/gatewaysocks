use axum::{
    Router,
    body::Body,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::get,
};
use metrics::METRICS_COUNTER;
use prometheus::{Encoder, TextEncoder};
use tokio::net::TcpListener;

pub mod metrics;

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
            .header(CONTENT_TYPE, encoder.format_type())
            .body(Body::from(buffer))
            .unwrap()
    }
}
