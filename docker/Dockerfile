FROM rust:latest AS builder

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

ENV http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    no_proxy=${NO_PROXY}

WORKDIR /gatewaysocks
COPY . .
RUN cargo build --release


FROM scratch AS exporter
COPY --from=builder /gatewaysocks/target/release/gatewaysocks /
