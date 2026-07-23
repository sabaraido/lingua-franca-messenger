# --- OpenSSL(legacy, SSLv3対応)ビルドステージ ---
FROM debian:bookworm AS openssl-legacy
RUN apt-get update && apt-get install -y build-essential wget perl
WORKDIR /build
RUN wget -O openssl-1.0.2u.tar.gz https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_0_2u.tar.gz \
    && tar xzf openssl-1.0.2u.tar.gz
WORKDIR /build/openssl-OpenSSL_1_0_2u
RUN ./config enable-ssl2 enable-ssl3 enable-ssl3-method shared --prefix=/opt/openssl-legacy \
    && make -j$(nproc) \
    && make install_sw

# --- stunnel(上記OpenSSLにリンクしてビルド)ステージ ---
FROM debian:bookworm AS stunnel-build
RUN apt-get update && apt-get install -y build-essential wget
COPY --from=openssl-legacy /opt/openssl-legacy /opt/openssl-legacy
WORKDIR /build
RUN wget https://www.stunnel.org/downloads/archive/5.x/stunnel-5.63.tar.gz \
    && tar xzf stunnel-5.63.tar.gz
WORKDIR /build/stunnel-5.63
RUN ./configure --with-ssl=/opt/openssl-legacy --prefix=/opt/stunnel \
    && make -j$(nproc) \
    && make install

# --- Goビルドステージ ---
FROM golang:1.22-bookworm AS builder
WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download
COPY src/ ./src/
RUN CGO_ENABLED=0 GOOS=linux go build -o /lfm ./src

# --- Runtime stage ---
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /lfm /app/lfm
COPY --from=openssl-legacy /opt/openssl-legacy /opt/openssl-legacy
COPY --from=stunnel-build /opt/stunnel /opt/stunnel

ENV LD_LIBRARY_PATH=/opt/openssl-legacy/lib

COPY docker-entrypoint.sh /app/docker-entrypoint.sh
COPY stunnel.conf /app/stunnel.conf
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 1863 1864 1865 443
ENTRYPOINT ["/app/docker-entrypoint.sh"]
