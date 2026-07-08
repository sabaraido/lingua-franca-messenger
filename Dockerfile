# --- Build stage ---
FROM golang:1.22-bookworm AS builder

WORKDIR /build

COPY go.mod go.sum* ./
RUN go mod download

COPY src/ ./src/

RUN CGO_ENABLED=0 GOOS=linux go build -o /lfm ./src

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /lfm /app/lfm

# DS / NS / SB 用ポート(用途に応じて調整)
EXPOSE 1863 1864 1865

ENTRYPOINT ["/app/lfm"]
