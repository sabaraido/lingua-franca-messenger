FROM golang:1.22-bookworm AS builder
WORKDIR /build
COPY go.mod go.sum* ./
RUN go mod download
COPY src/ ./src/
RUN CGO_ENABLED=0 GOOS=linux go build -o /lfm ./src

FROM lfm-base:latest
WORKDIR /app
COPY --from=builder /lfm /app/lfm
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
COPY stunnel.conf /app/stunnel.conf
RUN chmod +x /app/docker-entrypoint.sh
EXPOSE 1863 1864 1865 443 53/udp
ENTRYPOINT ["/app/docker-entrypoint.sh"]
