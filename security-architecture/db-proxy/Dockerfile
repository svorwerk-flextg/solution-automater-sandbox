# Database Connection Proxy - Enforces READ-ONLY access
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install dependencies
RUN apk add --no-cache git make gcc musl-dev

# Copy source code
COPY . .

# Build the proxy
RUN go mod init db-proxy && \
    go get -d -v ./... && \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o db-proxy .

# Runtime image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -g 1000 proxy && \
    adduser -D -u 1000 -G proxy proxy

WORKDIR /app

COPY --from=builder /build/db-proxy .
COPY config.yaml /etc/proxy/config.yaml

RUN chown -R proxy:proxy /app /etc/proxy

USER proxy

EXPOSE 3306 1433 27017

ENTRYPOINT ["./db-proxy"]
CMD ["--config", "/etc/proxy/config.yaml"]