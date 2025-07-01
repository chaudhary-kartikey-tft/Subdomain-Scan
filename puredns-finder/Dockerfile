# -----------------------------
# Build stage: builds app and installs Go tools
# -----------------------------
FROM golang:1.24 AS builder

WORKDIR /app

# Copy Go source files
COPY go.mod go.sum ./
COPY main.go ./

# Install Go dependencies
RUN go mod tidy

# Build your Go application
RUN go build -o app .

# Install Go-based tools
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/d3mondev/puredns/v2@latest

# -----------------------------
# Final image: minimal runtime
# -----------------------------
FROM debian:bookworm-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
        git ca-certificates dnsutils make gcc && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder stage
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=builder /go/bin/puredns /usr/local/bin/puredns
COPY --from=builder /app/app /usr/local/bin/app

# Install massdns
RUN git clone https://github.com/blechschmidt/massdns.git && \
    cd massdns && make && mv bin/massdns /usr/local/bin/ && cd .. && rm -rf massdns

# Default entrypoint
ENTRYPOINT ["app"]
    