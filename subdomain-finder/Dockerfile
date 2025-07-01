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
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# -----------------------------
# Final image: minimal runtime
# -----------------------------
FROM debian:bookworm-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
        curl ca-certificates python3-pip unzip dnsrecon && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder stage
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /app/app /usr/local/bin/app

# Install findomain
RUN curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip && \
    unzip findomain-linux.zip && \
    chmod +x findomain && \
    mv findomain /usr/local/bin/findomain && \
    rm findomain-linux.zip

# Default entrypoint
ENTRYPOINT ["app"]
    