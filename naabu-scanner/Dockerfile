# -----------------------------
# Build stage: builds app and installs Go tools
# -----------------------------
FROM golang:1.24 AS builder

WORKDIR /app

# Install system deps needed to build naabu
RUN apt-get update && apt-get install -y libpcap-dev

# Copy Go source files
COPY go.mod go.sum ./
COPY main.go ./

# Install Go dependencies
RUN go mod tidy

# Build your Go application
RUN go build -o app .

# Install Go-based tools
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# -----------------------------
# Final image: minimal runtime
# -----------------------------
FROM debian:bookworm-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y libpcap0.8 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder stage
COPY --from=builder /go/bin/naabu /usr/local/bin/naabu
COPY --from=builder /app/app /usr/local/bin/app

# Default entrypoint
ENTRYPOINT ["app"]
    