# Build stage
FROM golang:1.24-alpine AS builder

ARG VERSION=dev

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build binary with version info
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o /cloudforge \
    ./cmd/server

# Final stage - minimal runtime image
FROM alpine:3.20

# Security: Run as non-root user
RUN addgroup -g 1000 cloudforge && \
    adduser -u 1000 -G cloudforge -s /bin/sh -D cloudforge

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /cloudforge /app/cloudforge

# Copy config template
COPY configs/config.example.yaml /app/config.example.yaml

# Copy policies if they exist
COPY --from=builder /app/policies /app/policies 2>/dev/null || true

# Set ownership
RUN chown -R cloudforge:cloudforge /app

USER cloudforge

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/cloudforge"]
