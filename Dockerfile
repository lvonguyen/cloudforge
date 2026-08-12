# Build stage
FROM golang:1.26-alpine AS builder

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
    -o /aegis \
    ./cmd/server

# Final stage - minimal runtime image
FROM alpine:3.24

# Security: Run as non-root user
RUN addgroup -g 1000 aegis && \
    adduser -u 1000 -G aegis -s /bin/sh -D aegis

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Install Trivy for container scanning (optional — only used when CONTAINER_SCANNER=trivy)
# Pinned version — update when GitHub removes old releases
ARG TRIVY_VERSION=0.69.3
RUN apk add --no-cache curl && \
    curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -o /tmp/trivy.tar.gz && \
    tar xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    apk del curl

WORKDIR /app

# Copy binary from builder
COPY --from=builder /aegis /app/aegis

# Copy mock data files required by the in-memory GRC provider
COPY --from=builder /app/frontend/src/lib/mock /app/frontend/src/lib/mock
COPY --from=builder /app/frontend/public/mock /app/frontend/public/mock

# Copy config template
COPY configs/config.example.yaml /app/config.example.yaml

# Copy policies if they exist (use RUN to handle optional directory)
RUN mkdir -p /app/policies

# Set ownership
RUN chown -R aegis:aegis /app

USER aegis

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/aegis"]
