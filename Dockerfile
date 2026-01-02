# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /cloudforge ./cmd/server

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /cloudforge .

# Copy policies
COPY --from=builder /app/policies ./policies

# Create non-root user
RUN adduser -D -g '' cloudforge
USER cloudforge

EXPOSE 8080

ENTRYPOINT ["./cloudforge"]
