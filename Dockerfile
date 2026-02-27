# syntax=docker/dockerfile:1

# CSPM Aggregator Dockerfile
# Multi-stage build for minimal, secure production image

# ==============================================================================
# Stage 1: Builder
# ==============================================================================
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build arguments for version injection
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s \
        -X main.Version=${VERSION} \
        -X main.GitCommit=${GIT_COMMIT} \
        -X main.BuildTime=${BUILD_TIME}" \
    -o /build/aggregator \
    ./cmd/aggregator

# ==============================================================================
# Stage 2: Production
# ==============================================================================
FROM alpine:3.19 AS production

# Labels for container metadata
LABEL org.opencontainers.image.title="CSPM Aggregator" \
      org.opencontainers.image.description="Multi-cloud CSPM finding aggregator with AI-powered risk scoring" \
      org.opencontainers.image.vendor="Liem Vo-Nguyen" \
      org.opencontainers.image.source="https://github.com/lvonguyen/cspm-aggregator"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user for security
RUN addgroup -g 1000 aggregator && \
    adduser -u 1000 -G aggregator -s /bin/sh -D aggregator

# Create directories
RUN mkdir -p /app/configs /app/reports && \
    chown -R aggregator:aggregator /app

# Copy binary from builder
COPY --from=builder /build/aggregator /app/aggregator

# Copy default config
COPY --chown=aggregator:aggregator configs/config.yaml /app/configs/config.yaml

# Switch to non-root user
USER aggregator
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/app/aggregator", "-version"]

# Default entrypoint
ENTRYPOINT ["/app/aggregator"]
CMD ["--config", "/app/configs/config.yaml"]
