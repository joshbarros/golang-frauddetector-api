# Build stage
FROM golang:1.22.6-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fraud-detector ./cmd/engine

# Final stage
FROM alpine:latest

# Install certificates, timezone data and wget for health checks
RUN apk --no-cache add ca-certificates tzdata wget

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/fraud-detector .

# Copy configuration files if any (optional - only if configs directory exists)
# COPY --from=builder /app/configs /root/configs

# Create non-root user
RUN adduser -D -s /bin/sh frauddetector

# Change ownership
RUN chown -R frauddetector:frauddetector /root

# Switch to non-root user
USER frauddetector

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./fraud-detector"]