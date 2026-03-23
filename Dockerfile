# Stage 1: Build the binary
FROM golang:1.26.1-alpine AS builder

# Set working directory
WORKDIR /app

# Copy dependency files first (for better caching)
COPY go.mod ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with stripping for smaller size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o argus cmd/argus/main.go

# Stage 2: Final lightweight image
FROM alpine:latest

# Install security certificates
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy only the compiled binary from the builder stage
COPY --from=builder /app/argus .

# Set the entrypoint
ENTRYPOINT ["./argus"]
