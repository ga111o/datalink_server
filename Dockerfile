# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install git for go mod download
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests and wget for healthcheck
RUN apk --no-cache add ca-certificates wget

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/main .

# Create uploads directory
RUN mkdir -p /data/uploads

# Set environment variables
ENV GIN_MODE=release
ENV PORT=8080

# Expose port
EXPOSE 8080

# Command to run
CMD ["./main"] 