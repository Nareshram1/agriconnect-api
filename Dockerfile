# Start from the official Go image
FROM golang:1.17-alpine AS builder

# Set the current working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files to the working directory
COPY go.mod go.sum ./

# Download dependencies using go mod
RUN go mod download

# Copy the rest of the application code
COPY . .

# Build the Go application
RUN go build -o app .

# Start a new stage from scratch
FROM alpine:latest  

# Set the current working directory inside the container
WORKDIR /root/

# Copy the binary from the builder stage to the /root directory
COPY --from=builder /app/app .

# Expose port 5000 to the outside world
EXPOSE 5000

# Command to run the executable
CMD ["./app"]
