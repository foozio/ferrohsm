# Use Ubuntu as base image for better compatibility
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -r -s /bin/false ferrohsm

# Set working directory
WORKDIR /app

# Copy the binary
COPY target/release/hsm-server /app/hsm-server

# Make it executable
RUN chmod +x /app/hsm-server

# Create data directory
RUN mkdir -p /app/data && chown ferrohsm:ferrohsm /app/data

# Switch to non-root user
USER ferrohsm

# Expose port
EXPOSE 8443

# Set default command
CMD ["/app/hsm-server", "--bind", "0.0.0.0:8443"]