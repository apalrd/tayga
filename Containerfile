# Stage 1: Build environment
FROM alpine:latest AS build-env

# Install build tools
RUN apk add --no-cache g++ make linux-headers git binutils

# Set working directory
WORKDIR /app

# Copy source code into the container
COPY ./ ./

# Build the code statically
RUN make static

# Stage 2: Final image
FROM alpine:latest

# Add iproute2
RUN apk add --no-cache iproute2

# Set working directory
WORKDIR /app

# Copy the binary from the build stage
COPY --from=build-env /app/tayga /app/tayga

# Copy launch script
COPY launch-nat64.sh /app/launch-nat64.sh

# Set the entrypoint to the launch script
ENTRYPOINT ["/bin/sh","/app/launch-nat64.sh"]