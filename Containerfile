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

# Stage 2a: Final image (nat64)
FROM alpine:latest AS final-nat64

# Set working directory
WORKDIR /app

# Copy the binary from the build stage
COPY --from=build-env /app/tayga /app/tayga

# Copy launch script
COPY launch-nat64.sh /app/launch-nat64.sh

# Set the entrypoint to the launch script
ENTRYPOINT ["/bin/sh","/app/launch-nat64.sh"]

# Stage 2b: Final Image (clat)
FROM alpine:latest AS final-clat
# Clat needs to do ip neigh proxy, needs real iproute2
RUN apk add --no-cache iproute2
WORKDIR /app
COPY --from=build-env /app/tayga /app/tayga
COPY launch-clat.sh /app/launch-clat.sh
ENTRYPOINT ["/bin/sh","/app/launch-clat.sh"]

# Stage 2c: Final Image (No Config / Bring Your Own)
FROM alpine:latest AS final
# Installing real iproute2 for users
RUN apk add --no-cache iproute2
WORKDIR /app
COPY --from=build-env /app/tayga /app/tayga
COPY launch.sh /app/launch.sh
ENTRYPOINT ["/bin/sh","/app/launch.sh"]