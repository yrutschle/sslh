ARG ALPINE_VERSION="latest"
ARG TARGET_ARCH="library"

FROM docker.io/${TARGET_ARCH}/alpine:${ALPINE_VERSION} AS build

# Install build dependencies for sslh and libproxyprotocol
RUN apk add --no-cache \
        'gcc' \
        'libconfig-dev' \
        'make' \
        'musl-dev' \
        'pcre2-dev' \
        'perl' \
        'git' \
        'autoconf' \
        'automake' \
        'libtool' \
        ;

# Build libproxyprotocol
WORKDIR /tmp
RUN git clone https://github.com/kosmas-valianos/libproxyprotocol.git && \
    cd libproxyprotocol && \
    make && \
    mkdir -p /usr/local/include/ && \
    mv libs/libproxyprotocol.so /usr/local/lib/ && \
    mv src/* /usr/local/include/

# Set environment variables for sslh to find libproxyprotocol
ENV C_INCLUDE_PATH=/usr/local/include
ENV LIBRARY_PATH=/usr/local/lib
ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /sslh
COPY . /sslh

# Configure and build sslh
# The configure script should automatically detect libproxyprotocol
RUN ./configure && make sslh-select && strip sslh-select

FROM docker.io/${TARGET_ARCH}/alpine:${ALPINE_VERSION}

# Copy libproxyprotocol.so from the build stage
COPY --from=build /usr/local/lib/libproxyprotocol.so* /usr/local/lib/
COPY --from=build "/sslh/sslh-select" "/usr/local/bin/sslh"

RUN apk add --no-cache \
        'libconfig' \
        'pcre2' \
        'iptables' \
        'ip6tables' \
        'libcap' \
    && \
    adduser -s '/bin/sh' -S -D sslh && \
    setcap cap_net_bind_service,cap_net_raw+ep /usr/local/bin/sslh

COPY "./container-entrypoint.sh" "/init"
ENTRYPOINT [ "/init" ]

# required for updating iptables
USER root:root