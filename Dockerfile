ARG ALPINE_VERSION="latest"
ARG TARGET_ARCH="library"

FROM docker.io/${TARGET_ARCH}/alpine:${ALPINE_VERSION} AS build

WORKDIR /sslh

RUN apk add --no-cache \
        'gcc' \
        'libconfig-dev' \
        'make' \
        'musl-dev' \
        'pcre2-dev' \
        'perl' \
        ;

COPY . /sslh

RUN ./configure && make sslh-select && strip sslh-select

FROM docker.io/${TARGET_ARCH}/alpine:${ALPINE_VERSION}

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
