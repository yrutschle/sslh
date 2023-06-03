FROM alpine:latest as build

WORKDIR /sslh

COPY . /sslh
RUN \
  apk add \
    gcc \
    libconfig-dev \
    make \
    musl-dev \
    pcre2-dev \
    perl && \
  make sslh-select && \
  strip sslh-select

FROM alpine:latest

COPY --from=build "/sslh/sslh-select" "/usr/local/bin/sslh"

RUN apk --no-cache add libconfig pcre2

COPY "./container-entrypoint.sh" "/init"
ENTRYPOINT [ "/init" ]
