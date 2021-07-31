FROM alpine:latest as build

ADD . /sslh

RUN \
  apk add \
    gcc \
    libconfig-dev \
    make \
    musl-dev \
    pcre-dev \
    perl && \
  cd /sslh && \
  make sslh-select && \
  strip sslh-select

FROM alpine:latest

COPY --from=build /sslh/sslh-select /sslh

RUN apk --no-cache add libconfig pcre

ENTRYPOINT [ "/sslh", "--foreground"]
