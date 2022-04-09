FROM alpine:latest as build

ADD . /sslh

RUN \
  apk add \
    gcc \
    libconfig-dev \
    make \
    musl-dev \
    pcre2-dev \
    perl && \
  cd /sslh && \
  make sslh-select && \
  strip sslh-select

FROM alpine:latest

COPY --from=build /sslh/sslh-select /sslh

RUN apk --no-cache add libconfig pcre2

ENTRYPOINT [ "/sslh", "--foreground"]
