FROM alpine:latest as build

RUN \
  apk add \
    gcc \
    libconfig-dev \
    make \
    musl-dev \
    pcre2-dev \
    perl \
    perl-dev \
    perl-app-cpanminus \
    git

WORKDIR /sslh
RUN git clone https://github.com/yrutschle/conf2struct && \
	cpanm --force Conf::Libconfig && \
	make -C conf2struct checker && \
	make -C conf2struct install

COPY . ./
RUN make sslh-select && \
  strip sslh-select

FROM alpine:latest

COPY --from=build /sslh/sslh-select /sslh

RUN apk --no-cache add libconfig pcre2

ENTRYPOINT [ "/sslh", "--foreground"]
