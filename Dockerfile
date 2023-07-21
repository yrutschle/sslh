FROM alpine:latest as build

WORKDIR /sslh

RUN apk add gcc libconfig-dev make musl-dev pcre2-dev perl

COPY . /sslh
RUN make sslh-select && strip sslh-select

FROM alpine:latest

RUN apk --no-cache add libconfig pcre2 iptables ip6tables libcap

RUN adduser sslh --shell /bin/sh --disabled-password

COPY --from=build "/sslh/sslh-select" "/usr/local/bin/sslh"
RUN setcap cap_net_bind_service,cap_net_raw+ep /usr/local/bin/sslh

COPY "./container-entrypoint.sh" "/init"
ENTRYPOINT [ "/init" ]

# required for updating iptables
USER root:root