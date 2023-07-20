FROM alpine:latest as build

WORKDIR /sslh
COPY . /sslh

RUN apk add gcc libconfig-dev make musl-dev pcre2-dev perl
RUN make sslh-select && strip sslh-select

FROM alpine:latest

COPY --from=build "/sslh/sslh-select" "/usr/local/bin/sslh"

RUN apk --no-cache add libconfig pcre2 iptables ip6tables libcap

RUN adduser sslh --shell /bin/sh --disabled-password
RUN setcap cap_net_bind_service,cap_net_raw+ep /usr/local/bin/sslh

COPY "./container-entrypoint.sh" "/init"
ENTRYPOINT [ "/init" ]

# required for updating iptables
USER root:root