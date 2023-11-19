sslh -- A ssl/ssh multiplexer
=============================

`sslh` accepts connections on specified ports, and forwards
them further based on tests performed on the first data
packet sent by the remote client.

Probes for HTTP, TLS/SSL (including SNI and ALPN), SSH,
OpenVPN, tinc, XMPP, SOCKS5, are implemented, and any other
protocol that can be tested using a regular expression, can
be recognised. A typical use case is to allow serving
several services on port 443 (e.g. to connect to SSH from
inside a corporate firewall, which almost never block port
443) while still serving HTTPS on that port.

Hence `sslh` acts as a protocol demultiplexer, or a
switchboard. With the SNI and ALPN probe, it makes a good
front-end to a virtual host farm hosted behind a single IP
address.

`sslh` has the bells and whistles expected from a mature
daemon: privilege and capabilities dropping, inetd support,
systemd support, transparent proxying, chroot, logging,
IPv4 and IPv6, TCP and UDP, a fork-based, a select-based
model, and yet another based on libev for larger
installations.

Install
=======

Please refer to the [install guide](doc/INSTALL.md).


Configuration
=============

Please refer to the [configuration guide](doc/config.md).



Docker image
------------

How to use

---


```bash
docker run \
  --cap-add CAP_NET_RAW \
  --cap-add CAP_NET_BIND_SERVICE \
  --rm \
  -it \
  ghcr.io/yrutschle/sslh:latest \
  --foreground \
  --listen=0.0.0.0:443 \
  --ssh=hostname:22 \
  --tls=hostname:443
```

docker-compose example

```yaml
version: "3"

services:
  sslh:
    image: ghcr.io/yrutschle/sslh:latest
    hostname: sslh
    ports:
      - 443:443
    command: --foreground --listen=0.0.0.0:443 --tls=nginx:443 --openvpn=openvpn:1194
    depends_on:
      - nginx
      - openvpn

  nginx:
    image: nginx

  openvpn:
    image: openvpn
```

Transparent mode 1: using sslh container for networking

_Note: For transparent mode to work, the sslh container must be able to reach your services via **localhost**_
```yaml
version: "3"

services:
  sslh:
    build: https://github.com/yrutschle/sslh.git
    container_name: sslh
    environment:
      - TZ=${TZ}
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - NET_BIND_SERVICE
    sysctls:
      - net.ipv4.conf.default.route_localnet=1
      - net.ipv4.conf.all.route_localnet=1
    command: --transparent --foreground --listen=0.0.0.0:443 --tls=localhost:8443 --openvpn=localhost:1194
    ports:
      - 443:443 #sslh

      - 80:80 #nginx
      - 8443:8443 #nginx

      - 1194:1194 #openvpn
    extra_hosts:
      - localbox:host-gateway
    restart: unless-stopped

  nginx:
    image: nginx:latest
    .....
    network_mode: service:sslh #set nginx container to use sslh networking.
    # ^^^ This is required. This makes nginx reachable by sslh via localhost
  
  openvpn:
    image: openvpn:latest
    .....
    network_mode: service:sslh #set openvpn container to use sslh networking
```

Transparent mode 2: using host networking

```yaml
version: "3"

services:
  sslh:
    build: https://github.com/yrutschle/sslh.git
    container_name: sslh
    environment:
      - TZ=${TZ}
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - NET_BIND_SERVICE
    # must be set manually
    #sysctls:
    #  - net.ipv4.conf.default.route_localnet=1
    #  - net.ipv4.conf.all.route_localnet=1
    command: --transparent --foreground --listen=0.0.0.0:443 --tls=localhost:8443 --openvpn=localhost:1194
    network_mode: host
    restart: unless-stopped
  
  nginx:
    image: nginx:latest
    .....
    ports:
      - 8443:8443 # bind to docker host on port 8443

  openvpn:
    image: openvpn:latest
    .....
    ports:
      - 1194:1194 # bind to docker host on port 1194
```

Comments? Questions?
====================

You can subscribe to the `sslh` mailing list here:
<https://lists.rutschle.net/mailman/listinfo/sslh>

This mailing list should be used for discussion, feature
requests, and will be the preferred channel for announcements.

Of course, check the [FAQ](doc/FAQ.md) first!

