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
systemd support, transparent proxying,
chroot, logging, IPv4 and IPv6, a fork-based and a
select-based model, and more.

Install
=======

Please refer to the [install guide](doc/INSTALL.md).


Configuration
=============

Please refer to the [configuration guide](doc/config.md).



Comments? Questions?
====================

You can subscribe to the `sslh` mailing list here:
<http://rutschle.net/cgi-bin/mailman/listinfo/sslh>

This mailing list should be used for discussion, feature
requests, and will be the preferred channel for announcements.

