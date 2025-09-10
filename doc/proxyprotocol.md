Using Proxyprotocol with sslh
=============================

HAProxy defined the [Proxy protocol](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/proxying-essentials/client-ip-preservation/enable-proxy-protocol/), where a proxy adds external connection information directly inside the TCP connection, for the backend server to get. This achieves the same goal as transparent proxying, while requiring no networking knowledge and no administration rights.

Instead, the protocol needs to be supported in the servers.
Many do, e.g. Apache (with the `RemoteIPProxyProtocol` setting).

`sslh` supports this protocol both on the client and the
server side.

Proxyprotocol on the server side
--------------------------------

Presumably that's the most common setup, with `sslh` being
the client-facing proxy in front of the backend server.
Support is enabled by adding the `proxyprotocol: [1|2]`
setting in the target protocol:

```
listen:
(
    { host: "localhost"; port: "443"; }
);

protocols:
(
     { name: "ssh";  host: "localhost"; port: "2222"; },
     { name: "tls";  host: "localhost"; port: "8080"; proxyprotocol: 2; }
     );
);
```

Here `sslh` listens on port 443. It forwards `ssh`
connections to port 2222 without touching them (which means sshd does not see the external data) (Apparently openssh does not as of september 2025 support Proxyprotocol).
It forwards `tls` to port 8080, adding a proxy-protocol v2
header which allows Apache (configured with RemoteIPProxyProtocol) to log the external IP and port.


```
                   203.0.113.4:443           :2222
   Client -----------------> sslh -------------> sshd
 198.51.100.42:2342             |              logs: 127.0.0.1:<local port>
                                |
                                |            :8080
                                \--pp v2-------> apache
                                               logs: 198.51.100.42:2342

```

The `proxyprotocol` setting can be set to 1 or 2, which
selects the appropriate protocol version. Version 2 being
more efficient, this is what you should use unless you have
good reasons to use version 1 (e.g. your backend server only
supports v1, an unlikely scenario).


Proxyprotocol on the client side
--------------------------------

`sslh` also supports Proxy-protocol on incoming connections.
These are so-called "client side", but you should not enable
proxy-protocol on an Internet-facing server. Instead, this
can be useful if `sslh` is located behind another proxy that
adds proxy-protocol headers, e.g. HAProxy.

This is enabled by adding `proxyprotocol: true` to a
`listen` statement:

```
listen:
(
    { host: "localhost"; port: "443"; proxyprotocol: true; }
);

protocols:
(
     { name: "ssh";  host: "localhost"; port: "2222"; proxyprotocol: 0; },
     { name: "tls";  host: "localhost"; port: "8080"; }
     );
);
```

In that case, `sslh` expects to find a proxyprotocol header
on all incoming connections. It ignores the header to
perform its usual protocol detection. 

If the target protocol
specified nothing, the connection is passed untouched, i.e.
the proxyprotocol header is forwarded as usual: here, Apache
on 8080 will receive the proxyprotocol header.

If the target protocol specifies `proxyprotocol: 0`, then
`sslh` removes the proxyprotocol header, and logs an
additional message with the connection information extracted
from the header. Here, `sslh` logs the external information
for ssh connections, removes the header, and forwards the
connection to sshd. `sshd` does not support proxyprotocol,
and logs a connection coming from the local IP address.


```
              203.0.113.4:443                                   :2222
   Client ---------> HaProxy ----pp v2---------> sslh -------------> sshd
 198.51.100.42:2342                                 |                  logs: 127.0.0.1:<local port>
                                                    | sslh logs: 198.51.100.42:2342 to localhost:2222
                                                    |
                                                    |            :8080
                                                    \--pp v2-------> apache
                                                                       logs: 198.51.100.42:2342
                                           sslh logs: local connection
```

`sslh` always logs the 'real' network information, here the
local addresses, and only logs the proxyprotocol information
when it removes the header. It is not necessary to log the
proxyprotocol information when the target server will
receive it (as it is then the target server's job to log the
external IP address).

