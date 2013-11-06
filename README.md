sslh -- A ssl/ssh multiplexer
=============================

`sslh` accepts connections on specified ports, and forwards
them further based on tests performed on the first data
packet sent by the remote client.

Probes for HTTP, SSL, SSH, OpenVPN, tinc, XMPP are
implemented, and any other protocol that can be tested using
a regular expression, can be recognised. A typical use case
is to allow serving several services on port 443 (e.g. to
connect to SSH from inside a corporate firewall, which
almost never block port 443) while still serving HTTPS on
that port. 

Hence `sslh` acts as a protocol demultiplexer, or a
switchboard. Its name comes from its original function to
serve SSH and HTTPS on the same port.

Compile and install
===================

Dependencies
------------

`sslh` uses [libconfig](http://www.hyperrealm.com/libconfig/)
and [libwrap](http://packages.debian.org/source/unstable/tcp-wrappers).

For Debian, these are contained in packages `libwrap0-dev` and
`libconfig8-dev`.

For OpenSUSE, these are contained in packages libconfig9 and
libconfig-dev in repository
<http://download.opensuse.org/repositories/multimedia:/libs/openSUSE_12.1/>

For Fedora, you'll need packages `libconfig` and
`libconfig-devel`:

	yum install libconfig libconfig-devel

If you can't find `libconfig`, or just don't want a
configuration file, set `USELIBCONFIG=` in the Makefile.

Compilation
-----------

After this, the Makefile should work:

	make install

There are a couple of configuration options at the beginning
of the Makefile: 

* `USELIBWRAP` compiles support for host access control (see
  `hosts_access(3)`), you will need `libwrap` headers and
  library to compile (`libwrap0-dev` in Debian).

* `USELIBCONFIG` compiles support for the configuration
  file. You will need `libconfig` headers to compile
  (`libconfig8-dev` in Debian).


Binaries
--------

The Makefile produces two different executables: `sslh-fork`
and `sslh-select`:

* `sslh-fork` forks a new process for each incoming connection.
It is well-tested and very reliable, but incurs the overhead
of many processes.  
If you are going to use `sslh` for a "small" setup (less than
a dozen ssh connections and a low-traffic https server) then
`sslh-fork` is probably more suited for you. 

* `sslh-select` uses only one thread, which monitors all connections
at once. It is more recent and less tested, but only incurs a 16
byte overhead per connection. Also, if it stops, you'll lose all
connections, which means you can't upgrade it remotely.  
If you are going to use `sslh` on a "medium" setup (a few thousand ssh
connections, and another few thousand ssl connections),
`sslh-select` will be better.

If you have a very large site (tens of thousands of connections),
you'll need a vapourware version that would use libevent or
something like that.


Installation
------------

* In general:

		make
		cp sslh-fork /usr/local/sbin/sslh
		cp scripts/etc.default.sslh /etc/default/sslh

* For Debian:

		cp scripts/etc.init.d.sslh /etc/init.d/sslh
	
* For CentOS:

		cp scripts/etc.rc.d.init.d.sslh /etc/rc.d/init.d/sslh


You might need to create links in /etc/rc<x>.d so that the server
start automatically at boot-up, e.g. under Debian:

	update-rc.d sslh defaults


Configuration
=============

You can edit settings in /etc/default/sslh:

	LISTEN=ifname:443
	SSH=localhost:22
	SSL=localhost:443

A good scheme is to use the external name of the machine in
`$LISTEN`, and bind `httpd` to `localhost:443` (instead of all
binding to all interfaces): that way, HTTPS connections
coming from inside your network don't need to go through
`sslh`, and `sslh` is only there as a frontal for connections
coming from the internet.

Note that 'external name' in this context refers to the
actual IP address of the machine as seen from your network,
i.e. that that is not `127.0.0.1` in the output of
`ifconfig(8)`.

Libwrap support
---------------

Sslh can optionnaly perform `libwrap` checks for the sshd
service: because the connection to `sshd` will be coming
locally from `sslh`, `sshd` cannot determine the IP of the
client.

OpenVPN support
---------------

OpenVPN clients connecting to OpenVPN running with
`-port-share` reportedly take more than one second between
the time the TCP connexion is established and the time they
send the first data packet. This results in `sslh` with
default settings timing out and assuming an SSH connexion.
To support OpenVPN connexions reliably, it is necessary to
increase `sslh`'s timeout to 5 seconds.

Instead of using OpenVPN's port sharing, it is more reliable
to use `sslh`'s `-o` option to get `sslh` to do the port sharing.

Using proxytunnel with sslh
---------------------------

If you are connecting through a proxy that checks that the
outgoing connection really is SSL and rejects SSH, you can
encapsulate all your traffic in SSL using `proxytunnel` (this
should work with `corkscrew` as well). On the server side you
receive the traffic with `stunnel` to decapsulate SSL, then
pipe through `sslh` to switch HTTP on one side and SSL on the
other.

In that case, you end up with something like this:

	ssh -> proxytunnel -e ----[ssh/ssl]---> stunnel ---[ssh]---> sslh --> sshd
	Web browser -------------[http/ssl]---> stunnel ---[http]--> sslh --> httpd

Configuration goes like this on the server side, using `stunnel3`:

	stunnel -f -p mycert.pem  -d thelonious:443 -l /usr/local/sbin/sslh -- \
		sslh -i  --http localhost:80 --ssh localhost:22

* stunnel options:
  * `-f` for foreground/debugging
  * `-p` for specifying the key and certificate
  * `-d` for specifying which interface and port
	we're listening to for incoming connexions
  * `-l` summons `sslh` in inetd mode.

* sslh options:
  * `-i` for inetd mode
  * `--http` to forward HTTP connexions to port 80,
	and SSH connexions to port 22.

Capabilities support
--------------------

On Linux (only?), you can use POSIX capabilities to reduce a
server's capabilities to the minimum it needs (see
`capabilities(8)`.  For sslh, this is `CAP_NET_ADMIN` (to
perform transparent proxy-ing) and `CAP_NET_BIND_SERVICE` (to
bind to port 443 without being root).

The simplest way to use capabilities is to give them to the
executable as root:

	# setcap cap_net_bind_service,cap_net_admin+pe sslh-select

Then you can run `sslh-select` as an unpriviledged user, e.g.:

	$ sslh-select -p myname:443 --ssh localhost:22 --ssl localhost:443

This has 2 advantages over starting as root with `-u`:
- You no longer start as root (duh)
- This enables transparent proxying.

Caveat: `CAP_NET_ADMIN` does give `sslh` too many rights, e.g.
configuring the interface. If you're not going to use
transparent proxying, just don't use it.

Transparent proxy support
-------------------------

On Linux (only?) you can use the `--transparent` option to
request transparent proying. This means services behind `sslh`
(Apache, `sshd` and so on) will see the external IP and ports
as if the external world connected directly to them. This
simplifies IP-based access control (or makes it possible at
all).

`sslh` needs extended rights to perform this: you'll need to
give it `CAP_NET_ADMIN` capabilities (see appropriate chapter)
or run it as root (but don't do that).

The firewalling tables also need to be adjusted as follow.
The example connects to HTTPS on 4443 -- adapt to your needs ;
I don't think it is possible to have `httpd` listen to 443 in
this scheme -- let me know if you manage that:

	# iptables -t mangle -N SSLH
	# iptables -t mangle -A  OUTPUT --protocol tcp --out-interface eth0 --sport 22 --jump SSLH
	# iptables -t mangle -A OUTPUT --protocol tcp --out-interface eth0 --sport 4443 --jump SSLH
	# iptables -t mangle -A SSLH --jump MARK --set-mark 0x1
	# iptables -t mangle -A SSLH --jump ACCEPT
	# ip rule add fwmark 0x1 lookup 100
	# ip route add local 0.0.0.0/0 dev lo table 100

This will only work if `sslh` does not use any loopback
addresses (no `127.0.0.1` or `localhost`), you'll need to use
explicit IP addresses (or names):

	sslh --listen 192.168.0.1:443 --ssh 192.168.0.1:22 --ssl 192.168.0.1:4443

This will not work:

	sslh --listen 192.168.0.1:443 --ssh 127.0.0.1:22 --ssl 127.0.0.1:4443

Comments? Questions?
====================

You can subscribe to the `sslh` mailing list here:
<http://rutschle.net/cgi-bin/mailman/listinfo/sslh>

This mailing list should be used for discussion, feature
requests, and will be the prefered channel for announcements.

