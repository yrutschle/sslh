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

*  `USESYSTEMD` compiles support for using systemd socket activation.
   You will need `systemd` headers to compile (`systemd-devel` in Fedora).

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
		cp basic.cfg /etc/sslh.cfg
                vi /etc/sslh.cfg

* For Debian:

		cp scripts/etc.init.d.sslh /etc/init.d/sslh
	
* For CentOS:

		cp scripts/etc.rc.d.init.d.sslh.centos /etc/rc.d/init.d/sslh


You might need to create links in /etc/rc<x>.d so that the server
start automatically at boot-up, e.g. under Debian:

	update-rc.d sslh defaults


Configuration
=============

If you use the scripts provided, sslh will get its
configuration from /etc/sslh.cfg. Please refer to
example.cfg for an overview of all the settings.

A good scheme is to use the external name of the machine in
`listen`, and bind `httpd` to `localhost:443` (instead of all
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

Sslh can optionally perform `libwrap` checks for the sshd
service: because the connection to `sshd` will be coming
locally from `sslh`, `sshd` cannot determine the IP of the
client.

OpenVPN support
---------------

OpenVPN clients connecting to OpenVPN running with
`-port-share` reportedly take more than one second between
the time the TCP connection is established and the time they
send the first data packet. This results in `sslh` with
default settings timing out and assuming an SSH connection.
To support OpenVPN connections reliably, it is necessary to
increase `sslh`'s timeout to 5 seconds.

Instead of using OpenVPN's port sharing, it is more reliable
to use `sslh`'s `--openvpn` option to get `sslh` to do the
port sharing.

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

On Linux (only?), you can compile sslh with `USELIBCAP=1` to
make use of POSIX capabilities; this will save the required
capabilities needed for transparent proxying for unprivileged
processes.

Alternatively, you may use filesystem capabilities instead
of starting sslh as root and asking it to drop privileges.
You will need `CAP_NET_BIND_SERVICE` for listening on port 443
and `CAP_NET_ADMIN` for transparent proxying (see
`capabilities(7)`).

You can use the `setcap(8)` utility to give these capabilities
to the executable:

	# setcap cap_net_bind_service,cap_net_admin+pe sslh-select

Then you can run sslh-select as an unpriviledged user, e.g.:

	$ sslh-select -p myname:443 --ssh localhost:22 --ssl localhost:443

Caveat: `CAP_NET_ADMIN` does give sslh too many rights, e.g.
configuring the interface. If you're not going to use
transparent proxying, just don't use it (or use the libcap method).

Transparent proxy support
-------------------------

On Linux and FreeBSD you can use the `--transparent` option to
request transparent proxying. This means services behind `sslh`
(Apache, `sshd` and so on) will see the external IP and ports
as if the external world connected directly to them. This
simplifies IP-based access control (or makes it possible at
all).

Linux:

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

Tranparent proxying with IPv6 is similarly set up as follows:

        # ip6tables -t mangle -N SSLH
        # ip6tables -t mangle -A  OUTPUT --protocol tcp --out-interface eth0 --sport 22 --jump SSLH
        # ip6tables -t mangle -A OUTPUT --protocol tcp --out-interface eth0 --sport 4443 --jump SSLH
        # ip6tables -t mangle -A SSLH --jump MARK --set-mark 0x1
        # ip6tables -t mangle -A SSLH --jump ACCEPT
        # ip -6 rule add fwmark 0x1 lookup 100
        # ip -6 route add local ::/0 dev lo table 100

Note that these rules will prevent from connecting directly
to ssh on the port 22, as packets coming out of sshd will be
tagged. If you need to retain direct access to ssh on port
22 as well as through sslh, you can make sshd listen to
22 AND another port (e.g. 2222), and change the above rules
accordingly.

FreeBSD:

Given you have no firewall defined yet, you can use the following configuration
to have ipfw properly redirect traffic back to sslh

	/etc/rc.conf
	firewall_enable="YES"
	firewall_type="open"
	firewall_logif="YES"
	firewall_coscripts="/etc/ipfw/sslh.rules"


/etc/ipfw/sslh.rules

	#! /bin/sh

	# ssl
	ipfw add 20000 fwd 192.0.2.1,443 log tcp from 192.0.2.1 8443 to any out
	ipfw add 20010 fwd 2001:db8::1,443 log tcp from 2001:db8::1 8443 to any out

	# ssh
	ipfw add 20100 fwd 192.0.2.1,443 log tcp from 192.0.2.1 8022 to any out
	ipfw add 20110 fwd 2001:db8::1,443 log tcp from 2001:db8::1 8022 to any out

	# xmpp
	ipfw add 20200 fwd 192.0.2.1,443 log tcp from 192.0.2.1 5222 to any out
	ipfw add 20210 fwd 2001:db8::1,443 log tcp from 2001:db8::1 5222 to any out

	# openvpn (running on other internal system)
	ipfw add 20300 fwd 192.0.2.1,443 log tcp from 198.51.100.7 1194 to any out
	ipfw add 20310 fwd 2001:db8::1,443 log tcp from 2001:db8:1::7 1194 to any out

General notes:


This will only work if `sslh` does not use any loopback
addresses (no `127.0.0.1` or `localhost`), you'll need to use
explicit IP addresses (or names):

	sslh --listen 192.168.0.1:443 --ssh 192.168.0.1:22 --ssl 192.168.0.1:4443

This will not work:

	sslh --listen 192.168.0.1:443 --ssh 127.0.0.1:22 --ssl 127.0.0.1:4443
    
Transparent proxying means the target server sees the real
origin address, so it means if the client connects using
IPv6, the server must also support IPv6. It is easy to
support both IPv4 and IPv6 by configuring the server
accordingly, and setting `sslh` to connect to a name that
resolves to both IPv4 and IPv6, e.g.:

        sslh --transparent --listen <extaddr>:443 --ssh insideaddr:22

        /etc/hosts:
        192.168.0.1  insideaddr
        201::::2     insideaddr

Upon incoming IPv6 connection, `sslh` will first try to
connect to the IPv4 address (which will fail), then connect
to the IPv6 address.

Systemd Socket Activation
-------------------------
If compiled with `USESYSTEMD` then it is possible to activate 
the service on demand and avoid running any code as root.

In this mode any listen configuration options are ignored and 
the sockets are passed by systemd to the service.

Example socket unit:

	[Unit]
	Before=sslh.service
	
	[Socket]
	ListenStream=1.2.3.4:443
	ListenStream=5.6.7.8:444
	ListenStream=9.10.11.12:445
	FreeBind=true

	[Install]
	WantedBy=sockets.target

Example service unit:

	[Unit]
	PartOf=sslh.socket
	
	[Service]
	ExecStart=/usr/sbin/sslh -v -f --ssh 127.0.0.1:22 --ssl 127.0.0.1:443
	KillMode=process
	CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SETGID CAP_SETUID
	PrivateTmp=true
	PrivateDevices=true
	ProtectSystem=full
	ProtectHome=true
	User=sslh


With this setup only the socket needs to be enabled. The sslh service 
will be started on demand and does not need to run as root to bind the 
sockets as systemd has already bound and passed them over. If the sslh
service is started on its own without the sockets being passed by systemd
then it will look to use those defined on the command line or config
file as usual. Any number of ListenStreams can be defined in the socket
file and systemd will pass them all over to sslh to use as usual.

To avoid inconsistency between starting via socket and starting directly
via the service Requires=sslh.socket can be added to the service unit to
mandate the use of the socket configuration.

Rather than overwriting the entire socket file drop in values can be placed
in /etc/systemd/system/sslh.socket.d/<name>.conf with additional ListenStream
values that will be merged.

In addition to the above with manual .socket file configuration there is an
optional systemd generator which can be compiled - systemd-sslh-generator 

This parses the /etc/sslh.cfg (or /etc/sslh/sslh.cfg file if that exists 
instead) configuration file and dynamically generates a socket file to use.

This will also merge with any sslh.socket.d drop in configuration but will be 
overriden by a /etc/systemd/system/sslh.socket file.

To use the generator place it in /usr/lib/systemd/system-generators and then
call systemctl daemon-reload after any changes to /etc/sslh.cfg to generate 
the new dynamic socket unit.

Fail2ban
--------

If using transparent proxying, just use the standard ssh
rules. If you can't or don't want to use transparent
proxying, you can set `fail2ban` rules to block repeated ssh
connections from an IP address (obviously this depends
on the site, there might be legitimate reasons you would get
many connections to ssh from the same IP address...)

See example files in scripts/fail2ban.

Comments? Questions?
====================

You can subscribe to the `sslh` mailing list here:
<http://rutschle.net/cgi-bin/mailman/listinfo/sslh>

This mailing list should be used for discussion, feature
requests, and will be the prefered channel for announcements.

