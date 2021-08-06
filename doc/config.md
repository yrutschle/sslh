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
and `CAP_NET_RAW` for transparent proxying (see
`capabilities(7)`).

You can use the `setcap(8)` utility to give these capabilities
to the executable:

	sudo setcap cap_net_bind_service,cap_net_raw+pe sslh-select

Then you can run sslh-select as an unpriviledged user, e.g.:

	sslh-select -p myname:443 --ssh localhost:22 --tls localhost:443

Transparent proxy support
-------------------------

On Linux and FreeBSD you can use the `--transparent` option to
request transparent proxying. This means services behind `sslh`
(Apache, `sshd` and so on) will see the external IP and ports
as if the external world connected directly to them. This
simplifies IP-based access control (or makes it possible at
all).

You can refer to Sean Warn'ѕ [tutorial](tproxy.md) for a
different set-up which enables transparent proxying between
two different machines. The following may only work if
`sslh` and the final servers are on the same machine.

Note that getting this to work is very tricky and
detail-dependant: depending on whether the target server and
sslh are on the same machine, different machines, or
different dockers, and tool versions, all seem to change the
required network configuration somewhat. If it doesn't work,
it's almost certain that the problem is not linked to `sslh`
but to the network setup that surrounds it.

Linux:

`sslh` needs extended rights to perform this: you'll need to
give it `CAP_NET_RAW` capabilities (see appropriate chapter)
or run it as root (but don't do that).

The firewalling tables also need to be adjusted as follows.
I don't think it is possible to have `httpd` and `sslh` both listen to 443 in
this scheme -- let me know if you manage that:

	# Set route_localnet = 1 on all interfaces so that ssl can use "localhost" as destination
	sysctl -w net.ipv4.conf.default.route_localnet=1
	sysctl -w net.ipv4.conf.all.route_localnet=1

	# DROP martian packets as they would have been if route_localnet was zero
	# Note: packets not leaving the server aren't affected by this, thus sslh will still work
	iptables -t raw -A PREROUTING ! -i lo -d 127.0.0.0/8 -j DROP
	iptables -t mangle -A POSTROUTING ! -o lo -s 127.0.0.0/8 -j DROP

	# Mark all connections made by ssl for special treatment (here sslh is run as user "sslh")
	iptables -t nat -A OUTPUT -m owner --uid-owner sslh -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CONNMARK --set-xmark 0x01/0x0f

	# Outgoing packets that should go to sslh instead have to be rerouted, so mark them accordingly (copying over the connection mark)
	iptables -t mangle -A OUTPUT ! -o lo -p tcp -m connmark --mark 0x01/0x0f -j CONNMARK --restore-mark --mask 0x0f

	# Configure routing for those marked packets
	ip rule add fwmark 0x1 lookup 100
	ip route add local 0.0.0.0/0 dev lo table 100

Tranparent proxying with IPv6 is similarly set up as follows:

	# Set route_localnet = 1 on all interfaces so that ssl can use "localhost" as destination
	# Not sure if this is needed for ipv6 though
	sysctl -w net.ipv4.conf.default.route_localnet=1
	sysctl -w net.ipv4.conf.all.route_localnet=1

	# DROP martian packets as they would have been if route_localnet was zero
	# Note: packets not leaving the server aren't affected by this, thus sslh will still work
	ip6tables -t raw -A PREROUTING ! -i lo -d ::1/128 -j DROP
	ip6tables -t mangle -A POSTROUTING ! -o lo -s ::1/128 -j DROP

	# Mark all connections made by ssl for special treatment (here sslh is run as user "sslh")
	ip6tables -t nat -A OUTPUT -m owner --uid-owner sslh -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j CONNMARK --set-xmark 0x01/0x0f

	# Outgoing packets that should go to sslh instead have to be rerouted, so mark them accordingly (copying over the connection mark)
	ip6tables -t mangle -A OUTPUT ! -o lo -p tcp -m connmark --mark 0x01/0x0f -j CONNMARK --restore-mark --mask 0x0f

	# Configure routing for those marked packets
	ip -6 rule add fwmark 0x1 lookup 100
	ip -6 route add local ::/0 dev lo table 100

Explanation:
To be able to use `localhost` as destination in your sslh config along with transparent proxying
you have to allow routing of loopback addresses as done above.
This is something you usually should not do (see [this stackoverflow post](https://serverfault.com/questions/656279/how-to-force-linux-to-accept-packet-with-loopback-ip/656484#656484))
The two `DROP` iptables rules emulate the behaviour of `route_localnet` set to off (with one small difference:
allowing the reroute-check to happen after the fwmark is set on packets destined for sslh).
See [this diagram](https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg) for a good visualisation
showing how packets will traverse the iptables chains.

Note:
You have to run `sslh` as dedicated user (in this example the user is also named `sslh`), to not mess up with your normal networking.
These rules will allow you to connect directly to ssh on port
22 (or to any other service behind sslh) as well as through sslh on port 443.

Also remember that iptables configuration and ip routes and 
rules won't be necessarily persisted after you reboot. Make 
sure to save them properly. For example in CentOS7, you would 
do `iptables-save > /etc/sysconfig/iptables`, and add both 
`ip` commands to your `/etc/rc.local`.

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

	sslh --listen 192.168.0.1:443 --ssh 192.168.0.1:22 --tls 192.168.0.1:4443

This will not work:

	sslh --listen 192.168.0.1:443 --ssh 127.0.0.1:22 --tls 127.0.0.1:4443
    
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
	ExecStart=/usr/sbin/sslh -v -f --ssh 127.0.0.1:22 --tls 127.0.0.1:443
	KillMode=process
	CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
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

UDP
---

`sslh` can perform demultiplexing on UDP packets as well.
This only works with `sslh-select` (it is not possible to
support UDP with a forking model). Specify a listening
address and target protocols with `is_udp: true`. `sslh`
will wait for incoming UDP packets, run the probes in the
usual fashion, and forward packets to the appropriate
target. `sslh` will then remember the association between
remote host to target server for 60 seconds by default,
which can be overriden with `udp_timeout`. This allows to
process both single-datagram protocols such as DNS, and
connection-based protocols such as QUIC.
