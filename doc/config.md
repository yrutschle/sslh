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
	we're listening to for incoming connections
  * `-l` summons `sslh` in inetd mode.

* sslh options:
  * `-i` for inetd mode
  * `--http` to forward HTTP connections to port 80,
	and SSH connections to port 22.

Capabilities support
--------------------

On Linux (only?), you can compile sslh with `USELIBCAP=1` set 
in the Makefile to make use of POSIX capabilities; this will 
save the required capabilities needed for transparent proxying 
for unprivileged processes.

Alternatively, you may use filesystem capabilities instead
of starting sslh as root and asking it to drop privileges.
You will need `CAP_NET_BIND_SERVICE` for listening on port 443
and `CAP_NET_RAW` for transparent proxying (see
`capabilities(7)`).

You can use the `setcap(8)` utility to give these capabilities
to the executable:

	sudo setcap cap_net_bind_service,cap_net_raw+pe sslh-select

Then you can run sslh-select as an unprivileged user, e.g.:

	sslh-select -p myname:443 --ssh localhost:22 --tls localhost:443

Transparent proxy support
-------------------------

Transparent proxying is described in its own
[document](tproxy.md).

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
overridden by a /etc/systemd/system/sslh.socket file.

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
This does not work with `sslh-fork` (it is not possible to
support UDP with a forking model). Specify a listening
address and target protocols with `is_udp: true`. `sslh`
will wait for incoming UDP packets, run the probes in the
usual fashion, and forward packets to the appropriate
target. `sslh` will then remember the association between
remote host to target server for 60 seconds by default,
which can be overridden with `udp_timeout`. This allows to
process both single-datagram protocols such as DNS, and
connection-based protocols such as QUIC.

An example for supporting QUIC is shown in `example.cfg`.
