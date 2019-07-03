Transparent Proxy to Two Hosts
==============================

Tutorial by Sean Warner.  19 June 2019 20:35

Aim
---

* Show that `sslh` can transparently proxy requests from the internet to services on two separate hosts that are both on the same LAN.
* The IP address of the client initiating the request is what the destination should see… and not the IP address of the host that `sslh` is running on, which is what happens when `sslh` is not running in transparent mode.
* The solution here only works for my very specific use-case but hopefully others can adapt it to suits their needs.

Overview of my Network
----------------------

Two Raspberry Pis on my home LAN:
* Pi A: 192.168.1.124 – `sslh` (Port 4433), Apache2 web server for https (port 443), `stunnel` (port 4480) to decrypt ssh traffic and forward to SSH server (also on Pi A at Port 1022)
* Pi B: 192.168.1.123 - HTTP server (port 8000), SSH server (port 1022 on PiB).
* I send traffic from the internet to my router's external port 443 then use a port forward rule in my router to map that to internal port 4433 where sslh is listening.

![Architecture](tproxy.svg)

`sslh` build
------------
 
`sslh` Version: sslh v1.19c-2-gf451cc8-dirty.

I compiled sslh from sources giving the binary pretty much all possible options such as Posix capabilities and systemd support.. here are the first few lines of the makefile:
 
```
# Configuration
 
VERSION=$(shell ./genver.sh -r)
ENABLE_REGEX=1         # Enable regex probes
USELIBCONFIG=1         # Use libconfig? (necessary to use configuration files)
USELIBPCRE=1           # Use libpcre? (needed for regex on musl)
USELIBWRAP=1           # Use libwrap?
USELIBCAP=1            # Use libcap?
USESYSTEMD=1           # Make use of systemd socket activation
COV_TEST=              # Perform test coverage?
PREFIX=/usr/local
BINDIR=$(PREFIX)/sbin
MANDIR=$(PREFIX)/share/man/man8
MAN=sslh.8.gz          # man page name
 
# End of configuration -- the rest should take care of
# itself
```
 
systemd setup
-------------

Create an sslh systemd service file...
```
# nano /lib/systemd/system/sslh.service
```
 
Paste in this contents…
 
```
[Unit]
Description=SSL/SSH multiplexer
After=network.target
Documentation=man:sslh(8)
 
[Service]
#EnvironmentFile=/etc/default/sslh
#ExecStart=/usr/local/sbin/sslh $DAEMON_OPTS
ExecStart=/usr/local/sbin/sslh -F /etc/sslh/sslh.cfg
KillMode=process
 
[Install]
WantedBy=multi-user.target
```
 
Save it and then…
```
# systemctl daemon-reload
```
 
Start it again to test…
```
# systemctl start sslh
```
 
Configure `sslh`
----------------

First stop `sslh` then open the config file and replace with below, save and start `sslh` again
```
# systemctl stop sslh
# nano /etc/sslh/sslh.cfg
# systemctl start sslh
```
 
```
verbose: true;
foreground: true;
inetd: false;
numeric: true;
transparent: true;
timeout: 2;
user: "sslh";
pidfile: "/var/run/sslh.pid";
chroot: "/var/empty";
 
# You must have a port forward rule in the router: external port 443 <-> internal port 4433
# Local ip address of PiA is: 192.168.1.124, sslh and stunnel4 are running on this Pi
# Local ip address of PiB is: 192.168.1.123, http server and ssh server on this Pi
listen:
(
{ host: "192.168.1.124"; port: "4433"; }
);
 
# sslh demultiplexes based on the Protocol and Hostname
protocols:
(
{ name: "tls"; sni_hostnames: [ "www.example.com" ]; host: "192.168.1.124"; port: "443"; log_level: 1; },
# This probe is for tls encrypted ssh. SSLH forwards it to stunnel on port 4480 which decrypts it and sends it to the ssh server on PiA port 1022
{ name: "tls"; sni_hostnames: [ "ssh.example.com" ]; host: "192.168.1.124"; port: "4480"; log_level: 1; },
{ name: "http"; host: "192.168.1.123"; port: "8000"; log_level: 1; },
{ name: "ssh"; host: "192.168.1.123"; port: "1022"; log_level: 1; }
);
```
 
Configure `stunnel`
-------------------

First stop `stunnel` then open the config file and replace with below, save and start `stunnel` again
```
# systemctl stop stunnel4
# nano /etc/stunnel/stunnel.conf
# systemctl start stunnel4
```
 
```
# Debugging stuff (may be useful for troubleshooting)
foreground = yes
#debug = 5 # this is the default
debug = 7
output = /var/log/stunnel4/stunnel.log
pid = /var/run/stunnel4/stunnel.pid
fips = no
 
cert = /etc/letsencrypt/live/example.com/fullchain.pem
key = /etc/letsencrypt/live/example.com/privkey.pem
 
[ssh]
accept = 192.168.1.124:4480
connect = 192.168.1.124:1022
TIMEOUTclose  = 0
```
 
Configure iptables for Pi A
--------------------------

The `_add.sh` script creates the rules, the `_rm.sh` script removes the rules.
They will be lost if you reboot but there are ways to make them load again on start-up..
```
# nano /usr/local/sbin/piA_tproxy_add.sh
```
``` piA_tproxy_add.sh
iptables -t mangle -N SSLH
iptables -t mangle -A PREROUTING -p tcp -m socket --transparent -j SSLH
iptables -t mangle -A OUTPUT --protocol tcp --out-interface eth0 -m multiport --sport 443,4480 --jump SSLH
iptables -t mangle -A SSLH --jump MARK --set-mark 0x1
iptables -t mangle -A SSLH --jump ACCEPT
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```
 
```
# nano /usr/local/sbin/piA_tproxy_rm.sh
```
``` piA_tproxy_rm.sh
iptables -t mangle -D PREROUTING -p tcp -m socket --transparent -j SSLH
iptables -t mangle -D OUTPUT --protocol tcp --out-interface eth0 -m multiport --sport 443,4480 --jump SSLH
iptables -t mangle -D SSLH --jump MARK --set-mark 0x1
iptables -t mangle -D SSLH --jump ACCEPT
iptables -t mangle -X SSLH
ip rule del fwmark 0x1 lookup 100
ip route del local 0.0.0.0/0 dev lo table 100
```
 
Make them executable..
```
# chmod +rx piA_tproxy_add.sh
# chmod +rx piA_tproxy_rm.sh
```
 
Now run the "add" script on Pi A!
```
# piA_tproxy_add.sh
# piA_tproxy_rm.sh
```
 
Configure iptables for Pi B
--------------------------

```
# nano /usr/local/sbin/piB_tproxy_add.sh
```
``` piB_tproxy_add.sh
iptables -t mangle -N SSLHSSL
iptables -t mangle -A OUTPUT -o eth0 -p tcp -m multiport --sport 1022,8000 -j SSLHSSL
iptables -t mangle -A SSLHSSL --jump MARK --set-mark 0x1
iptables -t mangle -A SSLHSSL --jump ACCEPT
ip rule add fwmark 0x1 lookup 100
ip route add default via 192.168.1.124 table 100
ip route flush cache
```
 
```
# nano /usr/local/sbin/piB_tproxy_rm.sh
```
```
iptables -t mangle -D OUTPUT -o eth0 -p tcp -m multiport --sport 1022,8000 -j SSLHSSL
iptables -t mangle -D SSLHSSL --jump MARK --set-mark 0x1
iptables -t mangle -D SSLHSSL --jump ACCEPT
iptables -t mangle -X SSLHSSL
ip rule del fwmark 0x1 lookup 100
ip route del default via 192.168.1.124 table 100
ip route flush cache
```
 
Make them executable..
```
# chmod +rx piB_tproxy_add.sh
# chmod +rx piB_tproxy_rm.sh
```
 
Now run the "add" script on Pi B!
```
# piB_tproxy_add.sh
# piB_tproxy_rm.sh
```
 
Testing
-------
* Getting to sshd on PiA

I did this test using 4G from my phone (outside the LAN)

To simulate this I use `proxytunnel`. External port 443 is forwarded by my router to 4433. I need to arrive at `sslh` (port 4433) with ssh encrypted as TLS (hence I use the -e switch) and the `sni_hostname` set to ssh.example.com so that `sslh` will demultiplex to `stunnel` (port 4480) which will decrypt and forward to ssh server on PiA… see `sslh.cfg` and `stunnel.conf`.

The first IP:port is just a free HTTPS proxy I found on https://free-proxy-list.net
I execute this command from a terminal window..
 
```
# proxytunnel -v -e -C root.pem -p 78.141.192.198:8080 -d ssh.example.com:443
```
* Getting to sshd on PiB

I did this test using 4G from my phone (outside the LAN)

My smartphone telecom provider blocks ssh over port 443 so I need to use `proxytunnel` to encrypt.

Use the Proxytunnel `-X` switch to encrypt from local proxy to destination only so by the time we get to the destination it is unencrypted and `sslh` will see the ssh protocol and demultiplex to PiB as per `sslh.cfg`.
 
```
# proxytunnel -v -X -C root.pem -p 78.141.192.198:8080 -d ssh.example.com:443
```

Now when you test it all look at the output in daemon.log like this:
```
# grep -i 'ssl' /var/log/daemon.log
```
You should see that the IP address and port from the “connection from” and “forwarded from” fields are the same.

Special thanks and appreciation to Michael Yelsukov without whom I would never have got this working.

Any feedback or corrections very welcome!
