# Simple Transparent Proxy Configuration Explained #
This documentation is another explanation of the transparent proxy with the goal, beeing secure and minimalistic. Besides this documentation will explain, how and why this configuration works.
The explanation will only describe the connection to sshd, so the target sshd can be replace with any other target service, sslh supports.

## Introduction in the data flow ##
This chapter can be skipped, if you just like to configure things fast.
This chapter is a little excurse to the dataflow. First point of all is something, which you will unfortunately not see in the nice routing diagrams for iptables or netfilter-tables (nft) like: [Iptables at wikipedia](https://upload.wikimedia.org/wikipedia/commons/thumb/3/37/Netfilter-packet-flow.svg/2560px-Netfilter-packet-flow.svg.png), [Netfilter Flow](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks#Netfilter_hooks_into_Linux_networking_packet_flows).

Packets from local application talking to other local applications are routed through the loopback-interface. They leave postrouting to lo and reentering from there prerouting, without passing ingress/egress.
This has nothing to do with the "**route_localnet = 1**" trick, which only makes, that the the local ip range 10.0.0.0/8 gets routed!
As you can read in many articles, this is nothing you should do, as you may bring your system at risk, because it allows to leak packets from outside to applications, which feel themselves secure, by using those unroutable addresses.
#### A Simple Simulation ####
You can prove this behaviour with a simple test:
```
# In one terminal start socat as a local echo server
# this is simulating sshd

socat TCP4-LISTEN:2000,bind=SERVER_IP,fork EXEC:cat

# In the next terminal start another instance of socat,
# simulating sslh

socat TCP-LISTEN:3000,bind=SERVER_IP,fork TCP:SERVER_IP:2000

# In another terminal you can watch the traffic on lo

tcpdump -i lo port 2000

# In the last terminal talk to the echo server
telnet SERVER_IP 2000
```
You will see your traffic on lo, but not on eth0, if you retry the tcpdump there.

If you setup sslh as non transparent proxy, it will just work, as what we have seen.  

#### Going Transparent ####

In case of transparent proxy however, sslh uses some tricks, to reuse the clients IP on its outgoing interface to sshd. It opens the interface in raw mode, so it either needs to be started as root and drop privileges after binding, or you will need to give some capabilities to the sslh binary (cap_net_bind_service,cap_net_raw+ep), if you will start it as restricted user.
In this setup we continue, with dropping priviledges.

Doing so, you can send packets to the sshd, listening on another interface, but, the answer packets from sshd will get routed back to the client. This however will not work, as the client would refuse those packets, because they don't belong to a tcp session, the client opened. In most cases those packets would even not reach the client, as source ip addresses from private address space, will be blocked by most internet routers and connection providers.

So its mandatory, to use some tricks, to get those packets back to sslh. All configurations, I have seen so far, are using two components for that. They bind sshd to lo, and than they introduce some firewall rules, to mark packets, originating from the sshd port on lo, so that those packets can be routed in a next step -based on that marking- back to sslh.

##### Drawbacks From Using loopback #####
This idea has some serious drawbacks: First, you need to allow routing of the local address space, 127.0.0.0/8, with kernel configurations. Search for the string "net.ipv4.conf.default.route_localnet" and you will find lot of articles, why you should not do this.
By allowing this, you need additional firewall rules, dropping martian packets, which otherwise would get routed to the internet from other applications, running on lo, not aware, that their traffic could be routed.  You need further firewall rules, blocking incoming packets to loopback addresses, as otherwise some applications (especially udp) could be the goal of some bad traffic.

##### Using A Dedicated Interface #####
So this configuration makes use of a own interface, just for the services, where sslh should hide the traffic for. We use a interface of the dummy kernel module, which was designed just for this case.  It is an interface, beeing there, having no cable connection or whatsever, but applications can bind to it. We assign to this interface just a /32 private address, as this interface is not part of any network.

Doing so, we can avoid all the hassle with marking certain packets, coming from the single applications, sslh has to hide, as we now just route ALL traffic from this specific interface by its ip to sslh.
We need one routing rule and one routing table, this covers as many targets sslh will serve on this interface, without adding additional rules for adding apache, openvpn and others.

We need no firewall rules, preventing martians, as this single routing rule will deadroute all traffic from this interface, if sslh is not catching it up.

We only need firewall protection for this specific ip address, when we have activated ip forwarding on that system.  If the system is no router and needs no forwarding, there is no protection needed.

## Finally The Configuration ##

As described, we need as a first step a dedicated interface, just for the services, sslh should hide. Its possible, to generate individual interfaces for different configurations, however, that makes things again more complex and has no advantages seen so far.

### Dummy Interface ###
In the file _**/etc/network/interfaces**_, we place this entry:
```
auto dummy0
iface dummy0 inet static
    address 192.168.255.254/32
    pre-up modprobe dummy
    ## Attention! with kernels, not automatically creating a dummy0 interface after module loading this line should be:
    ## pre-up modprobe dummy; if [ ! -e /sys/class/net/dummy0 ]; then ip link add dummy0 type dummy ; fi
```
As long, as your system has no other interfaces with private address-space, or is routing such addresses, you can continue with the given example. Otherwise you need to select a conflict free address.
If you are updating a older current configuration, make sure, that you have no longer insecure localnet routing in place:
```
 sysctl  net.ipv4.conf.default.route_localnet  
 sysctl net.ipv4.conf.all.route_localnet
```
should both report "0"!

Now go to  _**/etc/iproute2/rt_tables**_ and add a line `111     sslh`

In your startup configuration, you need only two lines before starting the sslh service. Thise lines are:
```
        ip rule add from 192.168.255.254 table sslh
        ip route add local 0.0.0.0/0 dev dummy0 table sslh
```

The first line is an routing rule entry, routing everything coming from the dummy0 ip source address to a specual routing table _**sslh**_. The next line generates this table implicitly, by inserting a single rule, routing all from that ip address to dummy0.

A startup script for sysv-init.d (debian ) is provided here:
```
#! /bin/sh
### BEGIN INIT INFO
# Provides:          sslh
# Required-Start:    $remote_fs $syslog $network
# Required-Stop:     $remote_fs $syslog $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: ssl/ssh multiplexer
# Description:       sslh lets one accept both HTTPS and SSH connections on the
#                    same port. It makes it possible to connect to an SSH server
#                    on port 443 (e.g. from inside a corporate firewall) while
#                    still serving HTTPS on that port.
### END INIT INFO

# Author: Guillaume Delacour <gui@iroqwa.org>

# Do NOT "set -e"

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="ssl/ssh multiplexer"
NAME=sslh
DAEMON=/usr/sbin/$NAME
DAEMON_OPTS=""
PIDFILE=/var/run/sslh/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
RUN=yes

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
        # Return
        #   0 if daemon has been started
        #   1 if daemon was already running
        #   2 if daemon could not be started
    
    # Use this if you want the user to explicitly set 'RUN' in
    # /etc/default/
    if [ "$RUN" != "yes" ]
    then
        echo "$NAME disabled, please adjust the configuration to your needs "
        log_failure_msg "and then set RUN to 'yes' in /etc/default/$NAME to enable it."
        return 2
    fi
    
        # sslh write the pid as sslh user
        if [ ! -d /var/run/sslh/ ]
        then
                mkdir -p /var/run/sslh
                chown sslh:sslh /var/run/sslh
        fi
        ip rule add from 192.168.255.254 table sslh
        ip route add local 0.0.0.0/0 dev dummy0 table sslh
        start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --test > /dev/null \
                || return 1
        start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON -- $DAEMON_OPTS \
                || return 2   >>/dev/null
        # Add code here, if necessary, that waits for the process to be ready
        # to handle requests from services started subsequently which depend
        # on this one.  As a last resort, sleep for some time.
}

#
# Function that stops the daemon/service
#
do_stop()
{
        # Return
        #   0 if daemon has been stopped
        #   1 if daemon was already stopped
        #   2 if daemon could not be stopped
        #   other if a failure occurred
        ip route del local 0.0.0.0/0 dev dummy0 table sslh
        ip rule  del from 192.168.255.254 table sslh
        start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name $NAME    >>/dev/null
        RETVAL="$?"
        [ "$RETVAL" = 2 ] && return 2
        # Wait for children to finish too if this is a daemon that forks
        # and if the daemon is only ever run from this initscript.
        # If the above conditions are not satisfied then add some other code
        # that waits for the process to drop all resources that could be
        # needed by services started subsequently.  A last resort is to
        # sleep for some time.
        start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --exec $DAEMON    >>/dev/null
        [ "$?" = 2 ] && return 2
        # Many daemons don't delete their pidfiles when they exit.
        rm -f $PIDFILE
        return "$RETVAL"
}

#
# Function that sends a SIGHUP to the daemon/service
#
do_reload() {
        #
        # If the daemon can reload its configuration without
        # restarting (for example, when it is sent a SIGHUP),
        # then implement that here.
        #
        start-stop-daemon --stop --signal 1 --quiet --pidfile $PIDFILE --name $NAME    >>/dev/null
        return 0
}

case "$1" in
  start)
        # check if sslh is launched via inetd
        if [ -f /etc/inetd.conf ] && [ $(egrep -q "^https.*/usr/sbin/sslh" /etc/inetd.conf|wc -l) -ne 0 ]
        then
                echo "sslh is started from inetd."
                exit 1
        fi

        log_daemon_msg "Starting $DESC" "$NAME"
        do_start
        case "$?" in
                0|1) log_end_msg 0 ;;
                2) log_end_msg 1 ;;
        esac
        ;;
  stop)
        log_daemon_msg "Stopping $DESC" "$NAME"
        do_stop
        case "$?" in
                0|1) log_end_msg 0 ;;
                2) log_end_msg 1 ;;
        esac
        ;;
  status)
       status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
       ;;
  restart|force-reload)
        log_daemon_msg "Restarting $DESC" "$NAME"
        do_stop
        case "$?" in
          0|1)
                do_start
                case "$?" in
                        0) log_end_msg 0 ;;
                        1) log_end_msg 1 ;; # Old process is still running
                        *) log_end_msg 1 ;; # Failed to start
                esac
                ;;
          *)
                # Failed to stop
                log_end_msg 1
                ;;
        esac
        ;;
  *)
        echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
        exit 3
        ;;
esac

:
```
And finally you need to configute _**/etc/default/sslh**_ with the right settings for all the services, sslh should work for.
```
DAEMON_OPTS="--user sslh --listen SERVER_IP:443 --transparent  \
             --ssh 192.168.255.254:22 --tls 192.168.255.254:443 \
             --pidfile /var/run/sslh/sslh.pid"
```
 
This should also work with systemd, as that parses initd.d scripts. Perhaps some configuration remainders in other systemd configuration locations must be deleted or adapted. But not tried up to now.

