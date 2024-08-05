# Transparent Proxy Configuration Using IP Routing#
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

### Named Routing Table ###
As we configure the needed routing rules in the interface configuration, we need to define a name for the sslh routing table first.
Using named routing tables helps, understanding the routing configuration, as a name indicates, why this routing table is configured.
To do so go to  _**/etc/iproute2/rt_tables**_ and add a line

```
 111     sslh
```
With newer versions of iproute2 the /etc/iproute2 directory with the embedded templates got no longer installed. The cause maybe, that the example names, which were not used in any configuration, generated confusion. However, once you need those files, generate them and they will be honoured. You still can use just numbers for your routing table. But doing this, and having more than one routing table, you need a list, which numer belongs to which configuration. 
And seeing in the output from `ip route list table all ` the tables names instead just numbers is worth creating the file.

### Dummy Interface ###
Now we configure our dedicated interface.
In the file _**/etc/network/interfaces**_, we place this entry:
```
auto dummy0
iface dummy0 inet static
    address 192.168.255.254/32
    pre-up modprobe dummy
    ## Attention! with kernels, not automatically creating a dummy0
    ## interface after module loading the following line should be:
    ## pre-up modprobe dummy; if [ ! -e /sys/class/net/dummy0 ]; then ip link add dummy0 type dummy ; fi
    post-up ip rule add from 192.168.255.254 table sslh
    post-up ip route add local 0.0.0.0/0 dev dummy0 table sslh
    pre-down ip route del local 0.0.0.0/0 dev dummy0 table sslh
    pre-down ip rule del from 192.168.255.254 table sslh
```
As long, as your system has no other interfaces with private address-space, or is routing such addresses, you can continue with the given example. Otherwise you need to select a conflict free address.
If you are updating a older current configuration, make sure, that you have no longer insecure localnet routing in place:
```
 sysctl  net.ipv4.conf.default.route_localnet  
 sysctl net.ipv4.conf.all.route_localnet
```
should both report "0"! 


### Explanation Of The Routing Rules ###
The two routing rules in the dummy0 interface configuration are the key for this configuration.

The first line is an routing rule entry, routing everything coming from the dummy0 ip source address to a special routing table _**sslh**_. 

The next line generates this table implicitly, by inserting a single rule, routing everything from that ip address to dummy0.

Opposite to other firewall based configurations, we have those rules now tied to the dummy0 device, dedicated to the hidden services.
When this interface comes up, the routing rules are making sure, that no martian packets can leave the system, by some processes using this IP address. When the interface goes down, we delete those rules.
Also the startup script needs lo longer special treatment for the transparent mode.


#### SSLH Default Configuration ####
And finally you need to configute _**/etc/default/sslh**_ with the right settings for all the services, sslh should work for.
```
DAEMON_OPTS="--user sslh --listen SERVER_IP:443 --transparent  \
             --ssh 192.168.255.254:22 --tls 192.168.255.254:443 \
             --pidfile /var/run/sslh/sslh.pid"
```

#### Systemd #### 
This setup is now startup agnostic. As we don't need special treatment in the startup script, the sysV based init scripts will just work, like the systemd scripts. Nothing needs to be modified, when going transparent.

#### Remote Setups ####
This concept can also be adapted for several setups, where the sshd (or any other target service) is running in a container, kvm-virtual machine, etc.
Precondition is, that the target system is the next hop and uses the sslh-hosting system as default gateway. In addition you need to bind an additional ip-address, solely used for sshd on the corresponding interface.
Than you can adapt the routing rule, routing traffic coming back from this ip to the sslh-routing-table.
Its also possible, to forward to an next hop system, which has its own default gateway back, bypassing the sslh-host.
In this case, you need to add a special route back to the sslh host, for all traffic with the sshd source ip address. This can be done similar to the two rules described above:
```
  # first define a name for the table in /etc/iproute2/rt_tables e.g. sslh-routeback
  ip rule add from IPADRESS-OF-SERVIE table sslh-routeback
  ip route add default via IPADDRESS-OF_SSLH-HOST dev eth0 table sslh-routeback
```
The details are depending on your network settings. Als long, as the forward chain to the hidden service passes systems under your control, you can add backroutes on each system in that route. Precondition: The used ip address produces no conflict on those systems.

[I added a second document](./scenarios-for-simple-transparent-proxy.md), describing three possible scenarios in detail. Those three scenarios should cover all setups related to transparent proxying. 
