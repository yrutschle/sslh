# Daisy-Chaining-Transparency #
This documentation goes a level deeper, what happens in the operating system with IP-addresses, and why some combinations of programs are failing, when they use the same transparency method.
There are situations, where you need to combine two applications, both working as ip-transparent proxies, to reach your goal. One example is, having nginx or stunnel as an proxytunnel-endpoint for tls tunneled ssh connections through https-proxies. An example for such a combination will be desribed at the end of this article.<br>
Unfortunately you will see a lot of errors popping out: **Address already in use**<br>
[This article from Cloudflare blog](https://blog.cloudflare.com/how-to-stop-running-out-of-ephemeral-ports-and-start-to-love-long-lived-connections) explains why this is happening, while it is describing the solution to another problem. However this is a close relative to our problem.

Let us look to the following example: We have sslh (S) accepting connections from a client (C) and forwarding one of those connections to a man-in-the-middle (M), which finally forwards this connection to sshd. If everything works perfectly, we would like to see those connections.

![Dataflow-Of-Daisy-Chain](./detailed-ip-transparency.png)

But unfortunately we are receiving in many constellations errors, when M tries to open its connection to our final target sshd, here called T.
Let us look more close, why that is happening. We need for this two terminal windows on the same server.<br>
### First example, uncooperative applications ###
As the problem has nothing to do with transparency itself, but only of reuse of same IP-addresses and ports, we avoid the overhead of the additional capablities, to keep the example easy and clear.
In the first terminal we are starting python3 and entering the following three lines:
```
user@host:~$ python3
Python 3.11.2 (main, May  2 2024, 11:59:08) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
>>> sock.bind(("192.168.255.254", 12345))
>>> 
```

Now we are going to the second terminal window, and trying just the same:
```
Python 3.11.2 (main, May  2 2024, 11:59:08) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
>>> sock.bind(("192.168.255.254", 12345))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
OSError: [Errno 98] Address already in use
sock.bind(("192.168.255.254", 12346))  ##this however works!!
```
Here we are getting the error, which caused many of us hours of research.
The problem is caused by the fact, that the kernel does not know at the moment of the bind()-call, how we want to use the socket. If we use this as a server socket, and will do a listen()-call as next, this will not work, as for server sockets, the two-value tuple ADDRESS:PORT needs to be unique only to the process, tied to this socket.
That is the reason, that there are port ranges, reserved for servers, where the administrator is responsible not to assign the same port to two applications.
But as server ports are coming from a range, which will not be used for client connections, a server can be sure, that if it is started at any time in the future, no outgoing client has used its port for an outbound connection.
Clients are usually using ports from a so called [ephemeral port range](https://en.wikipedia.org/wiki/Ephemeral_port).
However, for clients each connection is valid, as long as one value in the four-tuples describing the connection is different. In our example above, the two values from the destination are different, so this connection could be established (in theory) without conflicts.
To make that happen, you need to deploy a special socket option to this socket, to explain, that we "know the risks" and we will reuse the ip-port combination.
And, as we see from the second bind() in the second example, the error message: _**Address already in use**_ really means: _**Address:Port already in use**_

### Taking Care, part I ###

Ok, now we are entering our two terminals again, pressing Ctrl-D to finish python, and start a new session like this in both terminals:
```
user@host:~$ python3
Python 3.11.2 (main, May  2 2024, 11:59:08) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>> sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
>>> sock.bind(("192.168.255.254", 12345))
>>> 
``` 
And we will see, that the problem is solved, when both applications are taking care.

### Taking Care, part II ###

Ok, now we are going back to our terminals, pressing again Ctrl-D to finish python, and start new sessions like this:
In the first terminal we repeat the input from our first example, without the setsockopt() call:
```
user@host:~$ python3
Python 3.11.2 (main, May  2 2024, 11:59:08) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
>>> sock.bind(("192.168.255.254", 12345))
>>> 
```
in the second terminal, we enter our modified cooperative example:

```
user@host:~$ python3
Python 3.11.2 (main, May  2 2024, 11:59:08) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>> sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
>>> sock.bind(("192.168.255.254", 12345))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
OSError: [Errno 98] Address already in use
>>> 
``` 
Oops, here is our error again. And this is the reason, why I called this method "cooperative". As the first application has bound to that IP:PORT combination, without telling, that "it knows the risk", the kernel denies us, to use this combinations, as we may break the already active application. The first application is not "cooperative" :-(<br>
 Ok, but the kernel gives as some more possibilities: As we now get connections from a uncoperative application, we can no longer use the Client-IP-Port combination. We need to use a conflict free port for the client IP, to succeed. So lets get back to terminal 2 and continue after the error with the following commands:
```
user@host:~$ python3
Python 3.11.2 (main, May  2 2024, 11:59:08) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>> sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  
>>> sock.bind(("192.168.255.254", 12345))
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
OSError: [Errno 98] Address already in use
>>> sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
>>> sock.setsockopt(socket.SOL_IP, socket.IP_BIND_ADDRESS_NO_PORT, 1)
>>> sock.bind(("192.168.255.254", 0))
>>>
```
This last example makes it neccessary, that you use a recent version of the python3 socket library, as older versions, have the option _IP_BIND_ADDRESS_NO_PORT_ not yet defined.
With his behaviour, we are telling the kernel, that the kernel should assign us a conflict free port address at latest possible moment, while calling connect().
From `man ip`:
```
Inform the kernel to not reserve an ephemeral port when using bind(2)
with a port number of 0. The port will later be automatically chosen
at connect(2) time, in a way that allows sharing a source port as 
long as the 4-tuple is unique.
```

Ok, now with those two actions an application is really ready for cooperative working in ip-transparent chains.
If you are running in problems, with any kind of application, where you are redirecting transparent traffic to from sslh, check the following:
- Are you using a recent version of sslh, having the described feature enabled
- are you using the most recent version of the other application
If you can confirm both checks, tell the maintainers of the other application, about possible fixes, and send them a link to this article.

## Practical Use Of Daisy-Chaining: Proxytunnel Endpoint ##

One reasons, why we want to combine two programs is related to the core functionality of sslh. You wish to hide your ssh connection behind a https port.
But now you would like, to reach this port via the [proxy-tunnel application](https://github.com/proxytunnel/proxytunnel), though an restrictive http(s) proxy. This is in many cases, one of the few methods, to escape from restricted private networks, like in companies, schools and universities. Unfortunately, many of those proxy-servers will check, that the protocol leaving the proxy is really tls. Therefore you need and endpoint in your system, which will terminate the tls-connection and forward the encapsulated ssh stream to the sshd.  Sslh can't do tls termination, as this is not a core job of tls. One of the solutions tried here is stunnel. Stunnel can do transparency like sslh, but unfortunately belongs to the uncooperative ip-transparent programs. At the time of writing this article, you can use stunnel as the first-in-chain, and a very recent sslh as second in chain. But nginx (or openresty) is capable of this, however it prefers (at least in the tested versions), mostly the second way just selecting a new random port and not (always) preserving the original source port, what makes debugging of events much easier.


```
stream {
  ssl_preread on;

  map $ssl_preread_server_name $name {
    default            master.yourdomain.top;
    t1.yourdomain.top  t1.yourdomain.top;
    t2.yourdomain.top  t2.yourdomain.top;
    cryptic.foo.bar    location.selfsigned.cert;
  }

## $destination port :443 is assumed, beeing as real
## webserver. Either anothe nginx http-server or apache 
## or anything other ...
  map $ssl_preread_server_name $dest {
    default              192.168.255.254:443;
    t1.yourdomain.top    192.168.255.254:443;
    t2.yourdomain.top    192.168.255.254:444;
    cryptic.foo.notexist 192.168.255.254:445;
  }


## this is the server, to handle incoming tcp streams
## and dispatching them transparent to $dest
## 192.168.255.254:1443 is the address, where
## the front facing sslh sends traffic to
  server {
    listen 192.168.255.254:1443;
    proxy_connect_timeout 5s;
    proxy_timeout 3m;
    proxy_bind $remote_addr transparent;
    proxy_pass $dest;
    ssl_preread on;
  }

  ## this is a basic endpoint for proxy-tunnel connections
  server {
    listen 192.168.255.254:444 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256";
    ## give facl to the nginx user, see later in article
    ssl_certificate /etc/letsencrypt/live/$name/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$name/privkey.pem;
    ssl_dhparam  /etc/nginx/dhparam-nginx.pem;
    ssl_session_cache shared:MySSL:10m;
    ssl_session_tickets off;
    proxy_connect_timeout 5s;
    proxy_timeout 3m;
    proxy_bind $remote_addr transparent;
    proxy_pass 192.168.255.254:22 ;
  }


## this is a fancy destination, using some tricks, to fool
## some proxies.
  server {
    listen 192.168.255.254:445 ssl;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256";
    ## this points to a directory, containg a self signed certificate
    ## created with CN and SAN to an not officially existing
    ## domain, e.g. cryptic.foo.notexists
    ssl_certificate /etc/nginx/$name/fullchain.pem;
    ssl_certificate_key /etc/nginx/$name/privkey.pem;
    ssl_dhparam  /etc/nginx/dhparam-nginx.pem;
    ssl_session_cache shared:MySSL:10m;
    ssl_session_tickets off;
    ## additional trick: requiring client certificate authentication
    ssl_client_certificate /etc/nginx/public.cert ;
    ssl_verify_client on ;
    proxy_connect_timeout 5s;
    proxy_timeout 3m;
    proxy_bind $remote_addr transparent;
    proxy_pass 192.168.255.254:22;
  }
}
```

This nginx stream server shows a combination of different possibilities, how to establish an endpoint for proxytunnel or similar programs, to hide your ssh connection. Remember: Hiding ssh tunneled in tls does not neccessarly raise the security of your connection. In theory a combination of two methods may also lower the security. In addition there are more drawbacks: Such a connection needs more cpu on both ends for doing double crypto, and the throughput through he connection drops, as the ratio payload/header increases. the single ssh-packets are smaller, than usual.
So it is not recommended for doing scp or sftp through such connections.

### Nginx Configration Explained ###

However, there are situations, where this is the only way, to reach your server.
So we have now this nginx instance helping us out.
The server stanza listening on _192.168.255.254:1443_ is the main process, accepting incoming connections forwarded from sslh. It prereads tls SNI names, to get destination information. When in the nginx-configuration a variable is used, which is set by an map action, the mapping takes place just in that moment, when the variable needs to be expanded.
So we have either default values, in case there is no SNI, or values for individual SNI.

The connection stream is than forwarded ip-transparent to a given destination, which is itself another nginx instance, defined in the configuration file.

#### The Standard TLS-Termination ####

The server stanza listening on _192.168.255.254:444_ is a very basic TLS terminating endpoint. In most cases, a proxy is happy with a destination like this. Here nginx just terminates the TLS connection and shovels the incoming packets over to sshd in ip-transparent way. The proxytunnel configuration for this target will look like:
```
host t2.yourdomain.top 
  ProxyCommand /path/to/proxytunnel -e -p PROXY-IP:3128 -d t2.yourdomain.top:443
  ServerAliveInterval 30
```
If you have no proxytunnel on your system, you can also use openssl. In this case the configuration looks like:
```
host t2-alias
  ProxyCommand openssl s_client -proxy PROXY-IP:3128  -connect t2.yourdomain.top:443 
  ServerAliveInterval 30
```
`ssh ts-alias` will use this configuration.

One point from the above configuration needs further explanation, as we just refer to our common letsencrypt store, for certificates.

##### Excurse To File ACLs #####

We are using here our common letsencrypt certificate store, as copying certificates after renewal is a pain in the as and prone to errors.
A small script makes sure, that all applications can read the certificates:
```
for i in  Debian-exim dovecot mail www-data nginx ; do
  setfacl -Rdm u:$i:rX ./archive/
  setfacl -Rdm u:$i:rX ./live/
  setfacl -Rm u:$i:rX ./archive/
  setfacl -Rm u:$i:rX ./live/
  for file in $( find ./live ./archive -type l,f ) ; do
    echo -e "$i $file set"
    setfacl -m u:$i:r $file
  done
done
```
This script needs only to be run, when a new application user needs access.
The first two lines are making sure (watch the **d**), that the given options
on those directories will be the default for newly created files below.
The uppercase **X** means, that **x**-access will only be granted to directories or files, having already **x** set for others.

#### The Tricky TLS Termination ####

The server stanza listening on _192.168.255.254:445_ is a more tricky TLS terminating endpoint. Some proxies are trying to inspect the destination, before letting you go. Some of them you can fool, others not.
One trick can be to use an phantasy domain name with a self signed certificate, no dns server will ever resolve. As you are using this name as SNI name in your proxy-tunnel connection, it will work.  This can be also a way, to hide your sshd, if someone, who knows you are using sslh tries to find your sshd. As long, as this person does not get access to proxies you are using, this may help in some situations.
Another trick is, requiring a client certificate for authentication. This is in each case the much better approach, as you can combine this also with official connected domain names. Without the client certificate no sshd!
The client certificate does not increase the above mentioned ratio between payload and headers, as this is only used while establishing the TLS connection.
It prevents however a proxy, doing a parallel sneak to your destination, to figure out what is behind. I have seen proxies letting you connect with this method, others are denying access.

To access this endpoint, the proxytunnel configuration inside `~/.ssh/config`
will look like:
```
host cryptic.foo.notexists
  ProxyCommand /path/to/proxytunnel -e -c ~/public.cert -k ~/private.pem -C ~/myOwnCA.cert -p PROXY-IP:3128 -o cryptic.foo.notexists  -d t1.yourdomain.top:443
  ServerAliveInterval 30
```
-C gives the certfile to your certificate used for selfsigning the server certificate. You can also set -z for not verifying the certificate, but that is not recommended! `t1.yourdomain.top` represents a valid domain name, where the listening sslh can be reached. This name is not taken for SNI, because **-o** sets our hidden SNI name. Whenever you enter `ssh cryptic.foo.notexists` you will get connected to your server!

The best reommendation however is: Avoid self signed certs, if you are not really sure, what you are doing.

