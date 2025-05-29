Here is an example of deployment of sslh in transparent mode
using ansible and podman, [submitted by Github user
olegstepura](https://github.com/yrutschle/sslh/issues/448)

```yaml
# ansible podman task
- name: "Create sslh-co pod"
  containers.podman.podman_pod:
    name: sslh-co # read as "sslh and company"
    state: started
    ports:
      - "80:80"
      - "443:444"
      # ... (more ports if needed)
    network:
      - '{{ containers.config.network }}' # other services from this network can access containers in this network for example prometheus can read caddy metrics at sslh-co:2020, also caddy itself can connect to other services to act as a reverse proxy

- name: "Create the sslh container"
  containers.podman.podman_container:
    name: sslh
    image: "yrutschle/sslh:latest"
    pod: sslh-co
    capabilities:
      - NET_RAW
      - NET_BIND_SERVICE
      - NET_ADMIN
    sysctl:
      net.ipv4.conf.default.route_localnet: 1
      net.ipv4.conf.all.route_localnet: 1
    expose:
      - 444
    volume:
      # ... (make sure to mount config as you like)
    command: --transparent -F/etc/sslh/sslh.cfg # parameter --transparent here is needed to trigger configure_iptables in init script
   state: started

- name: "Create the caddy container"
  containers.podman.podman_container:
    name: caddy
    image: "lucaslorentz/caddy-docker-proxy:alpine" # regular caddy or nginx image will also work
    pod: sslh-co
    expose:
      - 80
      - 443
      - 2020 # metrics, since caddy-docker-proxy uses :2019 internally
    volume:
      # ... (mount your configs and other stuff here)
      - "/var/run/podman/podman.sock:/var/run/docker.sock"
    state: started
  notify: podman restart sslh

- name: "Create the SSH proxy to host container"
  containers.podman.podman_container:
    name: ssh-proxy
    image: "alpine/socat:latest"
    pod: sslh-co
    expose:
      - 222
    command: TCP-LISTEN:222,fork TCP:host.containers.internal:22
    state: started
```

```ini
# sslh config
foreground: true;
inetd: false;
numeric: true;
transparent: true;
timeout: 5;

listen:
(
    { host: "0.0.0.0"; port: "444"; keepalive: true; },
);

protocols:
(
  {
    name: "ssh";
    service: "ssh";
    host: "localhost";
    port: "222";
    fork: true;
  },
  {
    name: "http";
    host: "localhost";
    port: "80";
  },
  {
    name: "tls";
    host: "localhost";
    port: "443";
  },
);
```

I omitted caddy configs here as it's not important. Some unrelated container configs were also dropped.
In the example above `sslh`, `caddy` and `ssh-proxy` are 3 containers in the same pod, all listening on `localhost`. SSLH has to listen on `444` because caddy already listens on `443` and it's more complex to reconfigure caddy port because of let's encrypt (caddy itself "thinks" it is bound to your host interface).

Scheme of port mapping is (all containers share same `localhost`):
```
host 443 → pod 444 (sslh) → pod 443 (caddy)
```
- podman connects host `443` port to pod's `444` port
- `sslh` listens `444` on `localhost`, reroutes tls to `caddy` on `localhost:443`
- `caddy` listens `443` on `localhost` (reverse-proxies to other apps on private network)
Reverse-proxied services get correct IP in `X-Forwarded-For` header.

Takeaways:
- `net.ipv4.conf.default.route_localnet` is setup only in container, not on host, which is nice.
- same with iptables and route rules applied by `init` script in sslh container
- `sslh` proxy to other services in the private network will not work (because transparent mode is enabled) even if that other service does not need real IP
	- with transparent mode all services that `sslh` will connect to should be attached to this pod making it listen on `localhost` of the pod
	- ports of containers should not clash
	- ports should be published on pod level, not on containers
	- containers should not be configured to connect to custom networks
- because of the above proxying ssh to host will also not work out of the box, `sslh` should connect to `localhost` and not to a random IP. While adding another proxy as a container to the same pod sounds like an overkill I don't see any other solution, so `socat` is used as an additional proxy.
- `reverse_proxy` by caddy to other containers in the same custom network (as pod is attached to) works (e.g. caddy can connect to other IPs from custom network). `socat` can also connect to host and/or other containers in custom network.

