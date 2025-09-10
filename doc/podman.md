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
   # ⚠️ Important: Never add a `network:` here, otherwise this setup will NOT work.
   # Adding a network disconnects the sslh container from the pod's shared localhost.

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

I omitted Caddy configs here since they're irrelevant, and some unrelated container configs were also dropped for clarity.

In the example above, `sslh`, `caddy`, and `ssh-proxy` are **three containers inside the same Podman pod**, all sharing the same **pod-local `localhost`**.  

`sslh` listens on port **444** instead of **443**, because `caddy` already binds to port `443`, and reconfiguring Caddy is more complex due to its Let's Encrypt integration (Caddy itself "thinks" it’s bound to your host interface).  

#### Port mapping scheme  
All containers **share the same `localhost`** inside the pod:  
```
host 443 → pod 444 (sslh) → pod 443 (caddy)
```


- **Podman** maps the host’s `443` → pod’s `444`.  
- **SSHL** listens on `localhost:444` inside the pod and forwards TLS traffic to `caddy` on `localhost:443`.  
- **Caddy** listens on `localhost:443` and reverse-proxies to other services in the private network.  

This ensures that **reverse-proxied services** receive the correct client IP in the `X-Forwarded-For` header.

---

### Important note  

⚠️ Do **not** set a `network:` parameter for the `sslh` container when it belongs to a Podman pod.  
Setting a custom network **forces Podman to detach the container from the pod’s shared network namespace** and creates a **separate `localhost`** for that container, breaking transparent routing.

For example:  

```yaml
command: --transparent -F/etc/sslh/sslh.cfg # parameter --transparent here is needed to trigger configure_iptables in init script
state: started
# ⚠️ Never add a `network:` here!
# Adding a network disconnects the sslh container from the pod's shared localhost,
# causing transparent routing to fail.
```

### Key takeaways  

- `net.ipv4.conf.default.route_localnet` and iptables rules are applied **inside the `sslh` container only**, not on the host.  
- The `sslh` **init** script manages all required `iptables` and routing rules inside of the container.  
- **Transparent mode restrictions**:
    - Any service `sslh` proxies traffic to **must** be inside the same pod and bound to its **pod-local `localhost`**.
    - Container ports must not conflict within the pod.
    - Ports should be published **at the pod level**, **not per-container**.
    - Containers inside this pod **must not** be attached to any custom networks.
- Because of transparent routing, `sslh` cannot directly proxy SSH to the host IP.  
  A workaround is to run a lightweight **socat** container in the same pod:  
  `TCP-LISTEN:222 → TCP:host.containers.internal:22`
- Caddy’s `reverse_proxy` **to other containers** in the **custom network attached to the pod** still works properly.
- `socat` can also connect to both the **host** and **other containers** inside the custom network without issues.

### Tested setup

- Confirmed working on **Debian Trixie**  
- Using **Podman 5.4.2**  
- Pinned `podman` and related dependencies (`conmon`, `slirp4netns`, `aardvark-dns`, etc.) from **Debian testing**,  
  since **stable** often ships outdated versions that can break this setup.
