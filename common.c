/* Code and variables that is common to both fork and select-based
 * servers.
 *
 * No code here should assume whether sockets are blocking or not.
 **/

#define _GNU_SOURCE
#include <stddef.h>
#include <stdarg.h>
#include <grp.h>

#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/un.h>

#include "common.h"
#include "probe.h"
#include "log.h"
#include "sslh-conf.h"

/* Added to make the code compilable under CYGWIN
 * */
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0
#endif

/* Make use of systemd socket activation
 * */
#ifdef SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef LIBBSD
#include <bsd/unistd.h>
#endif

/*
 * Settings that depend on the command line or the config file
 */
struct sslhcfg_item cfg;

struct addrinfo *addr_listen = NULL; /* what addresses do we listen to? */


#ifdef LIBWRAP
#include <tcpd.h>
int allow_severity =0, deny_severity = 0;
#endif

typedef enum {
    CR_DIE,
    CR_WARN
} CR_ACTION;

/* check result and die, printing the offending address and error */
void check_res_dump(CR_ACTION act, int res, struct addrinfo *addr, char* syscall)
{
    char buf[NI_MAXHOST];

    if (res == -1) {
        print_message(msg_system_error, "%s:%s: %s\n",
                sprintaddr(buf, sizeof(buf), addr),
                syscall,
                strerror(errno));

        if (act == CR_DIE)
            exit(1);
    }
}

int get_fd_sockets(struct listen_endpoint *sockfd[])
{
    int sd = 0;

#ifdef SYSTEMD
    sd = sd_listen_fds(0);
    if (sd < 0) {
      print_message(msg_system_error, "sd_listen_fds(): %s\n", strerror(-sd));
      exit(1);
    }
    if (sd > 0) {
      int i;
      *sockfd = malloc(sd * sizeof(*sockfd[0]));
      CHECK_ALLOC(*sockfd, "malloc");
      for (i = 0; i < sd; i++) {
        (*sockfd)[i].socketfd = SD_LISTEN_FDS_START + i;
        (*sockfd)[i].type = SOCK_STREAM;
      }
    }
#endif

    return sd;
}

/* Set TCP_FASTOPEN on listening socket if all client protocols support it */
int make_listen_tfo(int s)
{
    int i, qlen = 5;

    /* Don't do it if not supported */
    if (!TCP_FASTOPEN)
        return 0;

    /* Don't do it if any protocol does not specify it */
    for (i = 0; i < cfg.protocols_len; i++) {
        if (! cfg.protocols[i].tfo_ok)
            return 0;
    }

    return setsockopt(s, SOL_SOCKET, TCP_FASTOPEN, (char*)&qlen, sizeof(qlen));
}

/* Starts listening on a single address
 * Returns a socket filehandle, or dies with message in case of major error */
int listen_single_addr(struct addrinfo* addr, int keepalive, int udp)
{
    struct sockaddr_storage *saddr;
    int sockfd, one, res;

    saddr = (struct sockaddr_storage*)addr->ai_addr;

    sockfd = socket(saddr->ss_family, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    check_res_dump(CR_DIE, sockfd, addr, "socket");

    one = 1;
    res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    check_res_dump(CR_DIE, res, addr, "setsockopt(SO_REUSEADDR)");

    res = make_listen_tfo(sockfd);
    check_res_dump(CR_WARN, res, addr, "setsockopt(TCP_FASTOPEN)");

    if (keepalive) {
        res = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (char*)&one, sizeof(one));
        check_res_dump(CR_DIE, res, addr, "setsockopt(SO_KEEPALIVE)");
    }

    if (IP_FREEBIND) {
        res = setsockopt(sockfd, IPPROTO_IP, IP_FREEBIND, (char*)&one, sizeof(one));
        check_res_dump(CR_WARN, res, addr, "setsockopt(IP_FREEBIND)");
    }

    if (addr->ai_addr->sa_family == AF_INET6) {
        res = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&one, sizeof(one));
        check_res_dump(CR_WARN, res, addr, "setsockopt(IPV6_V6ONLY)");
    }

    res = bind(sockfd, addr->ai_addr, addr->ai_addrlen);
    check_res_dump(CR_DIE, res, addr, "bind");

    if (!udp) {
        res = listen (sockfd, 50);
        check_res_dump(CR_DIE, res, addr, "listen");
    }

    return sockfd;
}


/* Start listening internet sockets for configuration entry 'index' 
 * OUT: *sockfd[]: pointer to array of listen_endpoint object; we append new
 * endpoints to that array
 * IN: num_addr: how many entries are in sockfd[]
 *     *cfg: configuration data for the endpoint we are adding
 * Return: new value of num_addr
 * */
static int start_listen_inet(struct listen_endpoint *sockfd[], int num_addr, struct sslhcfg_listen_item* cfg)
{
    struct addrinfo *addr, *start_addr;
    char buf[NI_MAXHOST];
    int res;

    res = resolve_split_name(&start_addr, cfg->host, cfg->port);
    if (res) exit(4);

    for (addr = start_addr; addr; addr = addr->ai_next) {
        num_addr++;
        *sockfd = realloc(*sockfd, num_addr * sizeof(*sockfd[0]));
        (*sockfd)[num_addr-1].socketfd = listen_single_addr(addr, cfg->keepalive, cfg->is_udp);
        (*sockfd)[num_addr-1].type = cfg->is_udp ? SOCK_DGRAM : SOCK_STREAM;
        (*sockfd)[num_addr-1].family = AF_INET;
        print_message(msg_config, "%d:\t%s\t[%s] [%s]\n", (*sockfd)[num_addr-1].socketfd, sprintaddr(buf, sizeof(buf), addr),
                      cfg->keepalive ? "keepalive" : "",
                      cfg->is_udp ? "udp" : "");
    }
    freeaddrinfo(start_addr);
    return num_addr;
}

/* Same, but for UNIX sockets */
static int start_listen_unix(struct listen_endpoint *sockfd[], int num_addr, struct sslhcfg_listen_item* cfg)
{
    int fd = socket(AF_UNIX, cfg->is_udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    CHECK_RES_DIE(fd, "socket(AF_UNIX)");

    int res = unlink(cfg->host);
    if ((res == -1) && (errno != ENOENT)) {
        print_message(msg_config_error, "unlink unix socket `%s':%d:%s\n", cfg->host, errno, strerror(errno));
        exit(4);
    }

    struct sockaddr_un sun;
    sun.sun_family = AF_UNIX;
    strncpy(sun.sun_path, cfg->host, sizeof(sun.sun_path)-1);
    printf("binding [%s]\n", sun.sun_path);
    res = bind(fd, (struct sockaddr*)&sun, sizeof(sun));
    CHECK_RES_DIE(res, "bind(AF_UNIX)");

    res = listen(fd, 50);

    num_addr++;
    *sockfd = realloc(*sockfd, num_addr * sizeof(*sockfd[0]));
    (*sockfd)[num_addr-1].socketfd = fd;
    (*sockfd)[num_addr-1].type = cfg->is_udp ? SOCK_DGRAM : SOCK_STREAM;
    (*sockfd)[num_addr-1].family = AF_INET;

    return num_addr;
}


/* Starts listening sockets on specified addresses.
 * OUT: *sockfd[]  pointer to newly-allocated array of listen_endpoint objects
 * Returns number of addresses bound
   */
int start_listen_sockets(struct listen_endpoint *sockfd[])
{
    int i;
    int num_addr = 0, sd_socks = 0;

    sd_socks = get_fd_sockets(sockfd);

    if (sd_socks > 0) {
        return sd_socks;
    }

    *sockfd = NULL;

    print_message(msg_config, "Listening to:\n");

    for (i = 0; i < cfg.listen_len; i++) {
        if (cfg.listen[i].is_unix) {
            num_addr = start_listen_unix(sockfd, num_addr, &cfg.listen[i]);
        } else {
            num_addr = start_listen_inet(sockfd, num_addr, &cfg.listen[i]);
        }
    }

    return num_addr;
}


/* returns 1 if given address is on the local machine: iterate through all
 * network interfaces and check their addresses */
int is_same_machine(struct addrinfo* from)
{
    struct ifaddrs *ifaddrs_p = NULL, *ifa;
    int match = 0;

    getifaddrs(&ifaddrs_p);

    for (ifa = ifaddrs_p; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr)
            continue;
        if (from->ai_addr->sa_family == ifa->ifa_addr->sa_family)
        {
            int family = ifa->ifa_addr->sa_family;
            if (family == AF_INET)
            {
                struct sockaddr_in *from_addr = (struct sockaddr_in*)from->ai_addr;
                struct sockaddr_in *ifa_addr = (struct sockaddr_in*)ifa->ifa_addr;
                if (from_addr->sin_addr.s_addr == ifa_addr->sin_addr.s_addr) {
                    match = 1;
                    break;
                }
            }
            else if (family == AF_INET6)
            {
                struct sockaddr_in6 *from_addr = (struct sockaddr_in6*)from->ai_addr;
                struct sockaddr_in6 *ifa_addr = (struct sockaddr_in6*)ifa->ifa_addr;
                if (!memcmp(from_addr->sin6_addr.s6_addr, ifa_addr->sin6_addr.s6_addr, 16)) {
                    match = 1;
                    break;
                }
            }
        }
    }
    freeifaddrs(ifaddrs_p);
    return match;
}


/* Transparent proxying: bind the peer address of fd to the peer address of
 * fd_from */
#ifndef IP_TRANSPARENT
  #define IP_TRANSPARENT 19
#endif
#ifndef IP_BIND_ADDRESS_NO_PORT
  #define IP_BIND_ADDRESS_NO_PORT 24
#endif
int bind_peer(int fd, int fd_from)
{
    struct addrinfo from;
    struct sockaddr_storage ss;
    int res, enable = 1, disable = 0;

    memset(&from, 0, sizeof(from));
    from.ai_addr = (struct sockaddr*)&ss;
    from.ai_addrlen = sizeof(ss);

    /* getpeername can fail with ENOTCONN if connection was dropped before we
     * got here */
    res = getpeername(fd_from, from.ai_addr, &from.ai_addrlen);
    CHECK_RES_RETURN(res, "getpeername", res);

    /* if the destination is the same machine, there's no need to do bind */
    if (is_same_machine(&from))
        return 0;

#ifndef IP_BINDANY /* use IP_TRANSPARENT */
    res = setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &enable, sizeof(enable));
    CHECK_RES_DIE(res, "setsockopt IP_TRANSPARENT");
    res = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    CHECK_RES_DIE(res, "setsockopt SO_REUSEADDR");
#else
    if (from.ai_addr->sa_family==AF_INET) { /* IPv4 */
        res = setsockopt(fd, IPPROTO_IP, IP_BINDANY, &enable, sizeof(enable));
        CHECK_RES_RETURN(res, "setsockopt IP_BINDANY", res);
#ifdef IPV6_BINDANY
    } else { /* IPv6 */
        res = setsockopt(fd, IPPROTO_IPV6, IPV6_BINDANY, &enable, sizeof(enable));
        CHECK_RES_RETURN(res, "setsockopt IPV6_BINDANY", res);
#endif /* IPV6_BINDANY */
    }
#endif /* IP_TRANSPARENT / IP_BINDANY */
    res = bind(fd, from.ai_addr, from.ai_addrlen);
    if (res == -1) {
        if (errno != EADDRINUSE) {
            print_message(msg_system_error, "%s:%d:%s:%d:%s\n", __FILE__, __LINE__,
                        "bind", errno, strerror(errno));
            return res;
        }
        res = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &disable, sizeof(disable));
        CHECK_RES_DIE(res, "setsockopt SO_REUSEADDR");
        res = setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &enable, sizeof(enable));
        CHECK_RES_RETURN(res, "setsockopt IP_BIND_ADDRESS_NO_PORT", res);
        ((struct sockaddr_in *)from.ai_addr)->sin_port = 0;
        res = bind(fd, from.ai_addr, from.ai_addrlen);
        CHECK_RES_RETURN(res, "bind", res);
        /*
	 * There was a serious problem, when daisy-chaining programs using the same
	 * ip transparent mechanism, as sslh uses. stunnel was mentioned in a previous 
	 * comment. This problem should now be solved through the two methods, getting
	 * a connection established:
	 * In the first try, SO_REUSEADDR is set to socket, which will allow the same
	 * IP-address:port tuple, as it is used by another application. The check for
	 * inconsistency with other connections (same 4-value-tupel) is done at the 
	 * moment, when the connection gets established.
	 * If that fails, SO_REUSEADDR gets removed and IP_BIND_ADDRESS_NO_PORT get set.
	 * This will search for a free port, which will not collide with current 
	 * connections. Read more in this excellent blog-post: 
	 * https://blog.cloudflare.com/how-to-stop-running-out-of-ephemeral-ports-and-start-to-love-long-lived-connections
	 * The problem will still appear, if the another application in the daisy-chain
	 * does not use similar mechanisms. In that case you must either pull this 
	 * application at the beginning of the chain, or get it fixed.
         */
    }

    return 0;
}

/* Make the file descriptor non-block  */
int set_nonblock(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    CHECK_RES_RETURN(flags, "fcntl", -1);

    flags |= O_NONBLOCK;

    flags = fcntl(fd, F_SETFL, flags);
    CHECK_RES_RETURN(flags, "fcntl", -1);

    return flags;
}


/* Connects to INET/INET6 domain sockets and return a fd */
static int connect_inet(struct connection *cnx, int fd_from, connect_blocking blocking)
{
    struct addrinfo *a, from;
    struct sockaddr_storage ss;
    char buf[NI_MAXHOST];
    int fd, res, one;
    int transparent = cnx->proto->transparent || cfg.transparent;

    memset(&from, 0, sizeof(from));
    from.ai_addr = (struct sockaddr*)&ss;
    from.ai_addrlen = sizeof(ss);

    res = getpeername(fd_from, from.ai_addr, &from.ai_addrlen);
    CHECK_RES_RETURN(res, "getpeername", res);

    if (cnx->proto->resolve_on_forward) {
        resolve_split_name(&(cnx->proto->saddr), cnx->proto->host,
                           cnx->proto->port);
    }
    for (a = cnx->proto->saddr; a; a = a->ai_next) {
        /* When transparent, make sure both connections use the same address family */
        if (transparent && a->ai_family != from.ai_addr->sa_family)
            continue;
        print_message(msg_connections_try, "trying to connect to %s family %d len %d\n",
                    sprintaddr(buf, sizeof(buf), a),
                    a->ai_addr->sa_family, a->ai_addrlen);

        /* XXX Needs to match ai_family from fd_from when being transparent! */
        fd = socket(a->ai_family, SOCK_STREAM, 0);
        if (fd == -1) {
            print_message(msg_connections_error, "forward to %s failed:socket: %s\n",
                        cnx->proto->name, strerror(errno));
        } else {
            one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &one, sizeof(one));
            /* no need to check return value; if it's not supported, that's okay */

            if (blocking == NON_BLOCKING) {
                set_nonblock(fd);
            }

            if (transparent) {
                res = bind_peer(fd, fd_from);
                if (res == -1) close(fd);
                CHECK_RES_RETURN(res, "bind_peer", res);
            }
            res = connect(fd, a->ai_addr, a->ai_addrlen);

            /* EINPROGRESS indicates it might take time. If it eventually
             * fails, it'll be caught as a failed read */
            if ((res == -1) && (errno != EINPROGRESS)) {
                print_message(msg_connections_error, "forward to %s failed:connect: %s\n",
                                     cnx->proto->name, strerror(errno));
                close(fd);
                continue; /* Try the next address */
            }
            if (cnx->proto->keepalive) {
                res = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&one, sizeof(one));
                CHECK_RES_RETURN(res, "setsockopt(SO_KEEPALIVE)", res);
            }
            return fd;
        }
    }
    return -1;
}

/* Connects to AF_UNIX domain sockets */
static int connect_unix(struct connection *cnx, int fd_from, connect_blocking blocking)
{
    struct sockaddr_storage ss;
    struct sockaddr_un* sun = (struct sockaddr_un*)&ss;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    sun->sun_family = AF_UNIX;
    strncpy(sun->sun_path, cnx->proto->host, sizeof(sun->sun_path)-1);

    int res = connect(fd, (struct sockaddr*)sun, sizeof(*sun));
    CHECK_RES_RETURN(res, "connect", res);

    if (blocking == NON_BLOCKING) {
        set_nonblock(fd);
    }
    return fd;
}

/* Connect to first address that works and returns a file descriptor, or -1 if
 * none work.
 * If transparent proxying is on, use fd_from peer address on external address
 * of new file descriptor. */
int connect_addr(struct connection *cnx, int fd_from, connect_blocking blocking)
{
    int fd;

    if (cnx->proto->is_unix) {
        fd = connect_unix(cnx, fd_from, blocking);
    } else {
        fd = connect_inet(cnx, fd_from, blocking);
    }

    return fd;
}

/* Store some data to write to the queue later */
int defer_write(struct queue *q, void* data, ssize_t data_size)
{
    char *p;
    ptrdiff_t data_offset = q->deferred_data - q->begin_deferred_data;

    print_message(msg_fd, "writing deferred on fd %d\n", q->fd);
    p = realloc(q->begin_deferred_data, data_offset + q->deferred_data_size + data_size);
    CHECK_ALLOC(p, "realloc");

    q->begin_deferred_data = p;
    q->deferred_data = p + data_offset;
    p += data_offset + q->deferred_data_size;
    q->deferred_data_size += (int)data_size;
    memcpy(p, data, data_size);

    return 0;
}

/* tries to flush some of the data for specified queue
 * Upon success, the number of bytes written is returned.
 * Upon failure, -1 returned (e.g. connexion closed)
 * */
int flush_deferred(struct queue *q)
{
    ssize_t n;

    print_message(msg_fd, "flushing deferred data to fd %d\n", q->fd);

    n = write(q->fd, q->deferred_data, q->deferred_data_size);
    if (n == -1)
        return (int)n;

    if (n == q->deferred_data_size) {
        /* All has been written -- release the memory */
        free(q->begin_deferred_data);
        q->begin_deferred_data = NULL;
        q->deferred_data = NULL;
        q->deferred_data_size = 0;
    } else {
        /* There is data left */
        q->deferred_data += n;
        q->deferred_data_size -= (int)n;
    }

    return (int)n;
}


void init_cnx(struct connection *cnx)
{
    memset(cnx, 0, sizeof(*cnx));
    cnx->q[0].fd = -1;
    cnx->q[1].fd = -1;
    cnx->proto = NULL;
}

void dump_connection(struct connection *cnx)
{
    print_message(msg_int_error, "type: %s\n", cnx->type == SOCK_DGRAM ? "UDP" : "TCP");
    print_message(msg_int_error, "state: %d\n", cnx->state);
    print_message(msg_int_error, "0: fd %d, %d deferred\n", cnx->q[0].fd, cnx->q[0].deferred_data_size);
    hexdump(msg_int_error, cnx->q[0].deferred_data, cnx->q[0].deferred_data_size);
    print_message(msg_int_error, "1: fd %d, %d deferred\n", cnx->q[1].fd, cnx->q[1].deferred_data_size);
    hexdump(msg_int_error, cnx->q[1].deferred_data, cnx->q[1].deferred_data_size);
}


/*
 * moves data from one fd to other
 *
 * returns number of bytes copied if success
 * returns 0 (FD_CNXCLOSED) if incoming socket closed
 * returns FD_NODATA if no data was available
 * returns FD_STALLED if data was read, could not be written, and has been
 * stored in temporary buffer.
 */
int fd2fd(struct queue *target_q, struct queue *from_q)
{
   char buffer[BUFSIZ];
   int target, from;
   ssize_t size_r, size_w;

   target = target_q->fd;
   from = from_q->fd;

   size_r = read(from, buffer, sizeof(buffer));
   if (size_r == -1) {
       switch (errno) {
       case EAGAIN:
           return FD_NODATA;

       case ECONNRESET:
       case ENOTSOCK:
       case EPIPE:
           return FD_CNXCLOSED;
       }
   }

   CHECK_RES_RETURN(size_r, "read",FD_CNXCLOSED);

   if (size_r == 0)
      return FD_CNXCLOSED;

   size_w = write(target, buffer, size_r);
   /* process -1 when we know how to deal with it */
   if (size_w == -1) {
       switch (errno) {
       case EAGAIN:
           /* write blocked: Defer data */
           defer_write(target_q, buffer, size_r);
           return FD_STALLED;

       case ECONNRESET:
       case EPIPE:
           /* remote end closed -- drop the connection */
           return FD_CNXCLOSED;
       }
   } else if (size_w < size_r) {
       /* incomplete write -- defer the rest of the data */
       defer_write(target_q, buffer + size_w, size_r - size_w);
       return FD_STALLED;
   }

   CHECK_RES_RETURN(size_w, "write", FD_CNXCLOSED);

   return (int)size_w;
}

/* returns a string that prints the IP and port of the sockaddr */
char* sprintaddr(char* buf, size_t size, struct addrinfo *a)
{
   char host[NI_MAXHOST], serv[NI_MAXSERV];
   int res;

   memset(host, 0, sizeof(host));
   memset(serv, 0, sizeof(serv));

   res = getnameinfo(a->ai_addr, a->ai_addrlen,
               host, sizeof(host),
               serv, sizeof(serv),
               cfg.numeric ? NI_NUMERICHOST | NI_NUMERICSERV : 0 );

   if (res) {
       print_message(msg_system_error, "sprintaddr:getnameinfo: %s\n", gai_strerror(res));
       /* Name resolution failed: do it numerically instead */
       res = getnameinfo(a->ai_addr, a->ai_addrlen,
                         host, sizeof(host),
                         serv, sizeof(serv),
                         NI_NUMERICHOST | NI_NUMERICSERV);
       /* should not fail but... */
       if (res) {
           print_message(msg_system_error, "sprintaddr:getnameinfo(NUM): %s\n", gai_strerror(res));
           strcpy(host, "?");
           strcpy(serv, "?");
       }
   }

   snprintf(buf, size, "%s:%s", host, serv);

   return buf;
}

/* Turns a hostname and port (or service) into a list of struct addrinfo
 * On success, returns 0 
 * On failure, returns -1 or one of getaddrinfo() codes
 */
int resolve_split_name(struct addrinfo **out, char* host, char* serv)
{
   struct addrinfo hint;
   char *end;
   int res;

   memset(&hint, 0, sizeof(hint));
   hint.ai_family = PF_UNSPEC;
   hint.ai_socktype = SOCK_STREAM;

   /* If it is a RFC-Compliant IPv6 address ("[1234::12]:443"), remove brackets
    * around IP address */
   if (host[0] == '[') {
       end = strrchr(host, ']');
       if (!end) {
           print_message(msg_config_error, "%s: no closing bracket in IPv6 address?\n", host);
           return -1;
       }
       host++; /* skip first bracket */
       *end = 0; /* remove last bracket */
   }

   res = getaddrinfo(host, serv, &hint, out);
   if (res)
      print_message(msg_system_error, "resolve_split_name: %s `%s:%s'\n", gai_strerror(res), host, serv);
   return res;
}

/* turns a "hostname:port" string into a list of struct addrinfo;
out: list of newly allocated addrinfo (see getaddrinfo(3)); freeaddrinfo(3) when done
fullname: input string -- it gets clobbered
*/
void resolve_name(struct addrinfo **out, char* fullname)
{
   char *serv, *host;
   int res;

   /* Find port */
   char *sep = strrchr(fullname, ':');
   if (!sep) { /* No separator: parameter is just a port */
      print_message(msg_config_error, "%s: names must be fully specified as hostname:port\n", fullname);
      exit(1);
   }
   serv = sep+1;
   *sep = 0;

   host = fullname;

   res = resolve_split_name(out, host, serv);
   if (res) {
      print_message(msg_config_error, "%s `%s'\n", gai_strerror(res), fullname);
      if (res == EAI_SERVICE)
         print_message(msg_config_error, "(Check you have specified all ports)\n");
      exit(4);
   }
}


/* Fills a connection description; returns 0 on failure */
int get_connection_desc(struct connection_desc* desc, const struct connection *cnx)
{
    int res;
    struct addrinfo addr;
    struct sockaddr_storage ss;

    addr.ai_addr = (struct sockaddr*)&ss;
    addr.ai_addrlen = sizeof(ss);

    res = getpeername(cnx->q[0].fd, addr.ai_addr, &addr.ai_addrlen);
    if (res == -1) return 0; /* Can happen if connection drops before we get here.
                               In that case, don't log anything (there is no connection) */
    sprintaddr(desc->peer, sizeof(desc->peer), &addr);

    addr.ai_addrlen = sizeof(ss);
    res = getsockname(cnx->q[0].fd, addr.ai_addr, &addr.ai_addrlen);
    if (res == -1) return 0;
    sprintaddr(desc->service, sizeof(desc->service), &addr);

    addr.ai_addrlen = sizeof(ss);
    res = getpeername(cnx->q[1].fd, addr.ai_addr, &addr.ai_addrlen);
    if (res == -1) return 0;
    sprintaddr(desc->target, sizeof(desc->target), &addr);

    addr.ai_addrlen = sizeof(ss);
    res = getsockname(cnx->q[1].fd, addr.ai_addr, &addr.ai_addrlen);
    if (res == -1) return 0;
    sprintaddr(desc->local, sizeof(desc->local), &addr);

    return 1;
}


void set_proctitle_shovel(struct connection_desc* desc, const struct connection *cnx)
{
#ifdef LIBBSD
    struct connection_desc d;

    if (!desc) {
        desc = &d;
        get_connection_desc(desc, cnx);
    }
    setproctitle("shovel %s %s->%s => %s->%s",
        cnx->proto->name,
        desc->peer,
        desc->service,
        desc->local,
        desc->target);
#endif
}


/* libwrap (tcpd): check the connection is legal. This is necessary because
 * the actual server will only see a connection coming from localhost and can't
 * apply the rules itself.
 *
 * Returns -1 if access is denied, 0 otherwise
 */
int check_access_rights(int in_socket, const char* service)
{
#ifdef LIBWRAP
    union {
        struct sockaddr saddr;
        struct sockaddr_storage ss;
    } peer;
    socklen_t size = sizeof(peer);
    char addr_str[NI_MAXHOST], host[NI_MAXHOST];
    int res;

    res = getpeername(in_socket, &peer.saddr, &size);
    CHECK_RES_RETURN(res, "getpeername", res);

    /* extract peer address */
    res = getnameinfo(&peer.saddr, size, addr_str, sizeof(addr_str), NULL, 0, NI_NUMERICHOST);
    if (res) {
        print_message(msg_system_error, "getnameinfo(NI_NUMERICHOST):%s\n", gai_strerror(res));
        strcpy(addr_str, STRING_UNKNOWN);
    }
    /* extract peer name */
    strcpy(host, STRING_UNKNOWN);
    if (!cfg.numeric) {
        res = getnameinfo(&peer.saddr, size, host, sizeof(host), NULL, 0, NI_NAMEREQD);
        if (res) {
            print_message(msg_system_error, "getnameinfo(NI_NAMEREQD):%s\n", gai_strerror(res));
        }
    }

    if (!hosts_ctl(service, host, addr_str, STRING_UNKNOWN)) {
        print_message(msg_connections, "connection from %s(%s): access denied", host, addr_str);
        close(in_socket);
        return -1;
    }
#endif
    return 0;
}

void setup_signals(void)
{
    int res;
    struct sigaction action;

    /* Request no SIGCHLD is sent upon termination of
     * the children */
    memset(&action, 0, sizeof(action));
    action.sa_handler = NULL;
    action.sa_flags = SA_NOCLDWAIT;
    res = sigaction(SIGCHLD, &action, NULL);
    CHECK_RES_DIE(res, "sigaction");

    /* Set SIGTERM to exit. For some reason if it's not set explicitly,
     * coverage information is lost when killing the process */
    memset(&action, 0, sizeof(action));
    action.sa_handler = exit;
    res = sigaction(SIGTERM, &action, NULL);
    CHECK_RES_DIE(res, "sigaction");

    /* Ignore SIGPIPE . */
    action.sa_handler = SIG_IGN;
    res = sigaction(SIGPIPE, &action, NULL);
    CHECK_RES_DIE(res, "sigaction");

}


/* Ask OS to keep capabilities over a setuid(nonzero) */
void set_keepcaps(int val) {
#ifdef LIBCAP
    int res;
    res = prctl(PR_SET_KEEPCAPS, val, 0, 0, 0);
    if (res) {
        perror("prctl");
        exit(1);
    }
#endif
}

/* Returns true if anything requires transparent proxying. */
static int use_transparent(void)
{
#ifdef LIBCAP
    if (cfg.transparent)
        return 1;

    for (int i = 0; i < cfg.protocols_len; i++)
        if (cfg.protocols[i].transparent)
            return 1;

#endif
    return 0;
}

/* set needed capabilities for effective and permitted, clear rest
 * IN: cap_net_admin: set to 1 to set CAP_NET_RAW
 * */
void set_capabilities(int cap_net_admin) {
#ifdef LIBCAP
    int res;
    cap_t caps;
    cap_value_t cap_list[10];
    int ncap = 0;

    if (cap_net_admin)
        cap_list[ncap++] = CAP_NET_RAW;

    caps = cap_init();

#define _cap_set_flag(flag) do { \
        res = cap_clear_flag(caps, flag); \
        CHECK_RES_DIE(res, "cap_clear_flag(" #flag ")"); \
        if (ncap > 0) { \
            res = cap_set_flag(caps, flag, ncap, cap_list, CAP_SET); \
            CHECK_RES_DIE(res, "cap_set_flag(" #flag ")"); \
        } \
    } while(0)

    _cap_set_flag(CAP_EFFECTIVE);
    _cap_set_flag(CAP_PERMITTED);

#undef _cap_set_flag

    res = cap_set_proc(caps);
    CHECK_RES_DIE(res, "cap_set_proc");

    res = cap_free(caps);
    if (res) {
        perror("cap_free");
        exit(1);
    }
#endif
}

/* We don't want to run as root -- drop privileges if required */
void drop_privileges(const char* user_name, const char* chroot_path)
{
    int res;
    struct passwd *pw = NULL;

    if (user_name) {
        pw = getpwnam(user_name);
        if (!pw) {
            print_message(msg_config_error, "%s: not found\n", user_name);
            exit(2);
        }
        print_message(msg_config, "turning into %s\n", user_name);
    }

    if (chroot_path) {
        print_message(msg_config, "chrooting into %s\n", chroot_path);

        res = chroot(chroot_path);
        CHECK_RES_DIE(res, "chroot");
    }

    if (user_name) {
        set_keepcaps(1);

        /* remove extraneous groups in case we belong to several extra groups
         * that may have unwanted rights. If non-root when calling setgroups(),
         * it fails, which is fine because... we have no unwanted rights
         * (see POS36-C for security context)
         * */
        setgroups(0, NULL);

        res = setgid(pw->pw_gid);
        CHECK_RES_DIE(res, "setgid");
        res = setuid(pw->pw_uid);
        CHECK_RES_DIE(res, "setuid");

        set_capabilities(use_transparent());
        set_keepcaps(0);
    }
}

/* Writes my PID */
void write_pid_file(const char* pidfile)
{
    FILE *f;
    int res;

    f = fopen(pidfile, "w");
    if (!f) {
        print_message(msg_system_error, "write_pid_file: %s: %s\n", pidfile, strerror(errno));
        return;
    }

    res = fprintf(f, "%d\n", getpid());
    if (res < 0) {
        print_message(msg_system_error, "write_pid_file: fprintf: %s\n", strerror(errno));
    }

    res = fclose(f);
    if (res == EOF) {
        print_message(msg_system_error, "write_pid_file: fclose: %s\n", strerror(errno));
        return;
    }
}
