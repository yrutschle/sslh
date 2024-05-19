/* echosrv: a simple line echo server with optional prefix adding.
 *
 * echosrv --listen localhost6:1234 --prefix "ssl: "
 *
 * This will bind to 1234, and echo every line pre-pending "ssl: ". This is
 * used for testing: we create several such servers with different prefixes,
 * then we connect test clients that can then check they get the proper data
 * back (thus testing that shoveling works both ways) with the correct prefix
 * (thus testing it connected to the expected service).
 * **/

#define _GNU_SOURCE
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <syslog.h>
#include <libgen.h>
#include <getopt.h>
#include <errno.h>

#define cfg sslhcfg
#include "common.h"
#undef cfg

#include "echosrv-conf.h"

/* Added to make the code compilable under CYGWIN 
 * */
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0
#endif

struct echocfg_item cfg;

void check_res_dump(int res, struct addrinfo *addr, char* syscall)
{
    char buf[NI_MAXHOST];

    if (res == -1) {
        if (addr)
            fprintf(stderr, "error %s:%s: %s\n",
                    sprintaddr(buf, sizeof(buf), addr),
                    syscall,
                    strerror(errno));
        else 
            fprintf(stderr, "Dying just because\n");

        exit(1);
    }
}

void start_echo(int fd)
{
    ssize_t res;
    char buffer[1 << 20];
    ssize_t ret;
    size_t prefix_len;
    int first = 1;

    prefix_len = strlen(cfg.prefix);

    memset(buffer, 0, sizeof(buffer));
    strcpy(buffer, cfg.prefix);

    while (1) {
        ret = read(fd, buffer + prefix_len, sizeof(buffer) - prefix_len);
        if (ret <= 0) {
            fprintf(stderr, "%s", strerror(errno));
            return;
        }
        if (first) {
            res = write(fd, buffer, ret + prefix_len);
            first = 0;
            if (write(1, buffer, ret + prefix_len) < 0) {
                fprintf(stderr, "%s", strerror(errno));
            }
        } else {
            res = write(fd, buffer + prefix_len, ret);
        }
        if (res < 0) {
            fprintf(stderr, "%s", strerror(errno));
            return;
        }
    }
}

/* TCP echo server: accepts connections to an endpoint, forks an echo for each
 * connection, forever. Prefix is added at start of response stream */
void tcp_echo(struct listen_endpoint* listen_socket)
{
    while (1) {
        int in_socket = accept(listen_socket->socketfd, 0, 0);
        if (in_socket == -1) {
            perror("tcp_echo:accept");
            exit(1);
        }

        if (!fork())
        {
            close(listen_socket->socketfd);
            start_echo(in_socket);
            exit(0);
        }
        close(in_socket);
        waitpid(-1, NULL, WNOHANG);
    }
}

void print_udp_xchange(int sockfd, struct sockaddr* addr, socklen_t addrlen)
{
    struct addrinfo src_addrinfo, to_addrinfo;
    char str_addr[NI_MAXHOST+1+NI_MAXSERV+1];
    char str_addr2[NI_MAXHOST+1+NI_MAXSERV+1];
    struct sockaddr_storage ss;

    src_addrinfo.ai_addr = (struct sockaddr*)&ss;
    src_addrinfo.ai_addrlen = sizeof(ss);
    getsockname(sockfd, src_addrinfo.ai_addr, &src_addrinfo.ai_addrlen);

    to_addrinfo.ai_addr = addr;
    to_addrinfo.ai_addrlen = sizeof(*addr);

    fprintf(stderr, "UDP local %s remote %s\n", 
            sprintaddr(str_addr, sizeof(str_addr), &src_addrinfo),
            sprintaddr(str_addr2, sizeof(str_addr2), &to_addrinfo)
           );
}

/* UDP echo server: receive packets, return them, forever.
 * Prefix is added at each packet */
void udp_echo(struct listen_endpoint* listen_socket)
{
    char data[65536];
    struct sockaddr src_addr;
    socklen_t addrlen;

    memset(data, 0, sizeof(data));

    size_t prefix_len = strlen(cfg.prefix);
    memcpy(data, cfg.prefix, prefix_len);

    while (1) {
        addrlen = sizeof(src_addr);
        ssize_t len = recvfrom(listen_socket->socketfd,
                           data + prefix_len,
                           sizeof(data) - prefix_len,
                           0,
                           &src_addr,
                           &addrlen);

        if (len < 0) {
            perror("recvfrom");
        }
        *(data + prefix_len + len) = 0;
        fprintf(stderr, "%zd %s\n", len, data + prefix_len);

        print_udp_xchange(listen_socket->socketfd, &src_addr, addrlen);

        ssize_t res = sendto(listen_socket->socketfd,
                         data,
                         len + prefix_len,
                         0,
                         &src_addr,
                         addrlen);
        if (res < 0) {
            perror("sendto");
        }
    }
}

void main_loop(struct listen_endpoint listen_sockets[], int num_addr_listen)
{
    int i;

    for (i = 0; i < num_addr_listen; i++) {
        if (!fork()) {
            if (cfg.udp) {
                udp_echo(&listen_sockets[i]);
            } else {
                tcp_echo(&listen_sockets[i]);
            }
        }
    }
    wait(NULL);
}

/* Following is a number of utility functions copied from common.c: linking
 * against common.o directly means echosrv has to work with sslh config struct,
 * which makes it all too awkward */

/* simplified from common.c */
char* sprintaddr(char* buf, size_t size, struct addrinfo *a)
{
   char host[NI_MAXHOST], serv[NI_MAXSERV];
   int res;

   res = getnameinfo(a->ai_addr, a->ai_addrlen,
               host, sizeof(host),
               serv, sizeof(serv),
               0 );

   if (res) {
       /* Name resolution failed: do it numerically instead */
       res = getnameinfo(a->ai_addr, a->ai_addrlen,
                         host, sizeof(host),
                         serv, sizeof(serv),
                         NI_NUMERICHOST | NI_NUMERICSERV);
       /* should not fail but... */
       if (res) {
           strcpy(host, "?");
           strcpy(serv, "?");
       }
   }

   snprintf(buf, size, "%s:%s", host, serv);

   return buf;
}


/* simplified from common.c */
int listen_single_addr(struct addrinfo* addr, int keepalive, int udp)
{
    struct sockaddr_storage *saddr;
    int sockfd, one, res;

    saddr = (struct sockaddr_storage*)addr->ai_addr;

    sockfd = socket(saddr->ss_family, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    check_res_dump(sockfd, addr, "socket");

    one = 1;
    res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    check_res_dump(res, addr, "setsockopt(SO_REUSEADDR)");

    if (addr->ai_addr->sa_family == AF_INET6) {
        res = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&one, sizeof(one));
        check_res_dump(res, addr, "setsockopt(IPV6_V6ONLY)");
    }

    res = bind(sockfd, addr->ai_addr, addr->ai_addrlen);
    check_res_dump(res, addr, "bind");

    if (!udp) {
        res = listen (sockfd, 50);
        check_res_dump(res, addr, "listen");
    }

    return sockfd;
}

/* simplified from common.c */
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
           fprintf(stderr, "%s: no closing bracket in IPv6 address?\n", host);
           return -1;
       }
       host++; /* skip first bracket */
       *end = 0; /* remove last bracket */
   }

   res = getaddrinfo(host, serv, &hint, out);

   if (res)
      fprintf(stderr, "%s `%s:%s'\n", gai_strerror(res), host, serv);
   return res;
}

int start_listen_sockets(struct listen_endpoint *sockfd[])
{
    struct addrinfo *addr, *start_addr;
    char buf[NI_MAXHOST];
    int i, res;
    int num_addr = 0, keepalive = 0, udp = 0;

    *sockfd = NULL;

    fprintf(stderr, "Listening to:\n");

    for (i = 0; i < cfg.listen_len; i++) {
        udp = cfg.udp;


        res = resolve_split_name(&start_addr, cfg.listen[i].host, cfg.listen[i].port);
        if (res) exit(4);

        for (addr = start_addr; addr; addr = addr->ai_next) {
            num_addr++;
            *sockfd = realloc(*sockfd, num_addr * sizeof(*sockfd));
            (*sockfd)[num_addr-1].socketfd = listen_single_addr(addr, keepalive, udp);
            (*sockfd)[num_addr-1].type = udp ? SOCK_DGRAM : SOCK_STREAM;
            fprintf(stderr, "%d:\t%s\n", (*sockfd)[num_addr-1].socketfd, sprintaddr(buf, sizeof(buf), addr));
        }
        freeaddrinfo(start_addr);
    }

    return num_addr;
}

int main(int argc, char *argv[])
{

   extern char *optarg;
   extern int optind;
   int num_addr_listen;

   struct listen_endpoint *listen_sockets;

   memset(&cfg, 0, sizeof(cfg));
   if (echocfg_cl_parse(argc, argv, &cfg))
       exit(1);

   echocfg_fprint(stdout, &cfg, 0);

   num_addr_listen = start_listen_sockets(&listen_sockets);

   main_loop(listen_sockets, num_addr_listen);

   return 0;
}
