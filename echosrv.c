/* echosrv: a simple line echo server with optional prefix adding.
 *
 * echsrv --listen localhost6:1234 --prefix "ssl: "
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

#include "common.h"
#include "sslh-conf.h"

/* Added to make the code compilable under CYGWIN 
 * */
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0
#endif

const char* server_type = "echsrv"; /* keep setup_syslog happy */

void start_echo(int fd)
{
    int res;
    char buffer[1 << 20];
    int ret, prefix_len;

    prefix_len = strlen(cfg.prefix);

    memset(buffer, 0, sizeof(buffer));
    strcpy(buffer, cfg.prefix);

    while (1) {
        ret = read(fd, buffer + prefix_len, sizeof(buffer) - prefix_len);
        if (ret == -1) {
            fprintf(stderr, "%s", strerror(errno));
            return;
        }
        res = write(fd, buffer, ret + prefix_len);
        if (res < 0) {
            fprintf(stderr, "%s", strerror(errno));
            return;
        }
    }
}

void main_loop(struct listen_endpoint listen_sockets[], int num_addr_listen)
{
    int in_socket, i;

    for (i = 0; i < num_addr_listen; i++) {
        if (!fork()) {
            while (1)
            {
                in_socket = accept(listen_sockets[i].socketfd, 0, 0);
                if (cfg.verbose) fprintf(stderr, "accepted fd %d\n", in_socket);

                if (!fork())
                {
                    close(listen_sockets[i].socketfd);
                    start_echo(in_socket);
                    exit(0);
                }
                close(in_socket);
            }
        }
    }
    wait(NULL);
}

static int config_resolve_listen(struct addrinfo **listen)
{
    int i, res;
    for (i = 0; i < cfg.listen_len; i++) {
        res = resolve_split_name(listen, cfg.listen[i].host, cfg.listen[i].port);
        if (res) return res;

        /* getaddrinfo returned a list of addresses corresponding to the
         * specification; move the pointer to the end of that list before
         * processing the next specification, while setting flags for
         * start_listen_sockets() through ai_flags (which is not meant for
         * that, but is only used as hint in getaddrinfo, so it's OK) */
        for (; *listen; listen = &((*listen)->ai_next)) {
            if (cfg.listen[i].keepalive)
                (*listen)->ai_flags = SO_KEEPALIVE;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{

   extern char *optarg;
   extern int optind;
   int num_addr_listen;

   struct listen_endpoint *listen_sockets;

   memset(&cfg, 0, sizeof(cfg));
   if (sslhcfg_cl_parse(argc, argv, &cfg))
       exit(1);

   sslhcfg_fprint(stdout, &cfg, 0);

   config_resolve_listen(&addr_listen);
   num_addr_listen = start_listen_sockets(&listen_sockets);

   main_loop(listen_sockets, num_addr_listen);

   return 0;
}
