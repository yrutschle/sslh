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

/* Added to make the code compilable under CYGWIN 
 * */
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0
#endif

const char* USAGE_STRING =
"echosrv\n" \
"usage:\n" \
"\techosrv  [-v] --listen <address:port> [--prefix <prefix>]\n"
"-v: verbose\n" \
"--listen: address to listen on. Can be specified multiple times.\n" \
"--prefix: add specified prefix before every line echoed.\n"
"";

const char* server_type = "echsrv"; /* keep setup_syslog happy */

/* 
 * Settings that depend on the command line. 
 */
char* prefix = "";
int port;

int verbose, numeric;

void parse_cmdline(int argc, char* argv[])
{
    int c;
    struct option options[] = {
        { "verbose",    no_argument,            &verbose,       1 },
        { "numeric",    no_argument,            &numeric,       1 },
        { "listen",     required_argument,      0,              'l' },
        { "prefix",     required_argument,      0,              'p' },
    };
    struct addrinfo **a;

    while ((c = getopt_long_only(argc, argv, "l:p:", options, NULL)) != -1) {
        if (c == 0) continue;

        switch (c) {

        case 'l':
            /* find the end of the listen list */
            for (a = &addr_listen; *a; a = &((*a)->ai_next));
            /* append the specified addresses */
            resolve_name(a, optarg);
            break;

        case 'p':
            prefix = optarg;
            break;

        default:
            fprintf(stderr, "%s", USAGE_STRING);
            exit(2);
        }
    }

    if (!addr_listen) {
        fprintf(stderr, "No listening port specified\n");
        exit(1);
    }
}

void start_echo(int fd)
{
    int res;
    char buffer[1 << 20];
    int ret, prefix_len;

    prefix_len = strlen(prefix);

    memset(buffer, 0, sizeof(buffer));
    strcpy(buffer, prefix);

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

void main_loop(int listen_sockets[], int num_addr_listen)
{
    int in_socket, i;

    for (i = 0; i < num_addr_listen; i++) {
        if (!fork()) {
            while (1)
            {
                in_socket = accept(listen_sockets[i], 0, 0);
                if (verbose) fprintf(stderr, "accepted fd %d\n", in_socket);

                if (!fork())
                {
                    close(listen_sockets[i]);
                    start_echo(in_socket);
                    exit(0);
                }
                close(in_socket);
            }
        }
    }
    wait(NULL);
}

int main(int argc, char *argv[])
{

   extern char *optarg;
   extern int optind;
   int num_addr_listen;

   int *listen_sockets;

   parse_cmdline(argc, argv);

   num_addr_listen = start_listen_sockets(&listen_sockets, addr_listen);

   main_loop(listen_sockets, num_addr_listen);

   return 0;
}
