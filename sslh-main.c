/*
# main: processing of command line options and start the main loop.
#
# Copyright (C) 2007-2011  Yves Rutschle
# 
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more
# details.
# 
# The full text for the General Public License is here:
# http://www.gnu.org/licenses/gpl.html

*/

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

const char* USAGE_STRING =
"sslh " VERSION "\n" \
"usage:\n" \
"\tsslh  [-v] [-i] [-V] [-f] [-n]\n"
"\t[-t <timeout>] [-P <pidfile>] -u <username> -p <add> [-p <addr> ...] \n" \
"%s\n\n" \
"-v: verbose\n" \
"-V: version\n" \
"-f: foreground\n" \
"-n: numeric output\n" \
"-t: timeout before connecting to SSH.\n" \
"-p: address and port to listen on.\n    Can be used several times to bind to several addresses.\n" \
"--[ssh,ssl,...]: where to connect connections from corresponding protocol.\n" \
"-P: PID file. Default: /var/run/sslh.pid.\n" \
"-i: Run as a inetd service.\n" \
"";

void print_usage(void)
{
    int i;
    char *prots = "";

    for (i = 0; i < num_known_protocols; i++)
        asprintf(&prots, "%s\t[--%s <addr>]\n", prots, protocols[i].description);

    fprintf(stderr, USAGE_STRING, prots);
}

void parse_cmdline(int argc, char* argv[])
{
    int c, affected = 0;
    struct option const_options[] = {
        { "inetd",      no_argument,            &inetd,         1 },
        { "foreground", no_argument,            &foreground,    1 },
        { "verbose",    no_argument,            &verbose,       1 },
        { "numeric",    no_argument,            &numeric,       1 },
        { "user",       required_argument,      0,              'u' },
        { "pidfile",   required_argument,       0,              'P' },
        { "timeout",    required_argument,      0,              't' },
        { "listen",     required_argument,      0,              'p' },
    };
    struct option all_options[ARRAY_SIZE(const_options) + num_known_protocols + 1];
    struct addrinfo *addr, **a;

    memset(all_options, 0, sizeof(all_options));
    memcpy(all_options, const_options, sizeof(const_options));
    append_protocols(all_options, ARRAY_SIZE(const_options), protocols, num_known_protocols);

    while ((c = getopt_long_only(argc, argv, "t:T:p:VP:", all_options, NULL)) != -1) {
        if (c == 0) continue;

        if (c >= PROT_SHIFT) {
            affected++;
            protocols[c - PROT_SHIFT].affected = 1;
            resolve_name(&addr, optarg);
            protocols[c - PROT_SHIFT].saddr= *addr;
            continue;
        }

        switch (c) {

        case 't':
            probing_timeout = atoi(optarg);
            break;

        case 'p':
            /* find the end of the listen list */
            for (a = &addr_listen; *a; a = &((*a)->ai_next));
            /* append the specified addresses */
            resolve_name(a, optarg);
            
            break;

        case 'V':
            printf("%s %s\n", server_type, VERSION);
            exit(0);

        case 'u':
            user_name = optarg;
            break;

        case 'P':
            pid_file = optarg;
            break;

        default:
            print_usage();
            exit(2);
        }
    }

    if (!affected) {
        fprintf(stderr, "At least one target protocol must be specified.\n");
        exit(2);
    }

    if (!addr_listen) {
        fprintf(stderr, "No listening address specified; use at least one -p option\n");
        exit(1);
    }

}

int main(int argc, char *argv[])
{

   extern char *optarg;
   extern int optind;
   int res, num_addr_listen;

   int *listen_sockets;

   /* Init defaults */
   pid_file = "/var/run/sslh.pid";
   user_name = "nobody";
   foreground = 0;

   parse_cmdline(argc, argv);

   if (inetd)
   {
       verbose = 0;
       start_shoveler(0);
       exit(0);
   }

   if (verbose)
       printsettings();

   num_addr_listen = start_listen_sockets(&listen_sockets, addr_listen);

   if (!foreground)
       if (fork() > 0) exit(0); /* Detach */

   setup_signals();

   drop_privileges(user_name);

   /* New session -- become group leader */
   if (getuid() == 0) {
       res = setsid();
       CHECK_RES_DIE(res, "setsid: already process leader");
   }

   write_pid_file(pid_file);

   /* Open syslog connection */
   setup_syslog(argv[0]);

   main_loop(listen_sockets, num_addr_listen);

   return 0;
}
