/*
# main: processing of config file, command line options and start the main
# loop.
#
# Copyright (C) 2007-2018  Yves Rutschle
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
#ifdef LIBCONFIG
#include <libconfig.h>
#endif
#ifdef ENABLE_REGEX
#ifdef LIBPCRE
#include <pcreposix.h>
#else
#include <regex.h>
#endif
#endif

#include "common.h"
#include "probe.h"

const char* USAGE_STRING =
"sslh " VERSION "\n" \
"usage:\n" \
"\tsslh  [-v] [-i] [-V] [-f] [-n] [--transparent] [-F<file>]\n"
"\t[-t <timeout>] [-P <pidfile>] [-u <username>] [-C <chroot>] -p <addr> [-p <addr> ...] \n" \
"%s\n\n" /* Dynamically built list of builtin protocols */  \
"\t[--on-timeout <addr>]\n" \
"-v: verbose\n" \
"-V: version\n" \
"-f: foreground\n" \
"-n: numeric output\n" \
"-u: specify under which user to run\n" \
"-C: specify under which chroot path to run\n" \
"--transparent: behave as a transparent proxy\n" \
"-F: use configuration file (warning: no space between -F and file name!)\n" \
"--on-timeout: connect to specified address upon timeout (default: ssh address)\n" \
"-t: seconds to wait before connecting to --on-timeout address.\n" \
"-p: address and port to listen on.\n    Can be used several times to bind to several addresses.\n" \
"--[ssh,ssl,...]: where to connect connections from corresponding protocol.\n" \
"-P: PID file.\n" \
"-i: Run as a inetd service.\n" \
"";

/* Constants for options that have no one-character shorthand */
#define OPT_ONTIMEOUT   257

static struct option const_options[] = {
    { "inetd",      no_argument,            &cfg.inetd,         1 },
    { "foreground", no_argument,            &cfg.foreground,    1 },
    { "transparent", no_argument,           &cfg.transparent,   1 },
    { "numeric",    no_argument,            &cfg.numeric,       1 },
    { "verbose",    no_argument,            &cfg.verbose,       1 },
    { "user",       required_argument,      0,              'u' },
    { "config",     optional_argument,      0,              'F' },
    { "pidfile",    required_argument,      0,              'P' },
    { "chroot",     required_argument,      0,              'C' },
    { "timeout",    required_argument,      0,              't' },
    { "on-timeout", required_argument,      0,              OPT_ONTIMEOUT },
    { "listen",     required_argument,      0,              'p' },
    {}
};

static struct option* all_options;
static struct protocol_probe_desc* builtins;
static const char *optstr = "vt:T:p:VP:C:F::";



static void print_usage(void)
{
    struct protocol_probe_desc *p;
    int i;
    int res;
    char *prots = "";

    p = get_builtins();
    for (i = 0; i < get_num_builtins(); i++) {
        res = asprintf(&prots, "%s\t[--%s <addr>]\n", prots, p[i].name);
        CHECK_RES_DIE(res, "asprintf");
    }

    fprintf(stderr, USAGE_STRING, prots);
}

static void printcaps(void) {
#ifdef LIBCAP
    cap_t caps;
    char* desc;
    ssize_t len;

    caps = cap_get_proc();

    desc = cap_to_text(caps, &len);

    fprintf(stderr, "capabilities: %s\n", desc);

    cap_free(caps);
    cap_free(desc);
#endif
}

static void printsettings(void)
{
    char buf[NI_MAXHOST];
    struct addrinfo *a;
    int i;
    struct sslhcfg_protocols_item *p;
    
    for (i = 0; i < cfg.protocols_len; i++ ) {
        p = &cfg.protocols[i];
        fprintf(stderr,
                "%s addr: %s. libwrap service: %s log_level: %d family %d %d [%s] [%s]\n",
                p->name, 
                sprintaddr(buf, sizeof(buf), p->saddr), 
                p->service,
                p->log_level,
                p->saddr->ai_family,
                p->saddr->ai_addr->sa_family,
                p->keepalive ? "keepalive" : "",
                p->fork ? "fork" : "");
    }
    fprintf(stderr, "listening on:\n");
    for (a = addr_listen; a; a = a->ai_next) {
        fprintf(stderr, 
                "\t%s\t[%s]\n", 
                sprintaddr(buf, sizeof(buf), a), 
                a->ai_flags & SO_KEEPALIVE ? "keepalive" : "");
    }
    fprintf(stderr, "timeout: %d\non-timeout: %s\n", cfg.timeout,
            timeout_protocol()->name);
}


/* To removed in v1.21 */
const char* ssl_err_msg = "Usage of 'ssl' setting is deprecated and will be removed in v1.21. Please use 'tls' instead\n";
void ssl_to_tls(char* setting)
{
    if (!strcmp(setting, "ssl")) {
        strcpy(setting, "tls"); /* legacy configuration */
        log_message(LOG_INFO, ssl_err_msg);
    }
}


/* Turn 'ssl' command line option to 'tls'. To removed in v1.21 */
void cmd_ssl_to_tls(int argc, char* argv[])
{
    int i;
    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--ssl")) {
            strcpy(argv[i], "--tls");
            /* foreground option not parsed yet, syslog not open, just print on
             * stderr and hope for the best */
            fprintf(stderr, ssl_err_msg);
        }
    }
}


/* Extract configuration on addresses and ports on which to listen.
 * out: newly allocated list of addrinfo to listen to
 */
#ifdef LIBCONFIG
static int config_resolve_listen(struct addrinfo **listen)
{
    int i;
    for (i = 0; i < cfg.listen_len; i++) {
        resolve_split_name(listen, cfg.listen[i].host, cfg.listen[i].port);

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
#endif



#ifdef LIBCONFIG
static void setup_regex_probe(struct sslhcfg_protocols_item *p)
{
    int num_patterns, i, res;
    regex_t** pattern_list;
    size_t errsize;
    char* err;

    num_patterns = p->regex_patterns_len;

    pattern_list = calloc(num_patterns + 1, sizeof(*pattern_list));
    CHECK_ALLOC(pattern_list, "calloc");
    p->data = (void*)pattern_list;

    for (i = 0; i < num_patterns; i++) {
        pattern_list[i] = malloc(sizeof(*(pattern_list[i])));
        CHECK_ALLOC(pattern_list[i], "malloc");
        res = regcomp(pattern_list[i], p->regex_patterns[i], REG_EXTENDED);
        if (res) {
            err = malloc(errsize = regerror(res, pattern_list[i], NULL, 0));
            CHECK_ALLOC(err, "malloc");
            regerror(res, pattern_list[i], err, errsize);
            fprintf(stderr, "%s:%s\n", pattern_list[i], err);
            free(err);
            exit(1);
        }
    }
}
#endif

/* For each protocol in the configuration, resolve address and set up protocol
 * options if required
 */
#ifdef LIBCONFIG
static int config_protocols()
{
    int i;
    for (i = 0; i < cfg.protocols_len; i++) {
        struct sslhcfg_protocols_item* p = &(cfg.protocols[i]);
        if (resolve_split_name(&(p->saddr), p->host, p->port)) {
            fprintf(stderr, "cannot resolve %s:%s\n", p->host, p->port);
            exit(1);
        }

        p->probe = get_probe(p->name);
        if (!p->probe) {
            fprintf(stderr, "%s: probe unknown\n", p->name);
            exit(1);
        }

        if (!strcmp(cfg.protocols[i].name, "regex")) {
            setup_regex_probe(&cfg.protocols[i]);
        }

        if (!strcmp(cfg.protocols[i].name, "tls")) {
            cfg.protocols[i].data = (void*)new_tls_data();
            if (cfg.protocols[i].sni_hostnames_len)
                tls_data_set_list(cfg.protocols[i].data, 0,
                                  cfg.protocols[i].sni_hostnames,
                                  cfg.protocols[i].sni_hostnames_len);
            if (cfg.protocols[i].alpn_protocols_len)
                tls_data_set_list(cfg.protocols[i].data, 1, 
                                  cfg.protocols[i].alpn_protocols,
                                  cfg.protocols[i].alpn_protocols_len);
        }
    }
}
#endif

/* Parses a config file
 * in: *filename
 * out: *listen, a newly-allocated linked list of listen addrinfo
 *      1 on error, 0 on success
 */
#ifdef LIBCONFIG
static int config_parse(char *filename, struct addrinfo **listen)
{
    int res;
    const char* err;

    if (!sslhcfg_parse_file(filename, &cfg, &err)) {
        fprintf(stderr, err);
        return 1;
    }

    config_resolve_listen(listen);
    config_protocols();

    return 0;
}
#endif

/* Adds protocols to the list of options, so command-line parsing uses the
 * protocol definition array 
 * options: array of options to add to; must be big enough
 * n_opts: number of options in *options before calling (i.e. where to append)
 * prot: array of protocols
 * n_prots: number of protocols in *prot
 * */
static void append_protocols(struct option *options, int n_opts, struct protocol_probe_desc* prot , int n_prots)
{
    int o, p;

    for (o = n_opts, p = 0; p < n_prots; o++, p++) {
        options[o].name = prot[p].name;
        options[o].has_arg = required_argument;
        options[o].flag = 0;
        options[o].val = p + PROT_SHIFT;
    }
}

static void make_alloptions(void)
{
    builtins = get_builtins();

    /* Create all_options, composed of const_options followed by one option per
     * known protocol */
    all_options = calloc(ARRAY_SIZE(const_options) + get_num_builtins(), sizeof(struct option));
    CHECK_ALLOC(all_options, "calloc");
    memcpy(all_options, const_options, sizeof(const_options));
    append_protocols(all_options, ARRAY_SIZE(const_options) - 1, builtins, get_num_builtins());
}

/* Performs a first scan of command line options to see if a configuration file
 * is specified. If there is one, parse it now before all other options (so
 * configuration file settings can be overridden from the command line).
 *
 * prots: newly-allocated list of configured protocols, if any.
 */
static void cmdline_config(int argc, char* argv[], struct sslhcfg_protocols_item** prots)
{
#ifdef LIBCONFIG
    int c, res;
    char *config_filename;
#endif

    cmd_ssl_to_tls(argc, argv); /* To remove in v1.21 */

    make_alloptions();

#ifdef LIBCONFIG
    optind = 1;
    opterr = 0; /* we're missing protocol options at this stage so don't output errors */
    while ((c = getopt_long_only(argc, argv, optstr, all_options, NULL)) != -1) {
        if (c == 'v') {
            cfg.verbose++;
        }
        if (c == 'F') {
            config_filename = optarg;
            if (config_filename) {
                res = config_parse(config_filename, &addr_listen);
            } else {
                /* No configuration file specified -- try default file locations */
                res = config_parse("/etc/sslh/sslh.cfg", &addr_listen);
                if (!res && cfg.verbose) fprintf(stderr, "Using /etc/sslh/sslh.cfg\n");
                if (res) {
                    res = config_parse("/etc/sslh.cfg", &addr_listen);
                    if (!res && cfg.verbose) fprintf(stderr, "Using /etc/sslh.cfg\n");
                }
            }
            if (res)
                exit(4);
            break;
        }
    }
#endif
}


/* Parse command-line options. prots points to a list of configured protocols,
 * potentially non-allocated */
static void parse_cmdline(int argc, char* argv[], struct sslhcfg_protocols_item* prots)
{
    int c;
    struct addrinfo **a;
    int background, i;

    optind = 1;
    opterr = 1;
next_arg:
    while ((c = getopt_long_only(argc, argv, optstr, all_options, NULL)) != -1) {
        if (c == 0) continue;

        if (c >= PROT_SHIFT) {
            int prot_num = c - PROT_SHIFT;
            for (i = 0; i < cfg.protocols_len; i++) {
                /* override if protocol was already defined by config file  */
                if (!strcmp(cfg.protocols[i].name, builtins[prot_num].name)) {
                    resolve_name(&(cfg.protocols[i].saddr), optarg);
                    goto next_arg;
                }
            }
            /* At this stage, it's a new protocol: add it to the end of the
             * list */
            cfg.protocols_len++;
            cfg.protocols = realloc(cfg.protocols, cfg.protocols_len * sizeof(*cfg.protocols));
            CHECK_ALLOC(cfg.protocols, "realloc");

            /* set up name, target and probe. everything else defaults to 0 */
            memset(&cfg.protocols[cfg.protocols_len-1], 0, sizeof(cfg.protocols[0]));
            cfg.protocols[cfg.protocols_len-1].probe = get_probe(builtins[prot_num].name);
            cfg.protocols[cfg.protocols_len-1].name = builtins[prot_num].name;
            resolve_name(&cfg.protocols[cfg.protocols_len-1].saddr, optarg);
            continue;
        }

        switch (c) {

        case 'F':
            /* Legal option, but do nothing, it was already processed in
             * cmdline_config() */
#ifndef LIBCONFIG
            fprintf(stderr, "Built without libconfig support: configuration file not available.\n");
            exit(1);
#endif
            break;

        case 't':
             cfg.timeout = atoi(optarg);
            break;

        case OPT_ONTIMEOUT:
            set_ontimeout(optarg);
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
            cfg.user = optarg;
            break;

        case 'P':
            cfg.pidfile = optarg;
            break;

        case 'C':
            cfg.chroot = optarg;
            break;

        case 'v':
            cfg.verbose++;
            break;

        default:
            print_usage();
            exit(2);
        }
    }

    return;

    if (!cfg.protocols_len) {
        fprintf(stderr, "At least one target protocol must be specified.\n");
        exit(2);
    }

/* If compiling with systemd socket support no need to require listen address */
#ifndef SYSTEMD
    if (!addr_listen && !cfg.inetd) {
        fprintf(stderr, "No listening address specified; use at least one -p option\n");
        exit(1);
    }
#endif

    /* Did command-line override foreground setting? */
    if (background)
        cfg.foreground = 0;

}

int main(int argc, char *argv[])
{

   extern char *optarg;
   extern int optind;
   int res, num_addr_listen;
   struct sslhcfg_protocols_item* protocols = NULL;

   int *listen_sockets;

   /* Init defaults -- conf2struct sets them when parsing a config file 
    * but we may configure entirely from the command line */
   cfg.pidfile = NULL;
   cfg.user = NULL;
   cfg.chroot = NULL;
   cfg.syslog_facility = "auth";
   cfg.timeout = 2;

   cmdline_config(argc, argv, &protocols);
   parse_cmdline(argc, argv, protocols);

   if (cfg.inetd)
   {
       cfg.verbose = 0;
       start_shoveler(0);
       exit(0);
   }

   if (cfg.verbose)
       printsettings();

   num_addr_listen = start_listen_sockets(&listen_sockets, addr_listen);

#ifdef SYSTEMD
   if (num_addr_listen < 1) {
     fprintf(stderr, "No listening sockets found, restart sockets or specify addresses in config\n");
     exit(1);
    }
#endif

   if (!cfg.foreground) {
       if (fork() > 0) exit(0); /* Detach */

       /* New session -- become group leader */
       if (getuid() == 0) {
           res = setsid();
           CHECK_RES_DIE(res, "setsid: already process leader");
       }
   }

   setup_signals();

   if (cfg.pidfile)
       write_pid_file(cfg.pidfile);

   /* Open syslog connection before we drop privs/chroot */
   setup_syslog(argv[0]);

   if (cfg.user || cfg.chroot)
       drop_privileges(cfg.user, cfg.chroot);

   if (cfg.verbose)
       printcaps();

   main_loop(listen_sockets, num_addr_listen);

   return 0;
}
