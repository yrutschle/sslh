/*
# main: processing of config file, command line options and start the main
# loop.
#
# Copyright (C) 2007-2016  Yves Rutschle
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
"\t[-t <timeout>] [-P <pidfile>] [-u <username>] [-C <chroot>] -p <add> [-p <addr> ...] \n" \
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
    { "inetd",      no_argument,            &inetd,         1 },
    { "foreground", no_argument,            &foreground,    1 },
    { "background", no_argument,            &background,    1 },
    { "transparent", no_argument,           &transparent,   1 },
    { "numeric",    no_argument,            &numeric,       1 },
    { "verbose",    no_argument,            &verbose,       1 },
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
static struct proto* builtins;
static const char *optstr = "vt:T:p:VP:C:F::";



static void print_usage(void)
{
    struct proto *p;
    int i;
    int res;
    char *prots = "";

    p = get_builtins();
    for (i = 0; i < get_num_builtins(); i++) {
        res = asprintf(&prots, "%s\t[--%s <addr>]\n", prots, p[i].description);
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
    struct proto *p;
    
    for (p = get_first_protocol(); p; p = p->next) {
        fprintf(stderr,
                "%s addr: %s. libwrap service: %s log_level: %d family %d %d [%s] [%s]\n",
                p->description, 
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
    fprintf(stderr, "timeout: %d\non-timeout: %s\n", probing_timeout,
            timeout_protocol()->description);
}


/* Extract configuration on addresses and ports on which to listen.
 * out: newly allocated list of addrinfo to listen to
 */
#ifdef LIBCONFIG
static int config_listen(config_t *config, struct addrinfo **listen) 
{
    config_setting_t *setting, *addr;
    int len, i, keepalive;
    const char *hostname, *port;

    setting = config_lookup(config, "listen");
    if (setting) {
        len = config_setting_length(setting);
        for (i = 0; i < len; i++) {
            addr = config_setting_get_elem(setting, i);
            if (! (config_setting_lookup_string(addr, "host", &hostname) &&
                   config_setting_lookup_string(addr, "port", &port))) {
                fprintf(stderr,
                            "line %d:Incomplete specification (hostname and port required)\n",
                            config_setting_source_line(addr));
                return -1;
            }

            keepalive = 0;
            config_setting_lookup_bool(addr, "keepalive", &keepalive);

            resolve_split_name(listen, hostname, port);

            /* getaddrinfo returned a list of addresses corresponding to the
             * specification; move the pointer to the end of that list before
             * processing the next specification, while setting flags for
             * start_listen_sockets() through ai_flags (which is not meant for
             * that, but is only used as hint in getaddrinfo, so it's OK) */
            for (; *listen; listen = &((*listen)->ai_next)) {
                if (keepalive)
                    (*listen)->ai_flags = SO_KEEPALIVE;
            }
        }
    }

    return 0;
}
#endif



#ifdef LIBCONFIG
static void setup_regex_probe(struct proto *p, config_setting_t* probes)
{
#ifdef ENABLE_REGEX
    int num_probes, errsize, i, res;
    char *err;
    const char * expr;
    regex_t** probe_list;

    num_probes = config_setting_length(probes);
    if (!num_probes) {
        fprintf(stderr, "%s: no probes specified\n", p->description);
        exit(1);
    }

    p->probe = get_probe("regex");
    probe_list = calloc(num_probes + 1, sizeof(*probe_list));
    p->data = (void*)probe_list;

    for (i = 0; i < num_probes; i++) {
        probe_list[i] = malloc(sizeof(*(probe_list[i])));
        expr = config_setting_get_string_elem(probes, i);
        res = regcomp(probe_list[i], expr, REG_EXTENDED);
        if (res) {
            err = malloc(errsize = regerror(res, probe_list[i], NULL, 0));
            regerror(res, probe_list[i], err, errsize);
            fprintf(stderr, "%s:%s\n", expr, err);
            free(err);
            exit(1);
        }
    }
#else
    fprintf(stderr, "line %d: regex probe specified but not compiled in\n", config_setting_source_line(probes));
    exit(5);
#endif
}
#endif

#ifdef LIBCONFIG
static void setup_sni_alpn_list(struct proto *p, config_setting_t* config_items, const char* name, int alpn)
{
    int num_probes, i, max_server_name_len, server_name_len;
    const char * config_item;
    char** sni_hostname_list;

    num_probes = config_setting_length(config_items);
    if (!num_probes) {
        fprintf(stderr, "%s: no %s specified\n", p->description, name);
        return;
    }

    max_server_name_len = 0;
    for (i = 0; i < num_probes; i++) {
        server_name_len = strlen(config_setting_get_string_elem(config_items, i));
        if(server_name_len > max_server_name_len)
            max_server_name_len = server_name_len;
    }

    sni_hostname_list = calloc(num_probes + 1, ++max_server_name_len);

    for (i = 0; i < num_probes; i++) {
        config_item = config_setting_get_string_elem(config_items, i);
        sni_hostname_list[i] = malloc(max_server_name_len);
        strcpy (sni_hostname_list[i], config_item);
        if(verbose) fprintf(stderr, "%s: %s[%d]: %s\n", p->description, name, i, sni_hostname_list[i]);
    }

    p->data = (void*)tls_data_set_list(p->data, alpn, sni_hostname_list);
}

static void setup_sni_alpn(struct proto *p, config_setting_t* prot)
{
    config_setting_t *sni_hostnames, *alpn_protocols;

    p->data = (void*)new_tls_data();
    sni_hostnames = config_setting_get_member(prot, "sni_hostnames");
    alpn_protocols = config_setting_get_member(prot, "alpn_protocols");

    if(sni_hostnames && config_setting_is_array(sni_hostnames)) {
        p->probe = get_probe("sni_alpn");
        setup_sni_alpn_list(p, sni_hostnames, "sni_hostnames", 0);
    }
    if(alpn_protocols && config_setting_is_array(alpn_protocols)) {
        p->probe = get_probe("sni_alpn");
        setup_sni_alpn_list(p, alpn_protocols, "alpn_protocols", 1);
    }
}
#endif

/* Extract configuration for protocols to connect to.
 * out: newly-allocated list of protocols
 */
#ifdef LIBCONFIG
static int config_protocols(config_t *config, struct proto **prots)
{
    config_setting_t *setting, *prot, *patterns;
    const char *hostname, *port, *name;
    int i, num_prots;
    struct proto *p, *prev = NULL;

    setting = config_lookup(config, "protocols");
    if (setting) {
        num_prots = config_setting_length(setting);
        for (i = 0; i < num_prots; i++) {
            p = calloc(1, sizeof(*p));
            if (i == 0) *prots = p;
            if (prev) prev->next = p;
            prev = p;

            prot = config_setting_get_elem(setting, i);
            if ((config_setting_lookup_string(prot, "name", &name) &&
                 config_setting_lookup_string(prot, "host", &hostname) &&
                 config_setting_lookup_string(prot, "port", &port)
                )) {
                p->description = name;
                config_setting_lookup_string(prot, "service", &(p->service));
                config_setting_lookup_bool(prot, "keepalive", &p->keepalive);
                config_setting_lookup_bool(prot, "fork", &p->fork);

                if (config_setting_lookup_int(prot, "log_level", &p->log_level) == CONFIG_FALSE) {
                    p->log_level = 1;
                }

                if (resolve_split_name(&(p->saddr), hostname, port)) {
                    fprintf(stderr, "line %d: cannot resolve %s:%s\n", config_setting_source_line(prot), hostname, port);
                    exit(1);
                }

                p->probe = get_probe(name);
                if (!p->probe || !strcmp(name, "sni_alpn")) {
                    fprintf(stderr, "line %d: %s: probe unknown\n", config_setting_source_line(prot), name);
                    exit(1);
                }

                /* Probe-specific options: regex patterns */
                if (!strcmp(name, "regex")) {
                    patterns = config_setting_get_member(prot, "regex_patterns");
                    if (patterns && config_setting_is_array(patterns)) {
                        setup_regex_probe(p, patterns);
                    }
                }

                /* Probe-specific options: SNI/ALPN */
                if (!strcmp(name, "tls")) {
                    setup_sni_alpn(p, prot);
                }

            } else {
                fprintf(stderr, "line %d: Illegal protocol description (missing name, host or port)\n", config_setting_source_line(prot));
                exit(1);
            }
        }
    }

    return 0;
}
#endif

/* Parses a config file
 * in: *filename
 * out: *listen, a newly-allocated linked list of listen addrinfo
 *      *prots, a newly-allocated linked list of protocols
 *      1 on error, 0 on success
 */
#ifdef LIBCONFIG
static int config_parse(char *filename, struct addrinfo **listen, struct proto **prots)
{
    config_t config;
    int timeout;
    const char* str;

    config_init(&config);
    if (config_read_file(&config, filename) == CONFIG_FALSE) {
        /* If it's a parse error then there will be a line number for the failure
         * an I/O error (such as non-existent file) will have the error line as 0
         */
        if (config_error_line(&config) != 0) {
            fprintf(stderr, "%s:%d:%s\n", 
                    filename,
                    config_error_line(&config),
                    config_error_text(&config));
            exit(1);
        }
        fprintf(stderr, "%s:%s\n", 
                filename,
                config_error_text(&config));
        return 1;
    }

    if(config_lookup_bool(&config, "verbose", &verbose) == CONFIG_FALSE) {
	config_lookup_int(&config, "verbose", &verbose);
    }

    config_lookup_bool(&config, "inetd", &inetd);
    config_lookup_bool(&config, "foreground", &foreground);
    config_lookup_bool(&config, "numeric", &numeric);
    config_lookup_bool(&config, "transparent", &transparent);

    if (config_lookup_int(&config, "timeout", (int *)&timeout) == CONFIG_TRUE) {
        probing_timeout = timeout;
    }

    if (config_lookup_string(&config, "on-timeout", &str)) {
        set_ontimeout(str);
    }

    config_lookup_string(&config, "user", &user_name);
    config_lookup_string(&config, "pidfile", &pid_file);
    config_lookup_string(&config, "chroot", &chroot_path);

    config_lookup_string(&config, "syslog_facility", &facility);

    config_listen(&config, listen);
    config_protocols(&config, prots);

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
static void append_protocols(struct option *options, int n_opts, struct proto *prot , int n_prots)
{
    int o, p;

    for (o = n_opts, p = 0; p < n_prots; o++, p++) {
        options[o].name = prot[p].description;
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
    memcpy(all_options, const_options, sizeof(const_options));
    append_protocols(all_options, ARRAY_SIZE(const_options) - 1, builtins, get_num_builtins());
}

/* Performs a first scan of command line options to see if a configuration file
 * is specified. If there is one, parse it now before all other options (so
 * configuration file settings can be overridden from the command line).
 *
 * prots: newly-allocated list of configured protocols, if any.
 */
static void cmdline_config(int argc, char* argv[], struct proto** prots)
{
#ifdef LIBCONFIG
    int c, res;
    char *config_filename;
#endif

    make_alloptions();

#ifdef LIBCONFIG
    optind = 1;
    opterr = 0; /* we're missing protocol options at this stage so don't output errors */
    while ((c = getopt_long_only(argc, argv, optstr, all_options, NULL)) != -1) {
        if (c == 'v') {
            verbose++;
        }
        if (c == 'F') {
            config_filename = optarg;
            if (config_filename) {
                res = config_parse(config_filename, &addr_listen, prots);
            } else {
                /* No configuration file specified -- try default file locations */
                res = config_parse("/etc/sslh/sslh.cfg", &addr_listen, prots);
                if (!res && verbose) fprintf(stderr, "Using /etc/sslh/sslh.cfg\n");
                if (res) {
                    res = config_parse("/etc/sslh.cfg", &addr_listen, prots);
                    if (!res && verbose) fprintf(stderr, "Using /etc/sslh.cfg\n");
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
static void parse_cmdline(int argc, char* argv[], struct proto* prots)
{
    int c;
    struct addrinfo **a;
    struct proto *p;

    optind = 1;
    opterr = 1;
next_arg:
    while ((c = getopt_long_only(argc, argv, optstr, all_options, NULL)) != -1) {
        if (c == 0) continue;

        if (c >= PROT_SHIFT) {
            if (prots)
                for (p = prots; p && p->next; p = p->next) {
                    /* override if protocol was already defined by config file 
                     * (note it only overrides address and use builtin probe) */
                    if (!strcmp(p->description, builtins[c-PROT_SHIFT].description)) {
                        resolve_name(&(p->saddr), optarg);
                        p->probe = builtins[c-PROT_SHIFT].probe;
                        goto next_arg;
                    }
                }
            /* At this stage, it's a new protocol: add it to the end of the
             * list */
            if (!prots) {
                /* No protocols yet -- create the list */
                p = prots = calloc(1, sizeof(*p));
            } else {
                p->next = calloc(1, sizeof(*p));
                p = p->next;
            }
            memcpy(p, &builtins[c-PROT_SHIFT], sizeof(*p));
            resolve_name(&(p->saddr), optarg);
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
             probing_timeout = atoi(optarg);
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
            user_name = optarg;
            break;

        case 'P':
            pid_file = optarg;
            break;

        case 'C':
            chroot_path = optarg;
            break;

        case 'v':
            verbose++;
            break;

        default:
            print_usage();
            exit(2);
        }
    }

    if (!prots) {
        fprintf(stderr, "At least one target protocol must be specified.\n");
        exit(2);
    }

    set_protocol_list(prots);

/* If compiling with systemd socket support no need to require listen address */
#ifndef SYSTEMD
    if (!addr_listen && !inetd) {
        fprintf(stderr, "No listening address specified; use at least one -p option\n");
        exit(1);
    }
#endif

    /* Did command-line override foreground setting? */
    if (background)
        foreground = 0;

}

int main(int argc, char *argv[])
{

   extern char *optarg;
   extern int optind;
   int res, num_addr_listen;
   struct proto* protocols = NULL;

   int *listen_sockets;

   /* Init defaults */
   pid_file = NULL;
   user_name = NULL;
   chroot_path = NULL;

   cmdline_config(argc, argv, &protocols);
   parse_cmdline(argc, argv, protocols);

   if (inetd)
   {
       verbose = 0;
       start_shoveler(0);
       exit(0);
   }

   if (verbose)
       printsettings();

   num_addr_listen = start_listen_sockets(&listen_sockets, addr_listen);

#ifdef SYSTEMD
   if (num_addr_listen < 1) {
     fprintf(stderr, "No listening sockets found, restart sockets or specify addresses in config\n");
     exit(1);
    }
#endif

   if (!foreground) {
       if (fork() > 0) exit(0); /* Detach */

       /* New session -- become group leader */
       if (getuid() == 0) {
           res = setsid();
           CHECK_RES_DIE(res, "setsid: already process leader");
       }
   }

   setup_signals();

   if (pid_file)
       write_pid_file(pid_file);

   /* Open syslog connection before we drop privs/chroot */
   setup_syslog(argv[0]);

   if (user_name || chroot_path)
       drop_privileges(user_name, chroot_path);

   if (verbose)
       printcaps();

   main_loop(listen_sockets, num_addr_listen);

   return 0;
}
