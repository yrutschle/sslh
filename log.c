/*
# log: processing of all outgoing messages
#
# Copyright (C) 2007-2021  Yves Rutschle
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


#define SYSLOG_NAMES
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include "sslh-conf.h"
#include "common.h"
#include "log.h"

msg_info msg_config = {
    LOG_INFO,
    &cfg.verbose_config
};

msg_info msg_config_error = {
    LOG_ERR,
    &cfg.verbose_config_error
};

msg_info msg_fd = {
    LOG_DEBUG,
    &cfg.verbose_fd
};

/* Internal errors: inconsistent states, impossible values, things that should never happen, and are therefore the sign of memory corruption: hence the LOG_CRIT */
msg_info msg_int_error = {
    LOG_CRIT,
    &cfg.verbose_system_error
};

/* System errors: when the system around us fails us: memory allocation, fork, ... */
msg_info msg_system_error = {
    LOG_ERR,
    &cfg.verbose_system_error
};

msg_info msg_packets = {
    LOG_INFO,
    &cfg.verbose_packets
};

/* additional info when attempting outgoing connections */
msg_info msg_connections_try = {
    LOG_DEBUG,
    &cfg.verbose_connections_try
};

/* Connection information and failures (e.g. forbidden by policy) */
msg_info msg_connections = {
    LOG_INFO,
    &cfg.verbose_connections
};

/* Connection failures, e.g. target server not present */
msg_info msg_connections_error = {
    LOG_ERR,
    &cfg.verbose_connections_error
};


/* comment the probing process */
msg_info msg_probe_info = {
    LOG_INFO,
    &cfg.verbose_probe_info
};

/* probing errors, e.g. inconsistent data in connections */
msg_info msg_probe_error = {
    LOG_ERR,
    &cfg.verbose_probe_error
};



/* Bitmasks in verbose-* values */
#define MSG_STDOUT 1
#define MSG_SYSLOG 2
#define MSG_FILE   4

static FILE* logfile_fp = NULL;

/* Prints a message to stderr and/or syslog if appropriate */
void print_message(msg_info info, const char* str, ...)
{
    va_list ap;

    if ((*info.verbose & MSG_STDOUT) && ! cfg.inetd) {
        va_start(ap, str);
        vfprintf(stderr, str, ap);
        va_end(ap);
    }

    if (*info.verbose & MSG_SYSLOG) {
        va_start(ap, str);
        vsyslog(info.log_level, str, ap);
        va_end(ap);
    }

    if (*info.verbose & MSG_FILE && logfile_fp != NULL) {
        va_start(ap, str);
        vfprintf(logfile_fp, str, ap);
        fflush(logfile_fp);
        va_end(ap);
    }
}

static int do_syslog = 1; /* Should we syslog? controled by syslog_facility = "none" */

/* Open syslog connection with appropriate banner;
 * banner is made up of basename(bin_name)+"[pid]" */
void setup_syslog(const char* bin_name) {
    char *name1, *name2;
    int res, fn;

    if (!strcmp(cfg.syslog_facility, "none")) {
        do_syslog = 0;
        return;
    }

    name1 = strdup(bin_name);
    res = asprintf(&name2, "%s[%d]", basename(name1), getpid());
    CHECK_RES_DIE(res, "asprintf");

    for (fn = 0; facilitynames[fn].c_val != -1; fn++)
        if (strcmp(facilitynames[fn].c_name, cfg.syslog_facility) == 0)
            break;
    if (facilitynames[fn].c_val == -1) {
        fprintf(stderr, "Unknown facility %s\n", cfg.syslog_facility);
        exit(1);
    }

    openlog(name2, LOG_CONS, facilitynames[fn].c_val);
    free(name1);
    /* Don't free name2, as openlog(3) uses it (at least in glibc) */
}

void setup_logfile()
{
    if (cfg.logfile == NULL)
    {
        return;
    }

    logfile_fp = fopen(cfg.logfile, "a");
    if (logfile_fp == NULL)
    {
        fprintf(stderr, "Could not open logfile %s for writing: %s\n", cfg.logfile, strerror(errno));
        exit(1);
    }
}

void close_logfile()
{
    if (logfile_fp != NULL)
    {
        fclose(logfile_fp);
        logfile_fp = NULL;
    }
}

/* syslogs who connected to where 
 * desc: string description of the connection. if NULL, log_connection will
 * manage on its own
 * cnx: connection descriptor
 * */
void log_connection(struct connection_desc* desc, const struct connection *cnx)
{
    struct connection_desc d;

    if (cnx->proto->log_level < 1)
        return;

    if (!desc) {
        desc = &d;
        if (!get_connection_desc(desc, cnx)) {
            print_message(msg_connections, "%s: lost incoming connection\n",
                          cnx->proto->name);
            return;
        }
    }

    print_message(msg_connections, "%s:connection from %s to %s forwarded from %s to %s\n",
                cnx->proto->name,
                desc->peer,
                desc->service,
                desc->local,
                desc->target);
}
