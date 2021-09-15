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
#include <stdarg.h>
#include <stdio.h>
#include "sslh-conf.h"
#include "common.h"
#include "log.h"

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

    log_message(LOG_INFO, "%s %s started\n", server_type, VERSION);
}


/* Log to syslog or stderr if foreground */
void log_message(int type, const char* msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    if (cfg.foreground)
        vfprintf(stderr, msg, ap);
    va_end(ap);

    if (do_syslog) {
        va_start(ap, msg);
        vsyslog(type, msg, ap);
        va_end(ap);
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
        get_connection_desc(desc, cnx);
    }

    log_message(LOG_INFO, "%s:connection from %s to %s forwarded from %s to %s\n",
                cnx->proto->name,
                desc->peer,
                desc->service,
                desc->local,
                desc->target);
}
