/*
# tcp-probe.c: TCP code that is common to the sslh-fork and sslh-[ev|select] 
#
# Copyright (C) 2022  Yves Rutschle
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


#include "probe.h"

static struct sslhcfg_protocols_item** tcp_protocols;
static int tcp_protocols_len = 0;

/*
 * Read the beginning of data coming from the client connection and check if
 * it's a known protocol.
 * Return PROBE_AGAIN if not enough data, or PROBE_MATCH if it succeeded in
 * which case cnx->proto is set to the appropriate protocol.
 */
int probe_client_protocol(struct connection *cnx)
{
    char buffer[BUFSIZ];
    ssize_t n;

    n = read(cnx->q[0].fd, buffer, sizeof(buffer));
    /* It's possible that read() returns an error, e.g. if the client
     * disconnected between the previous call to select() and now. If that
     * happens, we just connect to the default protocol so the caller of this
     * function does not have to deal with a specific  failure condition (the
     * connection will just fail later normally). */

    if (n > 0) {
        defer_write(&cnx->q[1], buffer, n);
        return probe_buffer(cnx->q[1].begin_deferred_data,
                            cnx->q[1].deferred_data_size,
                            tcp_protocols, tcp_protocols_len,
                            &cnx->proto
                            );
    }

    /* read() returned an error, so just connect to the last protocol to die */
    cnx->proto = &cfg.protocols[cfg.protocols_len-1];
    return PROBE_MATCH;
}


static void tcp_protocol_list_init(void)
{
    tcp_protocols = calloc(cfg.protocols_len, sizeof(tcp_protocols));
    CHECK_ALLOC(tcp_protocols, "tcp_protocols");
    for (int i = 0; i < cfg.protocols_len; i++) {
        struct sslhcfg_protocols_item* p = &cfg.protocols[i];
        if (!p->is_udp) {
            tcp_protocols[tcp_protocols_len] = p;
            tcp_protocols_len++;
        }
    }
}

/* Configuration sanity check for TCP:
 * - If there is a listening socket, there must be at least one target
 */
static void tcp_sanity_check(void)
{
    int tcp_present = 0;

    for (int i = 0; i < cfg.listen_len; i++) {
        struct sslhcfg_listen_item* p = &cfg.listen[i];
        if (!p->is_udp) {
            tcp_present = 1;
            break;
        }
    }

    if (tcp_present && !tcp_protocols_len) {
        print_message(msg_config_error, "At least one TCP target protocol must be specified.\n");
        exit(2);
    }
}

void tcp_init(void)
{
    tcp_protocol_list_init();
    tcp_sanity_check();
}
