/*
# probe.c: Code for probing protocols
#
# Copyright (C) 2007-2012  Yves Rutschle
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

#include <regex.h>
#include "probe.h"



static int is_ssh_protocol(const char *p, int len, struct proto*);
static int is_openvpn_protocol(const char *p, int len, struct proto*);
static int is_tinc_protocol(const char *p, int len, struct proto*);
static int is_xmpp_protocol(const char *p, int len, struct proto*);
static int is_http_protocol(const char *p, int len, struct proto*);
static int is_true(const char *p, int len, struct proto* proto) { return 1; }

/* Table of protocols that have a built-in probe
 */
static struct proto builtins[] = {
    /* description   service  saddr   probe  */
    { "ssh",         "sshd",   NULL,   is_ssh_protocol},
    { "openvpn",     NULL,     NULL,   is_openvpn_protocol },
    { "tinc",        NULL,     NULL,   is_tinc_protocol },
    { "xmpp",        NULL,     NULL,   is_xmpp_protocol },
    { "http",        NULL,     NULL,   is_http_protocol },
    { "ssl",          NULL,     NULL,  is_true }
};

static struct proto *protocols;

struct proto*  get_builtins(void) {
    return builtins;
}

int get_num_builtins(void) {
    return ARRAY_SIZE(builtins);
}

/* Returns the protocol to connect to in case of timeout; conventionaly this is
 * the first protocol specified (but maybe we'll make it more explicit some
 * day)
 */
struct proto* timeout_protocol(void) {
    return protocols;
}

/* returns the first protocol (caller can then follow the *next pointers) */
struct proto* get_first_protocol(void)
{
    return protocols;
}

void set_protocol_list(struct proto* prots)
{
    protocols = prots;
}

/* Is the buffer the beginning of an SSH connection? */
static int is_ssh_protocol(const char *p, int len, struct proto *proto)
{
    if (!strncmp(p, "SSH-", 4)) {
        return 1;
    }
    return 0;
}

/* Is the buffer the beginning of an OpenVPN connection?
 * (code lifted from OpenVPN port-share option)
 */
static int is_openvpn_protocol (const char*p,int len, struct proto *proto)
{
#define P_OPCODE_SHIFT                 3
#define P_CONTROL_HARD_RESET_CLIENT_V2 7
    if (len >= 3)
    {
        return p[0] == 0
            && p[1] >= 14
            && p[2] == (P_CONTROL_HARD_RESET_CLIENT_V2<<P_OPCODE_SHIFT);
    }
    else if (len >= 2)
    {
        return p[0] == 0 && p[1] >= 14;
    }
    else
        return 0;
}

/* Is the buffer the beginning of a tinc connections?
 * (protocol is undocumented, but starts with "0 " in 1.0.15)
 * */
static int is_tinc_protocol( const char *p, int len, struct proto *proto)
{
    return !strncmp(p, "0 ", 2);
}

/* Is the buffer the beginning of a jabber (XMPP) connections?
 * (Protocol is documented (http://tools.ietf.org/html/rfc6120) but for lazy
 * clients, just checking first frame containing "jabber" in xml entity)
 * */
static int is_xmpp_protocol( const char *p, int len, struct proto *proto)
{
    return strstr(p, "jabber") ? 1 : 0;
}

static int probe_http_method(const char *p, const char *opt)
{
    return !strcmp(p, opt);
}

/* Is the buffer the beginning of an HTTP connection?  */
static int is_http_protocol(const char *p, int len, struct proto *proto)
{
    /* If it's got HTTP in the request (HTTP/1.1) then it's HTTP */
    if (strstr(p, "HTTP"))
        return 1;

    /* Otherwise it could be HTTP/1.0 without version: check if it's got an
     * HTTP method (RFC2616 5.1.1) */
    probe_http_method(p, "OPTIONS");
    probe_http_method(p, "GET");
    probe_http_method(p, "HEAD");
    probe_http_method(p, "POST");
    probe_http_method(p, "PUT");
    probe_http_method(p, "DELETE");
    probe_http_method(p, "TRACE");
    probe_http_method(p, "CONNECT");

    return 0;
}


static int regex_probe(const char *p, int len, struct proto *proto)
{
    regex_t** probe_list = (regex_t**)(proto->data);
    int i=0;

    while (probe_list[i]) {
        if (!regexec(probe_list[i], p, 0, NULL, 0)) {
            return 1;
        }
        i++;
    }
    return 0;
}

/* 
 * Read the beginning of data coming from the client connection and check if
 * it's a known protocol. Then leave the data on the defered
 * write buffer of the connection and returns a pointer to the protocol
 * structure
 */
struct proto* probe_client_protocol(struct connection *cnx)
{
    char buffer[BUFSIZ];
    struct proto *p;
    int n;

    n = read(cnx->q[0].fd, buffer, sizeof(buffer));
    /* It's possible that read() returns an error, e.g. if the client
     * disconnected between the previous call to select() and now. If that
     * happens, we just connect to the default protocol so the caller of this
     * function does not have to deal with a specific  failure condition (the
     * connection will just fail later normally). */
    if (n > 0) {
        defer_write(&cnx->q[1], buffer, n);

        for (p = protocols; p; p = p->next) {
            if (p->probe(buffer, n, p)) {
                return p;
            }
        }
    }

    /* If none worked, return the first one affected (that's completely
     * arbitrary) */
    return protocols;
}

/* Returns the probe for specified protocol:
 * parameter is the description in builtins[], or "regex" 
 * */
T_PROBE* get_probe(const char* description) {
    int i;

    for (i = 0; i < ARRAY_SIZE(builtins); i++) {
        if (!strcmp(builtins[i].description, description)) {
            return builtins[i].probe;
        }
    }
    /* Special case of "regex" probe (we don't want to set it in builtins
     * because builtins is also used to build the command-line options and
     * regexp is not legal on the command line)*/
    if (!strcmp(description, "regex"))
        return regex_probe;

    return NULL;
}


