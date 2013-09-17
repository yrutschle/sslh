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

#define _GNU_SOURCE
#include <stdio.h>
#include <regex.h>
#include <ctype.h>
#include "probe.h"



static int is_ssh_protocol(const char *p, int len, struct proto*);
static int is_openvpn_protocol(const char *p, int len, struct proto*);
static int is_tinc_protocol(const char *p, int len, struct proto*);
static int is_xmpp_protocol(const char *p, int len, struct proto*);
static int is_http_protocol(const char *p, int len, struct proto*);
static int is_tls_protocol(const char *p, int len, struct proto*);
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
    { "ssl",         NULL,     NULL,   is_tls_protocol },
    { "tls",         NULL,     NULL,   is_tls_protocol },
    { "anyprot",     NULL,     NULL,   is_true }
};

static struct proto *protocols;
static char* on_timeout = "ssh";

struct proto*  get_builtins(void) {
    return builtins;
}

int get_num_builtins(void) {
    return ARRAY_SIZE(builtins);
}

/* Sets the protocol name to connect to in case of timeout */
void set_ontimeout(const char* name)
{
    int res = asprintf(&on_timeout, "%s", name);
    CHECK_RES_DIE(res, "asprintf");
}

/* Returns the protocol to connect to in case of timeout; 
 * if not found, return the first protocol specified 
 */
struct proto* timeout_protocol(void) 
{
    struct proto* p = get_first_protocol();
    for (; p && strcmp(p->description, on_timeout); p = p->next);
    if (p) return p;
    return get_first_protocol();
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

/* From http://grapsus.net/blog/post/Hexadecimal-dump-in-C */
#define HEXDUMP_COLS 16
void hexdump(const char *mem, unsigned int len)
{
    unsigned int i, j;

    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if(i % HEXDUMP_COLS == 0)
            printf("0x%06x: ", i);

        /* print hex data */
        if(i < len)
            printf("%02x ", 0xFF & mem[i]);
        else /* end of block, just aligning for ASCII dump */
            printf("   ");

        /* print ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
                if(j >= len) /* end of block, not really printing */
                    putchar(' ');
                else if(isprint(mem[j])) /* printable char */
                    putchar(0xFF & mem[j]);        
                else /* other char */
                    putchar('.');
            }
            putchar('\n');
        }
    }
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
 *
 * Code inspired from OpenVPN port-share option; however, OpenVPN code is
 * wrong: users using pre-shared secrets have non-initialised key_id fields so
 * p[3] & 7 should not be looked at, and also the key_method can be specified
 * to 1 which changes the opcode to P_CONTROL_HARD_RESET_CLIENT_V1.
 * See:
 * http://www.fengnet.com/book/vpns%20illustrated%20tunnels%20%20vpnsand%20ipsec/ch08lev1sec5.html
 * and OpenVPN ssl.c, ssl.h and options.c
 */
static int is_openvpn_protocol (const char*p,int len, struct proto *proto)
{
    int packet_len = ntohs(*(uint16_t*)p);

    return packet_len == len - 2;
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

static int is_tls_protocol(const char *p, int len, struct proto *proto)
{
    /* TLS packet starts with a record "Hello" (0x16), followed by version
     * (0x03 0x00-0x03) (RFC6101 A.1)
     * This means we reject SSLv2 and lower, which is actually a good thing (RFC6176)
     */
    return p[0] == 0x16 && p[1] == 0x03 && ( p[2] >= 0 && p[2] <= 0x03);
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
            if (! p->probe) continue;
            if (verbose) fprintf(stderr, "probing for %s\n", p->description);
            if (p->probe(buffer, n, p)) {
                if (verbose) fprintf(stderr, "probe %s successful\n", p->description);
                return p;
            }
        }
    }

    if (verbose) 
        fprintf(stderr, 
                "all probes failed, connecting to first protocol: %s\n", 
                protocols->description);

    /* If none worked, return the first one affected (that's completely
     * arbitrary) */
    return protocols;
}

/* Returns the structure for specified protocol or NULL if not found */
static struct proto* get_protocol(const char* description)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(builtins); i++) {
        if (!strcmp(builtins[i].description, description)) {
            return &builtins[i];
        }
    }
    return NULL;
}

/* Returns the probe for specified protocol:
 * parameter is the description in builtins[], or "regex" 
 * */
T_PROBE* get_probe(const char* description) {
    struct proto* p = get_protocol(description);

    if (p)
        return p->probe;

    /* Special case of "regex" probe (we don't want to set it in builtins
     * because builtins is also used to build the command-line options and
     * regexp is not legal on the command line)*/
    if (!strcmp(description, "regex"))
        return regex_probe;

    return NULL;
}


