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
static int is_syslog_protocol(const char *p, int len, struct proto*);
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
    { "syslog",      NULL,     NULL,   is_syslog_protocol },
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
    if (len < 4)
        return PROBE_AGAIN;

    return !strncmp(p, "SSH-", 4);
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
    int packet_len;

    if (len < 2)
        return PROBE_AGAIN;

    packet_len = ntohs(*(uint16_t*)p);
    return packet_len == len - 2;
}

/* Is the buffer the beginning of a tinc connections?
 * (protocol is undocumented, but starts with "0 " in 1.0.15)
 * */
static int is_tinc_protocol( const char *p, int len, struct proto *proto)
{
    if (len < 2)
        return PROBE_AGAIN;

    return !strncmp(p, "0 ", 2);
}

/* Is the buffer the beginning of a jabber (XMPP) connections?
 * (Protocol is documented (http://tools.ietf.org/html/rfc6120) but for lazy
 * clients, just checking first frame containing "jabber" in xml entity)
 * */
static int is_xmpp_protocol( const char *p, int len, struct proto *proto)
{
    if (len < 6)
        return PROBE_AGAIN;

    return memmem(p, len, "jabber", 6) ? 1 : 0;
}

static int probe_http_method(const char *p, int len, const char *opt)
{
    if (len < strlen(opt))
        return PROBE_AGAIN;

    return !strncmp(p, opt, len);
}

/* Is the buffer the beginning of an HTTP connection?  */
static int is_http_protocol(const char *p, int len, struct proto *proto)
{
    int res;
    /* If it's got HTTP in the request (HTTP/1.1) then it's HTTP */
    if (memmem(p, len, "HTTP", 4))
        return PROBE_MATCH;

#define PROBE_HTTP_METHOD(opt) if ((res = probe_http_method(p, len, opt)) != PROBE_NEXT) return res

    /* Otherwise it could be HTTP/1.0 without version: check if it's got an
     * HTTP method (RFC2616 5.1.1) */
    PROBE_HTTP_METHOD("OPTIONS");
    PROBE_HTTP_METHOD("GET");
    PROBE_HTTP_METHOD("HEAD");
    PROBE_HTTP_METHOD("POST");
    PROBE_HTTP_METHOD("PUT");
    PROBE_HTTP_METHOD("DELETE");
    PROBE_HTTP_METHOD("TRACE");
    PROBE_HTTP_METHOD("CONNECT");

#undef PROBE_HTTP_METHOD

    return PROBE_NEXT;
}

static int is_tls_protocol(const char *p, int len, struct proto *proto)
{
    if (len < 3)
        return PROBE_AGAIN;

    /* TLS packet starts with a record "Hello" (0x16), followed by version
     * (0x03 0x00-0x03) (RFC6101 A.1)
     * This means we reject SSLv2 and lower, which is actually a good thing (RFC6176)
     */
    return p[0] == 0x16 && p[1] == 0x03 && ( p[2] >= 0 && p[2] <= 0x03);
}

/*
 * Checks if frame starts with <pri> and the priority is a valid syslog value
 */
static int is_valid_syslog_frame_start(const char *p, int len)
{
    const char *ptr=p;
    char ch;
    int priLen=0, priValue=0;

    if (len < 3)    /* must be at least <1> */
        return 0;

    if (*p != '<')
        return 0;
    
    for (priLen=0, ptr++; priLen < len; priLen++, ptr++)
    {
        ch = *ptr;

        /* check if found end delimiter */
        if ('>' == ch)
        {
            if (priLen > 3)
                return 0;   /* syslog priority can have at most 3 digits */
            
            /*
             * The Priority value is calculated by first multiplying the Facility
             * number by 8 and then adding the numerical value of the Severity.
             * We have max. facility value=23 (local7) and max. severity value=7
             * (debug) ==> 23 * 8 + 7 = 191
             */
            return (priValue < 192);
        }
        
        if ((ch < '0') || (ch > '9'))
            return 0;   /* up to the separator they must be digits only */
        
        if ((0 == priLen) && ('0' == ch))
            return !strncmp(p, "<0>", 3);    /* no leading zero is allowed - unless it is '<0>' itself */

        priValue *= 10;     /* make room for next digit */
        priValue += (ch - '0');
    }

    return 0;   // this point is reached if no separator found
}

/* Is the buffer the beginning of an RFC-6857 framed syslog message
 *
 * See:
 * https://tools.ietf.org/html/rfc6587#section-3.4
 * and OpenVPN ssl.c, ssl.h and options.c
 */
static int is_syslog_protocol(const char*p,int len, struct proto *proto)
{
    const char *ptr=p;
    char ch;
    int remainLen=len;

    /* even with octet count framing we should have at least a digit, a space and one character */
    if (len < 3)
        return PROBE_AGAIN;

    if ('<' == *p)  /* is it LF encapsulated frame - most common */
        return is_valid_syslog_frame_start(ptr, remainLen);

    // is it octet count frame encapsulation
    for ( ; remainLen > 0; remainLen--, ptr++)
    {
        ch = *ptr;
        if (' ' == ch)    /* found separator - the rest should be a valid syslog frame */
            return is_valid_syslog_frame_start(ptr + 1, remainLen - 1);
        
        if ((ch < '0') || (ch > '9'))
            return 0;   /* up to the separator they must be digits only */
    }

    return 0;   // this point is reached if no separator found
}

static int regex_probe(const char *p, int len, struct proto *proto)
{
    regex_t **probe = proto->data;
    regmatch_t pos = { 0, len };

    for (; *probe && regexec(*probe, p, 0, &pos, REG_STARTEND); probe++)
        /* try them all */;

    return (*probe != NULL);
}

/* 
 * Read the beginning of data coming from the client connection and check if
 * it's a known protocol. 
 * Return PROBE_AGAIN if not enough data, or PROBE_MATCH if it succeeded in
 * which case cnx->proto is set to the appropriate protocol.
 */
int probe_client_protocol(struct connection *cnx)
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
        int res = PROBE_NEXT;

        defer_write(&cnx->q[1], buffer, n);

        for (p = cnx->proto; p && res == PROBE_NEXT; p = p->next) {
            if (! p->probe) continue;
            if (verbose) fprintf(stderr, "probing for %s\n", p->description);

            cnx->proto = p;
            res = p->probe(cnx->q[1].begin_deferred_data, cnx->q[1].deferred_data_size, p);
        }
        if (res != PROBE_NEXT)
            return res;
    }

    if (verbose) 
        fprintf(stderr, 
                "all probes failed, connecting to first protocol: %s\n", 
                protocols->description);

    /* If none worked, return the first one affected (that's completely
     * arbitrary) */
    cnx->proto = protocols;
    return PROBE_MATCH;
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


