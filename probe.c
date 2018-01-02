/*
# probe.c: Code for probing protocols
#
# Copyright (C) 2007-2015  Yves Rutschle
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
#ifdef ENABLE_REGEX
#ifdef LIBPCRE
#include <pcreposix.h>
#else
#include <regex.h>
#endif
#endif
#include <ctype.h>
#include "probe.h"



static int is_ssh_protocol(const char *p, int len, struct proto*);
static int is_openvpn_protocol(const char *p, int len, struct proto*);
static int is_tinc_protocol(const char *p, int len, struct proto*);
static int is_xmpp_protocol(const char *p, int len, struct proto*);
static int is_http_protocol(const char *p, int len, struct proto*);
static int is_tls_protocol(const char *p, int len, struct proto*);
static int is_adb_protocol(const char *p, int len, struct proto*);
static int is_true(const char *p, int len, struct proto* proto) { return 1; }

/* Table of protocols that have a built-in probe
 */
static struct proto builtins[] = {
    /* description   service  saddr  log_level  keepalive  fork  probe  */
    { "ssh",         "sshd",   NULL,  1,        0,         1,    is_ssh_protocol},
    { "openvpn",     NULL,     NULL,  1,        0,         1,    is_openvpn_protocol },
    { "tinc",        NULL,     NULL,  1,        0,         1,    is_tinc_protocol },
    { "xmpp",        NULL,     NULL,  1,        0,         0,    is_xmpp_protocol },
    { "http",        NULL,     NULL,  1,        0,         0,    is_http_protocol },
    { "ssl",         NULL,     NULL,  1,        0,         0,    is_tls_protocol },
    { "tls",         NULL,     NULL,  1,        0,         0,    is_tls_protocol },
    { "adb",         NULL,     NULL,  1,        0,         0,    is_adb_protocol },
    { "anyprot",     NULL,     NULL,  1,        0,         0,    is_true }
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
            fprintf(stderr, "0x%06x: ", i);

        /* print hex data */
        if(i < len)
            fprintf(stderr, "%02x ", 0xFF & mem[i]);
        else /* end of block, just aligning for ASCII dump */
            fprintf(stderr, "   ");

        /* print ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
                if(j >= len) /* end of block, not really printing */
                    fputc(' ', stderr);
                else if(isprint(mem[j])) /* printable char */
                    fputc(0xFF & mem[j], stderr);
                else /* other char */
                    fputc('.', stderr);
            }
            fputc('\n', stderr);
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
 * Protocol is documented here: http://www.tinc-vpn.org/documentation/tinc.pdf
 * First connection starts with "0 " in 1.0.15)
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
    /* sometimes the word 'jabber' shows up late in the initial string,
       sometimes after a newline. this makes sure we snarf the entire preamble
       and detect it. (fixed for adium/pidgin) */
    if (len < 50)
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

static int is_sni_alpn_protocol(const char *p, int len, struct proto *proto)
{
    int valid_tls;

    valid_tls = parse_tls_header(proto->data, p, len);

    if(valid_tls < 0)
        return -1 == valid_tls ? PROBE_AGAIN : PROBE_NEXT;

    /* There *was* a valid match */
    return PROBE_MATCH;
}

static int is_tls_protocol(const char *p, int len, struct proto *proto)
{
    if (len < 6)
        return PROBE_AGAIN;

    /* TLS packet starts with a record "Hello" (0x16), followed by the number of
     * the highest version of SSL/TLS supported.
     *
     * A SSLv2 record header contains a two or three byte length code. If the
     * most significant bit is set in the first byte of the record length code
     * then the record has no padding and the total header length will be 2
     * bytes,  otherwise the record has padding and the total header length will
     * be 3 bytes. Next, a 1 char sized client-hello (0x01) is expected,
     * followed by a 2 char sized version that indicates the highest version of
     * TLS/SSL supported by the sender. [SSL2] Hickman, Kipp, "The SSL Protocol"
     *
     * We're checking the highest version of TLS/SSL supported against
     * (0x03 0x00-0x03) (RFC6101 A.1). This means we reject the usage of SSLv2
     * and lower, which is actually a good thing (RFC6176).
     */
    if (p[0] == 0x16) // TLS client-hello
        return p[1] == 0x03 && ( p[2] >= 0 && p[2] <= 0x03);
    if ((p[0] & 0x80) != 0) // SSLv2 client-hello, no padding
        return p[2] == 0x01 && p[3] == 0x03 && ( p[4] >= 0 && p[4] <= 0x03);
    else // SSLv2 client-hello, padded
        return p[3] == 0x01 && p[4] == 0x03 && ( p[5] >= 0 && p[5] <= 0x03);
}

static int probe_adb_cnxn_message(const char *p)
{
    /* The initial ADB host->device packet has a command type of CNXN, and a
     * data payload starting with "host:".  Note that current versions of the
     * client hardcode "host::" (with empty serialno and banner fields) but
     * other clients may populate those fields.
     */
    return !memcmp(&p[0], "CNXN", 4) && !memcmp(&p[24], "host:", 5);
}

static int is_adb_protocol(const char *p, int len, struct proto *proto)
{
    /* amessage.data_length is not being checked, under the assumption that
     * a packet >= 30 bytes will have "something" in the payload field.
     *
     * 24 bytes for the message header and 5 bytes for the "host:" tag.
     *
     * ADB protocol:
     * https://android.googlesource.com/platform/system/adb/+/master/protocol.txt
     */
    static const unsigned int min_data_packet_size = 30;

    if (len < min_data_packet_size)
        return PROBE_AGAIN;

    if (probe_adb_cnxn_message(&p[0]) == PROBE_MATCH)
        return PROBE_MATCH;

    /* In ADB v26.0.0 rc1-4321094, the initial host->device packet sends an
     * empty message before sending the CNXN command type. This was an
     * unintended side effect introduced in
     * https://android-review.googlesource.com/c/342653, and will be reverted for
     * a future release.
     */
    static const unsigned char empty_message[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
    };

    if (len < min_data_packet_size + sizeof(empty_message))
        return PROBE_AGAIN;

    if (memcmp(&p[0], empty_message, sizeof(empty_message)))
        return PROBE_NEXT;

    return probe_adb_cnxn_message(&p[sizeof(empty_message)]);
}

static int regex_probe(const char *p, int len, struct proto *proto)
{
#ifdef ENABLE_REGEX
    regex_t **probe = proto->data;
    regmatch_t pos = { 0, len };

    for (; *probe && regexec(*probe, p, 0, &pos, REG_STARTEND); probe++)
        /* try them all */;

    return (*probe != NULL);
#else
    /* Should never happen as we check when loading config file */
    fprintf(stderr, "FATAL: regex probe called but not built in\n");
    exit(5);
#endif
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

    /* Dump hex values of the packet */
    if (verbose>1) {
        fprintf(stderr, "hexdump of incoming packet:\n");
        hexdump(buffer, n);
    }

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

    /* Special case of "sni/alpn" probe for same reason as above*/
    if (!strcmp(description, "sni_alpn"))
        return is_sni_alpn_protocol;

    /* Special case of "timeout" is allowed as a probe name in the
     * configuration file even though it's not really a probe */
    if (!strcmp(description, "timeout"))
        return is_true;

    return NULL;
}


