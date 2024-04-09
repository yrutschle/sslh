/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * This is a minimal TLS implementation intended only to parse the server name
 * extension.  This was created based primarily on Wireshark dissection of a
 * TLS handshake and RFC4366.
 */
#include <stdio.h>
#include <stdlib.h> /* malloc() */
#include <fnmatch.h> /* fnmatch() */
#include "tls.h"
#include "sslh-conf.h"
#include "log.h"

#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

typedef struct {
    int tls_match_sni : 1;
    int tls_match_alpn : 1;
} TLS_MATCHMODE;

struct TLSProtocol {
    TLS_MATCHMODE match_mode;
    int sni_list_len;
    const char** sni_hostname_list;
    int alpn_list_len;
    const char** alpn_protocol_list;
};

static int parse_extensions(const struct TLSProtocol *, const char *, size_t);
static int parse_server_name_extension(const struct TLSProtocol *, const char *, size_t);
static int parse_alpn_extension(const struct TLSProtocol *, const char *, size_t);
static int has_match(const char**, size_t, const char*, size_t);

/* Parse a TLS packet for the Server Name Indication and ALPN extension in the client
 * hello handshake, returning a status code
 *
 * Returns:
 * 0: no match
 * 1: match
 *  < 0:  error code (see tls.h)
 */
int
parse_tls_header(const struct TLSProtocol *tls_data, const char *data, size_t data_len) {
    char tls_content_type;
    char tls_version_major;
    char tls_version_minor;
    size_t pos = TLS_HEADER_LEN;
    size_t len;

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return TLS_ELENGTH;

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        print_message(msg_probe_info, "Request did not begin with TLS handshake.\n");
        return TLS_EPROTOCOL;
    }

    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3) {
        print_message(msg_probe_error, "Received SSL %d.%d handshake which cannot be parsed.\n",
              tls_version_major, tls_version_minor);

        return TLS_EVERSION;
    }

    /* TLS record length */
    len = ((unsigned char)data[3] << 8) +
          (unsigned char)data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return TLS_ELENGTH;

    /*
     * Handshake
     */
    if (pos + 1 > data_len) {
        return TLS_EPROTOCOL;
    }
    if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        print_message(msg_probe_error, "Not a client hello\n");

        return TLS_EPROTOCOL;
    }

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    pos += 38;

    /* Session ID */
    if (pos + 1 > data_len)
        return TLS_EPROTOCOL;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return TLS_EPROTOCOL;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return TLS_EPROTOCOL;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        print_message(msg_probe_error, "Received SSL 3.0 handshake without extensions\n");
        return TLS_EVERSION;
    }

    /* Extensions */
    if (pos + 2 > data_len)
        return TLS_EPROTOCOL;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return TLS_EPROTOCOL;

    /* By now we know it's TLS. if SNI or ALPN is set, parse extensions to see if
     * they match. Otherwise, it's a match already */
    if (tls_data && 
        (tls_data->match_mode.tls_match_alpn || tls_data->match_mode.tls_match_sni)) {
        return parse_extensions(tls_data, data + pos, len);
    } else {
        return TLS_MATCH;
    }
}

static int
parse_extensions(const struct TLSProtocol *tls_data, const char *data, size_t data_len) {
    size_t pos = 0;
    size_t len;
    int sni_match = 0, alpn_match = 0;

    if (tls_data == NULL)
        return TLS_EINVAL;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = ((unsigned char) data[pos + 2] << 8) +
              (unsigned char) data[pos + 3];

        if (pos + 4 + len > data_len)
            return TLS_EPROTOCOL;

        size_t extension_type = ((unsigned char) data[pos] << 8) +
                                (unsigned char) data[pos + 1];

        if (extension_type == 0x00 && tls_data->match_mode.tls_match_sni) { /* Server Name */
            sni_match = parse_server_name_extension(tls_data, data + pos + 4, len);
            if (sni_match < 0) return sni_match;
        } else if (extension_type == 0x10 && tls_data->match_mode.tls_match_alpn) { /* ALPN */
            alpn_match = parse_alpn_extension(tls_data, data + pos + 4, len);
            if (alpn_match < 0) return alpn_match;
        }

        pos += 4 + len; /* Advance to the next extension header */
    }

    /* Check we ended where we expected to */
    if (pos != data_len)
        return TLS_EPROTOCOL;

    return (sni_match && alpn_match) 
        || (!tls_data->match_mode.tls_match_sni && alpn_match)
        || (!tls_data->match_mode.tls_match_alpn && sni_match);
}

static int
parse_server_name_extension(const struct TLSProtocol *tls_data, const char *data, size_t data_len) {
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < data_len) {
        len = ((unsigned char)data[pos + 1] << 8) +
              (unsigned char)data[pos + 2];

        if (pos + 3 + len > data_len)
            return TLS_EPROTOCOL;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                if(has_match(tls_data->sni_hostname_list, tls_data->sni_list_len, data + pos + 3, len)) {
                    return (int)len;
                } else {
                    return TLS_ENOEXT;
                }
            default:
                print_message(msg_probe_error, "Unknown server name extension name type: %d\n",
                      data[pos]);
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return TLS_EPROTOCOL;

    return TLS_ENOEXT;
}

static int
parse_alpn_extension(const struct TLSProtocol *tls_data, const char *data, size_t data_len) {
    size_t pos = 2;
    size_t len;

    while (pos + 1 < data_len) {
        len = (unsigned char)data[pos];

        if (pos + 1 + len > data_len)
            return TLS_EPROTOCOL;

        if (len > 0 && has_match(tls_data->alpn_protocol_list, tls_data->alpn_list_len, data + pos + 1, len)) {
            return (int)len;
        } else if (len > 0) {
            print_message(msg_probe_error, "Unknown ALPN name: %.*s\n", (int)len, data + pos + 1);
        }
        pos += 1 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return TLS_EPROTOCOL;

    return TLS_ENOEXT;
}

static int
has_match(const char** list, size_t list_len, const char* name, size_t name_len) {
    const char **item;
    int i;
    char *name_nullterminated = malloc(name_len+1);
    CHECK_ALLOC(name_nullterminated, "malloc");
    memcpy(name_nullterminated, name, name_len);
    name_nullterminated[name_len]='\0';

    for (i = 0; i < list_len; i++) {
        item = &list[i];
        print_message(msg_probe_error, "matching [%.*s] with [%s]\n", (int)name_len, name, *item);
        if(!fnmatch(*item, name_nullterminated, 0)) {
            free(name_nullterminated);
            return 1;
        }
    }
    free(name_nullterminated);
    return 0;
}

struct TLSProtocol *
new_tls_data() {
    struct TLSProtocol *tls_data = malloc(sizeof(struct TLSProtocol));
    CHECK_ALLOC(tls_data, "malloc");

    memset(tls_data, 0, sizeof(*tls_data));

    return tls_data;
}

struct TLSProtocol *
tls_data_set_list(struct TLSProtocol *tls_data, int alpn, const char** list, size_t list_len) {
    if (alpn) {
        tls_data->alpn_protocol_list = list;
        tls_data->alpn_list_len = (int)list_len;
        tls_data->match_mode.tls_match_alpn = 1;
    } else {
        tls_data->sni_hostname_list = list;
        tls_data->sni_list_len = (int)list_len;
        tls_data->match_mode.tls_match_sni = 1;
    }

    return tls_data;
}
