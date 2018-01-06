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

#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif


struct TLSProtocol {
    int use_alpn;
    char** sni_hostname_list;
    char** alpn_protocol_list;
};

static int parse_extensions(const struct TLSProtocol *, const char *, size_t);
static int parse_server_name_extension(const struct TLSProtocol *, const char *, size_t);
static int parse_alpn_extension(const struct TLSProtocol *, const char *, size_t);
static int has_match(char**, const char*, size_t);

/* Parse a TLS packet for the Server Name Indication and ALPN extension in the client
 * hello handshake, returning a status code
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  < -4 - Invalid TLS client hello
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
        return -1;

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        if (verbose) fprintf(stderr, "Request did not begin with TLS handshake.\n");
        return -5;
    }

    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3) {
        if (verbose) fprintf(stderr, "Received SSL %d.%d handshake which cannot be parsed.\n",
              tls_version_major, tls_version_minor);

        return -2;
    }

    /* TLS record length */
    len = ((unsigned char)data[3] << 8) +
          (unsigned char)data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return -1;

    /*
     * Handshake
     */
    if (pos + 1 > data_len) {
        return -5;
    }
    if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        if (verbose) fprintf(stderr, "Not a client hello\n");

        return -5;
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
        return -5;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return -5;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return -5;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        if (verbose) fprintf(stderr, "Received SSL 3.0 handshake without extensions\n");
        return -2;
    }

    /* Extensions */
    if (pos + 2 > data_len)
        return -5;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return -5;
    return parse_extensions(tls_data, data + pos, len);
}

static int
parse_extensions(const struct TLSProtocol *tls_data, const char *data, size_t data_len) {
    size_t pos = 0;
    size_t len;
    int last_matched = 0;

    if (tls_data == NULL)
        return -3;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        len = ((unsigned char) data[pos + 2] << 8) +
              (unsigned char) data[pos + 3];

        if (pos + 4 + len > data_len)
            return -5;

        size_t extension_type = ((unsigned char) data[pos] << 8) +
                                (unsigned char) data[pos + 1];


        /* Check if it's a server name extension */
        /* There can be only one extension of each type, so we break
           our state and move pos to beginning of the extension here */
        if (tls_data->use_alpn == 2) {
            /* we want BOTH alpn and sni to match */
            if (extension_type == 0x00) { /* Server Name */
                if (parse_server_name_extension(tls_data, data + pos + 4, len)) {
                    /* SNI matched */
                    if(last_matched) {
                        /* this is only true if ALPN matched, so return true */
                        return last_matched;
                    } else {
                        /* otherwise store that SNI matched */
                        last_matched = 1;
                    }
                } else {
                    /* both can't match */
                    return -2;
                }
            } else if (extension_type == 0x10) { /* ALPN */
                if (parse_alpn_extension(tls_data, data + pos + 4, len)) {
                    /* ALPN matched */
                    if(last_matched) {
                        /* this is only true if SNI matched, so return true */
                        return last_matched;
                    } else {
                        /* otherwise store that ALPN matched */
                        last_matched = 1;
                    }
                } else {
                    /* both can't match */
                    return -2;
                }
            }

        } else if (extension_type == 0x00 && tls_data->use_alpn == 0) { /* Server Name */
            return parse_server_name_extension(tls_data, data + pos + 4, len);
        } else if (extension_type == 0x10 && tls_data->use_alpn == 1) { /* ALPN */
            if (parse_alpn_extension(tls_data, data + pos + 4, len) > 0) {
                return 1;
            }
            return parse_alpn_extension(tls_data, data + pos + 4, len);
        }

        pos += 4 + len; /* Advance to the next extension header */
    }

    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static int
parse_server_name_extension(const struct TLSProtocol *tls_data, const char *data, size_t data_len) {
    size_t pos = 2; /* skip server name list length */
    size_t len;

    while (pos + 3 < data_len) {
        len = ((unsigned char)data[pos + 1] << 8) +
              (unsigned char)data[pos + 2];

        if (pos + 3 + len > data_len)
            return -5;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                if(has_match(tls_data->sni_hostname_list, data + pos + 3, len)) {
                    return len;
                } else {
                    return -2;
                }
            default:
                if (verbose) fprintf(stderr, "Unknown server name extension name type: %d\n",
                      data[pos]);
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static int
parse_alpn_extension(const struct TLSProtocol *tls_data, const char *data, size_t data_len) {
    size_t pos = 2;
    size_t len;

    while (pos + 1 < data_len) {
        len = (unsigned char)data[pos];

        if (pos + 1 + len > data_len)
            return -5;

        if (len > 0 && has_match(tls_data->alpn_protocol_list, data + pos + 1, len)) {
            return len;
        } else if (len > 0) {
            if (verbose) fprintf(stderr, "Unknown ALPN name: %.*s\n", (int)len, data + pos + 1);
        }
        pos += 1 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static int
has_match(char** list, const char* name, size_t name_len) {
    char **item;
    char *name_nullterminated = malloc(name_len+1);
    memcpy(name_nullterminated, name, name_len);
    name_nullterminated[name_len]='\0';

    for (item = list; *item; item++) {
        if (verbose) fprintf(stderr, "matching [%.*s] with [%s]\n", (int)name_len, name, *item);
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
    if (tls_data != NULL) {
        tls_data->use_alpn = -1;
    }

    return tls_data;
}

struct TLSProtocol *
tls_data_set_list(struct TLSProtocol *tls_data, int alpn, char** list) {
    if (alpn) {
        tls_data->alpn_protocol_list = list;
        if(tls_data->use_alpn == 0)
            tls_data->use_alpn = 2;
        else
            tls_data->use_alpn = 1;
    } else {
        tls_data->sni_hostname_list = list;
        if(tls_data->use_alpn == 1)
            tls_data->use_alpn = 2;
        else
            tls_data->use_alpn = 0;
    }

    return tls_data;
}
