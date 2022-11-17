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
 * This is a minimal HTTP implementation intended only to parse the host name of a
 * request
 */
#include <stdio.h>
#include <stdlib.h> /* malloc() */
#include <fnmatch.h> /* fnmatch() */
#include "http.h"
#include "sslh-conf.h"
#include "log.h"

#define HTTP_HEADER_LEN 5

typedef struct {
    int http_match_hostname : 1;
} TLS_MATCHMODE;

struct HTTPProtocol {
    TLS_MATCHMODE match_mode;
    int hostname_list_len;
    const char** hostname_list;
};

static int has_match(const char **, size_t, const char *, size_t);
static int parse_hostname(const struct HTTPProtocol *tls_data, const char *data, size_t data_len);
static int probe_http_method(const char *p, int len, const char *opt);

/* Parse a HTTP header for request hostname, returning a status code
 *
 * Returns:
 * 0: no match
 * 1: match
 *  < 0:  error code (see http.h)
 */
int
parse_http_header(const struct HTTPProtocol *http_data, const char *data, size_t data_len) {

    /* If it does not have HTTP in the request (HTTP/1.1) then lets check for the method */
    if (memmem(data, data_len, "HTTP", 4) == NULL) {
        int res;
#define PROBE_HTTP_METHOD(opt) if ((res = probe_http_method(data, data_len, opt)) != HTTP_NOMATCH) return res

        /* it could be HTTP/1.0 without version: check if it's got an
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

        // if neither match, this isnt a HTTP request
        return HTTP_NOMATCH;
    }

    /* By now we know it's HTTP. if hostname is set, parse request to see if
     * they match. Otherwise, it's a match already */
    if (http_data && 
        (http_data->match_mode.http_match_hostname || http_data->match_mode.http_match_hostname)) {
        return parse_hostname(http_data, data, data_len);
    } else {
        return HTTP_MATCH;
    }
}

static int
parse_hostname(const struct HTTPProtocol *http_data, const char *data, size_t data_len)
{
    if (http_data == NULL)
        return HTTP_EINVAL;
    
    // see if already have the hostname
    const char *start = memmem(data, data_len, "Host: ", 6);
    if (start != NULL)
    {
        start += 6;

        const char *end = memchr(start, '\r', data_len - (start - data));
        // if we have the end, we are ready to parse it
        if (end != NULL)
        {
            return has_match(http_data->hostname_list, http_data->hostname_list_len, start, end - start);
        }
    }
    else if (
        // or if we have already reached the end of the request
        memmem(data, data_len, "\r\n\r\n", 4)
    )
    {
        // no host informaiton available for this request
        return HTTP_ENOHOST;
    }

    return HTTP_ELENGTH;
}

static int 
probe_http_method(const char *p, int len, const char *opt)
{
    if (len < strlen(opt))
        return HTTP_ELENGTH;

    return !strncmp(p, opt, strlen(opt));
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

struct HTTPProtocol *
new_http_data() {
    struct HTTPProtocol *http_data = malloc(sizeof(struct HTTPProtocol));
    CHECK_ALLOC(http_data, "malloc");

    memset(http_data, 0, sizeof(*http_data));

    return http_data;
}

struct HTTPProtocol *
http_data_set_list(struct HTTPProtocol *http_data, const char** list, size_t list_len) {
    http_data->hostname_list = list;
    http_data->hostname_list_len = list_len;
    http_data->match_mode.http_match_hostname = 1;
    return http_data;
}
