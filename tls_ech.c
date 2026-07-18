/*
# tls_ech.c: support for RFC9849 TLS Encrypted Client Hello (ECH)
#
# Copyright (C) 2026  Yves Rutschle
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

#define WOLFSSL_USE_OPTION_H
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "log.h"
#include "sslh-conf.h"


void ech_get_client_hello_inner(const char* data, size_t datalen)
{
#if 0
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "Failed to create WOLFSSL object\n");
        close(client_fd);
        return;
    }
 
    // Disable certificate verification on this connection
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);


    char* sni_data = NULL;
    word16 sni_len = wolfSSL_SNI_GetRequest(ssl, WOLFSSL_SNI_HOST_NAME, (void**)&sni_data);
#endif
}

void ech_match_sni(void)
{
}

/* Generate a keypair for a config; later this will be moved to a separate
 * process, and sslh will just read it */
static void ech_genkey(WOLFSSL_CTX* ctx, const char* sni)
{
    int ret;

    print_message(msg_config, "Generating ECH config for outer SNI: %s\n", sni);
    ret = wolfSSL_CTX_GenerateEchConfig(ctx, sni, 0, 0, 0);
    if (ret != WOLFSSL_SUCCESS) {
        print_message(msg_system_error, "Failed to generate ECH config: %d\n", ret);
        exit(1);
    }

    byte echConfig[512];
    word32 echConfigLen = sizeof(echConfig);
    ret = wolfSSL_CTX_GetEchConfigs(ctx, echConfig, &echConfigLen);
    if (ret != WOLFSSL_SUCCESS) {
        print_message(msg_system_error, "Failed to get ECH config: %d\n", ret);
        exit(1);
    }

    char out[512];
    int outLen = sizeof(out);
    if (Base64_Encode_NoNl(echConfig, echConfigLen, (byte*)out, &outLen) != 0) {
        print_message(msg_system_error, "Failed to encode to base64: %d\n", ret);
        exit(1);
    }

    print_message(msg_config, "%s. IN HTTPS 1 . alpn=\"h2\" ech=\"%s\"\n", sni, out);

}


/* For all server names, create a keypair and configuration.
 * (Later, this will load the configurations from some place else */
static void ech_load_configs(WOLFSSL_CTX* ctx)
{
    int i, j;

    for (i = 0; i < cfg.protocols_len; i++) {
        struct sslhcfg_protocols_item* prot = &cfg.protocols[i];
        prot->wolfssl_ctx = malloc(prot->sni_hostnames_len * sizeof(prot->wolfssl_ctx[0]));
        /* TODO deal with malloc failure */

        for  (j = 0; j < prot->sni_hostnames_len; j++) {
            prot->wolfssl_ctx[j] = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
            if (prot->wolfssl_ctx[j] == NULL) {
                print_message(msg_system_error, "Failed to create WOLFSSL_CTX\n");
                exit(1);
            }

            ech_genkey(prot->wolfssl_ctx[j], prot->sni_hostnames[j]);
        }
    }

}


/* Initialises the ECH subsystem: create wolfSSL context, create ECH configs,
 * etc */
void ech_init()
{

    wolfSSL_Init();

    ech_load_configs(NULL);
}
