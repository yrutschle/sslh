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


/* Appends a configuration to the DNS configuration file */
static void append_conf(const char* sni, const char* ech)
{
    FILE* f = fopen(cfg.ech_conf_sink, "a");

    if (!f) {
        print_message(msg_config_error, "Unable to open %s:%d:%s\n", cfg.ech_conf_sink, errno, strerror(errno));
        return;
    }

    int res = fprintf(f, "%s IN HTTPS 1 . alpn=\"h2\" ech=\"%s\"\n", sni, ech);
    printf("append: %s IN HTTPS 1 . alpn=\"h2\" ech=\"%s\" : %d\n", sni, ech, res);

    fclose(f);
}


/* Erases the configuration file */
static void reset_conf(void)
{
    FILE* f = fopen(cfg.ech_conf_sink, "w");

    if (!f) {
        print_message(msg_config_error, "Unable to open %s:%d:%s\n", cfg.ech_conf_sink, errno, strerror(errno));
        return;
    }


    printf("erased and opend %s\n", cfg.ech_conf_sink);
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

    append_conf(sni, out);
}

/* For each public names, create a keypair and configuration.
 * (Later, this will load the configurations from some place else */
static void ech_create_configs(WOLFSSL_CTX** ctx)
{
    int i, j;

    reset_conf();

    for (i = 0; i < cfg.listen_len; i++) {
        struct sslhcfg_protocols_item* listen = &cfg.listen[i];
        printf("1\n");
        *ctx = malloc(cfg.listen_len * sizeof(*ctx));
        /* TODO deal with malloc failure */
        printf("2\n");

        ctx[i] = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
        if (!ctx[i]) {
            print_message(msg_system_error, "Failed to create WOLFSSL_CTX\n");
            exit(1);
        }

        printf("3\n");
        ech_genkey(ctx[i], cfg.listen[i].host);
        printf("4\n");
    }

}


/* Initialises the ECH subsystem: create wolfSSL context, create ECH configs,
 * etc */
void ech_init()
{
    WOLFSSL_CTX* ctx = NULL;

    wolfSSL_Init();

    ech_create_configs(&ctx);
}
