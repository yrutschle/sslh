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


#include "config.h"
#include "log.h"
#include "sslh-conf.h"
#include "tls.h"

WOLFSSL_CTX* wolfssl_ctx;


// Hard-coded server certificate (PEM format)
// from snakeoil -- these serves no purpose beyond initialising the context
static const char* SERVER_CERT_PEM = 
"-----BEGIN CERTIFICATE-----\n"
"MIICyjCCAbKgAwIBAgIUZrCzD4tEIu1r9EhkOn96raiupe4wDQYJKoZIhvcNAQEL\n"
"BQAwDzENMAsGA1UEAwwEc2FhejAeFw0yMTA1MjgyMDM0MjRaFw0zMTA1MjYyMDM0\n"
"MjRaMA8xDTALBgNVBAMMBHNhYXowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
"AoIBAQC5s1UhjcmsrRnSdJMH82NxRQ3hlwMxGZz5NnI0MukXN5kptAYSge4BQc6J\n"
"MAL1MbPtX0pfR+yBILWUdn6JCnDqhv9ipO8OpeVeh+RKa2kGiEdeoQhBbKNZdsoe\n"
"gD9FE3lE895GIhEv7Jd9bt/r8CcCpmOLuhJF6md0cLWGPrAp4l+iCV/ixyE0z0bK\n"
"fJzuOxi7oIeINLEiR0Z4hJsM2XAEXlBEsI4oh2KdDJiU6ow3w25IY7+/nYVDDLD2\n"
"QFMByfkEmAGp9Br+2tquRUmR8qmSvZPMtWpOzMv8+iKTrxUcAUCtCpDMjHqNR8fd\n"
"6G6TLenPbQPEaac5UgGZ7rJvL9idAgMBAAGjHjAcMAkGA1UdEwQCMAAwDwYDVR0R\n"
"BAgwBoIEc2FhejANBgkqhkiG9w0BAQsFAAOCAQEAZPasi1Hu7q4S9wJsbIzcGj7m\n"
"ZCAxNdm3AINeV3mxfhToeqtXSoa2sujCEgwCuiYi0OE8wmseLO8e1xIsRc/NEpOl\n"
"h9u5OupV2Xbf7nuKzPl31YQ7kv+90mnixizf6CFpHXAdU3WEZ33+fMtS+lV/ZBYo\n"
"Nh9GGNJ7Grv5KIKu/b2cR403pRF1hGrjWABrIDZO3ZCtNgRp/My1Qr+/04rTs8VF\n"
"WyDshOe0u6Xo//M3sCMbx5+62BopCMmAu2TxiPew0OTM8eDa3IBbc2kLGxp8c4J+\n"
"EYpAKTZbkhs/6SleNMC4BOEmZQ1tk6D0N0u4Y0b1IKEjgx7HqwZ6mIdmbU1lZQ==\n"
"-----END CERTIFICATE-----\n";

static const char* SERVER_KEY_PEM = 
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC5s1UhjcmsrRnS\n"
"dJMH82NxRQ3hlwMxGZz5NnI0MukXN5kptAYSge4BQc6JMAL1MbPtX0pfR+yBILWU\n"
"dn6JCnDqhv9ipO8OpeVeh+RKa2kGiEdeoQhBbKNZdsoegD9FE3lE895GIhEv7Jd9\n"
"bt/r8CcCpmOLuhJF6md0cLWGPrAp4l+iCV/ixyE0z0bKfJzuOxi7oIeINLEiR0Z4\n"
"hJsM2XAEXlBEsI4oh2KdDJiU6ow3w25IY7+/nYVDDLD2QFMByfkEmAGp9Br+2tqu\n"
"RUmR8qmSvZPMtWpOzMv8+iKTrxUcAUCtCpDMjHqNR8fd6G6TLenPbQPEaac5UgGZ\n"
"7rJvL9idAgMBAAECggEAbXNQctViD596/7rryhze+KztsI/UNsVU6uH3T+LN1XxU\n"
"jurnRVNFV4JU3DDrHV9tIDQw3pXCxJzlyRpKHDWGNgTZU2fI6sZGuX+4w1Apd8ss\n"
"3Y5mEkGYyaslF/MY13rR2B0wXf/IR4nYA/ssiaBjLcGqHHnQOVseHNgtdXFPXW9n\n"
"5IXJ2PSeaFW0Z13vbTQm9Cx2kCBKL4J3TymhkuSW3DUHxmlDfWUK14lkyXCZIZ3i\n"
"TbXQAXhwTrz3wqbG++iEP4MZM0Ka7/+WXqrsxA/yCirb+HnMewxwBKzGvkym2I2H\n"
"3BkjDn9exDgTePD7i0w22UYCF5uezDB9YOiPVZ634QKBgQDyKIgxD7XMMJezeg0Y\n"
"PaG+Eig/hE27mm2pyTQSd6MMZ1HpbDUpLQ/GO3Npy+bKS0/5eefNT4PWVcmpRL4W\n"
"blNIfixkcZq1a6wax9Nhk89jXZdhBinO8gfXFOiANFDS7B4fEXeTrfhmuryqUw9m\n"
"L6GJ0jk/H6fs6ads15y+O7A6tQKBgQDEUKlZg4qXxNMNKq7l+v7R6IH8VrNLt0I/\n"
"f4fhpW3IhmPJCRuOFOS0UpDPYjTeu14i3EFcpe0D+DVoQiggBTAh3I/qMHvRko5g\n"
"DT83YHp2/ec0AY0ocwnLwye224t6GF7S8R8vhG1FkIBk6DTJgWFZLDtY+dekZugz\n"
"IHvgtxSPSQKBgHWD7fPBJ/xbaIMUq94jqqZOsXGBhyePncBTgA2mOV3/leStOm8t\n"
"CwasOyoQZYOuYLU0z6T2/Ye6Qg7+6TCBgbEgafKknuuDwRWN+6rSzEXwWVIgZ5Gi\n"
"KuPZparxuHdjVorFMz5borxXys7tV//DBaWYe2eCuT9jdHiBefNni/IxAoGAWHTn\n"
"+deVqVEcsAAdkq8IBtk3SNZgL6vBhA8Y0QnTb9luOPWLnve3HbFeYrOjkwDmJ9sK\n"
"8I4rP/ClT/cPUW5FA9z4U9PI1uOsl4cghvlH9Tnu5bYVPranIVMsH+7I6Bj3ESFo\n"
"peaLvh6gW9dtgaZ0kNOnYi4hhoh/9Bmc9+JGt1ECgYAbGSQLa21L4Hx3NvMparVQ\n"
"bGjN26igvqKmhBaKrH8YolOlhEw/mCwTlg9zI7jrhdO0VClPrB8IVBoL+6HvrT21\n"
"LJM31J3ddqME9/5fQgKMQsD60kRDD6iV/iK2S6TOUjxJn1f6MuLmGSOHZYcbdBPZ\n"
"DyBKgbz/xGV6katjXvg74A==\n"
"-----END PRIVATE KEY-----\n";



#if 1
/* Will be provided by wolfSSL */
int  wolfSSL_GetEchClientHelloInner(
        WOLFSSL* ssl,      /* Connected to an existing context with the ECH configs. Stores hpke state */
        const byte* buffer_in,   /* The full ClientHelloOuter */
        word32 buffer_len, /* How many bytes in the buffer */
        byte* buffer_out,
        word32* buffer_out_len
        )
{
    char* inner = "some clienthelloinner";

    *buffer_out_len = strlen(inner);
    memcpy(buffer_out, inner, *buffer_out_len);
    print_message(msg_fd, "GetEchClientHelloInner set\n");
    return 0;
}
#endif


void ech_get_client_hello_inner(WOLFSSL_CTX* ctx, const byte* data, size_t datalen)
{
    WOLFSSL* ssl = NULL;

    printf("wolfSSL_new(%p)\n", ctx);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "Failed to create WOLFSSL object\n");
        return;
    }
 
    // Disable certificate verification on this connection
    wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, NULL);

    byte client_hello_inner[1024];
    word32 ch_len = sizeof(client_hello_inner);;

    int res = wolfSSL_GetEchClientHelloInner(
        ssl,
        data,   /* The full ClientHelloOuter */
        datalen, /* How many bytes in the buffer */
        (byte*)&client_hello_inner,
        &ch_len
        );
    client_hello_inner[ch_len] = 0;
    if (!res) {
        print_message(msg_fd, "GetEchClientHelloInner: Innerlen: %d\n", ch_len);
        hexdump(msg_fd, (char*)client_hello_inner, ch_len);
        print_message(msg_fd, "/GetEchClientHelloInner\n");
    }


    byte sni_data[1024];
    unsigned int sni_len = sizeof(sni_data);
    memset(sni_data, 'A', sni_len);

    printf("SNI_GetFromBuffer\n");
    wolfSSL_SNI_GetFromBuffer(data, datalen, 0, (byte*)&sni_data, &sni_len);
    sni_data[sni_len] = 0;
    printf("sni_len = %d\n", sni_len);
    printf("sni: %s\n", sni_data);
}

/* See if the context matches */
void ech_match_sni(const char* buffer_in, size_t buffer_len)
{
    ech_get_client_hello_inner(wolfssl_ctx, (byte*)buffer_in, buffer_len);
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

    printf("ech_genkey for ctx %p\n", ctx);

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
    word32 outLen = sizeof(out);
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
    int ret;

    reset_conf();

    *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!*ctx) {
        print_message(msg_system_error, "Failed to create WOLFSSL_CTX\n");
        exit(1);
    }
    
    // Load certificate from memory
    ret = wolfSSL_CTX_use_certificate_buffer(*ctx, 
                                             (const unsigned char*)SERVER_CERT_PEM,
                                             strlen(SERVER_CERT_PEM),
                                             WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load certificate: %d\n", ret);
        fprintf(stderr, "Please replace SERVER_CERT_PEM with a valid certificate\n");
        wolfSSL_CTX_free(*ctx);
        exit(1);
    }
    
    // Load private key from memory
    ret = wolfSSL_CTX_use_PrivateKey_buffer(*ctx,
                                            (const unsigned char*)SERVER_KEY_PEM,
                                            strlen(SERVER_KEY_PEM),
                                            WOLFSSL_FILETYPE_PEM);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "Failed to load private key: %d\n", ret);
        fprintf(stderr, "Please replace SERVER_KEY_PEM with a valid private key\n");
        wolfSSL_CTX_free(*ctx);
        exit(1);
    }
    
    printf("Certificate and key loaded successfully\n");

    ech_genkey(*ctx, cfg.listen[0].host);  /* For now this only works on the first host */
}



/* Initialises the ECH subsystem: create wolfSSL context, create ECH configs,
 * etc */

void ech_init()
{
    wolfSSL_Init();

    ech_create_configs(&wolfssl_ctx);
}
