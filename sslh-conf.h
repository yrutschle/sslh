/* Generated by conf2struct (https://www.rutschle.net/tech/conf2struct/README)
 * on Mon Feb 24 18:37:24 2025. 

# conf2struct: generate libconf parsers that read to structs
# Copyright (C) 2018-2024  Yves Rutschle
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

*/
 
#ifndef C2S_SSLHCFG_H
#define C2S_SSLHCFG_H
#ifdef LIBCONFIG
#    include <libconfig.h>
#endif


#include "probe.h"
#include  <sys/types.h>
#include  <sys/socket.h>
#include  <netdb.h>

struct sslhcfg_listen_item {
	char*	host;
	char*	port;
	int	is_udp;
	int	is_unix;
	int	keepalive;
};

struct sslhcfg_protocols_item {
	char*	name;
	char*	host;
	char*	port;
	int	service_is_present;
	char*	service;
	int	is_unix;
	int	is_udp;
	int	udp_timeout;
	int	fork;
	int	tfo_ok;
	int	transparent;
	int	resolve_on_forward;
	int	log_level;
	int	keepalive;
	size_t	sni_hostnames_len;
	char** sni_hostnames;
	size_t	alpn_protocols_len;
	char** alpn_protocols;
	size_t	regex_patterns_len;
	char** regex_patterns;
	int	minlength_is_present;
	int	minlength;
	int	proxyprotocol_is_present;
	int	proxyprotocol;
	T_PROBE*	probe;
	struct addrinfo*	saddr;
	void*	data;
	dl_list	timeouts;
};

struct sslhcfg_item {
	int	verbose;
	int	verbose_config;
	int	verbose_config_error;
	int	verbose_connections;
	int	verbose_connections_try;
	int	verbose_connections_error;
	int	verbose_fd;
	int	verbose_packets;
	int	verbose_probe_info;
	int	verbose_probe_error;
	int	verbose_system_error;
	int	verbose_int_error;
	int	version;
	int	foreground;
	int	inetd;
	int	numeric;
	int	transparent;
	int	timeout;
	int	udp_max_connections;
	int	user_is_present;
	char*	user;
	int	pidfile_is_present;
	char*	pidfile;
	int	chroot_is_present;
	char*	chroot;
	char*	syslog_facility;
	int	logfile_is_present;
	char*	logfile;
	char*	on_timeout;
	char*	prefix;
	size_t	listen_len;
	struct sslhcfg_listen_item* listen;
	size_t	protocols_len;
	struct sslhcfg_protocols_item* protocols;
};

int sslhcfg_parse_file(
        const char* filename,
        struct sslhcfg_item* sslhcfg, 
        const char** errmsg);

void sslhcfg_fprint(
    FILE* out,
    struct sslhcfg_item *sslhcfg,
    int depth);

int sslhcfg_cl_parse(
    int argc,
    char* argv[],
    struct sslhcfg_item *sslhcfg);

#endif
