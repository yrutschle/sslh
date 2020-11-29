/*
   sslh-fork: forking server

# Copyright (C) 2007-2021  Yves Rutschle
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

#include "common.h"
#include "probe.h"
#include "sslh-conf.h"

#ifdef LIBBSD
#include <bsd/unistd.h>
#endif

const char* server_type = "sslh-fork";

#define MAX(a, b)  (((a) > (b)) ? (a) : (b))

/* shovels data from one fd to the other and vice-versa 
   returns after one socket closed
 */
int shovel(struct connection *cnx)
{
   fd_set fds;
   int res, i;
   int max_fd = MAX(cnx->q[0].fd, cnx->q[1].fd) + 1;

   FD_ZERO(&fds);
   while (1) {
      FD_SET(cnx->q[0].fd, &fds);
      FD_SET(cnx->q[1].fd, &fds);

      res = select(
                   max_fd,
                   &fds,
                   NULL,
                   NULL,
                   NULL
                  );
      CHECK_RES_DIE(res, "select");

      for (i = 0; i < 2; i++) {
          if (FD_ISSET(cnx->q[i].fd, &fds)) {
              res = fd2fd(&cnx->q[1-i], &cnx->q[i]);
              if (!res) {
                  if (cfg.verbose) 
                      fprintf(stderr, "%s %s", i ? "client" : "server", "socket closed\n");
                  return res;
              }
          }
      }
   }
}

/* Child process that finds out what to connect to and proxies 
 */
void start_shoveler(int in_socket)
{
   fd_set fds;
   struct timeval tv;
   int res = PROBE_AGAIN;
   int out_socket;
   struct connection cnx;
   struct connection_desc desc;

   init_cnx(&cnx);
   cnx.q[0].fd = in_socket;

   FD_ZERO(&fds);
   FD_SET(in_socket, &fds);
   memset(&tv, 0, sizeof(tv));
   tv.tv_sec = cfg.timeout;

   while (res == PROBE_AGAIN) {
       /* POSIX does not guarantee that tv will be updated, but the client can
        * only postpone the inevitable for so long */
       res = select(in_socket + 1, &fds, NULL, NULL, &tv);
       if (res == -1)
           perror("select");

       if (FD_ISSET(in_socket, &fds)) {
           /* Received data: figure out what protocol it is */
           res = probe_client_protocol(&cnx);
       } else {
           /* Timed out: it's necessarily SSH */
           cnx.proto = timeout_protocol();
           if (cfg.verbose) 
               log_message(LOG_INFO, "timed out, connect to %s\n", cnx.proto->name);
           break;
       }
   }

   if (cnx.proto->service &&
       check_access_rights(in_socket, cnx.proto->service)) {
       exit(0);
   }

   /* Connect the target socket */
   out_socket = connect_addr(&cnx, in_socket);
   CHECK_RES_DIE(out_socket, "connect");

   cnx.q[1].fd = out_socket;

   get_connection_desc(&desc, &cnx);
   log_connection(&desc, &cnx);
   set_proctitle_shovel(&desc, &cnx);

   flush_deferred(&cnx.q[1]);

   shovel(&cnx);

   close(in_socket);
   close(out_socket);
   
   if (cfg.verbose)
      fprintf(stderr, "connection closed down\n");

   exit(0);
}

static pid_t *listener_pid;
static int listener_pid_number = 0;

void stop_listeners(int sig)
{
    int i;

    for (i = 0; i < listener_pid_number; i++) {
        kill(listener_pid[i], sig);
    }
}

void set_listen_procname(struct listen_endpoint *listen_socket)
{
#ifdef LIBBSD
    int res;
    struct addrinfo addr;
    struct sockaddr_storage ss;
    char listen_addr[NI_MAXHOST+1+NI_MAXSERV+1];

    addr.ai_addr = (struct sockaddr*)&ss;
    addr.ai_addrlen = sizeof(ss);
    res = getsockname(listen_socket->socketfd, addr.ai_addr, &addr.ai_addrlen);
    if (res != -1) {
        sprintaddr(listen_addr, sizeof(listen_addr), &addr);
        setproctitle("listener %s", listen_addr);
    }
#endif
}


/* TCP listenedr: connections, fork a child for each new connection 
 * IN: 
 *      endpoint: array of listening endpoint objects
 *      num_endpoints: size of endpoint array
 *      active_endpoint: which endpoint is this listener working on
 * Does not return
 * */
void tcp_listener(struct listen_endpoint* endpoint, int num_endpoints, int active_endpoint)
{
    int i, in_socket;

    while (1) {
        in_socket = accept(endpoint[active_endpoint].socketfd, 0, 0);
        if (cfg.verbose) fprintf(stderr, "accepted fd %d\n", in_socket);

        switch(fork()) {
        case -1: log_message(LOG_ERR, "fork failed: err %d: %s\n", errno, strerror(errno));
                 break;

        case 0: /* In child process */
                 /* Shoveler processes don't need to hog file descriptors */
                 for (i = 0; i < num_endpoints; ++i)
                     close(endpoint[i].socketfd);
                 start_shoveler(in_socket);
                 exit(0);

        default: /* In parent process */
                 break;
        }
        close(in_socket);
    }
}

/* UDP support types and stuff */
struct known_udp_source {
    int allocated;
    struct sockaddr sockaddr;
    socklen_t addrlen;
    time_t last_active;

    struct sslhcfg_protocols_item* proto; /* Where to connect it to */
    /* We need one local socket for each target server, so we know where to
     * forward server responses */
    int target_sock;  
};


/* Find if the specified source has been seen before. -1 if not found
 *
 * TODO This is linear search and needs to be changed to something better for
 * production if we have more than a dozen sources
 * Also, this assumes src_addr from recvfrom() are repeatable for a specific
 * source...
 * */
int known_source(struct known_udp_source* ks, int ks_len, struct sockaddr* addr, socklen_t addrlen)
{
    int i;

    for (i = 0; i < ks_len; i++) {
        if (ks[i].allocated) {
            if (!memcmp(&ks[i].sockaddr, addr, addrlen)) {
                return i;
            }
        }
    }
    return -1;
}

int get_empty_source(struct known_udp_source* ks, int ks_len)
{
    int i;
    for (i = 0; i < ks_len; i++)
        if (!ks[i].allocated) return i;
    return -1;
}

/* TODO: Make that dynamic... */
#define MAX_UDP_SRC 1024
/* Array to keep the UDP sources we have seen before */
struct known_udp_source udp_known_sources[MAX_UDP_SRC];

/* UDP listener: upon incoming packet, find where it should go */
void udp_listener(struct listen_endpoint* endpoint, int num_endpoints, int active_endpoint)
{
    char data[65536]; /* TODO what's right, here? */
    char addr_str[NI_MAXHOST+1+NI_MAXSERV+1];
    struct sockaddr src_addr;
    struct addrinfo addrinfo;
    struct known_udp_source* src;
    ssize_t len;
    socklen_t addrlen;
    int i, res, target;

    while (1) {
        fprintf(stderr, "recvfrom(%d)\n", getpid());
        addrlen = sizeof(src_addr);
        len = recvfrom(endpoint[active_endpoint].socketfd, data, sizeof(data), 0, &src_addr, &addrlen);
        if (len < 0) {
            perror("recvfrom");
            continue;
        }
        target = known_source(udp_known_sources, ARRAY_SIZE(udp_known_sources), 
                              &src_addr, addrlen);
        addrinfo.ai_addr = &src_addr;
        addrinfo.ai_addrlen = addrlen;
        if (cfg.verbose) 
            fprintf(stderr, "received %d UDP from %d:%s\n", len, target, sprintaddr(addr_str, sizeof(addr_str), &addrinfo));
        if (target == -1) {
            target = get_empty_source(udp_known_sources, ARRAY_SIZE(udp_known_sources));
            fprintf(stderr, "source target index %d\n", target);
            if (target == -1) exit(0); /* TODO handle this properly */
            /* A probe worked: save this as an active connection */
            src = &udp_known_sources[target];
            src->allocated = 1;
            src->sockaddr = src_addr;
            src->addrlen = addrlen;
            /* TODO fill in time */


            res = probe_buffer(data, len, &src->proto);
            /* First version: if we can't work out the protocol from the first
             * packet, drop it. Conceivably, we could store several packets to
             * run probes on packet sets */
            if (cfg.verbose) fprintf(stderr, "UDP probed: %d\n", res);
            if (res != PROBE_MATCH) continue;

            src->target_sock = socket(src->proto->saddr->ai_family, SOCK_DGRAM, 0);
        }

        src = &udp_known_sources[target];
        /* at this point src is the UDP connection */
        res = sendto(src->target_sock, data, len, 0, 
               src->proto->saddr->ai_addr, src->proto->saddr->ai_addrlen);
        fprintf(stderr, "sending %d to %s", 
                res, sprintaddr(data, sizeof(data), src->proto->saddr));
    }
}

void main_loop(struct listen_endpoint listen_sockets[], int num_addr_listen)
{
    int i, res;
    struct sigaction action;

    listener_pid_number = num_addr_listen;
    listener_pid = malloc(listener_pid_number * sizeof(listener_pid[0]));
    CHECK_ALLOC(listener_pid, "malloc");

    /* Start one process for each listening address */
    for (i = 0; i < num_addr_listen; i++) {
        listener_pid[i] = fork();
        switch(listener_pid[i]) {
        /* Log if fork() fails for some reason */
        case -1: log_message(LOG_ERR, "fork failed: err %d: %s\n", errno, strerror(errno));
                 break;
        /* We're in the child, we have work to do  */
        case 0:
            set_listen_procname(&listen_sockets[i]);
            if (listen_sockets[i].type == SOCK_DGRAM)
                udp_listener(listen_sockets, num_addr_listen, i);
            else
                tcp_listener(listen_sockets, num_addr_listen, i);
	    break;

	/* We're in the parent, we don't need to do anything */
	default:
	    break;
        }
    }

    /* Set SIGTERM to "stop_listeners" which further kills all listener
     * processes. Note this won't kill processes that listeners forked, which
     * means active connections remain active. */
    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_listeners;
    res = sigaction(SIGTERM, &action, NULL);
    CHECK_RES_DIE(res, "sigaction");


    wait(NULL);
}

/* The actual main is in common.c: it's the same for both version of
 * the server
 */

