/*
   sslh-fork: forking server

# Copyright (C) 2007-2025  Yves Rutschle
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

#include <poll.h>

#include "common.h"
#include "probe.h"
#include "sslh-conf.h"
#include "tcp-probe.h"
#include "log.h"

#if HAVE_LIBBSD
#include <bsd/unistd.h>
#endif

const char* server_type = "sslh-fork";

/* shovels data from one fd to the other and vice-versa 
   returns after one socket closed
 */
int shovel(struct connection *cnx)
{
   struct pollfd fds[2];
   int res, i;

   /* fds may be arbitrarily high if the daemon inherited a populated file
    * descriptor table, so we cannot use select()/FD_SET which are limited to
    * FD_SETSIZE */
   for (i = 0; i < 2; i++) {
       fds[i].fd = cnx->q[i].fd;
       fds[i].events = POLLIN;
   }

   while (1) {
      for (i = 0; i < 2; i++)
          fds[i].revents = 0;

      res = poll(fds, 2, -1);
      CHECK_RES_DIE(res, "poll");

      for (i = 0; i < 2; i++) {
          if (fds[i].revents) {
              res = fd2fd(&cnx->q[1-i], &cnx->q[i]);
              if (res == FD_CNXCLOSED) {
                  print_message(msg_fd, "%s %s", i ? "client" : "server", "socket closed\n");
                  return res;
              }
          }
      }
   }
}

/* Child process that finds out what to connect to and proxies 
 */
static void start_shoveler(int in_socket, struct listen_endpoint* endpoint)
{
   struct pollfd pfd;
   time_t deadline;
   int res = PROBE_AGAIN;
   struct connection cnx;
   struct connection_desc desc;

   init_cnx(&cnx);
   cnx.q[0].fd = in_socket;
   cnx.endpoint = endpoint;

   /* in_socket may be arbitrarily high if the daemon inherited a populated
    * file descriptor table, so we cannot use select()/FD_SET which are
    * limited to FD_SETSIZE */
   pfd.fd = in_socket;
   pfd.events = POLLIN;
   deadline = time(NULL) + cfg.timeout;

   while (res == PROBE_AGAIN) {
       /* The timeout applies to the entire probing phase: the client can only
        * postpone the inevitable for so long */
       int wait_ms = (int)(deadline - time(NULL)) * 1000;
       int pres;

       pfd.revents = 0;
       pres = poll(&pfd, 1, wait_ms > 0 ? wait_ms : 0);
       if (pres == -1)
           perror("poll");

       if (pres > 0 && pfd.revents) {
           /* Received data: figure out what protocol it is */
           res = probe_client_protocol(&cnx);
       } else {
           /* Timed out: it's necessarily SSH */
           cnx.proto = timeout_protocol();
           print_message(msg_fd, "timed out, connect to %s\n", cnx.proto->name);
           break;
       }
   }

   if (cnx.proto->service &&
       check_access_rights(in_socket, cnx.proto->service)) {
       exit(0);
   }

   /* Connect the target socket */
   connect_addr(&cnx, in_socket, BLOCKING);
   CHECK_RES_DIE(cnx.q[1].fd, "connect");

   set_capabilities(0);

   get_connection_desc(&desc, &cnx);
   log_connection(&desc, &cnx);
   set_proctitle_shovel(&desc, &cnx);

   flush_deferred(&cnx.q[1]);

   shovel(&cnx);

   close(in_socket);
   close(cnx.q[1].fd);
   
   print_message(msg_fd, "connection closed down\n");

   exit(0);
}


void main_inetd(void)
{
    struct listen_endpoint endpoint = {0};
    struct sslhcfg_listen_item endpoint_cfg = {0};

    /* Empty configuration: no connection limits, not proxyprotocol... */
    endpoint.endpoint_cfg = &endpoint_cfg;

    close(fileno(stderr)); /* Make sure no error will go to client */
    tcp_init();
    start_shoveler(0, &endpoint);
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
#if HAVE_LIBBSD
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

static void mask_sigchld(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = NULL;
    action.sa_flags = SA_NOCLDWAIT;
    int res = sigaction(SIGCHLD, &action, NULL);
    CHECK_RES_DIE(res, "sigaction");
}


extern volatile sig_atomic_t received_sigchld;
/* EINTR, so we probably received a signal; check if it's SIGCHLD */
static void process_signals(struct listen_endpoint* endpoint)
{
    int chld;
    if (received_sigchld) {
        received_sigchld = 0;
        do {
            chld = waitpid(-1, NULL, WNOHANG);
            CHECK_RES_RETURN(chld, "waitpid", );
            if (chld) {
                endpoint->num_connections--;
                print_message(msg_fd, "child died, %d concurrent connections remaining\n", endpoint->num_connections);
            }
        } while (chld);
    }
}

/* At least MacOS does not know these two options, so define them to something
 * equivalent for our use case */
#ifndef ENONET
#define ENONET EWOULDBLOCK
#endif
/* /MacOS kludge */

/* TCP listener: connections, fork a child for each new connection 
 * IN: 
 *      endpoint: array of listening endpoint objects
 *      num_endpoints: size of endpoint array
 *      active_endpoint: which endpoint is this listener working on
 * Does not return
 * */
void tcp_listener(struct listen_endpoint* endpoint, int num_endpoints, int active_endpoint)
{
    int i, in_socket;
    struct listen_endpoint* self = &endpoint[active_endpoint];

    while (1) {
        in_socket = accept(self->socketfd, 0, 0);
        if (in_socket == -1) {
            print_message(msg_system_error, "%s:%d:%s:%d:%s\n",
                          __FILE__, __LINE__, "accept", errno, strerror(errno));
            switch(errno) {
            case ENETDOWN:  /* accept(2) cites all these errnos as "you should retry" */
            case EPROTO:
            case ENOPROTOOPT:
            case EHOSTDOWN:
            case ENONET:
            case EHOSTUNREACH:
            case EOPNOTSUPP:
            case ENETUNREACH:
            case ECONNABORTED:
                continue;

            case EINTR:
                process_signals(self);
                continue;

            default:  /* Otherwise, it's something wrong in our parameters, we fail */
                return;
            }
        }
        self->num_connections++;
        print_message(msg_fd, "accepted fd %d (%d concurrent connections)\n", in_socket, self->num_connections);
        if ((self->endpoint_cfg->max_connections_is_present)
            && (self->num_connections > self->endpoint_cfg->max_connections))
        {
            print_message(msg_fd, "too many connection, reclosing fd %d\n", in_socket);
            self->num_connections--;
            close(in_socket);
            continue;
        }

        switch(fork()) {
        case -1: print_message(msg_system_error, "fork failed: err %d: %s\n", errno, strerror(errno));
                 self->num_connections--;  /* no child will reap it */
                 break;

        case 0: /* In child process */
                 /* Shoveler processes don't need to hog file descriptors */
                 for (i = 0; i < num_endpoints; i++)
                     close(endpoint[i].socketfd);
                 start_shoveler(in_socket, self);
                 exit(0);

        default: /* In parent process */
                 break;
        }
        close(in_socket);
    }
}


void main_loop(struct listen_endpoint listen_sockets[], int num_addr_listen)
{
    int i, res;
    struct sigaction action;

    listener_pid_number = num_addr_listen;
    listener_pid = malloc(listener_pid_number * sizeof(listener_pid[0]));
    CHECK_ALLOC(listener_pid, "malloc");

    tcp_init();

    /* Start one process for each listening address */
    for (i = 0; i < num_addr_listen; i++) {
        listener_pid[i] = fork();
        switch(listener_pid[i]) {
        /* Log if fork() fails for some reason */
        case -1: print_message(msg_system_error, "fork failed: err %d: %s\n", errno, strerror(errno));
                 break;
        /* We're in the child, we have work to do  */
        case 0:
            set_listen_procname(&listen_sockets[i]);
            if (listen_sockets[i].type == SOCK_DGRAM)
                print_message(msg_config_error, "UDP not supported in sslh-fork\n");
            else
                tcp_listener(listen_sockets, num_addr_listen, i);

            exit(0);
	    break;

	/* We're in the parent, which does nothing but wait to be killed by
         * SIGTERM, which it will send to its children */
	default:
            mask_sigchld();
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

/* The actual main() is in sslh_main.c: it's the same for all versions of
 * the server
 */

