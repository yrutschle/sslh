/*
   sslh-ev: mono-processus server based on libev

# Copyright (C) 2021  Yves Rutschle
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

#include <stdlib.h>
#include <ev.h>
#include "gap.h"
#include "log.h"
#include "udp-listener.h"
#include "tcp-listener.h"
#include "sslh-conf.h"


const char* server_type = "sslh-ev";

static struct ev_loop* loop;

/* Libev watchers */
struct watchers {
    /* one set of ev_io for read, one for write, indexed by file descriptor */
    gap_array *ev_ior, *ev_iow;

    struct listen_endpoint* listen_sockets;
    gap_array* fd2ls;  /* Array indexed by file descriptor, pointing to listen_sockets */
};

static void cnx_read_cb(EV_P_ ev_io *w, int revents);
static void cnx_write_cb(EV_P_ ev_io *w, int wevents);
static void cnx_accept_cb(EV_P_ ev_io *w, int revents);

/*******************************************************************************/
/* Helper functions */

/* Enable all accept() watchers */
static void start_accept_watchers(watchers* w, int num_addr_listen) 
{
    for (int i = 0; i < num_addr_listen; i++) {
        ev_io* io = gap_get(w->ev_ior, i);
        ev_io_start(EV_A_  io);
    }
}

/* Disable all accept() watchers */
static void stop_accept_watchers(watchers* w, int num_addr_listen)
{
    for (int i = 0; i < num_addr_listen; i++) {
        ev_io* io = gap_get(w->ev_ior, i);
        ev_io_stop(EV_A_  io);
    }
}

/*******************************************************************************/

static void watchers_init(watchers** w, struct listen_endpoint* listen_sockets, 
                          int num_addr_listen)
{
    *w = malloc(sizeof(**w));
    (*w)->ev_ior = gap_init(num_addr_listen);
    (*w)->ev_iow = gap_init(num_addr_listen);
    (*w)->listen_sockets = listen_sockets;
    (*w)->fd2ls = gap_init(0);

    /* Create watchers for listen sockets */
    for (int i = 0; i < num_addr_listen; i++) {
        ev_io* io = malloc(sizeof(*io));

        ev_io_init(io, &cnx_accept_cb, listen_sockets[i].socketfd, EV_READ);
        gap_set((*w)->ev_ior, i, io);
        gap_set((*w)->fd2ls, listen_sockets[i].socketfd, &listen_sockets[i]);
        set_nonblock(listen_sockets[i].socketfd);
    }
    start_accept_watchers(*w, num_addr_listen);
}

void watchers_add_read(watchers* w, int fd)
{
    ev_io* io = gap_get(w->ev_ior, fd);
    if (!io) {
        io = malloc(sizeof(*io));
        ev_io_init(io, &cnx_read_cb, fd, EV_READ);
        ev_io_set(io, fd, EV_READ);

        gap_set(w->ev_ior, fd, io);
    }
    ev_io_start(loop, io);
}

void watchers_del_read(watchers* w, int fd)
{
    ev_io* io = gap_get(w->ev_ior, fd);
    if (io) ev_io_stop(EV_A_ io);
}

void watchers_add_write(watchers* w, int fd)
{
    ev_io* io = gap_get(w->ev_iow, fd);
    if (!io) {
        io = malloc(sizeof(*io));
        ev_io_init(io, &cnx_write_cb, fd, EV_WRITE);
        ev_io_set(io, fd, EV_WRITE);

        gap_set(w->ev_iow, fd, io);
    }
    ev_io_start(loop, io);
}

void watchers_del_write(watchers* w, int fd)
{
    ev_io* io = gap_get(w->ev_iow, fd);
    if (io) ev_io_stop(EV_A_ io);
}

/* /watchers */

#include "processes.h"

/* Libev callbacks */
static void cnx_read_cb(EV_P_ ev_io *w, int revents)
{
    struct loop_info* info = ev_userdata(EV_A);
    cnx_read_process(info, w->fd);
}

static void cnx_write_cb(EV_P_ ev_io *w, int wevents)
{
    struct loop_info* info = ev_userdata(EV_A);
    cnx_write_process(info, w->fd);
}

/* Timer expired: destroy timer, restart the accept watchers */
static void restart_accept_cb( EV_P_ ev_timer *timer, int revents)
{
    struct loop_info* info = ev_userdata(EV_A);

    ev_timer_stop(EV_A_ timer);
    free(timer);

    start_accept_watchers(info->watchers, info->num_addr_listen);
}

/* Stop the accept() io watchers, start a timer
 */
static void temporary_stop_accept_watchers(ev_io* io)
{
    struct loop_info* info = ev_userdata(EV_A);

    ev_timer* timer = malloc(sizeof(*timer));
    stop_accept_watchers(info->watchers, info->num_addr_listen);
    ev_timer_init(timer, &restart_accept_cb, 1, 0);
    ev_timer_start(EV_A_ timer);
}


/* Timer to timeout incoming connections that send no data.
 * It's set to cnx.timeout during initialisation, then started when at least
 * one connection is probing. It's stopped when the last probing connection is
 * forwarded. Whenever it fires, it processes the first probing connection
 * (which is due to time out), then resets the timer to trigger when the next
 * connection is due. This relies on the loop->probing_list */
static ev_timer probe_timer;

static void probe_timeout_cb(EV_P_ ev_timer* timer, int revents)
{
    struct loop_info* info = ev_userdata(EV_A);

    ev_timer_stop(EV_A_ &probe_timer);

    /* Process all probing connections that have timed out */
    if (info->num_probing > 0) {
        struct connection* cnx = gap_get(info->probing_list, 0);
        if (cnx) {  /* impossible cnx is NULL? */
            probing_read_process(cnx, info);
        }
    }

    /* If there is at least one left, restart the timer to fire depending on
     * the next connection to time out */
    if (info->num_probing > 0) {
        struct connection* cnx = gap_get(info->probing_list, 0);
        time_t duration = cnx->probe_timeout - time(NULL);
        if (duration <= 0) duration = 1;
        ev_timer_set(EV_A_ &probe_timer, duration, 0);
        ev_timer_start(EV_A_ &probe_timer);
    }
}


/* The accept() callback, called when there is READ activity.
 *
 * accept()ing when the process as reached its file descriptor limit (ulimit -n) is can of worms with no solution (see libev's manual "The special problem of accept()ing when you can't").
 * When that happens, the strategy is: Disable all listening sockets, start a 1
 * second timer, enable all listening sockets. This is terrible, but apparently
 * the best we can do */
static void cnx_accept_cb(EV_P_ ev_io *w, int revents)
{
    struct loop_info* info = ev_userdata(EV_A);
    struct connection* cnx = cnx_accept_process(info, gap_get(info->watchers->fd2ls, w->fd));

    if (cnx) {
        if (info->num_probing == 1) {  /* This is the first connection, start the timer */
            ev_timer_set(EV_A_ &probe_timer, cfg.timeout, 0);
            ev_timer_start(EV_A_ &probe_timer);
        }
    } else {  /* accept() failed, probably all file descriptors are used */
        switch (errno) {
        case EMFILE:
        case ENFILE:  /* Not sure ENFILE should be included here */
            /* cancel accepting for a while */
            temporary_stop_accept_watchers(w);

        default:
            break;
        }
    }
}


void sigchld_cb(EV_P_ ev_child *w, int revents)
{
    struct loop_info* info = ev_userdata(EV_A);
    ev_child_stop(EV_A_ w);

    decrease_forked_connection(info, w->pid);
    free(w);
}

void watcher_sigchld(struct loop_info* fd_info, struct connection* cnx, pid_t pid)
{
    ev_child* cw = malloc(sizeof(*cw));

    ev_child_init(cw, sigchld_cb, pid, 0);
    ev_child_start(EV_DEFAULT_ cw);
}

void main_loop(struct listen_endpoint listen_sockets[], int num_addr_listen)
{
    struct loop_info ev_info;
    loop = EV_DEFAULT;

    ev_timer_init(&probe_timer, &probe_timeout_cb, cfg.timeout, 0);

    loop_init(&ev_info, listen_sockets, num_addr_listen);

    watchers_init(&ev_info.watchers, listen_sockets, num_addr_listen);
    ev_set_userdata(EV_A_ &ev_info);

    ev_run(EV_A_ 0);
}

void main_inetd(void) {
    print_message(msg_config_error, "inetd mode is not supported in libev mode\n");
    exit(1);
}


