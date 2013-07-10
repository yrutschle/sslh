/*
   Reimplementation of sslh in C

# Copyright (C) 2007-2008  Yves Rutschle
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

#define VERSION "1.5"

#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <syslog.h>

#ifdef LIBWRAP
#include <tcpd.h>
int allow_severity =0, deny_severity = 0;
#endif


#define CHECK_RES_DIE(res, str) \
if (res == -1) {    \
   perror(str);     \
   exit(1);         \
}

#define USAGE_STRING \
"sslh v" VERSION "\n" \
"usage:\n" \
"\texport PIDFILE=/var/run/sslhc.pid\n" \
"\tsslh [-t <timeout>] -u <username> -p [listenaddr:]<listenport> \n" \
"\t\t-s [sshhost:]port -l [sslhost:]port [-v]\n\n" \
"-v: verbose\n" \
"-p: address and port to listen on. default: 0.0.0.0:443\n" \
"-s: SSH address: where to connect an SSH connection. default: localhost:22\n" \
"-l: SSL address: where to connect an SSL connection.\n" \
""

int verbose = 0; /* That's really quite global */

/* Starts a listening socket on specified address.
   Returns file descriptor
   */
int start_listen_socket(struct sockaddr *addr)
{
   struct sockaddr_in *saddr = (struct sockaddr_in*)addr;
   int sockfd, res, reuse;

   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   CHECK_RES_DIE(sockfd, "socket");

   reuse = 1;
   res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
   CHECK_RES_DIE(res, "setsockopt");

   res = bind (sockfd, (struct sockaddr*)saddr, sizeof(*saddr));
   CHECK_RES_DIE(res, "bind");

   res = listen (sockfd, 5);
   CHECK_RES_DIE(res, "listen");

   return sockfd;
}


/* 
 * moves data from one fd to other
 * returns 0 if incoming socket closed, size moved otherwise
 */
int fd2fd(int target, int from)
{
   char buffer[BUFSIZ];
   int size;

   size = read(from, buffer, sizeof(buffer));
   CHECK_RES_DIE(size, "read");

   if (size == 0)
      return 0;

   size = write(target, buffer, size);
   CHECK_RES_DIE(size, "write");

   return size;
}

/* shovels data from one fd to the other and vice-versa 
   returns after one socket closed
 */
int shovel(int fd1, int fd2)
{
   fd_set fds;
   int res;

   FD_ZERO(&fds);
   while (1) {
      FD_SET(fd1, &fds);
      FD_SET(fd2, &fds);

      res = select( 
                      (fd1 > fd2 ? fd1 : fd2 ) + 1,
                      &fds,
                      NULL,
                      NULL,
                      NULL
            );
      CHECK_RES_DIE(res, "select");

      if (FD_ISSET(fd1, &fds)) {
         res = fd2fd(fd2, fd1);
         if (!res) {
            if (verbose) fprintf(stderr, "client socket closed\n");
            return res;
         }
      }

      if (FD_ISSET(fd2, &fds)) {
         res = fd2fd(fd1, fd2);
         if (!res) {
            if (verbose) fprintf(stderr, "server socket closed\n");
            return res;
         }
      }
   }
}

/* returns a string that prints the IP and port of the sockaddr */
char* sprintaddr(char* buf, size_t size, struct sockaddr* s)
{
   char addr_str[1024];

   inet_ntop(AF_INET, &((struct sockaddr_in*)s)->sin_addr, addr_str, sizeof(addr_str));
   snprintf(buf, size, "%s:%d", addr_str, ntohs(((struct sockaddr_in*)s)->sin_port));
   return buf;
}

/* turns a "hostname:port" string into a struct sockaddr;
sock: socket address to which to copy the addr
fullname: input string -- it gets clobbered
*/
void resolve_name(struct sockaddr *sock, char* fullname) {
   struct addrinfo *addr, hint;
   char *serv, *host;
   int res;

   char *sep = strchr(fullname, ':');

   if (!sep) /* No separator: parameter is just a port */
   {
      serv = fullname;
      fprintf(stderr, "names must be fully specified as hostname:port\n");
      exit(1);
   }
   else {
      host = fullname;
      serv = sep+1;
      *sep = 0;
   }

   memset(&hint, 0, sizeof(hint));
   hint.ai_family = PF_INET;
   hint.ai_socktype = SOCK_STREAM;

   res = getaddrinfo(host, serv, &hint, &addr);
   if (res) {
      fprintf(stderr, "%s\n", gai_strerror(res));
      if (res == EAI_SERVICE)
         fprintf(stderr, "(Check you have specified all ports)\n");
      exit(1);
   }

   memcpy(sock, addr->ai_addr, sizeof(*sock));
}

/* syslogs who connected to where */
void log_connection(int socket, char* target)
{
    struct sockaddr peeraddr;
    socklen_t size = sizeof(peeraddr);
    char buf[64];
    int res;

    res = getpeername(socket, &peeraddr, &size);
    CHECK_RES_DIE(res, "getpeername");

    syslog(LOG_INFO, "connection from %s forwarded to %s\n", 
           sprintaddr(buf, sizeof(buf), &peeraddr), target);

}

/* 
 * Settings that depend on the command line. That's less global than verbose * :-)
 * They're set in main(), but also used in start_shoveler(), and it'd be heavy-handed
 * to pass it all as parameters
 */
int timeout = 2;
struct sockaddr addr_listen;
struct sockaddr addr_ssl, addr_ssh;

/* libwrap (tcpd): check the ssh connection is legal. This is necessary because
 * the actual sshd will only see a connection coming from localhost and can't
 * apply the rules itself.
 */
void check_access_rights(int in_socket)
{
#ifdef LIBWRAP
    struct sockaddr peeraddr;
    socklen_t size = sizeof(peeraddr);
    char addr_str[1024];
    struct hostent *host;
    struct in_addr addr;
    int res;

    res = getpeername(in_socket, &peeraddr, &size);
    CHECK_RES_DIE(res, "getpeername");
    inet_ntop(AF_INET, &((struct sockaddr_in*)&peeraddr)->sin_addr, addr_str, sizeof(addr_str));

    addr.s_addr = inet_addr(addr_str);
    host = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);

    if (!hosts_ctl("sshd", (host ? host->h_name : STRING_UNKNOWN), addr_str, STRING_UNKNOWN)) {
        if (verbose)
            fprintf(stderr, "access denied\n");
        log_connection(in_socket, "access denied");
        close(in_socket);
        exit(0);
    }
#endif
}

/* Child process that finds out what to connect to and proxies 
 */
void start_shoveler(int in_socket)
{
   fd_set fds;
   struct timeval tv;
   struct sockaddr *saddr;
   int res;
   int out_socket;
   char *target;

   FD_ZERO(&fds);
   FD_SET(in_socket, &fds);
   memset(&tv, 0, sizeof(tv));
   tv.tv_sec = timeout;
   res = select(in_socket + 1, &fds, NULL, NULL, &tv);
   if (res == -1)
      perror("select");

   /* Pick the target address depending on whether we timed out or not */
   if (FD_ISSET(in_socket, &fds)) {
      /* The client wrote something to the socket: it's an SSL connection */
      saddr = &addr_ssl;
      target = "SSL";
   } else {
      /* The client hasn't written anything and we timed out: connect to SSH */
      saddr = &addr_ssh;
      target = "SSH";

      /* do hosts_access check if built with libwrap support */
      check_access_rights(in_socket);
   }

   log_connection(in_socket, target);

   /* Connect the target socket */
   out_socket = socket(AF_INET, SOCK_STREAM, 0);
   res = connect(out_socket, saddr, sizeof(addr_ssl));
   CHECK_RES_DIE(res, "connect");
   if (verbose)
      fprintf(stderr, "connected to something\n");

   shovel(in_socket, out_socket);

   close(in_socket);
   close(out_socket);
   
   if (verbose)
      fprintf(stderr, "connection closed down\n");

   exit(0);
}

/* SIGCHLD handling:
 * we need to reap our children
 */
void child_handler(int signo)
{
    signal(SIGCHLD, &child_handler);
    wait(NULL);
}
void setup_signals(void)
{
    void* res;

    res = signal(SIGCHLD, &child_handler);
    if (res == SIG_ERR) {
        perror("signal");
        exit(1);
    }
}


/* We don't want to run as root -- drop priviledges if required */
void drop_privileges(char* user_name)
{
    int res;
    struct passwd *pw = getpwnam(user_name);
    if (!pw) {
        fprintf(stderr, "%s: not found\n", user_name);
        exit(1);
    }
    if (verbose)
        fprintf(stderr, "turning into %s\n", user_name);

    res = setgid(pw->pw_gid);
    CHECK_RES_DIE(res, "setgid");
    setuid(pw->pw_uid);
    CHECK_RES_DIE(res, "setuid");
}

/* Writes my PID if $PIDFILE is defined */
void write_pid_file(void)
{
    char *pidfile = getenv("PIDFILE");
    FILE *f;

    if (!pidfile)
        return;

    f = fopen(pidfile, "w");
    if (!f) {
        perror(pidfile);
        exit(1);
    }

    fprintf(f, "%d\n", getpid());
    fclose(f);
}

void printsettings(void)
{
    char buf[64];

    fprintf(
            stderr, 
            "SSL addr: %s (after timeout %ds)\n",
            sprintaddr(buf, sizeof(buf), &addr_ssl), 
            timeout
           );
    fprintf(stderr, "SSH addr: %s\n", sprintaddr(buf, sizeof(buf), &addr_ssh));
    fprintf(stderr, "listening on %s\n", sprintaddr(buf, sizeof(buf), &addr_listen));
}

int main(int argc, char *argv[])
{

   extern char *optarg;
   extern int optind;
   int c, res;

   int in_socket, listen_socket;

   /* Init defaults */
   char *user_name = "nobody";
   char listen_str[] = "0.0.0.0:443";
   char ssl_str[] = "localhost:442";
   char ssh_str[] = "localhost:22";

   resolve_name(&addr_listen, listen_str);
   resolve_name(&addr_ssl, ssl_str);
   resolve_name(&addr_ssh, ssh_str);

   while ((c = getopt(argc, argv, "t:l:s:p:vu:")) != EOF) {
      switch (c) {

              case 't':
                      timeout = atoi(optarg);
                      break;

              case 'p':
                      resolve_name(&addr_listen, optarg);
                      break;

              case 'l':
                      resolve_name(&addr_ssl, optarg);
                      break;

              case 's':
                      resolve_name(&addr_ssh, optarg);
                      break;

              case 'v':
                      verbose += 1;
                      break;

              case 'u':
                      user_name = optarg;
                      break;

              default:
                      fprintf(stderr, USAGE_STRING);
                      exit(2);
      }
   }

   if (verbose)
       printsettings();

   setup_signals();

   listen_socket = start_listen_socket(&addr_listen);

   if (fork() > 0) exit(0); /* Detach */

   write_pid_file();

   drop_privileges(user_name);

   /* New session -- become group leader */
   res = setsid();
   CHECK_RES_DIE(res, "setsid: already process leader");

   /* Open syslog connection */
   openlog(argv[0], LOG_CONS, LOG_AUTH);

   /* Main server loop: accept connections, find what they are, fork shovelers */
   while (1)
   {
      in_socket = accept(listen_socket, 0, 0);
      if (verbose) fprintf(stderr, "accepted fd %d\n", in_socket);

      if (!fork())
      {
         start_shoveler(in_socket);
         exit(0);
      }
      close(in_socket);
   }

   return 0;
}


