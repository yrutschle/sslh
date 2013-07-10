/*
   Reimplementation of sslh in C

# Copyright (C) 2007  Yves Rutschle
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

Comments? questions? sslh@rutschle.net

Compilation instructions:

Solaris:
  cc -o sslh sslh.c -lresolv -lsocket -lnsl

LynxOS:
  gcc -o tcproxy tcproxy.c -lnetinet

*/

#define VERSION "1.0"

#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>

#define CHECK_RES_DIE(res, str) \
if (res == -1) {    \
   perror(str);     \
   exit(1);         \
}

#define USAGE_STRING "usage:\n\tsslh [-t <timeout>] -u <username> -p <listenport> -s [sshhost:]port -l [sslhost:]port [-v]\n"


/* Starts a listening socket on specified port.
   Returns file descriptor
   */
int start_listen_socket(int port)
{
   struct sockaddr_in saddr;
   int sockfd, res, reuse;

   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   CHECK_RES_DIE(sockfd, "socket");

   reuse = 1;
   res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
   CHECK_RES_DIE(res, "setsockopt");

   memset(&saddr, 0, sizeof(saddr));
   saddr.sin_port = htons(port);

   res = bind (sockfd, (struct sockaddr*)&saddr, sizeof(saddr));
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
            printf("client socket closed\n");
            return res;
         }
      }

      if (FD_ISSET(fd2, &fds)) {
         res = fd2fd(fd1, fd2);
         if (!res) {
            printf("server socket closed\n");
            return res;
         }
      }
   }
}

/* returns a static string that prints the IP and port of the sockaddr */
char* get_addr(struct sockaddr* s)
{
   char addr_str[1024];
   static char addr_name[1024];

   inet_ntop(AF_INET, &((struct sockaddr_in*)s)->sin_addr, addr_str, sizeof(addr_str));
   snprintf(addr_name, sizeof(addr_name), "%s:%d", addr_str,ntohs(((struct sockaddr_in*)s)->sin_port));
   return addr_name;
}

/* turns a "hostname:port" string into a struct sockaddr;
sock: socket address to which to copy the addr
fullname: input string -- it gets clobbered
serv: default service/port
(defaults don't work yet)
*/
int resolve_name(struct sockaddr *sock, char* fullname, int port) {
   struct addrinfo *addr, hint;
   char *serv, *host;
   int res;

   char *sep = strchr(fullname, ':');

   if (!sep) /* No separator: parameter is just a port */
   {
      serv = fullname;
      fprintf(stderr, "names must be fully specified as hostname:port for the moment\n");
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

/* 
 * Settings that depend on the command line.
 * They're set in main(), but also used in start_shoveler(), and it'd be heavy-handed
 * to pass it all as parameters
 */
int verbose = 0;
int timeout = 2;
int listen_port = 443;
struct sockaddr addr_ssl, addr_ssh;


/* Child process that finds out what to connect to and proxies 
 */
void start_shoveler(int in_socket)
{
   fd_set fds;
   struct timeval tv;
   struct sockaddr *saddr;
   int res;
   int out_socket;

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
      if (verbose)
         fprintf(stderr, "Forwarding to SSL\n");
   } else {
      /* The client hasn't written anything and we timed out: connect to SSH */
      saddr = &addr_ssh;
      if (verbose)
         fprintf(stderr, "Forwarding to SSH\n");
   }

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
    int res;

    res = (int)signal(SIGCHLD, &child_handler);
    CHECK_RES_DIE(res, "signal");
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

int main(int argc, char *argv[])
{

   extern char *optarg;
   extern int optind;
   int c, res;

   int in_socket, out_socket, listen_socket;

   /* Init defaults */
   char *user_name = "nobody";
   char ssl_str[] = "localhost:443"; /* need to copy -- Linux doesn't let write to BSS? */
   char ssh_str[] = "localhost:22";
   resolve_name(&addr_ssl, ssl_str, 443);
   resolve_name(&addr_ssh, ssh_str, 22);

   while ((c = getopt(argc, argv, "t:l:s:p:vu:")) != EOF) {
      switch (c) {

              case 't':
                      timeout = atoi(optarg);
                      break;

              case 'p':
                      listen_port = atoi(optarg);
                      break;

              case 'l':
                      resolve_name(&addr_ssl, optarg, 443);
                      break;

              case 's':
                      resolve_name(&addr_ssh, optarg, 22);
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

   if (verbose) {
      fprintf(stderr, "SSL addr: %s (after timeout %ds)\n", get_addr(&addr_ssl), timeout);
      fprintf(stderr, "SSH addr: %s\n", get_addr(&addr_ssh));
      fprintf(stderr, "listening on port %d\n", listen_port);
   }


   setup_signals();

   listen_socket = start_listen_socket(listen_port);

   drop_privileges(user_name);

   /* Main server loop: accept connections, find what they are, fork shovelers */
   while (1)
   {
      in_socket = accept(listen_socket, 0, 0);
      fprintf(stderr, "accepted fd %d\n", in_socket);

      if (!fork())
      {
         start_shoveler(in_socket);
         exit(0);
      }
      close(in_socket);
   }

   return 0;
}


