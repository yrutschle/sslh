#ifndef __COMMON_H_
#define __COMMON_H_


#define _GNU_SOURCE
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
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
#include <libgen.h>
#include <time.h>
#include <getopt.h>

#ifndef VERSION
#define VERSION "v?"
#endif

#define CHECK_RES_DIE(res, str) \
    if (res == -1) {    \
       perror(str);     \
       exit(1);         \
    }

#define CHECK_RES_RETURN(res, str) \
    if (res == -1) {                                    \
        log_message(LOG_CRIT, "%s:%d:%s\n", str, errno, strerror(errno));  \
        return res;                                     \
    } 

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#if 1
#define TRACE fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
#else
#define TRACE
#endif

enum connection_state {
    ST_PROBING=1,    /* Waiting for timeout to find where to forward */
    ST_SHOVELING   /* Connexion is established */
};

/* this is used to pass protocols through the command-line parameter parsing */
#define PROT_SHIFT 1000  /* protocol options will be 1000, 1001, etc */

/* A 'queue' is composed of a file descriptor (which can be read from or
 * written to), and a queue for defered write data */
struct queue {
    int fd;
    void *begin_defered_data;
    void *defered_data;
    int defered_data_size;
};

struct connection {
    enum connection_state state;
    time_t probe_timeout;

    /* q[0]: queue for external connection (client);
     * q[1]: queue for internal connection (httpd or sshd);
     * */
    struct queue q[2];
};

#define FD_CNXCLOSED    0
#define FD_NODATA       -1
#define FD_STALLED      -2


/* common.c */
void init_cnx(struct connection *cnx);
int connect_addr(struct addrinfo *addr, int fd_from, const char* cnx_name);
int fd2fd(struct queue *target, struct queue *from);
char* sprintaddr(char* buf, size_t size, struct addrinfo *a);
void resolve_name(struct addrinfo **out, char* fullname);
struct proto* probe_client_protocol(struct connection *cnx);
void log_connection(struct connection *cnx);
int check_access_rights(int in_socket, const char* service);
void setup_signals(void);
void setup_syslog(const char* bin_name);
void drop_privileges(const char* user_name);
void write_pid_file(const char* pidfile);
void log_message(int type, char* msg, ...);
void dump_connection(struct connection *cnx);
int resolve_split_name(struct addrinfo **out, const char* hostname, const char* port);

int start_listen_sockets(int *sockfd[], struct addrinfo *addr_list);

int defer_write(struct queue *q, void* data, int data_size);
int flush_defered(struct queue *q);

extern int probing_timeout, verbose, inetd, foreground, 
       background, transparent, numeric;
extern struct sockaddr_storage addr_ssl, addr_ssh, addr_openvpn;
extern struct addrinfo *addr_listen;
extern const char* USAGE_STRING;
extern const char* user_name, *pid_file;
extern const char* server_type;

/* sslh-fork.c */
void start_shoveler(int);

void main_loop(int *listen_sockets, int num_addr_listen);

#endif
