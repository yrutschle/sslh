#ifndef COMMON_H
#define COMMON_H

/* FD_SETSIZE is 64 on Cygwin, which is really low. Just redefining it is
 * enough for the macros to adapt (http://support.microsoft.com/kb/111855)
 */
#ifdef __CYGWIN__
#undef FD_SETSIZE
#define FD_SETSIZE 4096
#endif

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

#ifdef LIBCAP
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#include "version.h"

#define MAX(a, b)  (((a) > (b)) ? (a) : (b))


#define CHECK_RES_DIE(res, str) \
    if (res == -1) {    \
       print_message(msg_system_error, "%s:%d:", __FILE__, __LINE__); \
       perror(str);     \
       exit(1);         \
    }

#define CHECK_RES_RETURN(res, str, ret) \
    if (res == -1) {                                    \
        print_message(msg_system_error, "%s:%d:%s:%d:%s\n", __FILE__, __LINE__, str, errno, strerror(errno));  \
        return ret;                                     \
    } 

#define CHECK_ALLOC(a, str) \
    if (!a) { \
        print_message(msg_system_error, "%s:%d:", __FILE__, __LINE__); \
        perror(str); \
        exit(1); \
    }

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#if 1
#define TRACE fprintf(stderr, "%s:%d\n", __FILE__, __LINE__);
#else
#define TRACE
#endif

#ifndef IP_FREEBIND
#define IP_FREEBIND 0
#endif

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 0
#endif

#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30 /* Attempt FastOpen with connect.  */
#endif

enum connection_state {
    ST_PROBING=1,    /* Waiting for timeout to find where to forward */
    ST_SHOVELING   /* Connexion is established */
};

/* A 'queue' is composed of a file descriptor (which can be read from or
 * written to), and a queue for deferred write data */
struct queue {
    int fd;
    void *begin_deferred_data;
    void *deferred_data;
    int deferred_data_size;
};

/* Double linked list for timeout management */
typedef struct {
    struct connection* head;
    struct connection* tail;
} dl_list;

struct connection {
    int type;           /* SOCK_DGRAM | SOCK_STREAM */
    struct sslhcfg_protocols_item* proto; /* Where to connect to */

    /* SOCK_STREAM */
    enum connection_state state;
    time_t probe_timeout;

    /* q[0]: queue for external connection (client);
     * q[1]: queue for internal connection (httpd or sshd);
     * */
    struct queue q[2];

    /* SOCK_DGRAM */
    struct sockaddr_storage client_addr; /* Contains the remote client address */
    socklen_t addrlen;

    int local_endpoint; /* Contains the local address */

    time_t last_active;

    /* double linked list of timeouts */
    struct connection *timeout_prev, *timeout_next;

    /* We need one local socket for each target server, so we know where to
     * forward server responses */
    int target_sock;  
};


struct listen_endpoint {
    int socketfd;       /* file descriptor of listening socket */
    int type;           /* SOCK_DGRAM | SOCK_STREAM */
    int family;         /* AF_INET | AF_UNIX */
};

#define FD_CNXCLOSED    0
#define FD_NODATA       -1
#define FD_STALLED      -2

/* String description of a connection */
#define MAX_NAMELENGTH (NI_MAXHOST + NI_MAXSERV + 1)
struct connection_desc {
    char peer[MAX_NAMELENGTH], service[MAX_NAMELENGTH],
        local[MAX_NAMELENGTH], target[MAX_NAMELENGTH];
};

typedef enum {
    NON_BLOCKING = 0,
    BLOCKING = 1
} connect_blocking;


/* common.c */
void init_cnx(struct connection *cnx);
int set_nonblock(int fd);
int connect_addr(struct connection *cnx, int fd_from, connect_blocking blocking);
int fd2fd(struct queue *target, struct queue *from);
char* sprintaddr(char* buf, size_t size, struct addrinfo *a);
void resolve_name(struct addrinfo **out, char* fullname);
int get_connection_desc(struct connection_desc* desc, const struct connection *cnx);
void log_connection(struct connection_desc* desc, const struct connection *cnx);
void set_proctitle_shovel(struct connection_desc* desc, const struct connection *cnx);
int check_access_rights(int in_socket, const char* service);
void setup_signals(void);
void setup_syslog(const char* bin_name);
void drop_privileges(const char* user_name, const char* chroot_path);
void set_capabilities(int cap_net_admin);
void write_pid_file(const char* pidfile);
void dump_connection(struct connection *cnx);
int resolve_split_name(struct addrinfo **out, char* hostname, char* port);

int start_listen_sockets(struct listen_endpoint *sockfd[]);

int defer_write(struct queue *q, void* data, ssize_t data_size);
int flush_deferred(struct queue *q);

extern struct sslhcfg_item cfg;
extern struct addrinfo *addr_listen;
extern const char* server_type;

/* sslh-fork.c */
void start_shoveler(int);

void main_loop(struct listen_endpoint *listen_sockets, int num_addr_listen);

/* landlock.c */
void setup_landlock(void);


#endif
