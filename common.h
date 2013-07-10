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
        log_message(LOG_CRIT, "%s: %d\n", str, errno);  \
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


/* Different types of protocols we support.
 * These must match the order of the protocols[] array in common.c */
typedef enum protocol_type {
    PROT_SSH,
    PROT_OPENVPN,
    PROT_SSL,
} T_PROTO_ID;

/* For each protocol we need: */
struct proto {
    int affected;       /* are we actually using it? */
    char* description;  /* a string that says what it is (for logging) */
    char* service;      /* service name to do libwrap checks */
    struct sockaddr saddr; /* where to switch that protocol */
    int (*probe)(const char*, int); /* function to probe that protocol */
};

/* A table in common.c contains all the known protocols */
extern struct proto protocols[];

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
int start_listen_socket(struct sockaddr *addr);
int fd2fd(struct queue *target, struct queue *from);
T_PROTO_ID probe_client_protocol(struct connection *cnx);
char* sprintaddr(char* buf, size_t size, struct sockaddr* s);
void resolve_name(struct sockaddr *sock, char* fullname) ;
void log_connection(struct connection *cnx);
int check_access_rights(int in_socket, const char* service);
void setup_signals(void);
void setup_syslog(char* bin_name);
void drop_privileges(char* user_name);
void write_pid_file(char* pidfile);
void printsettings(void);
void parse_cmdline(int argc, char* argv[]);
void log_message(int type, char* msg, ...);
void dump_connection(struct connection *cnx);


int defer_write(struct queue *q, void* data, int data_size);
int flush_defered(struct queue *q);

extern int probing_timeout, verbose, inetd;
extern struct sockaddr addr_listen, addr_ssl, addr_ssh, addr_openvpn;
extern const char* USAGE_STRING;
extern char* user_name, *pid_file;
extern const char* server_type;

/* sslh-fork.c */
void start_shoveler(int);

void main_loop(int);


