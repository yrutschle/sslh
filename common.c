/* Code and variables that is common to both fork and select-based
 * servers.
 *
 * No code here should assume whether sockets are blocking or not.
 **/

#define _GNU_SOURCE
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
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
#include <getopt.h>

#include "common.h"

/* Added to make the code compilable under CYGWIN 
 * */
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0
#endif

int is_ssh_protocol(const char *p, int len);
int is_openvpn_protocol(const char *p, int len);
int is_tinc_protocol(const char *p, int len);
int is_true(const char *p, int len) { return 1; }

struct proto protocols[] = {
    /* affected  description   service  saddr   probe  */
    { 0,         "ssh",        "sshd",  {0},   is_ssh_protocol },
    { 0,         "openvpn",     NULL,   {0},   is_openvpn_protocol },
    { 0,         "tinc",        NULL,   {0},   is_tinc_protocol },
    /* probe for SSL always successes: it's the default, and must be tried last
     **/
    { 0,        "ssl",          NULL,   {0},   is_true }
};


const char* USAGE_STRING =
"sslh " VERSION "\n" \
"usage:\n" \
"\tsslh  [-v] [-i] [-V] [-f]\n"
"\t[-t <timeout>] [-P <pidfile>] -u <username> -p <add> [-p <addr> ...] \n" \
"\t[--ssh <addr>] [--ssl <addr>] [--openvpn <addr>] [--tinc <addr>]\n\n" \
"-v: verbose\n" \
"-V: version\n" \
"-f: foreground\n" \
"-p: address and port to listen on. default: 0.0.0.0:443.\n    Can be used several times to bind to several addresses.\n" \
"--ssh: SSH address: where to connect an SSH connection.\n" \
"--ssl: SSL address: where to connect an SSL connection.\n" \
"--openvpn: OpenVPN address: where to connect an OpenVPN connection.\n" \
"--tinc: tinc address: where to connect a tinc connection.\n" \
"-P: PID file. Default: /var/run/sslh.pid.\n" \
"-i: Run as a inetd service.\n" \
"";


/* 
 * Settings that depend on the command line. 
 * They're set in main(), but also used in other places, and it'd be
 * heavy-handed to pass it all as parameters
 */
int verbose = 0;
int probing_timeout = 2;
int inetd = 0;
int foreground = 0;
int numeric = 0;
char *user_name, *pid_file;

struct sockaddr_storage *addr_listen = NULL; /* what addresses do we listen to? */
int num_addr_listen = 0; /* How many addresses do we listen to? */

#ifdef LIBWRAP
#include <tcpd.h>
int allow_severity =0, deny_severity = 0;
#endif


/* check result and die, printing the offending address and error */
void check_res_dumpdie(int res, struct sockaddr_storage *sock, char* syscall)
{
    char buf[64];

    if (res == -1) {
        fprintf(stderr, "%s:%s: %s\n", 
                sprintaddr(buf, sizeof(buf), sock), 
                syscall, 
                strerror(errno));
        exit(1);
    }
}

/* Starts listening sockets on specified addresses.
 * IN: addr[], num_addr
 * OUT: sockfd[]
 * Bound file descriptors are returned in alread-allocated *sockfd pointer
   Returns file descriptor
   */
void start_listen_sockets(int sockfd[], struct sockaddr_storage addr[], int num_addr)
{
   struct sockaddr_storage *saddr;
   int i, res, reuse;

   for (i = 0; i < num_addr; i++) {
       saddr = &addr[i];

       sockfd[i] = socket(saddr->ss_family, SOCK_STREAM, 0);
       check_res_dumpdie(sockfd[i], saddr, "socket");

       reuse = 1;
       res = setsockopt(sockfd[i], SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));
       check_res_dumpdie(res, saddr, "setsockopt");

       res = bind (sockfd[i], (struct sockaddr*)saddr, sizeof(*saddr));
       check_res_dumpdie(res, saddr, "bind");

       res = listen (sockfd[i], 50);
       check_res_dumpdie(res, saddr, "listen");
   }
}

/* Store some data to write to the queue later */
int defer_write(struct queue *q, void* data, int data_size) 
{
    if (verbose) 
        fprintf(stderr, "**** writing defered on fd %d\n", q->fd);
    q->defered_data = malloc(data_size);
    q->begin_defered_data = q->defered_data;
    q->defered_data_size = data_size;
    memcpy(q->defered_data, data, data_size);

    return 0;
}

/* tries to flush some of the data for specified queue
 * Upon success, the number of bytes written is returned.
 * Upon failure, -1 returned (e.g. connexion closed)
 * */
int flush_defered(struct queue *q)
{
    int n;

    if (verbose)
        fprintf(stderr, "flushing defered data to fd %d\n", q->fd);

    n = write(q->fd, q->defered_data, q->defered_data_size);
    if (n == -1)
        return n;

    if (n == q->defered_data_size) {
        /* All has been written -- release the memory */
        free(q->begin_defered_data);
        q->begin_defered_data = NULL;
        q->defered_data = NULL;
        q->defered_data_size = 0;
    } else {
        /* There is data left */
        q->defered_data += n;
        q->defered_data_size -= n;
    }


    return n;
}


void init_cnx(struct connection *cnx)
{
    memset(cnx, 0, sizeof(*cnx));
    cnx->q[0].fd = -1;
    cnx->q[1].fd = -1;
}

void dump_connection(struct connection *cnx)
{
    printf("state: %d\n", cnx->state);
    printf("fd %d, %d defered\n", cnx->q[0].fd, cnx->q[0].defered_data_size);
    printf("fd %d, %d defered\n", cnx->q[1].fd, cnx->q[1].defered_data_size);
}


/* 
 * moves data from one fd to other
 *
 * retuns number of bytes copied if success
 * returns 0 (FD_CNXCLOSED) if incoming socket closed
 * returns FD_NODATA if no data was available
 * returns FD_STALLED if data was read, could not be written, and has been
 * stored in temporary buffer.
 *
 * slot for debug only and may go away at some point
 */
int fd2fd(struct queue *target_q, struct queue *from_q)
{
   char buffer[BUFSIZ];
   int target, from, size_r, size_w;

   target = target_q->fd;
   from = from_q->fd;

   size_r = read(from, buffer, sizeof(buffer));
   if (size_r == -1) {
       switch (errno) {
       case EAGAIN:
           if (verbose)
               fprintf(stderr, "reading 0 from %d\n", from);
           return FD_NODATA;

       case ECONNRESET:
       case EPIPE:
           return FD_CNXCLOSED;
       }
   }

   CHECK_RES_RETURN(size_r, "read");

   if (size_r == 0)
      return FD_CNXCLOSED;

   size_w = write(target, buffer, size_r);
   /* process -1 when we know how to deal with it */
   if ((size_w == -1)) {
       switch (errno) {
       case EAGAIN:
           /* write blocked: Defer data */
           defer_write(target_q, buffer, size_r);
           return FD_STALLED;

       case ECONNRESET:
       case EPIPE:
           /* remove end closed -- drop the connection */
           return FD_CNXCLOSED;
       }
   } else if (size_w < size_r) {
       /* incomplete write -- defer the rest of the data */
       defer_write(target_q, buffer + size_w, size_r - size_w);
       return FD_STALLED;
   }

   CHECK_RES_RETURN(size_w, "write");

   return size_w;
}

/* If the client wrote something first, read it and check if it's a SSH banner.
 * Data is left in appropriate defered write buffer.
 */
int is_ssh_protocol(const char *p, int len)
{
    if (!strncmp(p, "SSH-", 4)) {
        return 1;
    }
    return 0;
}

/* Is the buffer the beginning of an OpenVPN connection?
 * (code lifted from OpenVPN port-share option)
 */
int is_openvpn_protocol (const char*p,int len)
{
#define P_OPCODE_SHIFT                 3
#define P_CONTROL_HARD_RESET_CLIENT_V2 7
    if (len >= 3)
    {
        return p[0] == 0
            && p[1] >= 14
            && p[2] == (P_CONTROL_HARD_RESET_CLIENT_V2<<P_OPCODE_SHIFT);
    }
    else if (len >= 2)
    {
        return p[0] == 0 && p[1] >= 14;
    }
    else
        return 0;
}

/* Is the buffer the beginning of a tinc connections?
 * (protocol is undocumented, but starts with "0 " in 1.0.15)
 * */
int is_tinc_protocol( const char *p, int len)
{
    return !strncmp(p, "0 ", len);
}

/* 
 * Read the beginning of data coming from the client connection and check if
 * it's a known protocol. Then leave the data on the defered
 * write buffer of the connection and returns the protocol index in the
 * protocols[] array *
 */
T_PROTO_ID probe_client_protocol(struct connection *cnx)
{
    char buffer[BUFSIZ];
    int n, i;

    n = read(cnx->q[0].fd, buffer, sizeof(buffer));
    /* It's possible that read() returns an error, e.g. if the client
     * disconnected between the previous call to select() and now. If that
     * happens, we just connect to the default protocol so the caller of this
     * function does not have to deal with a specific  failure condition (the
     * connection will just fail later normally). */
    if (n > 0) {
        defer_write(&cnx->q[1], buffer, n);

        for (i = 0; i < ARRAY_SIZE(protocols); i++) {
            if (protocols[i].affected) {
                if (protocols[i].probe(buffer, n)) {
                    return i;
                }
            }
        }
    }

    /* If none worked, return the first one affected (that's completely
     * arbitrary) */
    for (i = 0; i < ARRAY_SIZE(protocols); i++)
        if (protocols[i].affected)
            return i;

    /* At this stage... nothing is affected. This shouldn't happen as we check
     * at least one target exists when we parse the commnand line */
    fprintf(stderr, "FATAL: No protocol affected. This should not happen.\n");
    exit(1);
}

/* returns a string that prints the IP and port of the sockaddr */
char* sprintaddr(char* buf, size_t size, struct sockaddr_storage* s)
{
   char host[NI_MAXHOST], serv[NI_MAXSERV];

   getnameinfo((struct sockaddr*)s, sizeof(*s), host, sizeof(host), serv, sizeof(serv), numeric ? NI_NUMERICHOST | NI_NUMERICSERV : 0 );
   snprintf(buf, size, "%s:%s", host, serv);

   return buf;
}

/* turns a "hostname:port" string into a struct sockaddr;
sock: socket address to which to copy the addr
fullname: input string -- it gets clobbered
*/
void resolve_name(struct sockaddr_storage *sock, char* fullname)
{
   struct addrinfo *addr, hint;
   char *serv, *host;
   int res;

   char *sep = strrchr(fullname, ':');

   if (!sep) /* No separator: parameter is just a port */
   {
      fprintf(stderr, "names must be fully specified as hostname:port\n");
      exit(1);
   }

   host = fullname;
   serv = sep+1;
   *sep = 0;

   memset(&hint, 0, sizeof(hint));
   hint.ai_family = PF_UNSPEC;
   hint.ai_socktype = SOCK_STREAM;

   res = getaddrinfo(host, serv, &hint, &addr);
   if (res) {
      fprintf(stderr, "%s `%s'\n", gai_strerror(res), fullname);
      if (res == EAI_SERVICE)
         fprintf(stderr, "(Check you have specified all ports)\n");
      exit(1);
   }

   memcpy(sock, addr->ai_addr, sizeof(*sock));

   freeaddrinfo(addr);
}

/* Log to syslog, and to stderr if foreground */
void log_message(int type, char* msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    vsyslog(type, msg, ap);
    va_end(ap);

    va_start(ap, msg);
    if (foreground)
        vfprintf(stderr, msg, ap);
    va_end(ap);
}

/* syslogs who connected to where */
void log_connection(struct connection *cnx)
{
    struct sockaddr_storage peeraddr; /* Who's connecting to sshd */
    struct sockaddr_storage listenaddr; /* Where is it connecting to */
    struct sockaddr_storage forwardfromaddr; /* Where is it forwarded from */
    struct sockaddr_storage targetaddr; /* Where is it forwarded to */
    socklen_t size = sizeof(peeraddr);
#define MAX_NAMELENGTH (NI_MAXHOST + NI_MAXSERV + 1)
    char buf[MAX_NAMELENGTH], buf2[MAX_NAMELENGTH], buf3[MAX_NAMELENGTH], buf4[MAX_NAMELENGTH];
    int res;

    memset(&peeraddr, 0, sizeof(peeraddr));
    memset(&listenaddr, 0, sizeof(listenaddr));
    memset(&forwardfromaddr, 0, sizeof(forwardfromaddr));
    memset(&targetaddr, 0, sizeof(targetaddr));

    res = getpeername(cnx->q[0].fd, (struct sockaddr*)&peeraddr, &size);
    if (res == -1) return; /* that should never happen, right? */

    size = sizeof(listenaddr);
    res = getsockname(cnx->q[0].fd, (struct sockaddr*)&listenaddr, &size);
    if (res == -1) return;

    size = sizeof(targetaddr);
    res = getpeername(cnx->q[1].fd, (struct sockaddr*)&targetaddr, &size);
    if (res == -1) return;

    size = sizeof(forwardfromaddr);
    res = getsockname(cnx->q[1].fd, (struct sockaddr*)&forwardfromaddr, &size);
    if (res == -1) return;

    log_message(LOG_INFO, "connection from %s to %s forwarded from %s to %s\n", 
           sprintaddr(buf, sizeof(buf), &peeraddr), 
           sprintaddr(buf2, sizeof(buf2), &listenaddr),
           sprintaddr(buf3, sizeof(buf3), &forwardfromaddr),
           sprintaddr(buf4, sizeof(buf4), &targetaddr));

}


/* libwrap (tcpd): check the connection is legal. This is necessary because
 * the actual server will only see a connection coming from localhost and can't
 * apply the rules itself.
 *
 * Returns -1 if access is denied, 0 otherwise
 */
int check_access_rights(int in_socket, char* service)
{
#ifdef LIBWRAP
    struct sockaddr peeraddr;
    socklen_t size = sizeof(peeraddr);
    char addr_str[NI_MAXHOST], host[NI_MAXHOST];
    int res;

    res = getpeername(in_socket, &peeraddr, &size);
    CHECK_RES_DIE(res, "getpeername");

    /* extract peer address */
    res = getnameinfo(&peeraddr, size, addr_str, sizeof(addr_str), NULL, 0, NI_NUMERICHOST);
    if (res) {
        if (verbose)
            fprintf(stderr, "getnameinfo(NI_NUMERICHOST):%s\n", gai_strerror(res));
        strcpy(addr_str, STRING_UNKNOWN);
    }
    /* extract peer name */
    strcpy(host, STRING_UNKNOWN);
    if (!numeric) {
        res = getnameinfo(&peeraddr, size, host, sizeof(host), NULL, 0, NI_NAMEREQD);
        if (res) {
            if (verbose)
                fprintf(stderr, "getnameinfo(NI_NAMEREQD):%s\n", gai_strerror(res));
        }
    }

    if (!hosts_ctl(service, host, addr_str, STRING_UNKNOWN)) {
        if (verbose)
            fprintf(stderr, "access denied\n");
        log_message(LOG_INFO, "connection from %s(%s): access denied", host, addr_str);
        close(in_socket);
        return -1;
    }
#endif
    return 0;
}


void setup_signals(void)
{
    int res;
    struct sigaction action;

    /* Request no SIGCHLD is sent upon termination of
     * the children */
    memset(&action, 0, sizeof(action));
    action.sa_handler = NULL;
    action.sa_flags = SA_NOCLDWAIT;
    res = sigaction(SIGCHLD, &action, NULL);
    CHECK_RES_DIE(res, "sigaction");
}

/* Open syslog connection with appropriate banner; 
 * banner is made up of basename(bin_name)+"[pid]" */
void setup_syslog(char* bin_name) {
    char *name1, *name2;

    name1 = strdup(bin_name);
    asprintf(&name2, "%s[%d]", basename(name1), getpid());
    openlog(name2, LOG_CONS, LOG_AUTH);
    free(name1); 
    /* Don't free name2, as openlog(3) uses it (at least in glibc) */

    log_message(LOG_INFO, "%s %s started\n", server_type, VERSION);
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

/* Writes my PID */
void write_pid_file(char* pidfile)
{
    FILE *f;

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
    int i;
    
    for (i = 0; i < ARRAY_SIZE(protocols); i++) {
        if (protocols[i].affected)
            fprintf(stderr,
                    "%s addr: %s. libwrap service: %s\n", 
                    protocols[i].description, 
                    sprintaddr(buf, sizeof(buf), &protocols[i].saddr), 
                    protocols[i].service);
    }
    fprintf(stderr, "listening on:\n");
    for (i = 0; i < num_addr_listen; i++) {
        fprintf(stderr, "\t%s\n", sprintaddr(buf, sizeof(buf), &addr_listen[i]));
    }
    fprintf(stderr, "timeout to ssh: %d\n", probing_timeout);
}

/* Adds protocols to the list of options, so command-line parsing uses the
 * protocol definition array 
 * options: array of options to add to; must be big enough
 * n_opts: number of options in *options before calling (i.e. where to append)
 * prot: array of protocols
 * n_prots: number of protocols in *prot
 * */
#define PROT_SHIFT 1000  /* protocol options will be 1000, 1001, etc */
void append_protocols(struct option *options, int n_opts, struct proto *prot, int n_prots)
{
    int o, p;

    for (o = n_opts, p = 0; p < n_prots; o++, p++) {
        options[o].name = prot[p].description;
        options[o].has_arg = required_argument;
        options[o].flag = 0;
        options[o].val = p + PROT_SHIFT;
    }
}

void parse_cmdline(int argc, char* argv[])
{
    int c, affected = 0;
    struct option const_options[] = {
        { "inetd",      no_argument,            &inetd,         1 },
        { "foreground", no_argument,            &foreground,    1 },
        { "verbose",    no_argument,            &verbose,       1 },
        { "numeric",    no_argument,            &numeric,       1 },
        { "user",       required_argument,      0,              'u' },
        { "pidfile",   required_argument,       0,              'P' },
        { "timeout",    required_argument,      0,              't' },
        { "listen",     required_argument,      0,              'p' },
    };
    struct option all_options[ARRAY_SIZE(const_options) + ARRAY_SIZE(protocols) + 1];

    memset(all_options, 0, sizeof(all_options));
    memcpy(all_options, const_options, sizeof(const_options));
    append_protocols(all_options, ARRAY_SIZE(const_options), protocols, ARRAY_SIZE(protocols));

    while ((c = getopt_long_only(argc, argv, "t:l:s:o:T:p:VP:", all_options, NULL)) != -1) {
        if (c == 0) continue;

        if (c >= PROT_SHIFT) {
            affected++;
            protocols[c - PROT_SHIFT].affected = 1;
            resolve_name(&protocols[c - PROT_SHIFT].saddr, optarg);
            continue;
        }

        switch (c) {

        case 't':
            probing_timeout = atoi(optarg);
            break;

        case 'p':
            num_addr_listen++;
            addr_listen = realloc(addr_listen, num_addr_listen * sizeof(addr_listen[0]));
            resolve_name(&addr_listen[num_addr_listen - 1], optarg);
            break;

        case 'V':
            printf("%s %s\n", server_type, VERSION);
            exit(0);

        case 'u':
            user_name = optarg;
            break;

        case 'P':
            pid_file = optarg;
            break;

        default:
            fprintf(stderr, USAGE_STRING);
            exit(2);
        }
    }

    if (!affected) {
        fprintf(stderr, "At least one target protocol must be specified.\n");
        exit(2);
    }

    if (!num_addr_listen) {
        fprintf(stderr, "No listening address specified; use at least one -p option\n");
        exit(1);
    }

}

int main(int argc, char *argv[])
{

   extern char *optarg;
   extern int optind;
   int res;

   int *listen_sockets;

   /* Init defaults */
   pid_file = "/var/run/sslh.pid";
   user_name = "nobody";
   foreground = 0;

   parse_cmdline(argc, argv);

   if (inetd)
   {
       verbose = 0;
       start_shoveler(0);
       exit(0);
   }

   if (verbose)
       printsettings();

   listen_sockets = malloc(num_addr_listen * sizeof(*listen_sockets));
   start_listen_sockets(listen_sockets, addr_listen, num_addr_listen);
   free(addr_listen);

   if (!foreground)
       if (fork() > 0) exit(0); /* Detach */

   setup_signals();

   write_pid_file(pid_file);

   drop_privileges(user_name);

   /* New session -- become group leader */
   if (getuid() == 0) {
       res = setsid();
       CHECK_RES_DIE(res, "setsid: already process leader");
   }

   /* Open syslog connection */
   setup_syslog(argv[0]);

   main_loop(listen_sockets, num_addr_listen);

   return 0;
}
