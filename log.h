#ifndef LOG_H
#define LOG_H

#include "common.h"

void setup_syslog(const char* bin_name);

void setup_logfile();

void close_logfile();

void log_connection(struct connection_desc* desc, const struct connection *cnx);

typedef struct s_msg_info{
    int log_level;
    int *verbose;
} msg_info;

void print_message(msg_info info, const char* str, ...);
extern msg_info msg_config;
extern msg_info msg_config_error;

extern msg_info msg_fd;
extern msg_info msg_packets;

extern msg_info msg_int_error;
extern msg_info msg_system_error;

extern msg_info msg_connections_try;
extern msg_info msg_connections_error;
extern msg_info msg_connections;

extern msg_info msg_probe_info;
extern msg_info msg_probe_error;

#endif /* LOG_H */
