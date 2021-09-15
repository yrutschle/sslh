#ifndef LOG_H
#define LOG_H

void setup_syslog(const char* bin_name);

void log_message(int type, const char* msg, ...);

void log_connection(struct connection_desc* desc, const struct connection *cnx);

#endif /* LOG_H */
