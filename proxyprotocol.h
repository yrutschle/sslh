#ifndef PROXYPROTOCOL_H
#define PROXYPROTOCOL_H


#if HAVE_PROXYPROTOCOL


int pp_write_header(int pp_version, struct connection* cnx);
int pp_header_len(char* buffer, int len);


#else /* HAVE_PROXYPROTOCOL */

static inline int pp_write_header(int pp_version, struct connection* cnx) { return 0; }
static inline int pp_header_len(char*, int) { return 0; }

#endif /* HAVE_PROXYPROTOCOL */

#endif /* PROXYPROTOCOL_H */
