#ifndef PROXYPROTOCOL_H
#define PROXYPROTOCOL_H


#if HAVE_PROXYPROTOCOL
int pp_write_header(int pp_version, struct connection* cnx);


#else /* HAVE_PROXYPROTOCOL */

static inline int pp_write_header(int pp_version, struct connection* cnx) {}

#endif /* HAVE_PROXYPROTOCOL */

#endif /* PROXYPROTOCOL_H */
