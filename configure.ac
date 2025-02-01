
dnl Use autoconf to generate the `configure` script from this and Makefile.in
dnl This is awkardly adapted from https://github.com/edrosten/autoconf_tutorial
dnl (all mistakes mine)

AC_INIT
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile])

have_proxyprotocol=0
AC_CHECK_HEADERS(linux/landlock.h, AC_DEFINE(HAVE_LANDLOCK), [])
AC_CHECK_HEADERS(proxy_protocol.h, AC_DEFINE(HAVE_PROXYPROTOCOL), [have_proxyprotocol=1])
if test $have_proxyprotocol == 0
then
    LIBS="$LIBS -lproxyprotocol"
fi

LIBS="$LIBS"
AC_SUBST([LIBS])

AC_OUTPUT
