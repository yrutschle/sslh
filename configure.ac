
dnl Use autoconf to generate the `configure` script from this and Makefile.in
dnl This is awkardly adapted from https://github.com/edrosten/autoconf_tutorial
dnl (all mistakes mine)

AC_INIT
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile])

AC_CHECK_LIB([wrap], [hosts_ctl], [AC_DEFINE(HAVE_LIBWRAP) LIBS="$LIBS -lwrap" ], [])
AC_CHECK_LIB([cap], [cap_get_proc], [AC_DEFINE(HAVE_LIBCAP) LIBS="$LIBS -lcap" ], [])
AC_CHECK_LIB([bsd], [setproctitle], [AC_DEFINE(HAVE_LIBBSD) LIBS="$LIBS -lbsd" ], [])

dnl TODO: check that wolfssl contains  wolfSSL_GetEchClientHelloInner instead of just existing
AC_CHECK_LIB([wolfssl], [wolfSSL_Init], [AC_DEFINE(HAVE_WOLFSSL) LIBS="$LIBS -lwolfssl" ], [])

AC_CHECK_HEADERS(linux/landlock.h, AC_DEFINE(HAVE_LANDLOCK), [])
AC_CHECK_HEADERS(proxy_protocol.h, [AC_DEFINE(HAVE_PROXYPROTOCOL) LIBS="$LIBS -lproxyprotocol" ], [])

LIBS="$LIBS"
AC_SUBST([LIBS])

AC_OUTPUT
