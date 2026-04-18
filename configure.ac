
dnl Use autoconf to generate the `configure` script from this and Makefile.in
dnl This is awkardly adapted from https://github.com/edrosten/autoconf_tutorial
dnl (all mistakes mine)

AC_INIT
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile])

AC_CHECK_LIB([wrap], [hosts_ctl],
  [AC_DEFINE([HAVE_LIBWRAP], [1], [Libwrap, to support host_ctl, /etc/allow and /etc/deny]) LIBS="$LIBS -lwrap"])
AC_CHECK_LIB([cap], [cap_get_proc],
  [AC_DEFINE([HAVE_LIBCAP], [1], [libcap support, to use Linux capabilities]) LIBS="$LIBS -lcap"])
AC_CHECK_LIB([bsd], [setproctitle],
  [AC_DEFINE([HAVE_LIBBSD], [1], [libbsd, to change process name]) LIBS="$LIBS -lbsd"])

AC_CHECK_HEADERS(linux/landlock.h,
  AC_DEFINE([HAVE_LANDLOCK], [1], [Landlock sandboxing Linux LSM]))
AC_CHECK_HEADERS(proxy_protocol.h,
  [AC_DEFINE([HAVE_PROXYPROTOCOL], [1], [Support for Proxy-protocol using libproxyprotocol]) LIBS="$LIBS -lproxyprotocol"])

LIBS="$LIBS"
AC_SUBST([LIBS])

AC_OUTPUT
