
dnl Use autoconf to generate the `configure` script from this and Makefile.in

AC_INIT
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile])

AC_CHECK_HEADERS(linux/landlock.h, AC_DEFINE(HAVE_LANDLOCK), [])
AC_OUTPUT
