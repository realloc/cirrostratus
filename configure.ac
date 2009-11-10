AC_INIT([GGs AoE target], [1.0], [gombasg@sztaki.hu], [ggaoed])
AC_PREREQ([2.59])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([scripts])
AC_CONFIG_MACRO_DIR([cf])
AC_CANONICAL_HOST
AC_CONFIG_SRCDIR([ggaoed.c])
AM_INIT_AUTOMAKE([foreign])

dnl ===================================================================
dnl Check for programs

AC_PROG_CC
AC_GNU_SOURCE

dnl We need large file support on 32-bit hosts
AC_SYS_LARGEFILE

dnl Enable useful warnings
if test "$ac_cv_c_compiler_gnu" = yes; then
	CFLAGS="-Wall -Wmissing-prototypes -Wstrict-prototypes -Wsign-compare ${CFLAGS}"
fi

AC_CHECK_HEADER([libaio.h],, [AC_MSG_ERROR([libaio.h is missing])])
AC_CHECK_LIB([aio], [io_submit],, [AC_MSG_ERROR([libaio is missing])])
AC_CHECK_MEMBERS([struct iocb.u.c.resfd],,
	[AC_MSG_ERROR([your libaio is too old, we need at least 0.3.107])],
	[#include <libaio.h>])

AC_CHECK_HEADER([sys/epoll.h],, [AC_MSG_ERROR([epoll support is missing from libc])])

AC_CHECK_HEADERS([sys/eventfd.h])
AC_CHECK_FUNCS([eventfd],, [AC_MSG_ERROR([eventfd support is missing from libc])])

AC_CHECK_HEADERS([sys/timerfd.h])
AC_CHECK_FUNCS([timerfd_create],, [AC_MSG_ERROR([timerfd support is missing from libc])])

AM_PATH_GLIB_2_0([2.12.0])
if test "$no_glib" = yes; then
	AC_MSG_ERROR([glib libraries were not found])
fi

AC_CHECK_HEADER([blkid/blkid.h],, [AC_MSG_ERROR([blkid/blkid.h is missing])])
AC_CHECK_LIB([blkid], [blkid_get_cache],, [AC_MSG_ERROR([libblkid is missing])])

AC_CHECK_HEADER([atomic_ops.h],, [AC_MSG_ERROR([atomic_ops.h is missing])])

dnl ===================================================================
dnl Tools needed to build the documentation

AC_PATH_PROG([DOCBOOK2X_MAN], [docbook2x-man], [false])
AM_CONDITIONAL([HAVE_DOCBOOK2X_MAN], [test "$DOCBOOK2X_MAN" != false])

dnl ===================================================================
dnl Instantiate config-dependent files

AC_CONFIG_FILES([Makefile doc/Makefile])
AC_OUTPUT
