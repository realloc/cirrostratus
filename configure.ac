AC_INIT([GGs AoE target], [0.9], [gombasg@sztaki.hu], [ggaoed])
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

AM_PATH_GLIB_2_0([2.12.0])
if test "$no_glib" = yes; then
	AC_MSG_ERROR([glib libraries were not found])
fi

AC_CHECK_HEADER([blkid/blkid.h],, [AC_MSG_ERROR([blkid/blkid.h is missing])])
AC_CHECK_LIB([blkid], [blkid_get_cache],, [AC_MSG_ERROR([libblkid is missing])])

dnl ===================================================================
dnl Tools needed to build the documentation

AC_PATH_PROG([XSLTPROC], [xsltproc], [no])
if test "$XSLTPROC" != no; then
	XSLTPROC="$XSLTPROC --nonet"
	AC_CACHE_CHECK([for DocBook XML manpage stylesheets], [gg_cv_docbook_man],
	[
		cat >conftest.xml <<"EOF"
<?xml version="1.0"?>
	<!-- "http://www.oasis-open.org/docbook/xml/4.5/docbookx.dtd" @<:@ -->
<?xml-stylesheet href="http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl" type="text/xsl"?>
<!DOCTYPE refentry PUBLIC "-//OASIS//DTD DocBook XML V4.5//EN"
	"http://www.oasis-open.org/docbook/xml/4.5/docbookx.dtd" @<:@
@:>@>
<refentry id="test">
<refmeta>
    <refentrytitle>TEST</refentrytitle>
    <manvolnum>test</manvolnum>
</refmeta>
</refentry>
EOF
		$XSLTPROC --noout http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl conftest.xml >/dev/null 2>/dev/null
		rm -f .test
		result=$?
		if test $result = 0; then
			gg_cv_docbook_man=yes
		else
			gg_cv_docbook_man=no
		fi
	])
fi
AM_CONDITIONAL([HAVE_DOCBOOK_MAN], [test "$gg_cv_docbook_man" = yes])

dnl ===================================================================
dnl Instantiate config-dependent files

AC_CONFIG_FILES([Makefile doc/Makefile])
AC_OUTPUT
