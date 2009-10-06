sbin_PROGRAMS = ggaoed ggaoectl

AM_CPPFLAGS = $(GLIB_CFLAGS) -DSYSCONFDIR='"$(sysconfdir)"' -DLOCALSTATEDIR='"$(localstatedir)"'

noinst_HEADERS = aoe.h ctl.h ggaoed.h util.h

ggaoed_SOURCES = ctl.c device.c ggaoed.c mem.c netlink.c network.c
ggaoed_LDADD = $(GLIB_LIBS) -lrt -latomic_ops

ggaoectl_SOURCES = ggaoectl.c
ggaoectl_LDADD = $(GLIB_LIBS)

doc_DATA = ggaoed.conf.dist

EXTRA_DIST = \
		COPYING \
		NEWS \
		README \
		ggaoed.conf.dist

CLEANFILES = *.gcda *.gcno *.gcov gmon.out

SUBDIRS = .

if HAVE_DOCBOOK_MAN
SUBDIRS += doc
endif
