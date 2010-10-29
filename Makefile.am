sbin_PROGRAMS = ggaoed ggaoectl

AM_CPPFLAGS = $(GLIB_CFLAGS) -DSYSCONFDIR='"$(sysconfdir)"' -DLOCALSTATEDIR='"$(localstatedir)"'

noinst_HEADERS = aoe.h ctl.h ggaoed.h util.h dppolicy.h cs_crush.h ceph-client-standalone/crush/crush.h ceph-client-standalone/crush/hash.h ceph-client-standalone/crush/mapper.h

ggaoed_SOURCES = ctl.c device.c ggaoed.c mem.c netlink.c network.c dppolicy.c cs_crush.c ceph-client-standalone/crush/crush.c ceph-client-standalone/crush/hash.c ceph-client-standalone/crush/mapper.c

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

SUBDIRS = . doc
