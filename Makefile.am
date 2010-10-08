
-sbin_PROGRAMS = ggaoed ggaoectl
2	 	
-
3	 	
-AM_CPPFLAGS = $(GLIB_CFLAGS) -DSYSCONFDIR='"$(sysconfdir)"' -DLOCALSTATEDIR='"$(localstatedir)"'
4	 	
-
5	 	
-noinst_HEADERS = aoe.h ctl.h ggaoed.h util.h map_test.h
6	 	
-
7	 	
-ggaoed_SOURCES = ctl.c device.c ggaoed.c mem.c netlink.c network.c map_test.c
8	 	
-ggaoed_LDADD = $(GLIB_LIBS) -lrt -latomic_ops
9	 	
-
10	 	
-ggaoectl_SOURCES = ggaoectl.c
11	 	
-ggaoectl_LDADD = $(GLIB_LIBS)
12	 	
-
13	 	
-doc_DATA = ggaoed.conf.dist
14	 	
-
15	 	
-EXTRA_DIST = \
16	 	
-    COPYING \
17	 	
-    NEWS \
18	 	
-    README \
19	 	
-    ggaoed.conf.dist
20	 	
-
21	 	
-CLEANFILES = *.gcda *.gcno *.gcov gmon.out
22	 	
-
23	 	
-SUBDIRS = . doc
