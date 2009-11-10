man_MANS = ggaoed.8 ggaoectl.8 ggaoed.conf.5

EXTRA_DIST = $(addsuffix .xml,$(man_MANS)) $(addsuffix .in,$(man_MANS))
DISTCLEANFILES = $(man_MANS)

if HAVE_DOCBOOK2X_MAN

$(addsuffix .in,$(man_MANS)): %.in: %.xml
	$(DOCBOOK2X_MAN) --encoding=utf-8 $<
	-mv -f `basename $(basename $<)` $@

endif

# Perform variable substitutions on (mainly) config file templates.
CONFSUBST_CMD = sed \
	-e "s,@bindir\@,$(bindir),g" \
	-e "s,@libdir\@,$(libdir),g" \
	-e "s,@datadir\@,$(datadir),g" \
	-e "s,@localstatedir\@,$(localstatedir),g" \
	-e "s,@sbindir\@,$(sbindir),g" \
	-e "s,@sysconfdir\@,$(sysconfdir),g" \
	-e "s,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g"

$(man_MANS): %: %.in
	$(CONFSUBST_CMD) $< >$@
