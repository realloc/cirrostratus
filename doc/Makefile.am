man_MANS = ggaoed.8 ggaoectl.8 ggaoed.conf.5

STYLESHEET = stylesheet.xsl

EXTRA_DIST = $(addsuffix .xml,$(man_MANS)) $(addsuffix .in,$(man_MANS)) $(STYLESHEET)
DISTCLEANFILES = $(man_MANS)

$(addsuffix .in,$(man_MANS)): %.in: %.xml $(STYLESHEET)
	$(XSLTPROC) $(STYLESHEET) $<
	-mv -f `basename $(basename $<)` $@

# Perform variable substitutions on (mainly) config file templates.
CONFSUBST_CMD = sed \
	-e "s,@bindir\@,$(bindir),g" \
	-e "s,@libdir\@,$(libdir),g" \
	-e "s,@datadir\@,$(datadir),g" \
	-e "s,@localstatedir\@,$(localstatedir),g" \
	-e "s,@sbindir\@,$(sbindir),g" \
	-e "s,@sysconfdir\@,$(sysconfdir),g" \
	-e "s,@PACKAGE_VERSION\@,$(PACKAGE_VERSION),g"

# The manpage stylesheet generates Latin-1 output. Replace the non-breaking
# space and aacute with named characters
$(man_MANS): %: %.in
	$(CONFSUBST_CMD) -e 's/\xa0/\\ /g' -e "s/\\xe1/\\\\('a/g" $< >$@
