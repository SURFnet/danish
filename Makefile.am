ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
        config.log config.status \
        $(srcdir)/Makefile.in \
        $(srcdir)/config.h.in $(srcdir)/config.h.in~ \
        $(srcdir)/configure \
        $(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
        $(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
        $(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/m4/libtool.m4 $(srcdir)/m4/ltoptions.m4 \
	$(srcdir)/m4/ltsugar.m4 $(srcdir)/m4/ltversion.m4 \
	$(srcdir)/m4/lt~obsolete.m4 $(srcdir)/test-driver

# Top level
bin_PROGRAMS =
dist_man_MANS = 
EXTRA_DIST =
doc_DATA =

# Documentation
EXTRA_DIST += 		AUTHORS \
			ChangeLog \
			LICENSE \
			NEWS \
			README.md

doc_DATA +=		AUTHORS \
			ChangeLog \
			LICENSE \
			NEWS \
			README.md

# Sources
bin_PROGRAMS +=			bin/danish

bin_danish_CFLAGS =		-Isrc @OPENSSL_CFLAGS@

bin_danish_SOURCES =		src/danish.c \
				src/cert.h \
				src/cert.c

bin_danish_LDADD =		@OPENSSL_LIBS@

# Manual page
dist_man_MANS += 		man/danish.1
