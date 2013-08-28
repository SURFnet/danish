MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

				-I$(srcdir)/.. \
				@OPENSSL_CFLAGS@

bin_PROGRAMS =			danish

danish_SOURCES =		danish.c \
				cert.h \
				cert.c

danish_LDADD =			@OPENSSL_LIBS@
