AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBCARES_CFLAGS)
AM_LDFLAGS = -no-install

EXTRA_DIST = sndcp_xid_test.ok

check_PROGRAMS = sndcp_xid_test

sndcp_xid_test_SOURCES = sndcp_xid_test.c

sndcp_xid_test_LDADD = \
	$(top_builddir)/src/sgsn/gprs_sndcp_xid.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBGTP_LIBS) \
	-lrt -lm


