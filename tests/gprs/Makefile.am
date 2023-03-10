AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOABIS_CFLAGS)
AM_LDFLAGS = -no-install

EXTRA_DIST = gprs_test.ok

check_PROGRAMS = gprs_test

gprs_test_SOURCES = gprs_test.c $(top_srcdir)/src/gprs/gprs_utils.c

gprs_test_LDADD = $(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS)
