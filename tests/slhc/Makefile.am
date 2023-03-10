AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBCARES_CFLAGS)
AM_LDFLAGS = -no-install

EXTRA_DIST = slhc_test.ok

check_PROGRAMS = slhc_test

slhc_test_SOURCES = slhc_test.c

slhc_test_LDADD = \
	$(top_builddir)/src/sgsn/slhc.o \
	$(LIBOSMOCORE_LIBS)


