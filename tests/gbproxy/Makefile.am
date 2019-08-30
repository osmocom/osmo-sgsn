AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

EXTRA_DIST = \
	gbproxy_test.ok \
	$(NULL)

noinst_PROGRAMS = \
	gbproxy_test \
	$(NULL)

gbproxy_test_SOURCES = \
	gbproxy_test.c \
	$(NULL)

gbproxy_test_LDFLAGS = \
	-Wl,--wrap=osmo_get_rand_id \
	$(NULL)

gbproxy_test_LDADD = \
	$(top_builddir)/src/gbproxy/gb_proxy.o \
	$(top_builddir)/src/gbproxy/gb_proxy_patch.o \
	$(top_builddir)/src/gbproxy/gb_proxy_peer.o \
	$(top_builddir)/src/gbproxy/gb_proxy_tlli.o \
	$(top_builddir)/src/gprs/gprs_gb_parse.o \
	$(top_builddir)/src/gprs/gprs_llc_parse.o \
	$(top_builddir)/src/gprs/crc24.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBRARY_DL) \
	-lrt \
	$(NULL)
