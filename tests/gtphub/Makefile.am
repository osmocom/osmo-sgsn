AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBGTP_CFLAGS) \
	$(NULL)

AM_LDFLAGS = -no-install

EXTRA_DIST = \
	gtphub_test.ok \
	$(NULL)

check_PROGRAMS = \
	gtphub_test \
	$(NULL)

gtphub_test_SOURCES = \
	gtphub_test.c \
	$(NULL)

gtphub_test_LDFLAGS = \
	-Wl,--wrap=gtphub_resolve_ggsn_addr \
	-Wl,--wrap=gtphub_ares_init \
	-Wl,--wrap=gtphub_write \
	$(AM_LDFLAGS) \
	$(NULL)

gtphub_test_LDADD = \
	$(top_builddir)/src/gtphub/gtphub.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBGTP_LIBS) \
	-lrt \
	$(NULL)
