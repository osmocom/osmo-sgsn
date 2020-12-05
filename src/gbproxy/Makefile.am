AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	-I$(top_builddir) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-fno-strict-aliasing \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOGB_CFLAGS) \
	$(LIBOSMOGSUPCLIENT_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBGTP_CFLAGS) \
	$(NULL)

bin_PROGRAMS = \
	osmo-gbproxy \
	$(NULL)

osmo_gbproxy_SOURCES = \
	gb_proxy.c \
	gb_proxy_main.c \
	gb_proxy_vty.c \
	gb_proxy_ctrl.c \
	gb_proxy_peer.c \
	$(NULL)
osmo_gbproxy_LDADD = \
	$(top_builddir)/src/gprs/gprs_gb_parse.o \
	$(top_builddir)/src/gprs/gprs_llc_parse.o \
	$(top_builddir)/src/gprs/crc24.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBGTP_LIBS) \
	-lrt \
	$(NULL)
