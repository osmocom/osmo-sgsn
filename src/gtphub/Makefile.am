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
	$(LIBOSMOGSUPCLIENT_CFLAGS) \
	$(COVERAGE_CFLAGS) \
	$(LIBGTP_CFLAGS) \
	$(NULL)
if BUILD_IU
AM_CFLAGS += \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(NULL)
endif

bin_PROGRAMS = osmo-gtphub

osmo_gtphub_SOURCES = \
	gtphub_main.c \
	gtphub.c \
	gtphub_sock.c \
	gtphub_ares.c \
	gtphub_vty.c \
	$(NULL)

osmo_gtphub_LDADD = \
	$(top_builddir)/src/gprs/sgsn_ares.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBGTP_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	-lrt \
	$(NULL)
