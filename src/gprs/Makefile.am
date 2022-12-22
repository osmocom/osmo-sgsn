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
	$(LIBCARES_CFLAGS) \
	$(LIBGTP_CFLAGS) \
	$(NULL)
if BUILD_IU
AM_CFLAGS += \
	$(LIBASN1C_CFLAGS) \
	$(LIBOSMOSIGTRAN_CFLAGS) \
	$(LIBOSMORANAP_CFLAGS) \
	$(NULL)
endif

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = \
	gprs_llc_parse.c \
	crc24.c \
	gprs_utils.c \
	sgsn_ares.c \
	$(NULL)

libcommon_la_LIBADD = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBGTP_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBCARES_LIBS) \
	$(NULL)
