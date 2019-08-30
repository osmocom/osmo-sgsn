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

OSMO_LIBS = \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBGTP_LIBS) \
	$(NULL)

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = \
	gprs_gb_parse.c \
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

bin_PROGRAMS = \
	osmo-sgsn \
	osmo-gtphub \
	$(NULL)

osmo_sgsn_SOURCES = \
	gprs_gb.c \
	gprs_gmm_attach.c \
	gprs_gmm.c \
	gprs_mm_state_gb_fsm.c \
	gprs_mm_state_iu_fsm.c \
	gprs_ranap.c \
	gprs_sgsn.c \
	gprs_sndcp.c \
	gprs_sndcp_comp.c \
	gprs_sndcp_dcomp.c \
	gprs_sndcp_pcomp.c \
	gprs_sndcp_vty.c \
	gprs_sndcp_xid.c \
	sgsn_main.c \
	sgsn_vty.c \
	sgsn_libgtp.c \
	gprs_llc.c \
	gprs_llc_vty.c \
	sgsn_ctrl.c \
	sgsn_auth.c \
	gprs_subscriber.c \
	sgsn_cdr.c \
	slhc.c \
	gprs_llc_xid.c \
	v42bis.c \
	$(NULL)
osmo_sgsn_LDADD = \
	libcommon.la \
	$(OSMO_LIBS) \
	$(LIBOSMOABIS_LIBS) \
	$(LIBOSMOGSUPCLIENT_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBGTP_LIBS) \
	-lrt \
	-lm \
	$(NULL)
if BUILD_IU
osmo_sgsn_LDADD += \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBOSMORANAP_LIBS) \
	$(LIBASN1C_LIBS) \
	$(NULL)
endif

osmo_gtphub_SOURCES = \
	gtphub_main.c \
	gtphub.c \
	gtphub_sock.c \
	gtphub_ares.c \
	gtphub_vty.c \
	$(NULL)
osmo_gtphub_LDADD = \
	libcommon.la \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBGTP_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	-lrt \
	$(NULL)
