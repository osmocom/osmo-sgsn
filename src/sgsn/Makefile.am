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

bin_PROGRAMS = \
	osmo-sgsn \
	$(NULL)

osmo_sgsn_SOURCES = \
	gprs_gb.c \
	gprs_gmm_attach.c \
	gprs_gmm.c \
	gprs_gmm_fsm.c \
	gprs_mm_state_gb_fsm.c \
	gprs_sgsn.c \
	gprs_sm.c \
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
	$(top_builddir)/src/gprs/gprs_llc_parse.o \
	$(top_builddir)/src/gprs/crc24.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(top_builddir)/src/gprs/sgsn_ares.o \
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

osmo_sgsn_SOURCES += \
	gprs_mm_state_iu_fsm.c \
	gprs_ranap.c

endif
