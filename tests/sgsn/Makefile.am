AM_CPPFLAGS = \
	$(all_includes) \
	-I$(top_srcdir)/include \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	-ggdb3 \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOCTRL_CFLAGS) \
	$(LIBOSMOABIS_CFLAGS) \
	$(LIBOSMOGSM_CFLAGS) \
	$(LIBOSMOGSUPCLIENT_CFLAGS) \
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

AM_LDFLAGS = -no-install

EXTRA_DIST = \
	sgsn_test.ok \
	$(NULL)

check_PROGRAMS = \
	sgsn_test \
	$(NULL)

noinst_HEADERS = \
	gprs_gb_parse.h \
	$(NULL)

sgsn_test_SOURCES = \
	sgsn_test.c \
	gprs_gb_parse.c \
	$(NULL)

sgsn_test_LDFLAGS = \
	-Wl,--wrap=osmo_get_rand_id \
	-Wl,--wrap=sgsn_update_subscriber_data \
	-Wl,--wrap=gprs_subscr_request_update_location \
	-Wl,--wrap=gprs_subscr_request_auth_info \
	-Wl,--wrap=osmo_gsup_client_send \
	$(AM_LDFLAGS) \
	$(NULL)

sgsn_test_LDADD = \
	$(top_builddir)/src/sgsn/apn.o \
	$(top_builddir)/src/sgsn/gprs_bssgp.o \
	$(top_builddir)/src/sgsn/gprs_llc.o \
	$(top_builddir)/src/sgsn/gprs_ns.o \
	$(top_builddir)/src/sgsn/gprs_sndcp.o \
	$(top_builddir)/src/sgsn/gprs_gmm_attach.o \
	$(top_builddir)/src/sgsn/gprs_gmm.o \
	$(top_builddir)/src/sgsn/gprs_gmm_fsm.o \
	$(top_builddir)/src/sgsn/gprs_gmm_util.o \
	$(top_builddir)/src/sgsn/gprs_mm_state_gb_fsm.o \
	$(top_builddir)/src/sgsn/gprs_routing_area.o \
	$(top_builddir)/src/sgsn/gtp_ggsn.o \
	$(top_builddir)/src/sgsn/gtp_mme.o \
	$(top_builddir)/src/sgsn/mmctx.o \
	$(top_builddir)/src/sgsn/pdpctx.o \
	$(top_builddir)/src/sgsn/sgsn.o \
	$(top_builddir)/src/sgsn/sgsn_cdr.o \
	$(top_builddir)/src/sgsn/sgsn_ctrl.o \
	$(top_builddir)/src/sgsn/sgsn_vty.o \
	$(top_builddir)/src/sgsn/sgsn_libgtp.o \
	$(top_builddir)/src/sgsn/sgsn_auth.o \
	$(top_builddir)/src/sgsn/gprs_subscriber.o \
        $(top_builddir)/src/sgsn/gprs_llc_xid.o \
	$(top_builddir)/src/sgsn/gprs_sndcp_xid.o \
        $(top_builddir)/src/sgsn/slhc.o \
	$(top_builddir)/src/sgsn/gprs_sm.o \
        $(top_builddir)/src/sgsn/gprs_sndcp_comp.o \
        $(top_builddir)/src/sgsn/gprs_sndcp_pcomp.o \
        $(top_builddir)/src/sgsn/v42bis.o \
        $(top_builddir)/src/sgsn/gprs_sndcp_dcomp.o \
	$(top_builddir)/src/sgsn/sgsn_rim.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(top_builddir)/src/gprs/gprs_llc_parse.o \
	$(top_builddir)/src/gprs/crc24.o \
	$(top_builddir)/src/gprs/sgsn_ares.o \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOCTRL_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOGB_LIBS) \
	$(LIBOSMOGSUPCLIENT_LIBS) \
	$(LIBCARES_LIBS) \
	$(LIBGTP_LIBS) \
	-lrt \
	-lm \
	$(NULL)

if BUILD_IU
sgsn_test_LDADD += \
	$(top_builddir)/src/sgsn/gprs_ranap.o \
	$(top_builddir)/src/sgsn/gprs_mm_state_iu_fsm.o \
	$(top_builddir)/src/sgsn/iu_client.o \
	$(top_builddir)/src/sgsn/iu_rnc.o \
	$(top_builddir)/src/sgsn/sccp.o \
	$(LIBOSMORANAP_LIBS) \
	$(LIBOSMOSIGTRAN_LIBS) \
	$(LIBASN1C_LIBS) \
	$(NULL)
endif
