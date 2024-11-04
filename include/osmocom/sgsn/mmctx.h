#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/timer.h>

#include <osmocom/gsm/gsm48.h>

#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/crypt/auth.h>

#include <osmocom/sgsn/apn.h>
#include <osmocom/sgsn/auth.h>
#include <osmocom/sgsn/gprs_subscriber.h>

#define GSM_EXTENSION_LENGTH 15

struct gprs_llc_lle;
struct ctrl_handle;
struct gprs_subscr;
struct sgsn_ggsn_ctx;
struct sgsn_pdp_ctx;

enum gsm48_gsm_cause;

enum gprs_mm_ctr {
	GMM_CTR_PKTS_SIG_IN,
	GMM_CTR_PKTS_SIG_OUT,
	GMM_CTR_PKTS_UDATA_IN,
	GMM_CTR_PKTS_UDATA_OUT,
	GMM_CTR_BYTES_UDATA_IN,
	GMM_CTR_BYTES_UDATA_OUT,
	GMM_CTR_PDP_CTX_ACT,
	GMM_CTR_SUSPEND,
	GMM_CTR_PAGING_PS,
	GMM_CTR_PAGING_CS,
	GMM_CTR_RA_UPDATE,
};

enum gprs_t3350_mode {
	GMM_T3350_MODE_NONE,
	GMM_T3350_MODE_ATT,
	GMM_T3350_MODE_RAU,
	GMM_T3350_MODE_PTMSI_REALL,
};

enum sgsn_ggsn_lookup_state {
	SGSN_GGSN_2DIGIT,
	SGSN_GGSN_3DIGIT,
};

struct sgsn_ggsn_lookup {
	int state;

	struct sgsn_mm_ctx *mmctx;

	/* APN string */
	char apn_str[GSM_APN_LENGTH];

	/* the original data */
	struct msgb *orig_msg;
	struct tlv_parsed tp;

	/* for dealing with re-transmissions */
	uint8_t nsapi;
	uint8_t sapi;
	uint8_t ti;
};

enum sgsn_ran_type {
	/* GPRS/EDGE via Gb */
	MM_CTX_T_GERAN_Gb,
	/* UMTS via Iu */
	MM_CTX_T_UTRAN_Iu,
#if 0
	/* GPRS/EDGE via Iu, not supported */
	MM_CTX_T_GERAN_Iu,
#endif
};
extern const struct value_string sgsn_ran_type_names[];

struct service_info {
	uint8_t type;
	uint16_t pdp_status;
};

struct ranap_ue_conn_ctx;

/* According to TS 03.60, Table 5: SGSN MM and PDP Contexts */
/* Extended by 3GPP TS 23.060, Table 6: SGSN MM and PDP Contexts */
struct sgsn_mm_ctx {
	struct llist_head	list;

	enum sgsn_ran_type	ran_type;

	char 			imsi[GSM23003_IMSI_MAX_DIGITS+1];
	struct osmo_fsm_inst	*gmm_fsm;
	struct {
		/* When a Common Procedure Succeeds, to which state do we change? */
		bool common_proc_to_registered;
	} gmm_priv;

	uint32_t 		p_tmsi;
	uint32_t 		p_tmsi_old;	/* old P-TMSI before new is confirmed */
	uint32_t 		p_tmsi_sig;
	char 			imei[GSM23003_IMEISV_NUM_DIGITS+1];
	/* Opt: Software Version Numbber / TS 23.195 */
	char 			msisdn[GSM_EXTENSION_LENGTH];
	struct osmo_routing_area_id	ra;
	struct {
		uint16_t		cell_id;	/* Gb only */
		uint32_t		cell_id_age;	/* Gb only */
		uint8_t			radio_prio_sms;

		/* Additional bits not present in the GSM TS */
		uint16_t		nsei;
		uint16_t		bvci;
		struct gprs_llc_llme	*llme;
		uint32_t		tlli;
		uint32_t		tlli_new;

		/* TS 23.060 6.1.1 Mobility Management States (A/Gb mode) */
		struct osmo_fsm_inst	*mm_state_fsm;
	} gb;
	struct {
		int			new_key;
		uint16_t		sac;		/* Iu: Service Area Code */
		uint32_t		sac_age;	/* Iu: Service Area Code age */
		/* CSG ID */
		/* CSG Membership */
		/* Access Mode */
		/* Seelected CN Operator ID (TS 23.251) */
		/* CSG Subscription Data */
		/* LIPA Allowed */
		/* Voice Support Match Indicator */
		struct ranap_ue_conn_ctx	*ue_ctx;
		struct service_info	service;
		/* TS 23.060 6.1.2 Mobility Management States (Iu mode) */
		struct osmo_fsm_inst	*mm_state_fsm;
	} iu;
	struct {
		struct osmo_fsm_inst *fsm;

		/* when a second attach req arrives while in this procedure,
		 * the fsm needs to compare it against old to decide what to do */
		struct msgb *attach_req;
		uint32_t id_type;
		unsigned int auth_reattempt; /* tracking UMTS resync auth attempts */
	} gmm_att_req;
	/* VLR number */
	uint32_t		new_sgsn_addr;
	/* Authentication Triplet */
	struct gsm_auth_tuple	auth_triplet;
	/* Kc */
	/* Iu: CK, IK, KSI */
	/* CKSN */
	enum gprs_ciph_algo	ciph_algo;
	uint8_t ue_cipher_mask;
	/* Auth & Ciphering Request reference from 3GPP TS 24.008 § 10.5.5.19: */
	uint8_t ac_ref_nr_used;

	struct {
		uint8_t	len;
		uint8_t	buf[50];	/* GSM 04.08 10.5.5.12a, extended in TS 24.008 */
	} ms_radio_access_capa;
	/* Supported Codecs (SRVCC) */
	struct {
		uint8_t	len;
		uint8_t	buf[8];		/* GSM 04.08 10.5.5.12, extended in TS 24.008 */
	} ms_network_capa;
	/* UE Netowrk Capability (E-UTRAN) */
	uint16_t		drx_parms;
	/* Active Time value for PSM */
	int			mnrg;	/* MS reported to HLR? */
	int			ngaf;	/* MS reported to MSC/VLR? */
	int			ppf;	/* paging for GPRS + non-GPRS? */
	/* Subscribed Charging Characteristics */
	/* Trace Reference */
	/* Trace Type */
	/* Trigger ID */
	/* OMC Identity */
	/* SMS Parameters */
	int			recovery;
	/* Access Restriction */
	/* GPRS CSI (CAMEL) */
	/* MG-CSI (CAMEL) */
	/* Subscribed UE-AMBR */
	/* UE-AMBR */
	/* APN Subscribed */

	struct llist_head	pdp_list;

	struct rate_ctr_group	*ctrg;
	struct osmo_timer_list	timer;
	unsigned int		T;		/* Txxxx number */
	unsigned int		num_T_exp;	/* number of consecutive T expirations */

	enum gprs_t3350_mode	t3350_mode;
	uint8_t			t3370_id_type;
	uint8_t			pending_req;	/* the request's message type */
	/* TODO: There isn't much semantic difference between t3350_mode
	 * (refers to the timer) and pending_req (refers to the procedure),
	 * where mm->T == 3350 => mm->t3350_mode == f(mm->pending_req). Check
	 * whether one of them can be dropped. */

	enum sgsn_auth_state	auth_state;
	enum osmo_sub_auth_type sec_ctx;

	/* the string representation of the current hlr */
	char 			hlr[GSM_EXTENSION_LENGTH];

	/* the current GGSN look-up operation */
	struct sgsn_ggsn_lookup *ggsn_lookup;

	/* When a GSN requests a SGSN Context, we need to keep a reference */
	uint32_t gtp_local_ref;
	bool gtp_local_ref_valid;

	struct gprs_subscr	*subscr;
	struct vlr_subscr	*vsub;
	/* to know if subscriber is doing an attach or location update */
	bool attached;
};

static inline bool sgsn_mm_ctx_is_authenticated(struct sgsn_mm_ctx *ctx)
{
	switch (ctx->sec_ctx) {
	case OSMO_AUTH_TYPE_GSM:
	case OSMO_AUTH_TYPE_UMTS:
		return true;
	default:
		return false;
	}
}

#define LOGMMCTXP(level, mm, fmt, args...) \
	LOGP(DMM, level, "MM(%s/%08x) " fmt, (mm) ? (mm)->imsi : "---", \
	     (mm) ? (mm)->p_tmsi : GSM_RESERVED_TMSI, ## args)

#ifdef BUILD_IU
#define LOGIUP(ue, level, fmt, args...) \
	LOGP(DMM, level, "UE(0x%x){%s} " fmt, ue->conn_id, osmo_rai_name(&(ue)->ra_id), ## args)
#else
#define LOGIUP(ue, level, fmt, args...) \
	LOGP(DMM, level, "UE(%p){NOTSUPPORTED} " fmt, ue, ## args)
#endif

#define LOGGBP(llme, category, level, fmt, args...) \
	LOGP(category, level, "LLME(%08x/%08x){%s} " fmt, (llme)->old_tlli, \
	     (llme)->tlli, get_value_string_or_null(gprs_llc_llme_state_names, (llme)->state), ## args);

#define LOGGBIUP(llme, msg, level, fmt, args...) \
	do { \
	struct ranap_ue_conn_ctx * _ue; \
	if (llme) { \
		LOGGBP(llme, DMM, level, fmt, ## args); \
	} else if ((msg) && (_ue = MSG_IU_UE_CTX(msg))) { \
		LOGIUP(_ue, level, fmt, ## args); \
	} else { OSMO_ASSERT(0); } \
	} while (0)

/* look-up a SGSN MM context based on TLLI + RAI */
struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli(uint32_t tlli,
					const struct osmo_routing_area_id *raid);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_ptmsi(uint32_t tmsi);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_imsi(const char *imsi);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_gtp_local_ref(uint32_t local_ref);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_ue_ctx(const void *uectx);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_llme(const struct gprs_llc_llme *llme);

/* look-up by matching TLLI and P-TMSI (think twice before using this) */
struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli_and_ptmsi(uint32_t tlli,
					const struct osmo_routing_area_id *raid);

/* Allocate a new SGSN MM context */
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc_gb(uint32_t tlli,
					const struct osmo_routing_area_id *raid);
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc_iu(void *uectx);

void sgsn_mm_ctx_cleanup_free(struct sgsn_mm_ctx *ctx);

struct sgsn_ggsn_ctx *sgsn_mm_ctx_find_ggsn_ctx(struct sgsn_mm_ctx *mmctx,
						struct tlv_parsed *tp,
						enum gsm48_gsm_cause *gsm_cause,
						char *apn_str);

/* look up PDP context by MM context and NSAPI */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_nsapi(const struct sgsn_mm_ctx *mm,
					   uint8_t nsapi);
/* look up PDP context by MM context and transaction ID */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_tid(const struct sgsn_mm_ctx *mm,
					 uint8_t tid);

bool sgsn_mm_ctx_is_r99(const struct sgsn_mm_ctx *mm);

uint32_t sgsn_alloc_ptmsi(void);

/* Called on subscriber data updates */
void sgsn_update_subscriber_data(struct sgsn_mm_ctx *mmctx);
