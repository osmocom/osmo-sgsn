#pragma once

#include <stdint.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/gsm/gsm48.h>

#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/crypt/auth.h>

#include <osmocom/sgsn/apn.h>
#include <osmocom/sgsn/gprs_subscriber.h>

struct sgsn_mm_ctx;
struct sgsn_ggsn_ctx;

enum gprs_pdp_ctx {
	PDP_CTR_PKTS_UDATA_IN,
	PDP_CTR_PKTS_UDATA_OUT,
	PDP_CTR_BYTES_UDATA_IN,
	PDP_CTR_BYTES_UDATA_OUT,
};

enum pdp_ctx_state {
	PDP_STATE_NONE,
	PDP_STATE_CR_REQ,
	PDP_STATE_CR_CONF,

	/* when received via SGSN Context Req from another SGSN/MME,
	 * the PDP context needs to be updated with our own address */
	PDP_STATE_NEED_UPDATE_GSN,

	/* 04.08 / Figure 6.2 / 6.1.2.2 */
	PDP_STATE_INACT_PEND,
	PDP_STATE_INACTIVE = PDP_STATE_NONE,
};

enum pdp_type {
	PDP_TYPE_NONE,
	PDP_TYPE_ETSI_PPP,
	PDP_TYPE_IANA_IPv4,
	PDP_TYPE_IANA_IPv6,
};

struct sgsn_pdp_ctx {
	struct llist_head	list;	/* list_head for mmctx->pdp_list */
	struct llist_head	g_list;	/* list_head for global list */
	struct sgsn_mm_ctx	*mm;	/* back pointer to MM CTX */
	int			destroy_ggsn; /* destroy it on destruction */
	struct sgsn_ggsn_ctx	*ggsn;	/* which GGSN serves this PDP */
	struct llist_head	ggsn_list;	/* list_head for ggsn->pdp_list */
	struct rate_ctr_group	*ctrg;

	//unsigned int		id;
	struct pdp_t		*lib;	/* pointer to libgtp PDP ctx */
	enum pdp_ctx_state	state;
	enum pdp_type		type;
	uint32_t		address;
	char			*apn_subscribed;
	//char			*apn_used;
	uint16_t		nsapi;	/* SNDCP */
	uint16_t		sapi;	/* LLC */
	uint8_t			ti;	/* transaction identifier */
	int			vplmn_allowed;
	uint32_t		qos_profile_subscr;
	//uint32_t		qos_profile_req;
	//uint32_t		qos_profile_neg;
	uint8_t			radio_prio;
	//uint32_t		charging_id;
	bool			ue_pdp_active; /* PDP Context is active for this NSAPI?  */
	/* Keeps original SGSN local TEID when lib->teid_own is updated with
	 * RNC's TEID upon use of Direct Tunnel feature: */
	uint32_t		sgsn_teid_own;

	struct osmo_timer_list	timer;
	unsigned int		T;		/* Txxxx number */
	unsigned int		num_T_exp;	/* number of consecutive T expirations */

	struct osmo_timer_list	cdr_timer;	/* CDR record wird timer */
	struct timespec		cdr_start;	/* The start of the CDR */
	uint64_t		cdr_bytes_in;
	uint64_t		cdr_bytes_out;
	uint32_t		cdr_charging_id;
};

#define LOGPDPCTXP(level, pdp, fmt, args...) \
	LOGP(DGPRS, level, "PDP(%s/%u) " \
	     fmt, (pdp)->mm ? (pdp)->mm->imsi : "---", (pdp)->ti, ## args)

struct sgsn_pdp_ctx *sgsn_pdp_ctx_alloc(struct sgsn_mm_ctx *mm,
					struct sgsn_ggsn_ctx *ggsn,
					uint8_t nsapi);
void sgsn_pdp_ctx_terminate(struct sgsn_pdp_ctx *pdp);
void sgsn_pdp_ctx_free(struct sgsn_pdp_ctx *pdp);
int sgsn_pdp_ctx_gn_update(struct sgsn_pdp_ctx *pctx);

char *gprs_pdpaddr2str(uint8_t *pdpa, uint8_t len, bool return_ipv6);

