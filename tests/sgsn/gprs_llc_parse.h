#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/sgsn/gprs_sgsn.h>

/* Section 4.7 LLC Layer Structure */
enum gprs_llc_sapi {
	GPRS_SAPI_GMM		= 1,
	GPRS_SAPI_TOM2		= 2,
	GPRS_SAPI_SNDCP3	= 3,
	GPRS_SAPI_SNDCP5	= 5,
	GPRS_SAPI_SMS		= 7,
	GPRS_SAPI_TOM8		= 8,
	GPRS_SAPI_SNDCP9	= 9,
	GPRS_SAPI_SNDCP11	= 11,
};

/* Section 6.4 Commands and Responses */
enum gprs_llc_u_cmd {
	GPRS_LLC_U_DM_RESP		= 0x01,
	GPRS_LLC_U_DISC_CMD		= 0x04,
	GPRS_LLC_U_UA_RESP		= 0x06,
	GPRS_LLC_U_SABM_CMD		= 0x07,
	GPRS_LLC_U_FRMR_RESP		= 0x08,
	GPRS_LLC_U_XID			= 0x0b,
	GPRS_LLC_U_NULL_CMD		= 0x00,
};

/* TS 04.64 Section 7.1.2 Table 7: LLC layer primitives (GMM/SNDCP/SMS/TOM) */
/* TS 04.65 Section 5.1.2 Table 2: Service primitives used by SNDCP */
enum gprs_llc_primitive {
	/* GMM <-> LLME */
	LLGMM_ASSIGN_REQ,	/* GMM tells us new TLLI: TLLI old, TLLI new, Kc, CiphAlg */
	LLGMM_RESET_REQ,	/* GMM tells us to perform XID negotiation: TLLI */
	LLGMM_RESET_CNF,	/* LLC informs GMM that XID has completed: TLLI */
	LLGMM_SUSPEND_REQ,	/* GMM tells us MS has suspended: TLLI, Page */
	LLGMM_RESUME_REQ,	/* GMM tells us MS has resumed: TLLI */
	LLGMM_PAGE_IND,		/* LLC asks GMM to page MS: TLLI */
	LLGMM_IOV_REQ,		/* GMM tells us to perform XID: TLLI */
	LLGMM_STATUS_IND,	/* LLC informs GMM about error: TLLI, Cause */
	/* LLE <-> (GMM/SNDCP/SMS/TOM) */
	LL_RESET_IND,		/* TLLI */
	LL_ESTABLISH_REQ,	/* TLLI, XID Req */
	LL_ESTABLISH_IND,	/* TLLI, XID Req, N201-I, N201-U */
	LL_ESTABLISH_RESP,	/* TLLI, XID Negotiated */
	LL_ESTABLISH_CONF,	/* TLLI, XID Neg, N201-i, N201-U */
	LL_RELEASE_REQ,		/* TLLI, Local */
	LL_RELEASE_IND,		/* TLLI, Cause */
	LL_RELEASE_CONF,	/* TLLI */
	LL_XID_REQ,		/* TLLI, XID Requested */
	LL_XID_IND,		/* TLLI, XID Req, N201-I, N201-U */
	LL_XID_RESP,		/* TLLI, XID Negotiated */
	LL_XID_CONF,		/* TLLI, XID Neg, N201-I, N201-U */
	LL_DATA_REQ,		/* TLLI, SN-PDU, Ref, QoS, Radio Prio, Ciph */
	LL_DATA_IND,		/* TLLI, SN-PDU */
	LL_DATA_CONF,		/* TLLI, Ref */
	LL_UNITDATA_REQ,	/* TLLI, SN-PDU, Ref, QoS, Radio Prio, Ciph */
	LL_UNITDATA_IND,	/* TLLI, SN-PDU */
	LL_STATUS_IND,		/* TLLI, Cause */
};

/* Section 4.5.2 Logical Link States + Annex C.2 */
enum gprs_llc_lle_state {
	GPRS_LLES_UNASSIGNED	= 1,	/* No TLLI yet */
	GPRS_LLES_ASSIGNED_ADM	= 2,	/* TLLI assigned */
	GPRS_LLES_LOCAL_EST	= 3,	/* Local Establishment */
	GPRS_LLES_REMOTE_EST	= 4,	/* Remote Establishment */
	GPRS_LLES_ABM		= 5,
	GPRS_LLES_LOCAL_REL	= 6,	/* Local Release */
	GPRS_LLES_TIMER_REC 	= 7,	/* Timer Recovery */
};

enum sgsn_llme_state {
	GPRS_LLMS_UNASSIGNED	= 1,	/* No TLLI yet */
	GPRS_LLMS_ASSIGNED	= 2,	/* TLLI assigned */
};
extern const struct value_string sgsn_llme_state_names[];

/* 3GPP TS 44.064 § 4.7.1: Logical Link Entity: One per DLCI (TLLI + SAPI) */
struct gprs_llc_lle {
	struct llist_head list;

	uint32_t sapi;

	struct sgsn_llme *llme; /* backpointer to the Logical Link Management Entity */

	enum gprs_llc_lle_state state;

	struct osmo_timer_list t200;
	struct osmo_timer_list t201;	/* wait for acknowledgement */

	uint16_t v_sent;
	uint16_t v_ack;
	uint16_t v_recv;

	uint16_t vu_send;
	uint16_t vu_recv;

	/* non-standard LLC state */
	uint16_t vu_recv_last;
	uint16_t vu_recv_duplicates;

	/* Overflow Counter for ABM */
	uint32_t oc_i_send;
	uint32_t oc_i_recv;

	/* Overflow Counter for unconfirmed transfer */
	uint32_t oc_ui_send;
	uint32_t oc_ui_recv;

	unsigned int retrans_ctr;

	/* Copy of the XID fields we have sent with the last
	 * network originated XID-Request. Since the phone
	 * may strip the optional fields in the confirmation
	 * we need to remeber those fields in order to be
	 * able to create the compression entity. */
	struct llist_head *xid;
};

#define NUM_SAPIS	16

/* 3GPP TS 44.064 § 4.7.3: Logical Link Management Entity: One per TLLI */
struct sgsn_llme {
	struct llist_head list;

	enum sgsn_llme_state state;

	uint32_t tlli;
	uint32_t old_tlli;

	/* Crypto parameters */
	enum gprs_ciph_algo algo;
	uint8_t kc[16];
	uint8_t cksn;
	/* 3GPP TS 44.064 § 8.9.2: */
	uint32_t iov_ui;

	/* over which BSSGP BTS ctx do we need to transmit */
	uint16_t bvci;
	uint16_t nsei;
	struct gprs_llc_lle lle[NUM_SAPIS];

	/* Compression entities */
	struct {
		/* In these two list_heads we will store the
		 * data and protocol compression entities,
		 * together with their compression states */
		struct llist_head *proto;
		struct llist_head *data;
	} comp;

	/* Internal management */
	uint32_t age_timestamp;
};

#define GPRS_LLME_RESET_AGE (0)

/* 3GPP TS 44.064 § 8.3 TLLI assignment procedures */
#define TLLI_UNASSIGNED (0xffffffff)

/* LLC low level types */

enum gprs_llc_cmd {
	GPRS_LLC_NULL,
	GPRS_LLC_RR,
	GPRS_LLC_ACK,
	GPRS_LLC_RNR,
	GPRS_LLC_SACK,
	GPRS_LLC_DM,
	GPRS_LLC_DISC,
	GPRS_LLC_UA,
	GPRS_LLC_SABM,
	GPRS_LLC_FRMR,
	GPRS_LLC_XID,
	GPRS_LLC_UI,
};

struct gprs_llc_hdr_parsed {
	uint8_t sapi;
	uint8_t is_cmd:1,
		 ack_req:1,
		 is_encrypted:1;
	uint32_t seq_rx;
	uint32_t seq_tx;
	uint32_t fcs;
	uint32_t fcs_calc;
	uint8_t *data;
	uint16_t data_len;
	uint16_t crc_length;
	enum gprs_llc_cmd cmd;
};

/* parse a GPRS LLC header, also check for invalid frames */
int gprs_llc_hdr_parse(struct gprs_llc_hdr_parsed *ghp,
		       uint8_t *llc_hdr, int len);
void gprs_llc_hdr_dump(struct gprs_llc_hdr_parsed *gph, struct gprs_llc_lle *lle);
int gprs_llc_fcs(const uint8_t *data, unsigned int len);