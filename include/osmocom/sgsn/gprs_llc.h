#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/timer.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/crypt/gprs_cipher.h>

struct sgsn_mm_ctx;

/* 3GPP TS 44.064 § 4.7.1: Logical Link Entity: One per DLCI (TLLI + SAPI) */
struct sgsn_lle {
	struct llist_head list;

	uint32_t sapi;

	struct sgsn_llme *llme; /* backpointer to the Logical Link Management Entity */

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
	struct sgsn_lle lle[NUM_SAPIS];

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

extern struct llist_head sgsn_llmes;


/////////////////////////////////////
// NEW HEADER:
/////////////////////////////////////

/* 3GPP TS 44.064 § 8.3 TLLI assignment procedures */
#define TLLI_UNASSIGNED (0xffffffff)

/* 04.64 Chapter 7.2.1.1 LLGMM-ASSIGN */
int sgsn_llgmm_assign_req(uint32_t old_tlli, uint32_t new_tlli);
int sgsn_llgmm_assign_req_mmctx(struct sgsn_mm_ctx *mmctx,
		      uint32_t old_tlli, uint32_t new_tlli);
int sgsn_llgmm_unassign_req(unsigned int tlli);
int sgsn_llgmm_unassign_req_mmctx(struct sgsn_mm_ctx *mmctx);


int sgsn_llgmm_reset_req(unsigned int tlli);
int sgsn_llgmm_reset_req_oldmsg(struct msgb* oldmsg, uint8_t sapi, unsigned int tlli);


/* LLC low level functions */
struct sgsn_mm_ctx;
void gprs_llme_copy_key(const struct sgsn_mm_ctx *mm, struct sgsn_llme *llme);

int sgsn_llc_init(const char *cipher_plugin_path);
int sgsn_llc_vty_init(void);