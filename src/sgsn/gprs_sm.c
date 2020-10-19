/* Section "9.5 GPRS Session Management Messages"
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2009-2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "bscconfig.h"

#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/sgsn/gprs_sm.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_utils.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_sndcp.h>
#include <osmocom/sgsn/gprs_ranap.h>

extern void *tall_sgsn_ctx;

/* 3GPP TS 04.08 sec 6.1.3.4.3(.a) "Abnormal cases" */
#define T339X_MAX_RETRANS 4

static const struct tlv_definition gsm48_sm_att_tlvdef = {
	.def = {
		[GSM48_IE_GSM_APN]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_PROTO_CONF_OPT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_PDP_ADDR]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_AA_TMR]		= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GSM_NAME_FULL]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_NAME_SHORT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_TIMEZONE]		= { TLV_TYPE_FIXED, 1 },
		[GSM48_IE_GSM_UTC_AND_TZ]	= { TLV_TYPE_FIXED, 7 },
		[GSM48_IE_GSM_LSA_ID]		= { TLV_TYPE_TLV, 0 },
	},
};

static struct gsm48_qos default_qos = {
	.delay_class = 4,	/* best effort */
	.reliab_class = GSM48_QOS_RC_LLC_UN_RLC_ACK_DATA_PROT,
	.peak_tput = GSM48_QOS_PEAK_TPUT_32000bps,
	.preced_class = GSM48_QOS_PC_NORMAL,
	.mean_tput = GSM48_QOS_MEAN_TPUT_BEST_EFFORT,
	.traf_class = GSM48_QOS_TC_INTERACTIVE,
	.deliv_order = GSM48_QOS_DO_UNORDERED,
	.deliv_err_sdu = GSM48_QOS_ERRSDU_YES,
	.max_sdu_size = GSM48_QOS_MAXSDU_1520,
	.max_bitrate_up = GSM48_QOS_MBRATE_63k,
	.max_bitrate_down = GSM48_QOS_MBRATE_63k,
	.resid_ber = GSM48_QOS_RBER_5e_2,
	.sdu_err_ratio = GSM48_QOS_SERR_1e_2,
	.handling_prio = 3,
	.xfer_delay = 0x10,	/* 200ms */
	.guar_bitrate_up = GSM48_QOS_MBRATE_0k,
	.guar_bitrate_down = GSM48_QOS_MBRATE_0k,
	.sig_ind = 0,	/* not optimised for signalling */
	.max_bitrate_down_ext = 0,	/* use octet 9 */
	.guar_bitrate_down_ext = 0,	/* use octet 13 */
};

/* GPRS SESSION MANAGEMENT */

static void pdpctx_timer_cb(void *_mm);

static void pdpctx_timer_rearm(struct sgsn_pdp_ctx *pdp, unsigned int T)
{
	unsigned long seconds;
	if (osmo_timer_pending(&pdp->timer))
		LOGPDPCTXP(LOGL_ERROR, pdp, "Scheduling PDP timer %u while old "
			"timer %u pending\n", T, pdp->T);
	seconds = osmo_tdef_get(sgsn->cfg.T_defs, T, OSMO_TDEF_S, -1);
	osmo_timer_schedule(&pdp->timer, seconds, 0);
}

static void pdpctx_timer_start(struct sgsn_pdp_ctx *pdp, unsigned int T)
{
	if (osmo_timer_pending(&pdp->timer))
		LOGPDPCTXP(LOGL_ERROR, pdp, "Starting PDP timer %u while old "
			"timer %u pending\n", T, pdp->T);
	pdp->T = T;
	pdp->num_T_exp = 0;

	osmo_timer_setup(&pdp->timer, pdpctx_timer_cb, pdp);
	pdpctx_timer_rearm(pdp, pdp->T);
}

static void pdpctx_timer_stop(struct sgsn_pdp_ctx *pdp, unsigned int T)
{
	if (pdp->T != T)
		LOGPDPCTXP(LOGL_ERROR, pdp, "Stopping PDP timer %u but "
			"%u is running\n", T, pdp->T);
	osmo_timer_del(&pdp->timer);
}

void pdp_ctx_detach_mm_ctx(struct sgsn_pdp_ctx *pdp)
{
	/* Detach from MM context */
	llist_del(&pdp->list);
	pdp->mm = NULL;

	/* stop timer 3395 */
	pdpctx_timer_stop(pdp, 3395);
}

#if 0
static void msgb_put_pdp_addr_ipv4(struct msgb *msg, uint32_t ipaddr)
{
	uint8_t v[6];

	v[0] = PDP_TYPE_ORG_IETF;
	v[1] = PDP_TYPE_N_IETF_IPv4;
	*(uint32_t *)(v+2) = htonl(ipaddr);

	msgb_tlv_put(msg, GSM48_IE_GSM_PDP_ADDR, sizeof(v), v);
}

static void msgb_put_pdp_addr_ppp(struct msgb *msg)
{
	uint8_t v[2];

	v[0] = PDP_TYPE_ORG_ETSI;
	v[1] = PDP_TYPE_N_ETSI_PPP;

	msgb_tlv_put(msg, GSM48_IE_GSM_PDP_ADDR, sizeof(v), v);
}
#endif

/* Chapter 9.4.18 */
static int _tx_status(struct msgb *msg, uint8_t cause,
		      struct sgsn_mm_ctx *mmctx)
{
	struct gsm48_hdr *gh;

	/* MMCTX might be NULL! */

	DEBUGP(DMM, "<- GPRS MM STATUS (cause: %s)\n",
		get_value_string(gsm48_gmm_cause_names, cause));

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_SM_GPRS;
	gh->msg_type = GSM48_MT_GSM_STATUS;
	gh->data[0] = cause;

	return gsm48_gmm_sendmsg(msg, 0, mmctx, true);
}

static int gsm48_tx_sm_status(struct sgsn_mm_ctx *mmctx, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SM STATUS");

	mmctx2msgid(msg, mmctx);
	return _tx_status(msg, cause, mmctx);
}

/* 3GPP TS 24.008 § 9.5.2: Activate PDP Context Accept */
int gsm48_tx_gsm_act_pdp_acc(struct sgsn_pdp_ctx *pdp)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 PDP ACC");
	struct gsm48_hdr *gh;
	uint8_t transaction_id = pdp->ti ^ 0x8; /* flip */

	LOGPDPCTXP(LOGL_INFO, pdp, "<- ACTIVATE PDP CONTEXT ACK\n");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_ACTIVATE_ACCEPT]);

	mmctx2msgid(msg, pdp->mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_ACT_PDP_ACK;

	/* Negotiated LLC SAPI */
	msgb_v_put(msg, pdp->sapi);

	/* FIXME: copy QoS parameters from original request */
	//msgb_lv_put(msg, pdp->lib->qos_neg.l, pdp->lib->qos_neg.v);
	msgb_lv_put(msg, sizeof(default_qos), (uint8_t *)&default_qos);

	/* Radio priority 10.5.7.2 */
	msgb_v_put(msg, pdp->lib->radio_pri);

	/* PDP address */
	/* Highest 4 bits of first byte need to be set to 1, otherwise
	 * the IE is identical with the 04.08 PDP Address IE */
	pdp->lib->eua.v[0] &= ~0xf0;
	msgb_tlv_put(msg, GSM48_IE_GSM_PDP_ADDR,
		     pdp->lib->eua.l, pdp->lib->eua.v);
	pdp->lib->eua.v[0] |= 0xf0;

	/* Optional: Protocol configuration options (FIXME: why 'req') */
	if (pdp->lib->pco_req.l)
		msgb_tlv_put(msg, GSM48_IE_GSM_PROTO_CONF_OPT,
			     pdp->lib->pco_req.l, pdp->lib->pco_req.v);

	/* Optional: Packet Flow Identifier */

	return gsm48_gmm_sendmsg(msg, 0, pdp->mm, true);
}

/* 3GPP TS 24.008 § 9.5.3: Activate PDP Context reject */
int gsm48_tx_gsm_act_pdp_rej(struct sgsn_mm_ctx *mm, uint8_t tid,
			     uint8_t cause, uint8_t pco_len, uint8_t *pco_v)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 PDP REJ");
	struct gsm48_hdr *gh;
	uint8_t transaction_id = tid ^ 0x8; /* flip */

	LOGMMCTXP(LOGL_NOTICE, mm, "<- ACTIVATE PDP CONTEXT REJ: %s\n",
		  get_value_string(gsm48_gsm_cause_names, cause));
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_ACTIVATE_REJECT]);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_ACT_PDP_REJ;

	msgb_v_put(msg, cause);
	if (pco_len && pco_v)
		msgb_tlv_put(msg, GSM48_IE_GSM_PROTO_CONF_OPT, pco_len, pco_v);

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}

/* 3GPP TS 24.008 § 9.5.8: Deactivate PDP Context Request */
static int _gsm48_tx_gsm_deact_pdp_req(struct sgsn_mm_ctx *mm, uint8_t tid,
					uint8_t sm_cause, bool teardown)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 PDP DET REQ");
	struct gsm48_hdr *gh;
	uint8_t transaction_id = tid ^ 0x8; /* flip */
	uint8_t tear_down_ind = (0x9 << 4) | (!!teardown);

	LOGMMCTXP(LOGL_INFO, mm, "<- DEACTIVATE PDP CONTEXT REQ\n");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_DL_DEACTIVATE_REQUEST]);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_DEACT_PDP_REQ;

	msgb_v_put(msg, sm_cause);
	msgb_v_put(msg, tear_down_ind);

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}
int gsm48_tx_gsm_deact_pdp_req(struct sgsn_pdp_ctx *pdp, uint8_t sm_cause, bool teardown)
{
	pdpctx_timer_start(pdp, 3395);

	return _gsm48_tx_gsm_deact_pdp_req(pdp->mm, pdp->ti, sm_cause, teardown);
}

/* 3GPP TS 24.008 § 9.5.9: Deactivate PDP Context Accept */
static int _gsm48_tx_gsm_deact_pdp_acc(struct sgsn_mm_ctx *mm, uint8_t tid)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 PDP DET ACC");
	struct gsm48_hdr *gh;
	uint8_t transaction_id = tid ^ 0x8; /* flip */

	LOGMMCTXP(LOGL_INFO, mm, "<- DEACTIVATE PDP CONTEXT ACK\n");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_DL_DEACTIVATE_ACCEPT]);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_DEACT_PDP_ACK;

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}
int gsm48_tx_gsm_deact_pdp_acc(struct sgsn_pdp_ctx *pdp)
{
	return _gsm48_tx_gsm_deact_pdp_acc(pdp->mm, pdp->ti);
}

static int activate_ggsn(struct sgsn_mm_ctx *mmctx,
		struct sgsn_ggsn_ctx *ggsn, const uint8_t transaction_id,
		const uint8_t req_nsapi, const uint8_t req_llc_sapi,
		struct tlv_parsed *tp, int destroy_ggsn)
{
	struct sgsn_pdp_ctx *pdp;

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Using GGSN %u\n", ggsn->id);
	ggsn->gsn = sgsn->gsn;
	pdp = sgsn_create_pdp_ctx(ggsn, mmctx, req_nsapi, tp);
	if (!pdp)
		return -1;

	/* Store SAPI and Transaction Identifier */
	pdp->sapi = req_llc_sapi;
	pdp->ti = transaction_id;
	pdp->destroy_ggsn = destroy_ggsn;

	return 0;
}

static void ggsn_lookup_cb(void *arg, int status, int timeouts, struct hostent *hostent)
{
	struct sgsn_ggsn_ctx *ggsn;
	struct sgsn_ggsn_lookup *lookup = arg;
	struct in_addr *addr = NULL;
	char buf[INET_ADDRSTRLEN];

	/* The context is gone while we made a request */
	if (!lookup->mmctx) {
		talloc_free(lookup->orig_msg);
		talloc_free(lookup);
		return;
	}

	if (status != ARES_SUCCESS) {
		struct sgsn_mm_ctx *mmctx = lookup->mmctx;

		LOGMMCTXP(LOGL_ERROR, mmctx, "DNS query failed.\n");

		/* Need to try with three digits now */
		if (lookup->state == SGSN_GGSN_2DIGIT) {
			char *hostname;
			int rc;

			lookup->state = SGSN_GGSN_3DIGIT;
			hostname = osmo_apn_qualify_from_imsi(mmctx->imsi,
					lookup->apn_str, 1);
			LOGMMCTXP(LOGL_DEBUG, mmctx,
				"Going to query %s\n", hostname);
			rc = sgsn_ares_query(sgsn, hostname,
					ggsn_lookup_cb, lookup);
			if (rc != 0) {
				LOGMMCTXP(LOGL_ERROR, mmctx, "Couldn't start GGSN\n");
				goto reject_due_failure;
			}
			return;
		}

		LOGMMCTXP(LOGL_ERROR, mmctx, "Couldn't resolve GGSN\n");
		goto reject_due_failure;
	}

	if (hostent->h_length != sizeof(struct in_addr)) {
		LOGMMCTXP(LOGL_ERROR, lookup->mmctx,
			"Wrong addr size(%zu)\n", sizeof(struct in_addr));
		goto reject_due_failure;
	}

	/* Get the first addr from the list */
	addr = (struct in_addr *) hostent->h_addr_list[0];
	if (!addr) {
		LOGMMCTXP(LOGL_ERROR, lookup->mmctx, "No host address.\n");
		goto reject_due_failure;
	}

	ggsn = sgsn_ggsn_ctx_alloc(UINT32_MAX);
	if (!ggsn) {
		LOGMMCTXP(LOGL_ERROR, lookup->mmctx, "Failed to create ggsn.\n");
		goto reject_due_failure;
	}
	ggsn->remote_addr = *addr;
	LOGMMCTXP(LOGL_NOTICE, lookup->mmctx,
		  "Selected %s as GGSN.\n",
		  inet_ntop(AF_INET, addr, buf, sizeof(buf)));

	/* forget about the ggsn look-up */
	lookup->mmctx->ggsn_lookup = NULL;

	activate_ggsn(lookup->mmctx, ggsn, lookup->ti, lookup->nsapi,
			lookup->sapi, &lookup->tp, 1);

	/* Now free it */
	talloc_free(lookup->orig_msg);
	talloc_free(lookup);
	return;

reject_due_failure:
	gsm48_tx_gsm_act_pdp_rej(lookup->mmctx, lookup->ti,
				GMM_CAUSE_NET_FAIL, 0, NULL);
	lookup->mmctx->ggsn_lookup = NULL;
	talloc_free(lookup->orig_msg);
	talloc_free(lookup);
}

static int do_act_pdp_req(struct sgsn_mm_ctx *mmctx, struct msgb *msg, bool *delete)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	struct gsm48_act_pdp_ctx_req *act_req = (struct gsm48_act_pdp_ctx_req *) gh->data;
	uint8_t req_qos_len, req_pdpa_len;
	uint8_t *req_qos, *req_pdpa;
	struct tlv_parsed tp;
	uint8_t transaction_id = gsm48_hdr_trans_id(gh);
	struct sgsn_ggsn_ctx *ggsn;
	struct sgsn_pdp_ctx *pdp;
	enum gsm48_gsm_cause gsm_cause;
	char apn_str[GSM_APN_LENGTH] = { 0, };
	char *hostname;
	int rc;
	struct gprs_llc_lle *lle;
	char buf[INET_ADDRSTRLEN];

	LOGMMCTXP(LOGL_INFO, mmctx, "-> ACTIVATE PDP CONTEXT REQ: SAPI=%u NSAPI=%u ",
		act_req->req_llc_sapi, act_req->req_nsapi);

	/* FIXME: length checks! */
	req_qos_len = act_req->data[0];
	req_qos = act_req->data + 1;	/* 10.5.6.5 */
	req_pdpa_len = act_req->data[1 + req_qos_len];
	req_pdpa = act_req->data + 1 + req_qos_len + 1;	/* 10.5.6.4 */

	switch (req_pdpa[0] & 0xf) {
	case 0x0:
		DEBUGPC(DMM, "ETSI ");
		break;
	case 0x1:
		DEBUGPC(DMM, "IETF ");
		break;
	case 0xf:
		DEBUGPC(DMM, "Empty ");
		break;
	}

	switch (req_pdpa[1]) {
	case 0x21:
		DEBUGPC(DMM, "IPv4 ");
		if (req_pdpa_len >= 6) {
			struct in_addr ia;
			ia.s_addr = ntohl(*((uint32_t *) (req_pdpa+2)));
			DEBUGPC(DMM, "%s ", inet_ntop(AF_INET, &ia, buf, sizeof(buf)));
		}
		break;
	case 0x57:
		DEBUGPC(DMM, "IPv6 ");
		if (req_pdpa_len >= 18) {
			/* FIXME: print IPv6 address */
		}
		break;
	default:
		DEBUGPC(DMM, "0x%02x ", req_pdpa[1]);
		break;
	}

	LOGPC(DMM, LOGL_INFO, "\n");

	/* Check if NSAPI is out of range (TS 04.65 / 7.2) */
	if (act_req->req_nsapi < 5 || act_req->req_nsapi > 15) {
		/* Send reject with GSM_CAUSE_INV_MAND_INFO */
		return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
						GSM_CAUSE_INV_MAND_INFO,
						0, NULL);
	}

	/* Optional: Access Point Name, Protocol Config Options */
	if (req_pdpa + req_pdpa_len < msg->data + msg->len)
		tlv_parse(&tp, &gsm48_sm_att_tlvdef, req_pdpa + req_pdpa_len,
			  (msg->data + msg->len) - (req_pdpa + req_pdpa_len), 0, 0);
	else
		memset(&tp, 0, sizeof(tp));


	/* put the non-TLV elements in the TLV parser structure to
	 * pass them on to the SGSN / GTP code */
	tp.lv[OSMO_IE_GSM_REQ_QOS].len = req_qos_len;
	tp.lv[OSMO_IE_GSM_REQ_QOS].val = req_qos;
	tp.lv[OSMO_IE_GSM_REQ_PDP_ADDR].len = req_pdpa_len;
	tp.lv[OSMO_IE_GSM_REQ_PDP_ADDR].val = req_pdpa;

	/* Check if NSAPI is already in use */
	pdp = sgsn_pdp_ctx_by_nsapi(mmctx, act_req->req_nsapi);
	if (pdp) {
		/* Make sure pdp ctx was not already torn down on GTP side */
		if (!pdp->lib) {
			gsm_cause = GSM_CAUSE_REACT_RQD;
			goto no_context;
		}
		/* We already have a PDP context for this TLLI + NSAPI tuple */
		if (pdp->sapi == act_req->req_llc_sapi &&
		    pdp->ti == transaction_id) {
			/* This apparently is a re-transmission of a PDP CTX
			 * ACT REQ (our ACT ACK must have got dropped) */
			rc = gsm48_tx_gsm_act_pdp_acc(pdp);
			if (rc < 0)
				return rc;

			if (pdp->mm->ran_type == MM_CTX_T_GERAN_Gb) {
				/* Also re-transmit the SNDCP XID message */
				lle = &pdp->mm->gb.llme->lle[pdp->sapi];
				rc = sndcp_sn_xid_req(lle,pdp->nsapi);
				if (rc < 0)
					return rc;
			}

			return 0;
		}

		/* Send reject with GSM_CAUSE_NSAPI_IN_USE */
		return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
						GSM_CAUSE_NSAPI_IN_USE,
						0, NULL);
	}

	if (mmctx->ggsn_lookup) {
		if (mmctx->ggsn_lookup->sapi == act_req->req_llc_sapi &&
			mmctx->ggsn_lookup->ti == transaction_id) {
			LOGMMCTXP(LOGL_NOTICE, mmctx,
				"Re-transmission while doing look-up. Ignoring.\n");
			return 0;
		}
	}

	/* Only increment counter for a real activation, after we checked
	 * for re-transmissions */
	rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PDP_CTX_ACT]);

	/* Determine GGSN based on APN and subscription options */
	ggsn = sgsn_mm_ctx_find_ggsn_ctx(mmctx, &tp, &gsm_cause, apn_str);
	if (ggsn)
		return activate_ggsn(mmctx, ggsn, transaction_id,
				act_req->req_nsapi, act_req->req_llc_sapi,
				&tp, 0);

	if (strlen(apn_str) == 0)
		goto no_context;
	if (!sgsn->cfg.dynamic_lookup)
		goto no_context;

	/* schedule a dynamic look-up */
	mmctx->ggsn_lookup = talloc_zero(tall_sgsn_ctx, struct sgsn_ggsn_lookup);
	if (!mmctx->ggsn_lookup)
		goto no_context;

	mmctx->ggsn_lookup->state = SGSN_GGSN_2DIGIT;
	mmctx->ggsn_lookup->mmctx = mmctx;
	strcpy(mmctx->ggsn_lookup->apn_str, apn_str);

	mmctx->ggsn_lookup->orig_msg = msg;
	mmctx->ggsn_lookup->tp = tp;

	mmctx->ggsn_lookup->ti = transaction_id;
	mmctx->ggsn_lookup->nsapi = act_req->req_nsapi;
	mmctx->ggsn_lookup->sapi = act_req->req_llc_sapi;

	hostname = osmo_apn_qualify_from_imsi(mmctx->imsi,
				mmctx->ggsn_lookup->apn_str, 0);

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Going to query %s\n", hostname);
	rc = sgsn_ares_query(sgsn, hostname,
				ggsn_lookup_cb, mmctx->ggsn_lookup);
	if (rc != 0) {
		LOGMMCTXP(LOGL_ERROR, mmctx, "Failed to start ares query.\n");
		goto no_context;
	}
	*delete = 0;

	return 0;

no_context:
	LOGMMCTXP(LOGL_ERROR, mmctx, "No GGSN context found!\n");
	return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
					gsm_cause, 0, NULL);
}

/* 3GPP TS 24.008 § 9.5.1: Activate PDP Context Request */
static int gsm48_rx_gsm_act_pdp_req(struct sgsn_mm_ctx *mmctx,
				    struct msgb *_msg)
{
	bool delete = 1;
	struct msgb *msg;
	int rc;

	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_ACTIVATE_REQUEST]);

	/*
	 * This is painful. We might not have a static GGSN
	 * configuration and then would need to copy the msg
	 * and re-do most of this routine (or call it again
	 * and make sure it only goes through the dynamic
	 * resolving. The question is what to optimize for
	 * and the dynamic resolution will be the right thing
	 * in the long run.
	 */
	msg = bssgp_msgb_copy(_msg, __func__);
	if (!msg) {
		struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(_msg);
		uint8_t transaction_id = gsm48_hdr_trans_id(gh);

		LOGMMCTXP(LOGL_ERROR, mmctx, "-> ACTIVATE PDP CONTEXT REQ failed copy.\n");
		/* Send reject with GSM_CAUSE_INV_MAND_INFO */
		return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
						GSM_CAUSE_NET_FAIL,
						0, NULL);
	}

	rc = do_act_pdp_req(mmctx, msg, &delete);
	if (delete)
		msgb_free(msg);
	return rc;
}

/* 3GPP TS 24.008 § 9.5.8: Deactivate PDP Context Request */
static int gsm48_rx_gsm_deact_pdp_req(struct sgsn_mm_ctx *mm, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t transaction_id = gsm48_hdr_trans_id(gh);
	struct sgsn_pdp_ctx *pdp;

	LOGMMCTXP(LOGL_INFO, mm, "-> DEACTIVATE PDP CONTEXT REQ (cause: %s)\n",
		get_value_string(gsm48_gsm_cause_names, gh->data[0]));
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_UL_DEACTIVATE_REQUEST]);

	pdp = sgsn_pdp_ctx_by_tid(mm, transaction_id);
	if (!pdp) {
		LOGMMCTXP(LOGL_NOTICE, mm, "Deactivate PDP Context Request for "
			"non-existing PDP Context (IMSI=%s, TI=%u)\n",
			mm->imsi, transaction_id);
		return _gsm48_tx_gsm_deact_pdp_acc(mm, transaction_id);
	}

	if (pdp->ggsn)
		return sgsn_delete_pdp_ctx(pdp);
	/* GTP side already detached, freeing */
	sgsn_pdp_ctx_free(pdp);
	return 0;
}

/* 3GPP TS 24.008 § 9.5.9: Deactivate PDP Context Accept */
static int gsm48_rx_gsm_deact_pdp_ack(struct sgsn_mm_ctx *mm, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t transaction_id = gsm48_hdr_trans_id(gh);
	struct sgsn_pdp_ctx *pdp;

	LOGMMCTXP(LOGL_INFO, mm, "-> DEACTIVATE PDP CONTEXT ACK\n");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_UL_DEACTIVATE_ACCEPT]);

	pdp = sgsn_pdp_ctx_by_tid(mm, transaction_id);
	if (!pdp) {
		LOGMMCTXP(LOGL_NOTICE, mm, "Deactivate PDP Context Accept for "
			"non-existing PDP Context (IMSI=%s, TI=%u)\n",
			mm->imsi, transaction_id);
		return 0;
	}
	/* stop timer 3395 */
	pdpctx_timer_stop(pdp, 3395);
	if (pdp->ggsn)
		return sgsn_delete_pdp_ctx(pdp);
	/* GTP side already detached, freeing */
	sgsn_pdp_ctx_free(pdp);
	return 0;
}

static int gsm48_rx_gsm_status(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	LOGMMCTXP(LOGL_INFO, ctx, "-> GPRS SM STATUS (cause: %s)\n",
		get_value_string(gsm48_gsm_cause_names, gh->data[0]));

	return 0;
}

static void pdpctx_timer_cb(void *_pdp)
{
	struct sgsn_pdp_ctx *pdp = _pdp;

	pdp->num_T_exp++;

	switch (pdp->T) {
	case 3395:	/* waiting for PDP CTX DEACT ACK */
		if (pdp->num_T_exp > T339X_MAX_RETRANS) {
			LOGPDPCTXP(LOGL_NOTICE, pdp, "T3395 expired > %d times\n", T339X_MAX_RETRANS);
			pdp->state = PDP_STATE_INACTIVE;
			if (pdp->ggsn)
				sgsn_delete_pdp_ctx(pdp);
			else
				sgsn_pdp_ctx_free(pdp);
			break;
		}
		_gsm48_tx_gsm_deact_pdp_req(pdp->mm, pdp->ti, GSM_CAUSE_NET_FAIL, true);
		pdpctx_timer_rearm(pdp, 3395);
		break;
	default:
		LOGPDPCTXP(LOGL_ERROR, pdp, "timer expired in unknown mode %u\n",
			pdp->T);
	}
}

/* GPRS Session Management */
int gsm0408_rcv_gsm(struct sgsn_mm_ctx *mmctx, struct msgb *msg,
			   struct gprs_llc_llme *llme)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	int rc;

	/* MMCTX can be NULL when called */

	if (!mmctx) {
		LOGGBIUP(llme, msg, LOGL_NOTICE, "Cannot handle SM for unknown MM CTX\n");
		/* 6.1.3.6 */
		if (gh->msg_type == GSM48_MT_GSM_STATUS)
			return 0;

		return gsm0408_gprs_force_reattach_oldmsg(msg, llme);
	}

	switch (gh->msg_type) {
	case GSM48_MT_GSM_ACT_PDP_REQ:
		rc = gsm48_rx_gsm_act_pdp_req(mmctx, msg);
		break;
	case GSM48_MT_GSM_DEACT_PDP_REQ:
		rc = gsm48_rx_gsm_deact_pdp_req(mmctx, msg);
		break;
	case GSM48_MT_GSM_DEACT_PDP_ACK:
		rc = gsm48_rx_gsm_deact_pdp_ack(mmctx, msg);
		break;
	case GSM48_MT_GSM_STATUS:
		rc = gsm48_rx_gsm_status(mmctx, msg);
		break;
	case GSM48_MT_GSM_REQ_PDP_ACT_REJ:
	case GSM48_MT_GSM_ACT_AA_PDP_REQ:
	case GSM48_MT_GSM_DEACT_AA_PDP_REQ:
		LOGMMCTXP(LOGL_NOTICE, mmctx, "Unimplemented GSM 04.08 GSM msg type 0x%02x: %s\n",
			gh->msg_type, osmo_hexdump((uint8_t *)gh, msgb_l3len(msg)));
		rc = gsm48_tx_sm_status(mmctx, GSM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mmctx, "Unknown GSM 04.08 GSM msg type 0x%02x: %s\n",
			gh->msg_type, osmo_hexdump((uint8_t *)gh, msgb_l3len(msg)));
		rc = gsm48_tx_sm_status(mmctx, GSM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		break;

	}

	return rc;
}
