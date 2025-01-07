/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2009-2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/tdef.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/crypt/utran_cipher.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_utils.h>
#include <osmocom/sgsn/gprs_subscriber.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_gmm_attach.h>
#include <osmocom/sgsn/gprs_mm_state_gb_fsm.h>
#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>
#include <osmocom/sgsn/gprs_gmm_fsm.h>
#include <osmocom/sgsn/signal.h>
#include <osmocom/sgsn/gprs_sndcp.h>
#include <osmocom/sgsn/gprs_ranap.h>
#include <osmocom/sgsn/gprs_sm.h>
#include <osmocom/sgsn/gtp.h>
#include <osmocom/sgsn/pdpctx.h>

#include <pdp.h>

#define PTMSI_ALLOC

static const struct tlv_definition gsm48_gmm_att_tlvdef = {
	.def = {
		[GSM48_IE_GMM_CIPH_CKSN]	= { TLV_TYPE_SINGLE_TV, 1 },
		[GSM48_IE_GMM_TIMER_READY]	= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GMM_ALLOC_PTMSI]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PTMSI_SIG]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_GMM_AUTH_RAND]	= { TLV_TYPE_FIXED, 16 },
		[GSM48_IE_GMM_AUTH_SRES]	= { TLV_TYPE_FIXED, 4 },
		[GSM48_IE_GMM_AUTH_RES_EXT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_AUTH_FAIL_PAR]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_IMEISV]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_RX_NPDU_NUM_LIST] = { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_DRX_PARAM]	= { TLV_TYPE_FIXED, 2 },
		[GSM48_IE_GMM_MS_NET_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PDP_CTX_STATUS]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PS_LCS_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_GMM_MBMS_CTX_ST]	= { TLV_TYPE_TLV, 0 },
	},
};

/* Our implementation, should be kept in SGSN */

static void mmctx_timer_cb(void *_mm);

static void mmctx_timer_start(struct sgsn_mm_ctx *mm, unsigned int T)
{
	unsigned long seconds;
	if (osmo_timer_pending(&mm->timer))
		LOGMMCTXP(LOGL_ERROR, mm, "Starting MM timer %u while old "
			"timer %u pending\n", T, mm->T);

	seconds = osmo_tdef_get(sgsn->cfg.T_defs, T, OSMO_TDEF_S, -1);

	mm->T = T;
	mm->num_T_exp = 0;

	/* FIXME: we should do this only once ? */
	osmo_timer_setup(&mm->timer, mmctx_timer_cb, mm);
	osmo_timer_schedule(&mm->timer, seconds, 0);
}

static void mmctx_timer_stop(struct sgsn_mm_ctx *mm, unsigned int T)
{
	if (!osmo_timer_pending(&mm->timer)) {
		LOGMMCTXP(LOGL_NOTICE, mm, "Stopping *inactive* MM timer %u\n", T);
		return;
	}
	if (mm->T != T) {
		LOGMMCTXP(LOGL_ERROR, mm, "Stopping MM timer %u but "
			"%u is running\n", T, mm->T);
	}
	osmo_timer_del(&mm->timer);
}

time_t gprs_max_time_to_idle(void)
{
	unsigned long T3314, T3312;

	T3314 = osmo_tdef_get(sgsn->cfg.T_defs, 3314, OSMO_TDEF_S, -1);
	T3312 = osmo_tdef_get(sgsn->cfg.T_defs, 3312, OSMO_TDEF_S, -1);
	return T3314 + (T3312 + 4 * 60);
}

/* Send a message through the underlying layer.
 * For param encryptable, see 3GPP TS 24.008 § 4.7.1.2 and
 * gsm48_hdr_gmm_cipherable(). Pass false for not cipherable messages. */
int gsm48_gmm_sendmsg(struct msgb *msg, int command,
			     struct sgsn_mm_ctx *mm, bool encryptable)
{
	if (mm) {
		rate_ctr_inc(rate_ctr_group_get_ctr(mm->ctrg, GMM_CTR_PKTS_SIG_OUT));
#ifdef BUILD_IU
		if (mm->ran_type == MM_CTX_T_UTRAN_Iu)
			return ranap_iu_tx(msg, GPRS_SAPI_GMM);
#endif
	}

#ifdef BUILD_IU
	if (MSG_IU_UE_CTX(msg))
		return ranap_iu_tx(msg, GPRS_SAPI_GMM);
#endif

	/* caller needs to provide TLLI, BVCI and NSEI */
	return gprs_llc_tx_ui(msg, GPRS_SAPI_GMM, command, mm, encryptable);
}

/* copy identifiers from old message to new message, this
 * is required so lower layers can route it correctly */
static void gmm_copy_id(struct msgb *msg, const struct msgb *old)
{
	msgb_tlli(msg) = msgb_tlli(old);
	msgb_bvci(msg) = msgb_bvci(old);
	msgb_nsei(msg) = msgb_nsei(old);
	MSG_IU_UE_CTX_SET(msg, MSG_IU_UE_CTX(old));
}

/* Store BVCI/NSEI in MM context */
void msgid2mmctx(struct sgsn_mm_ctx *mm, const struct msgb *msg)
{
	/* check for Iu or Gb */
	if (!MSG_IU_UE_CTX(msg)) {
		mm->gb.bvci = msgb_bvci(msg);
		mm->gb.nsei = msgb_nsei(msg);
	}
#ifdef BUILD_IU
	else {
		/* In case a Iu connection is reconnected we need to update the ue ctx */
		/* FIXME: the old ue_ctx have to be freed/disconnected */
		mm->iu.ue_ctx = MSG_IU_UE_CTX(msg);
		if (mm->ran_type == MM_CTX_T_UTRAN_Iu
				&& mm->iu.ue_ctx) {
			mm->iu.ue_ctx->rab_assign_addr_enc =
					sgsn->cfg.iu.rab_assign_addr_enc;
		}
	}
#endif
}

/* Store BVCI/NSEI in MM context */
void mmctx2msgid(struct msgb *msg, const struct sgsn_mm_ctx *mm)
{
	msgb_tlli(msg) = mm->gb.tlli;
	msgb_bvci(msg) = mm->gb.bvci;
	msgb_nsei(msg) = mm->gb.nsei;
	MSG_IU_UE_CTX_SET(msg, mm->iu.ue_ctx);
}

static void mm_ctx_cleanup_free(struct sgsn_mm_ctx *ctx, const char *log_text)
{
	LOGMMCTXP(LOGL_INFO, ctx, "Cleaning MM context due to %s\n", log_text);

	/* Mark MM state as deregistered */
	osmo_fsm_inst_dispatch(ctx->gmm_fsm, E_GMM_CLEANUP, NULL);

	switch(ctx->ran_type) {
	case MM_CTX_T_UTRAN_Iu:
		osmo_fsm_inst_dispatch(ctx->iu.mm_state_fsm, E_PMM_PS_DETACH, NULL);
		break;
	case MM_CTX_T_GERAN_Gb:
		osmo_fsm_inst_dispatch(ctx->gb.mm_state_fsm, E_MM_GPRS_DETACH, NULL);
		break;
	}

	sgsn_mm_ctx_cleanup_free(ctx);
}


/* 3GPP TS 24.008 § 10.5.7.1 Process PDP context status value, bit 0 corresponds to nsapi 0 */
static void process_ms_ctx_status(struct sgsn_mm_ctx *mmctx,
				  uint16_t pdp_status)
{
	struct sgsn_pdp_ctx *pdp, *pdp2;
	/* 24.008 4.7.5.1.3: If the PDP context status information element is
	 * included in ROUTING AREA UPDATE REQUEST message, then the network
	 * shall deactivate all those PDP contexts locally (without peer to
	 * peer signalling between the MS and the network), which are not in SM
	 * state PDP-INACTIVE on network side but are indicated by the MS as
	 * being in state PDP-INACTIVE. */

	/* NSAPI 0 - 4 are spare, ignore these */
	pdp_status &= 0xffe0;

	llist_for_each_entry_safe(pdp, pdp2, &mmctx->pdp_list, list) {
		bool active = (pdp_status & (1 << pdp->nsapi));
		if (active)
			continue;

		LOGMMCTXP(LOGL_NOTICE, mmctx, "Dropping PDP context for NSAPI=%u "
					      "due to PDP CTX STATUS IE=0x%02x\n",
			  pdp->nsapi, pdp_status);
		pdp->ue_pdp_active = false;
		if (pdp->ggsn)
			sgsn_delete_pdp_ctx(pdp);
		else /* GTP side already detached, freeing */
			sgsn_pdp_ctx_free(pdp);
	}
}

/* 3GPP TS 24.008 § 10.5.7.1 Encode PDP context status value, bit 0 correspond to nsapi 0 */
uint16_t encode_ms_ctx_status(struct sgsn_mm_ctx *mmctx)
{
	struct sgsn_pdp_ctx *pdp;

	uint16_t pdp_status = 0;

	llist_for_each_entry(pdp, &mmctx->pdp_list, list) {
		if (pdp->ue_pdp_active)
			pdp_status |= (1 << pdp->nsapi);
	}

	return pdp_status;
}

/* 3GPP TS 24.008 § 4.7.13.4/10.5.7.1 Service request procedure not accepted by the
 * network. Returns true if MS has active PDP contexts in pdp_status */
bool pdp_status_has_active_nsapis(uint16_t pdp_status)
{
	/* NSAPI 0 - 4 are spare and should be ignored 0 */
	return (pdp_status >> 5) != 0;
}

/* Chapter 9.4.18 */
static int _tx_status(struct msgb *msg, uint8_t cause,
		      struct sgsn_mm_ctx *mmctx)
{
	struct gsm48_hdr *gh;

	/* MMCTX might be NULL! */

	DEBUGP(DMM, "<- GMM STATUS (cause: %s)\n",
		get_value_string(gsm48_gmm_cause_names, cause));

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_STATUS;
	gh->data[0] = cause;

	return gsm48_gmm_sendmsg(msg, 0, mmctx, true);
}

static int gsm48_tx_gmm_status(struct sgsn_mm_ctx *mmctx, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 GMM STATUS");

	mmctx2msgid(msg, mmctx);
	return _tx_status(msg, cause, mmctx);
}

static int _tx_detach_req(struct msgb *msg, uint8_t detach_type, uint8_t cause,
			  struct sgsn_mm_ctx *mmctx)
{
	struct gsm48_hdr *gh;

	/* MMCTX might be NULL! */

	DEBUGP(DMM, "<- GMM DETACH REQ (type: %s, cause: %s)\n",
		get_value_string(gprs_det_t_mt_strs, detach_type),
		get_value_string(gsm48_gmm_cause_names, cause));

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);

	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_DETACH_REQ;
	gh->data[0] = detach_type & 0x07;

	msgb_tv_put(msg, GSM48_IE_GMM_CAUSE, cause);

	return gsm48_gmm_sendmsg(msg, 0, mmctx, true);
}

static int gsm48_tx_gmm_detach_req(struct sgsn_mm_ctx *mmctx,
				   uint8_t detach_type, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DET REQ");

	mmctx2msgid(msg, mmctx);
	return _tx_detach_req(msg, detach_type, cause, mmctx);
}

static int gsm48_tx_gmm_detach_req_oldmsg(struct msgb *oldmsg,
					  uint8_t detach_type, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DET OLD");

	gmm_copy_id(msg, oldmsg);
	return _tx_detach_req(msg, detach_type, cause, NULL);
}

/* Chapter 9.4.2: Attach accept */
int gsm48_tx_gmm_att_ack(struct sgsn_mm_ctx *mm)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ATT ACK");
	struct gsm48_hdr *gh;
	struct gsm48_attach_ack *aa;
	unsigned long t;
#ifdef PTMSI_ALLOC
	struct osmo_mobile_identity mi;
	uint8_t *l;
	int rc;
#endif
#if 0
	uint8_t *ptsig;
#endif

	LOGMMCTXP(LOGL_INFO, mm, "<- GMM ATTACH ACCEPT (new P-TMSI=0x%08x)\n", mm->p_tmsi);
	rate_ctr_inc(rate_ctr_group_get_ctr(sgsn->rate_ctrs, CTR_GPRS_ATTACH_ACKED));

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_ACK;

	aa = (struct gsm48_attach_ack *) msgb_put(msg, sizeof(*aa));
	aa->force_stby = 0;	/* not indicated */
	aa->att_result = 1;	/* GPRS only */
	t = osmo_tdef_get(sgsn->cfg.T_defs, 3312, OSMO_TDEF_S, -1);
	aa->ra_upd_timer = gprs_secs_to_tmr_floor(t);
	aa->radio_prio = 0x44;	/* lowest */
	osmo_routing_area_id_encode_buf((uint8_t *) &aa->ra_id, sizeof(struct gsm48_ra_id), &mm->ra);

#if 0
	/* Optional: P-TMSI signature */
	msgb_v_put(msg, GSM48_IE_GMM_PTMSI_SIG);
	ptsig = msgb_put(msg, 3);
	ptsig[0] = mm->p_tmsi_sig >> 16;
	ptsig[1] = mm->p_tmsi_sig >> 8;
	ptsig[2] = mm->p_tmsi_sig & 0xff;

#endif
	/* Optional: Negotiated Ready timer value
	 * (fixed 44s, default value, GSM 04.08, table 11.4a) to safely limit
	 * the inactivity time READY->STANDBY.
	 */
	t = osmo_tdef_get(sgsn->cfg.T_defs, 3314, OSMO_TDEF_S, -1);
	msgb_tv_put(msg, GSM48_IE_GMM_TIMER_READY, gprs_secs_to_tmr_floor(t));

#ifdef PTMSI_ALLOC
	/* Optional: Allocated P-TMSI */
	mi = (struct osmo_mobile_identity){
		.type = GSM_MI_TYPE_TMSI,
		.tmsi = mm->p_tmsi,
	};
	l = msgb_tl_put(msg, GSM48_IE_GMM_ALLOC_PTMSI);
	rc = osmo_mobile_identity_encode_msgb(msg, &mi, false);
	if (rc < 0) {
		LOGMMCTXP(LOGL_ERROR, mm, "Cannot encode Mobile Identity\n");
		msgb_free(msg);
		return -EINVAL;
	}
	*l = rc;
#endif

	/* Optional: MS-identity (combined attach) */
	/* Optional: GMM cause (partial attach result for combined attach) */

	/* Optional: Network feature support 10.5.5.23 */
	/* msgb_v_put(msg, GSM48_IE_GMM_NET_FEAT_SUPPORT | 0x00);*/

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}

/* Chapter 9.4.5: Attach reject */
static int _tx_gmm_att_rej(struct msgb *msg, uint8_t gmm_cause,
			   const struct sgsn_mm_ctx *mm)
{
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_NOTICE, mm, "<- GMM ATTACH REJECT: %s\n",
		  get_value_string(gsm48_gmm_cause_names, gmm_cause));
	rate_ctr_inc(rate_ctr_group_get_ctr(sgsn->rate_ctrs, CTR_GPRS_ATTACH_REJECTED));

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_REJ;
	gh->data[0] = gmm_cause;

	return gsm48_gmm_sendmsg(msg, 0, NULL, false);
}
static int gsm48_tx_gmm_att_rej_oldmsg(const struct msgb *old_msg,
					uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ATT REJ OLD");
	gmm_copy_id(msg, old_msg);
	return _tx_gmm_att_rej(msg, gmm_cause, NULL);
}
int gsm48_tx_gmm_att_rej(struct sgsn_mm_ctx *mm,
				uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ATT REJ");
	mmctx2msgid(msg, mm);
	return _tx_gmm_att_rej(msg, gmm_cause, mm);
}

/* Chapter 9.4.6.2 Detach accept */
static int _tx_detach_ack(struct msgb *msg, uint8_t force_stby,
			  struct sgsn_mm_ctx *mm)
{
	struct gsm48_hdr *gh;

	/* MMCTX might be NULL! */

	DEBUGP(DMM, "<- GMM DETACH ACC (force-standby: %d)\n", force_stby);
	rate_ctr_inc(rate_ctr_group_get_ctr(sgsn->rate_ctrs, CTR_GPRS_DETACH_ACKED));

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_DETACH_ACK;
	gh->data[0] = force_stby;

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}

static int gsm48_tx_gmm_det_ack(struct sgsn_mm_ctx *mm, uint8_t force_stby)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DET ACK");

	mmctx2msgid(msg, mm);
	return _tx_detach_ack(msg, force_stby, mm);
}

static int gsm48_tx_gmm_det_ack_oldmsg(struct msgb *oldmsg, uint8_t force_stby)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DET ACK OLD");

	gmm_copy_id(msg, oldmsg);
	return _tx_detach_ack(msg, force_stby, NULL);
}

/* Transmit Chapter 9.4.12 Identity Request */
int gsm48_tx_gmm_id_req(struct sgsn_mm_ctx *mm, uint8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ID REQ");
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_DEBUG, mm, "<- GMM IDENTITY REQUEST: mi_type=%s\n",
		  gsm48_mi_type_name(id_type));

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ID_REQ;
	/* 10.5.5.9 ID type 2 + identity type and 10.5.5.7 'force to standby' IE */
	gh->data[0] = id_type & 0xf;

	return gsm48_gmm_sendmsg(msg, 1, mm, false);
}

/* determine if the MS/UE supports R99 or later */
static bool mmctx_is_r99(const struct sgsn_mm_ctx *mm)
{
	if (mm->ms_network_capa.len < 1)
		return false;
	if (mm->ms_network_capa.buf[0] & 0x01)
		return true;
	return false;
}

static enum gprs_ciph_algo gprs_ms_net_select_best_gea(uint8_t net_mask, uint8_t ms_mask) {
	uint8_t common_mask = net_mask & ms_mask;
	uint8_t r = 0;

	while (common_mask >>= 1) {
		r++;
	}

	return r;
}

/* 3GPP TS 24.008 § 9.4.9: Authentication and Ciphering Request */
int gsm48_tx_gmm_auth_ciph_req(struct sgsn_mm_ctx *mm,
				      const struct osmo_auth_vector *vec,
				      uint8_t key_seq, bool force_standby)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 AUTH CIPH REQ");
	struct gsm48_hdr *gh;
	struct gsm48_auth_ciph_req *acreq;
	uint8_t *m_rand, *m_cksn, rbyte;
	int rc;

	LOGMMCTXP(LOGL_INFO, mm, "<- GMM AUTH AND CIPHERING REQ (rand = %s,"
		  " mmctx_is_r99=%d, vec->auth_types=0x%x",
		  osmo_hexdump(vec->rand, sizeof(vec->rand)),
		  mmctx_is_r99(mm), vec->auth_types);
	if (mmctx_is_r99(mm) && vec
	    && (vec->auth_types & OSMO_AUTH_TYPE_UMTS)) {
		LOGPC(DMM, LOGL_INFO, ", autn = %s)\n",
		      osmo_hexdump(vec->autn, sizeof(vec->autn)));
	} else
		LOGPC(DMM, LOGL_INFO, ")\n");

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_AUTH_CIPH_REQ;

	acreq = (struct gsm48_auth_ciph_req *) msgb_put(msg, sizeof(*acreq));
	acreq->ciph_alg = mm->ciph_algo & 0xf;
	/* § 10.5.5.10: */
	acreq->imeisv_req = 0x1;
	/* § 10.5.5.7: */
	acreq->force_stby = force_standby;
	/* 3GPP TS 24.008 § 10.5.5.19: */
	rc = osmo_get_rand_id(&rbyte, 1);
	if (rc < 0) {
		LOGMMCTXP(LOGL_ERROR, mm, "osmo_get_rand_id() failed for A&C ref: %s\n", strerror(-rc));
		return rc;
	}

	acreq->ac_ref_nr = rbyte;
	mm->ac_ref_nr_used = acreq->ac_ref_nr;

	/* Only if authentication is requested we need to set RAND + CKSN */
	if (vec) {
		m_rand = msgb_put(msg, sizeof(vec->rand) + 1);
		m_rand[0] = GSM48_IE_GMM_AUTH_RAND;
		memcpy(m_rand + 1, vec->rand, sizeof(vec->rand));

		/* § 10.5.1.2: */
		m_cksn = msgb_put(msg, 1);
		m_cksn[0] = (GSM48_IE_GMM_CIPH_CKSN << 4) | (key_seq & 0x07);

		/* A Release99 or higher MS/UE must be able to handle
		 * the optional AUTN IE.  If a classic GSM SIM is
		 * inserted, it will simply ignore AUTN and just use
		 * RAND */
		if (mmctx_is_r99(mm) &&
		    (vec->auth_types & OSMO_AUTH_TYPE_UMTS)) {
			msgb_tlv_put(msg, GSM48_IE_GMM_AUTN,
				     sizeof(vec->autn), vec->autn);
		}
	}

	return gsm48_gmm_sendmsg(msg, 1, mm, false);
}

/* 3GPP TS 24.008 § 9.4.11: Authentication and Ciphering Reject */
static int gsm48_tx_gmm_auth_ciph_rej(struct sgsn_mm_ctx *mm)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 AUTH CIPH REJ");
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_NOTICE, mm, "<- GMM AUTH AND CIPH REJECT\n");

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_AUTH_CIPH_REJ;

	return gsm48_gmm_sendmsg(msg, 0, mm, false);
}

/* check if the received authentication response matches */
static enum osmo_sub_auth_type check_auth_resp(struct sgsn_mm_ctx *ctx,
					       bool is_utran,
					       const struct osmo_auth_vector *vec,
					       const uint8_t *res, uint8_t res_len)
{
	const uint8_t *expect_res;
	uint8_t expect_res_len;
	enum osmo_sub_auth_type expect_type;
	const char *expect_str;

	/* On UTRAN (3G) we always expect UMTS AKA. On GERAN (2G) we sent AUTN
	 * and expect UMTS AKA if there is R99 capability and our vector
	 * supports UMTS AKA, otherwise we expect GSM AKA.
	 * However, on GERAN, even if we sent a UMTS AKA Authentication Request, the MS may decide to
	 * instead reply with a GSM AKA SRES response. */
	if (is_utran
	    || (mmctx_is_r99(ctx) && (vec->auth_types & OSMO_AUTH_TYPE_UMTS)
		&& (res_len > sizeof(vec->sres)))) {
		expect_type = OSMO_AUTH_TYPE_UMTS;
		expect_str = "UMTS RES";
		expect_res = vec->res;
		expect_res_len = vec->res_len;
	} else {
		expect_type = OSMO_AUTH_TYPE_GSM;
		expect_str = "GSM SRES";
		expect_res = vec->sres;
		expect_res_len = sizeof(vec->sres);
	}

	if (!(vec->auth_types & expect_type)) {
		LOGMMCTXP(LOGL_ERROR, ctx, "Auth error: auth vector does"
			  " not provide the expected auth type:"
			  " expected %s = 0x%x, auth_types are 0x%x\n",
			  expect_str, expect_type, vec->auth_types);
		return OSMO_AUTH_TYPE_NONE;
	}

	if (!res)
		goto auth_mismatch;

	if (res_len != expect_res_len)
		goto auth_mismatch;

	if (memcmp(res, expect_res, res_len) != 0)
		goto auth_mismatch;

	/* Authorized! */
	return expect_type;

auth_mismatch:
	LOGMMCTXP(LOGL_ERROR, ctx, "Auth mismatch: expected %s = %s\n",
		  expect_str, osmo_hexdump_nospc(expect_res, expect_res_len));
	return OSMO_AUTH_TYPE_NONE;
}

/* 3GPP TS 24.008 § 9.4.10: Authentication and Ciphering Response */
static int gsm48_rx_gmm_auth_ciph_resp(struct sgsn_mm_ctx *ctx,
					struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	struct gsm48_auth_ciph_resp *acr = (struct gsm48_auth_ciph_resp *)gh->data;
	struct tlv_parsed tp;
	struct gsm_auth_tuple *at;
	const char *res_name = "(no response)";
	uint8_t res[16];
	uint8_t res_len;
	int rc;

	LOGMMCTXP(LOGL_INFO, ctx, "-> GMM AUTH AND CIPH RESPONSE\n");

	if (ctx->auth_triplet.key_seq == GSM_KEY_SEQ_INVAL) {
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "Unexpected Auth & Ciph Response (ignored)\n");
		return 0;
	}

	if (acr->ac_ref_nr != ctx->ac_ref_nr_used) {
		LOGMMCTXP(LOGL_NOTICE, ctx, "Reference mismatch for Auth & Ciph"
			  " Response: %u received, %u expected\n",
			  acr->ac_ref_nr, ctx->ac_ref_nr_used);
		return 0;
	}

	/* Stop T3360 */
	mmctx_timer_stop(ctx, 3360);

	tlv_parse(&tp, &gsm48_gmm_att_tlvdef, acr->data,
			(msg->data + msg->len) - acr->data, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM48_IE_GMM_AUTH_SRES) ||
	    !TLVP_PRESENT(&tp, GSM48_IE_GMM_IMEISV) ||
	    TLVP_LEN(&tp,GSM48_IE_GMM_AUTH_SRES) != 4) {
		/* TODO: missing mandatory IE, return STATUS or REJ? */
		LOGMMCTXP(LOGL_ERROR, ctx, "Missing mandantory IE\n");
		return -EINVAL;
	}

	/* Start with the good old 4-byte SRES */
	memcpy(res, TLVP_VAL(&tp, GSM48_IE_GMM_AUTH_SRES), 4);
	res_len = 4;
	res_name = "GSM SRES";

	/* Append extended RES as part of UMTS AKA, if any */
	if (TLVP_PRESENT(&tp, GSM48_IE_GMM_AUTH_RES_EXT)) {
		unsigned int l = TLVP_LEN(&tp, GSM48_IE_GMM_AUTH_RES_EXT);
		if (l > sizeof(res)-4)
			l = sizeof(res)-4;
		memcpy(res+4, TLVP_VAL(&tp, GSM48_IE_GMM_AUTH_RES_EXT), l);
		res_len += l;
		res_name = "UMTS RES";
	}

	at = &ctx->auth_triplet;

	LOGMMCTXP(LOGL_DEBUG, ctx, "checking auth: received %s = %s\n",
		  res_name, osmo_hexdump(res, res_len));
	ctx->sec_ctx = check_auth_resp(ctx, false, &at->vec, res, res_len);
	if (!sgsn_mm_ctx_is_authenticated(ctx)) {
		rc = gsm48_tx_gmm_auth_ciph_rej(ctx);
		mm_ctx_cleanup_free(ctx, "GMM AUTH AND CIPH REJECT");
		return rc;
	}

	if (ctx->ran_type == MM_CTX_T_UTRAN_Iu)
		ctx->iu.new_key = 1;

	/* FIXME: enable LLC cipheirng */

	/* Check if we can let the mobile station enter */
	return osmo_fsm_inst_dispatch(ctx->gmm_att_req.fsm, E_AUTH_RESP_RECV_SUCCESS, NULL);
}

/* 3GPP TS 24.008 § 9.4.10: Authentication and Ciphering Failure */
static int gsm48_rx_gmm_auth_ciph_fail(struct sgsn_mm_ctx *ctx,
					struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	struct tlv_parsed tp;
	const uint8_t gmm_cause = gh->data[0];
	const uint8_t *auts;
	int rc;

	LOGMMCTXP(LOGL_INFO, ctx, "-> GMM AUTH AND CIPH FAILURE (cause = %s)\n",
		  get_value_string(gsm48_gmm_cause_names, gmm_cause));

	tlv_parse(&tp, &gsm48_gmm_att_tlvdef, gh->data+1, msg->len - 1, 0, 0);

	/* Only if GMM cause is present and the AUTS is provided, we can
	 * start re-sync procedure */
	if (gmm_cause == GMM_CAUSE_SYNC_FAIL &&
	    TLVP_PRESENT(&tp, GSM48_IE_GMM_AUTH_FAIL_PAR)) {
		if (TLVP_LEN(&tp, GSM48_IE_GMM_AUTH_FAIL_PAR) != 14) {
			LOGMMCTXP(LOGL_ERROR, ctx, "AUTS IE has wrong size:"
				  " expected %d, got %u\n", 14,
				  TLVP_LEN(&tp, GSM48_IE_GMM_AUTH_FAIL_PAR));
			return -EINVAL;
		}
		auts = TLVP_VAL(&tp, GSM48_IE_GMM_AUTH_FAIL_PAR);

		LOGMMCTXP(LOGL_INFO, ctx,
			  "R99 AUTHENTICATION SYNCH (AUTS = %s)\n",
			  osmo_hexdump_nospc(auts, 14));

		/* make sure we'll refresh the auth_triplet in
		 * sgsn_auth_update() */
		ctx->auth_triplet.key_seq = GSM_KEY_SEQ_INVAL;

		/* make sure we'll retry authentication after the resync */
		ctx->auth_state = SGSN_AUTH_UMTS_RESYNC;

		/* Send AUTS to HLR and wait for new Auth Info Result */
		rc = gprs_subscr_request_auth_info(ctx, auts,
						   ctx->auth_triplet.vec.rand);
		if (!rc)
			return osmo_fsm_inst_dispatch(ctx->gmm_att_req.fsm, E_AUTH_RESP_RECV_RESYNC, NULL);
		/* on error, fall through to send a reject */
		LOGMMCTXP(LOGL_ERROR, ctx,
			  "Sending AUTS to HLR failed (rc = %d)\n", rc);
	}

	LOGMMCTXP(LOGL_NOTICE, ctx, "Authentication failed\n");
	rc = gsm48_tx_gmm_auth_ciph_rej(ctx);
	mm_ctx_cleanup_free(ctx, "GMM AUTH FAILURE");
	return rc;
}

void extract_subscr_msisdn(struct sgsn_mm_ctx *ctx)
{
	struct gsm_mncc_number called;
	uint8_t msisdn[sizeof(ctx->subscr->sgsn_data->msisdn) + 1];

	/* Convert MSISDN from encoded to string.. */
	if (!ctx->subscr)
		return;

	if (ctx->subscr->sgsn_data->msisdn_len < 1)
		return;

	/* prepare the data for the decoder */
	memset(&called, 0, sizeof(called));
	msisdn[0] = ctx->subscr->sgsn_data->msisdn_len;
	memcpy(&msisdn[1], ctx->subscr->sgsn_data->msisdn,
		ctx->subscr->sgsn_data->msisdn_len);

	/* decode the string now */
	gsm48_decode_called(&called, msisdn);

	/* Prepend a '+' for international numbers */
	if (called.plan == 1 && called.type == 1) {
		ctx->msisdn[0] = '+';
		osmo_strlcpy(&ctx->msisdn[1], called.number,
			     sizeof(ctx->msisdn));
	} else {
		osmo_strlcpy(ctx->msisdn, called.number, sizeof(ctx->msisdn));
	}
}

void extract_subscr_hlr(struct sgsn_mm_ctx *ctx)
{
	struct gsm_mncc_number called;
	uint8_t hlr_number[sizeof(ctx->subscr->sgsn_data->hlr) + 1];

	if (!ctx->subscr)
		return;

	if (ctx->subscr->sgsn_data->hlr_len < 1)
		return;

	/* prepare the data for the decoder */
	memset(&called, 0, sizeof(called));
	hlr_number[0] = ctx->subscr->sgsn_data->hlr_len;
	memcpy(&hlr_number[1], ctx->subscr->sgsn_data->hlr,
		ctx->subscr->sgsn_data->hlr_len);

	/* decode the string now */
	gsm48_decode_called(&called, hlr_number);

	if (called.plan != 1) {
		LOGMMCTXP(LOGL_ERROR, ctx,
				"Numbering plan(%d) not allowed\n",
				called.plan);
		return;
	}

	if (called.type != 1) {
		LOGMMCTXP(LOGL_ERROR, ctx,
				"Numbering type(%d) not allowed\n",
				called.type);
		return;
	}

	osmo_strlcpy(ctx->hlr, called.number, sizeof(ctx->hlr));
}

#ifdef BUILD_IU
/* Chapter 9.4.21: Service accept */
static int gsm48_tx_gmm_service_ack(struct sgsn_mm_ctx *mm)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERVICE ACK");
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_INFO, mm, "<- GMM SERVICE ACCEPT (P-TMSI=0x%08x)\n", mm->p_tmsi);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_SERVICE_ACK;

	/* Optional: PDP context status */
	/* Optional: MBMS context status */

	return gsm48_gmm_sendmsg(msg, 0, mm, false);
}
#endif

/* Chapter 9.4.22: Service reject */
static int _tx_gmm_service_rej(struct msgb *msg, uint8_t gmm_cause,
			   const struct sgsn_mm_ctx *mm)
{
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_NOTICE, mm, "<- GMM SERVICE REJECT: %s\n",
		  get_value_string(gsm48_gmm_cause_names, gmm_cause));

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_SERVICE_REJ;
	gh->data[0] = gmm_cause;

	return gsm48_gmm_sendmsg(msg, 0, NULL, true);
}
static int gsm48_tx_gmm_service_rej_oldmsg(const struct msgb *old_msg,
					uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERVICE REJ OLD");
	gmm_copy_id(msg, old_msg);
	return _tx_gmm_service_rej(msg, gmm_cause, NULL);
}
#if 0
-- currently unused --
static int gsm48_tx_gmm_service_rej(struct sgsn_mm_ctx *mm,
				uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERVICE REJ");
	mmctx2msgid(msg, mm);
	return _tx_gmm_service_rej(msg, gmm_cause, mm);
}
#endif

static int gsm48_tx_gmm_ra_upd_ack(struct sgsn_mm_ctx *mm);

/* Check if we can already authorize a subscriber */
int gsm48_gmm_authorize(struct sgsn_mm_ctx *ctx)
{
#ifdef BUILD_IU
	int rc;
#endif
#ifndef PTMSI_ALLOC
	struct sgsn_signal_data sig_data;
#endif

	/* Request IMSI and IMEI from the MS if they are unknown */
	if (!strlen(ctx->imei)) {
		ctx->t3370_id_type = GSM_MI_TYPE_IMEI;
		mmctx_timer_start(ctx, 3370);
		return gsm48_tx_gmm_id_req(ctx, GSM_MI_TYPE_IMEI);
	}
	if (!strlen(ctx->imsi)) {
		ctx->t3370_id_type = GSM_MI_TYPE_IMSI;
		mmctx_timer_start(ctx, 3370);
		return gsm48_tx_gmm_id_req(ctx, GSM_MI_TYPE_IMSI);
	}

	/* All information required for authentication is available */
	ctx->t3370_id_type = GSM_MI_TYPE_NONE;

	if (ctx->auth_state == SGSN_AUTH_UNKNOWN) {
		/* Request authorization, this leads to a call to
		 * sgsn_auth_update which in turn calls
		 * gsm0408_gprs_access_granted or gsm0408_gprs_access_denied */

		sgsn_auth_request(ctx);
		/* Note that gsm48_gmm_authorize can be called recursively via
		 * sgsn_auth_request iff ctx->auth_info changes to AUTH_ACCEPTED
		 */
		return 0;
	}

	if (ctx->auth_state == SGSN_AUTH_AUTHENTICATE
	    && !sgsn_mm_ctx_is_authenticated(ctx)) {
		struct gsm_auth_tuple *at = &ctx->auth_triplet;

		mmctx_timer_start(ctx, 3360);
		return gsm48_tx_gmm_auth_ciph_req(ctx, &at->vec, at->key_seq,
						  false);
	}

	if (ctx->auth_state == SGSN_AUTH_AUTHENTICATE && sgsn_mm_ctx_is_authenticated(ctx) &&
	    ctx->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL) {
		/* Check again for authorization */
		sgsn_auth_request(ctx);
		return 0;
	}

	if (ctx->auth_state != SGSN_AUTH_ACCEPTED) {
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "authorization is denied, aborting procedure\n");
		return -EACCES;
	}

	/* The MS is authorized */
#ifdef BUILD_IU
	if (ctx->ran_type == MM_CTX_T_UTRAN_Iu && !ctx->iu.ue_ctx->integrity_active) {
		/* Is any encryption above UEA0 enabled? */
		bool send_ck = sgsn->cfg.uea_encryption_mask > (1 << OSMO_UTRAN_UEA0);
		LOGMMCTXP(LOGL_DEBUG, ctx, "Iu Security Mode Command: %s encryption key (UEA encryption mask = 0x%x)\n",
			  send_ck ? "sending" : "not sending", sgsn->cfg.uea_encryption_mask);
		/* FIXME: we should send the set of allowed UEA, as in ranap_new_msg_sec_mod_cmd2(). However, this
		 * is not possible in the iu_client API. See OS#5487. */
		rc = ranap_iu_tx_sec_mode_cmd(ctx->iu.ue_ctx, &ctx->auth_triplet.vec, send_ck, ctx->iu.new_key);
		ctx->iu.new_key = 0;
		return rc;
	}
#endif

	switch (ctx->pending_req) {
	case 0:
		LOGMMCTXP(LOGL_INFO, ctx,
			  "no pending request, authorization completed\n");
		break;
	case GSM48_MT_GMM_ATTACH_REQ:
		ctx->pending_req = 0;

		extract_subscr_msisdn(ctx);
		extract_subscr_hlr(ctx);
#ifdef PTMSI_ALLOC
		/* Start T3350 and re-transmit up to 5 times until ATTACH COMPLETE */
		mmctx_timer_start(ctx, 3350);
		ctx->t3350_mode = GMM_T3350_MODE_ATT;
#else
		memset(&sig_data, 0, sizeof(sig_data));
		sig_data.mm = ctx;
		osmo_signal_dispatch(SS_SGSN, S_SGSN_ATTACH, &sig_data);
		osmo_fsm_inst_dispatch(ctx->gmm_fsm, E_GMM_ATTACH_SUCCESS, NULL);
#endif

		return gsm48_tx_gmm_att_ack(ctx);
#ifdef BUILD_IU
	case GSM48_MT_GMM_SERVICE_REQ:
		ctx->pending_req = 0;
		osmo_fsm_inst_dispatch(ctx->iu.mm_state_fsm, E_PMM_PS_CONN_ESTABLISH, NULL);
		rc = gsm48_tx_gmm_service_ack(ctx);

		if (ctx->iu.service.type != GPRS_SERVICE_T_SIGNALLING)
			activate_pdp_rabs(ctx);

		return rc;
#endif
	case GSM48_MT_GMM_RA_UPD_REQ:
		ctx->pending_req = 0;
		/* Send RA UPDATE ACCEPT */
		return gsm48_tx_gmm_ra_upd_ack(ctx);

	default:
		LOGMMCTXP(LOGL_ERROR, ctx,
			  "only Attach Request is supported yet, "
			  "got request type %u\n", ctx->pending_req);
		break;
	}

	return 0;
}

void gsm0408_gprs_authenticate(struct sgsn_mm_ctx *ctx)
{
	ctx->sec_ctx = OSMO_AUTH_TYPE_NONE;

	if (ctx->gmm_att_req.fsm->state != ST_INIT)
		osmo_fsm_inst_dispatch(ctx->gmm_att_req.fsm, E_VLR_ANSWERED, (void *) 0);
	else
		gsm48_gmm_authorize(ctx);
}

void gsm0408_gprs_access_granted(struct sgsn_mm_ctx *ctx)
{
	switch (ctx->gmm_fsm->state) {
	case ST_GMM_COMMON_PROC_INIT:
		LOGMMCTXP(LOGL_NOTICE, ctx,
		     "Authorized, continuing procedure, IMSI=%s\n",
		     ctx->imsi);
		/* Continue with the authorization */
		if (ctx->gmm_att_req.fsm->state != ST_INIT)
			osmo_fsm_inst_dispatch(ctx->gmm_att_req.fsm, E_VLR_ANSWERED, (void *) 0);
		break;
	default:
		LOGMMCTXP(LOGL_INFO, ctx,
		     "Authorized, ignored, IMSI=%s\n",
		     ctx->imsi);
	}
}

void gsm0408_gprs_access_denied(struct sgsn_mm_ctx *ctx, int gmm_cause)
{
	if (gmm_cause == SGSN_ERROR_CAUSE_NONE)
		gmm_cause = GMM_CAUSE_GPRS_NOTALLOWED;

	switch (ctx->gmm_fsm->state) {
	case ST_GMM_COMMON_PROC_INIT:
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "Not authorized, rejecting ATTACH REQUEST "
			  "with cause '%s' (%d)\n",
			  get_value_string(gsm48_gmm_cause_names, gmm_cause),
			  gmm_cause);
		if (ctx->gmm_att_req.fsm->state != ST_INIT)
			osmo_fsm_inst_dispatch(ctx->gmm_att_req.fsm, E_REJECT, (void *) (long) gmm_cause);
		break;
	case ST_GMM_REGISTERED_NORMAL:
	case ST_GMM_REGISTERED_SUSPENDED:
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "Authorization lost, detaching "
			  "with cause '%s' (%d)\n",
			  get_value_string(gsm48_gmm_cause_names, gmm_cause),
			  gmm_cause);
		gsm48_tx_gmm_detach_req(
			ctx, GPRS_DET_T_MT_IMSI, gmm_cause);

		mm_ctx_cleanup_free(ctx, "auth lost");
		break;
	default:
		LOGMMCTXP(LOGL_INFO, ctx,
			  "Authorization lost, cause is '%s' (%d)\n",
			  get_value_string(gsm48_gmm_cause_names, gmm_cause),
			  gmm_cause);
		mm_ctx_cleanup_free(ctx, "auth lost");
	}
}

void gsm0408_gprs_access_cancelled(struct sgsn_mm_ctx *ctx, int gmm_cause)
{
	if (gmm_cause != SGSN_ERROR_CAUSE_NONE) {
		LOGMMCTXP(LOGL_INFO, ctx,
			  "Cancelled with cause '%s' (%d), deleting context\n",
			  get_value_string(gsm48_gmm_cause_names, gmm_cause),
			  gmm_cause);
		gsm0408_gprs_access_denied(ctx, gmm_cause);
		return;
	}

	LOGMMCTXP(LOGL_INFO, ctx, "Cancelled, deleting context silently\n");
	mm_ctx_cleanup_free(ctx, "access cancelled");
}

/* Parse Chapter 9.4.13 Identity Response */
static int gsm48_rx_gmm_id_resp(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	long mi_typel;
	char mi_log_string[32];
	struct osmo_mobile_identity mi;

	if (!ctx) {
		DEBUGP(DMM, "from unknown TLLI 0x%08x?!? This should not happen\n", msgb_tlli(msg));
		return -EINVAL;
	}

	if (osmo_mobile_identity_decode(&mi, &gh->data[1], gh->data[0], false)) {
		LOGMMCTXP(LOGL_ERROR, ctx, "-> GMM IDENTITY RESPONSE: cannot decode Mobile Identity\n");
		return -EINVAL;
	}
	osmo_mobile_identity_to_str_buf(mi_log_string, sizeof(mi_log_string), &mi);

	LOGMMCTXP(LOGL_DEBUG, ctx, "-> GMM IDENTITY RESPONSE: MI=%s\n", mi_log_string);

	if (ctx->t3370_id_type == GSM_MI_TYPE_NONE) {
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "Got unexpected IDENTITY RESPONSE: MI=%s, "
			  "ignoring message\n",
			  mi_log_string);
		return -EINVAL;
	}

	if (mi.type == ctx->t3370_id_type)
		mmctx_timer_stop(ctx, 3370);

	switch (mi.type) {
	case GSM_MI_TYPE_IMSI:
		/* we already have a mm context with current TLLI, but no
		 * P-TMSI / IMSI yet.  What we now need to do is to fill
		 * this initial context with data from the HLR */
		if (strlen(ctx->imsi) == 0) {
			/* Check if we already have a MM context for this IMSI */
			struct sgsn_mm_ctx *ictx;
			ictx = sgsn_mm_ctx_by_imsi(mi.imsi);
			if (ictx) {
				/* Handle it like in gsm48_rx_gmm_det_req,
				 * except that no messages are sent to the BSS */

				LOGMMCTXP(LOGL_NOTICE, ctx, "Deleting old MM Context for same IMSI "
				       "p_tmsi_old=0x%08x\n",
					ictx->p_tmsi);

				mm_ctx_cleanup_free(ictx, "GMM IMSI re-use");
			}
		}
		OSMO_STRLCPY_ARRAY(ctx->imsi, mi.imsi);
		break;
	case GSM_MI_TYPE_IMEI:
		OSMO_STRLCPY_ARRAY(ctx->imei, mi.imei);
		break;
	case GSM_MI_TYPE_IMEISV:
		break;
	}

	/* Check if we can let the mobile station enter */
	mi_typel = mi.type;
	return osmo_fsm_inst_dispatch(ctx->gmm_att_req.fsm, E_IDEN_RESP_RECV, (void *)mi_typel);
}

/* Allocate a new P-TMSI and change context state */
static inline void ptmsi_update(struct sgsn_mm_ctx *ctx)
{
	uint32_t ptmsi;
	/* Don't change the P-TMSI if a P-TMSI re-assignment is under way */
	if (ctx->gmm_fsm->state != ST_GMM_COMMON_PROC_INIT) {
		ptmsi = sgsn_alloc_ptmsi();
		if (ptmsi != GSM_RESERVED_TMSI) {
			ctx->p_tmsi_old = ctx->p_tmsi;
			ctx->p_tmsi = ptmsi;
		} else
			LOGMMCTXP(LOGL_ERROR, ctx, "P-TMSI allocation failure: using old one.\n");
	}
	osmo_fsm_inst_dispatch(ctx->gmm_fsm, E_GMM_COMMON_PROC_INIT_REQ, NULL);
}

/* Detect if RAT has changed */
static bool mmctx_did_rat_change(struct sgsn_mm_ctx *mmctx, struct msgb *msg)
{
	if (MSG_IU_UE_CTX(msg) && mmctx->ran_type != MM_CTX_T_UTRAN_Iu)
		return true;
	if (!MSG_IU_UE_CTX(msg) && mmctx->ran_type != MM_CTX_T_GERAN_Gb)
		return true;
	return false;
}

/* Notify the FSM of a RAT change */
static void mmctx_handle_rat_change(struct sgsn_mm_ctx *mmctx, struct msgb *msg, struct gprs_llc_llme *llme)
{
	struct gmm_rat_change_data rat_chg = {
		.llme = llme
	};

	rat_chg.new_ran_type = MSG_IU_UE_CTX(msg) ? MM_CTX_T_UTRAN_Iu : MM_CTX_T_GERAN_Gb;

	if (rat_chg.new_ran_type != mmctx->ran_type)
		osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_RAT_CHANGE, (void *) &rat_chg);
	else
		LOGMMCTXP(LOGL_ERROR, mmctx, "RAT didn't change or not implemented (ran_type=%u, "
				"msg_iu_ue_ctx=%p\n", mmctx->ran_type, MSG_IU_UE_CTX(msg));

}

static uint8_t gprs_ms_net_cap_gea_mask(const uint8_t *ms_net_cap, uint8_t cap_len)
{
	uint8_t mask = (1 << GPRS_ALGO_GEA0);
	mask |= (0x80 & ms_net_cap[0]) ? (1 << GPRS_ALGO_GEA1) : 0;

	if (cap_len < 2)
		return mask;

	/* extended GEA bits start from 2nd bit of the next byte */
	mask |= (0x40 & ms_net_cap[1]) ? (1 << GPRS_ALGO_GEA2) : 0;
	mask |= (0x20 & ms_net_cap[1]) ? (1 << GPRS_ALGO_GEA3) : 0;
	mask |= (0x10 & ms_net_cap[1]) ? (1 << GPRS_ALGO_GEA4) : 0;
	return mask;
}

/* 3GPP TS 24.008 § 9.4.1 Attach request */
static int gsm48_rx_gmm_att_req(struct sgsn_mm_ctx *ctx, struct msgb *msg,
				struct gprs_llc_llme *llme)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t *cur = gh->data, *msnc, *mi_data, *ms_ra_acc_cap;
	uint8_t msnc_len, att_type, mi_len, ms_ra_acc_cap_len;
	uint16_t drx_par;
	char mi_log_string[32];
	struct osmo_routing_area_id ra_id;
	uint16_t cid = 0;
	enum gsm48_gmm_cause reject_cause;
	struct osmo_mobile_identity mi;
	int rc;

	LOGMMCTXP(LOGL_INFO, ctx, "-> GMM ATTACH REQUEST ");
	rate_ctr_inc(rate_ctr_group_get_ctr(sgsn->rate_ctrs, CTR_GPRS_ATTACH_REQUEST));

	/* As per TS 04.08 Chapter 4.7.1.4, the attach request arrives either
	 * with a foreign TLLI (P-TMSI that was allocated to the MS before),
	 * or with random TLLI. */

	if (!MSG_IU_UE_CTX(msg)) {
		/* Gb mode */
		bssgp_parse_cell_id2(&ra_id, &cid, msgb_bcid(msg), 8);
	} else {
#ifdef BUILD_IU
		gprs_rai_to_osmo(&ra_id, &MSG_IU_UE_CTX(msg)->ra_id);
#else
		LOGMMCTXP(LOGL_ERROR, ctx, "Cannot handle Iu Attach Request, built without Iu support\n");
		return -ENOTSUP;
#endif
	}

	/* MS network capability 10.5.5.12 */
	msnc_len = *cur++;
	msnc = cur;
	if (msnc_len > sizeof(ctx->ms_network_capa.buf))
		goto err_inval;
	cur += msnc_len;

	/* TODO: In iu mode - handle follow-on request.
	 * The follow-on request can be signaled in an Attach Request on IuPS.
	 * This means the MS/UE asks to keep the PS connection open for further requests
	 * after the Attach Request succeed.
	 * The SGSN can decide if it close the connection or not. Both are spec conform. */

	/* aTTACH Type 10.5.5.2 */
	att_type = *cur++ & 0x07;

	/* DRX parameter 10.5.5.6 */
	drx_par = *cur++ << 8;
	drx_par |= *cur++;

	/* Mobile Identity (P-TMSI or IMSI) 10.5.1.4 */
	mi_len = *cur++;
	mi_data = cur;
	cur += mi_len;

	rc = osmo_mobile_identity_decode(&mi, mi_data, mi_len, false);
	if (rc)
		goto err_inval;
	osmo_mobile_identity_to_str_buf(mi_log_string, sizeof(mi_log_string), &mi);

	DEBUGPC(DMM, "MI(%s) type=\"%s\" ", mi_log_string,
		get_value_string(gprs_att_t_strs, att_type));

	/* Old routing area identification 10.5.5.15. Skip it */
	cur += 6;

	/* MS Radio Access Capability 10.5.5.12a */
	ms_ra_acc_cap_len = *cur++;
	ms_ra_acc_cap = cur;
	if (ms_ra_acc_cap_len > sizeof(ctx->ms_radio_access_capa.buf))
		goto err_inval;
	cur += ms_ra_acc_cap_len;

	LOGPC(DMM, LOGL_INFO, "\n");

	/* Optional: Old P-TMSI Signature, Requested READY timer, TMSI Status */

	switch (mi.type) {
	case GSM_MI_TYPE_IMSI:
		/* Try to find MM context based on IMSI */
		if (!ctx)
			ctx = sgsn_mm_ctx_by_imsi(mi.imsi);
		if (!ctx) {
			if (MSG_IU_UE_CTX(msg))
				ctx = sgsn_mm_ctx_alloc_iu(MSG_IU_UE_CTX(msg));
			else
				ctx = sgsn_mm_ctx_alloc_gb(0, &ra_id);
			if (!ctx) {
				reject_cause = GMM_CAUSE_NET_FAIL;
				goto rejected;
			}
			OSMO_STRLCPY_ARRAY(ctx->imsi, mi.imsi);
		}
		break;
	case GSM_MI_TYPE_TMSI:
		/* Try to find MM context based on P-TMSI */
		if (!ctx)
			ctx = sgsn_mm_ctx_by_ptmsi(mi.tmsi);
		if (!ctx) {
			/* Allocate a context as most of our code expects one.
			 * Context will not have an IMSI ultil ID RESP is received */
			if (MSG_IU_UE_CTX(msg))
				ctx = sgsn_mm_ctx_alloc_iu(MSG_IU_UE_CTX(msg));
			else
				ctx = sgsn_mm_ctx_alloc_gb(msgb_tlli(msg), &ra_id);
			if (!ctx) {
				reject_cause = GMM_CAUSE_NET_FAIL;
				goto rejected;
			}
			ctx->p_tmsi = mi.tmsi;
		}
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, ctx, "Rejecting ATTACH REQUEST with "
			"MI %s\n", mi_log_string);
		reject_cause = GMM_CAUSE_MS_ID_NOT_DERIVED;
		goto rejected;
	}

	if (mmctx_did_rat_change(ctx, msg))
		mmctx_handle_rat_change(ctx, msg, llme);

	if (ctx->ran_type == MM_CTX_T_GERAN_Gb) {
		ctx->gb.tlli = msgb_tlli(msg);
		ctx->gb.llme = llme;
	}
	msgid2mmctx(ctx, msg);
	/* Update MM Context with currient RA and Cell ID */
	ctx->ra = ra_id;
	if (ctx->ran_type == MM_CTX_T_GERAN_Gb)
		ctx->gb.cell_id = cid;

	/* Update MM Context with other data */
	ctx->drx_parms = drx_par;
	ctx->ms_radio_access_capa.len = ms_ra_acc_cap_len;
	memcpy(ctx->ms_radio_access_capa.buf, ms_ra_acc_cap,
		ctx->ms_radio_access_capa.len);
	ctx->ms_network_capa.len = msnc_len;
	memcpy(ctx->ms_network_capa.buf, msnc, msnc_len);

	ctx->ue_cipher_mask = gprs_ms_net_cap_gea_mask(ctx->ms_network_capa.buf, msnc_len);

	if (!(ctx->ue_cipher_mask & sgsn->cfg.gea_encryption_mask)) {
		reject_cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
		LOGMMCTXP(LOGL_NOTICE, ctx, "Rejecting ATTACH REQUEST with MI "
			  "%s because MS do not support required encryption, mask UE:0x%02x NW:0x%02x \n",
				  mi_log_string, ctx->ue_cipher_mask, sgsn->cfg.gea_encryption_mask);
		goto rejected;
	}

	/* just assume that everythig is fine if the phone offers a5/4:
	 * it requires a valid umts security context which we can only have after
	 * 1) IDENTITY REQUEST to know what to ask the HLR for
	 * 2) and AUTHENTICATION AND CIPHERING REQUEST
	 * ... but 2) already requires selecting a cipher mode.
	 * So let's just assume we will have the auth data required to make it work.
	 */

	ctx->ciph_algo = gprs_ms_net_select_best_gea(ctx->ue_cipher_mask, sgsn->cfg.gea_encryption_mask);

#ifdef PTMSI_ALLOC
	/* Allocate a new P-TMSI (+ P-TMSI signature) and update TLLI */
	ptmsi_update(ctx);
#endif

	if (ctx->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Even if there is no P-TMSI allocated, the MS will
		 * switch from foreign TLLI to local TLLI */
		ctx->gb.tlli_new = gprs_tmsi2tlli(ctx->p_tmsi, TLLI_LOCAL);

		/* Inform LLC layer about new TLLI but keep old active */
		if (sgsn_mm_ctx_is_authenticated(ctx))
			gprs_llme_copy_key(ctx, ctx->gb.llme);

		gprs_llgmm_assign(ctx->gb.llme, ctx->gb.tlli, ctx->gb.tlli_new);
	}

	osmo_fsm_inst_dispatch(ctx->gmm_att_req.fsm, E_ATTACH_REQ_RECV, msg);
	return 0;

err_inval:
	LOGPC(DMM, LOGL_INFO, "\n");
	reject_cause = GMM_CAUSE_SEM_INCORR_MSG;

rejected:
	/* Send ATTACH REJECT */
	LOGMMCTXP(LOGL_NOTICE, ctx,
		  "Rejecting Attach Request with cause '%s' (%d)\n",
		  get_value_string(gsm48_gmm_cause_names, reject_cause), reject_cause);
	rc = gsm48_tx_gmm_att_rej_oldmsg(msg, reject_cause);
	if (ctx)
		mm_ctx_cleanup_free(ctx, "GMM ATTACH REJ");
	else if (llme)
		gprs_llgmm_unassign(llme);

	return rc;

}

/* 3GPP TS 24.008 § 9.4.3 Attach complete */
static int gsm48_rx_gmm_att_compl(struct sgsn_mm_ctx *mmctx)
{
	struct sgsn_signal_data sig_data;
	/* only in case SGSN offered new P-TMSI */
	LOGMMCTXP(LOGL_INFO, mmctx, "-> GMM ATTACH COMPLETE\n");

#ifdef BUILD_IU
	if (mmctx->iu.ue_ctx) {
		ranap_iu_tx_release(mmctx->iu.ue_ctx, NULL);
	}
#endif

	mmctx_timer_stop(mmctx, 3350);
	mmctx->t3350_mode = GMM_T3350_MODE_NONE;
	mmctx->p_tmsi_old = 0;
	mmctx->pending_req = 0;
	osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_ATTACH_SUCCESS, NULL);
	switch(mmctx->ran_type) {
	case MM_CTX_T_UTRAN_Iu:
		osmo_fsm_inst_dispatch(mmctx->iu.mm_state_fsm, E_PMM_PS_ATTACH, NULL);
		break;
	case MM_CTX_T_GERAN_Gb:
		/* Unassign the old TLLI */
		mmctx->gb.tlli = mmctx->gb.tlli_new;
		gprs_llme_copy_key(mmctx, mmctx->gb.llme);
		gprs_llgmm_assign(mmctx->gb.llme, TLLI_UNASSIGNED,
				  mmctx->gb.tlli_new);
		osmo_fsm_inst_dispatch(mmctx->gb.mm_state_fsm, E_MM_GPRS_ATTACH, NULL);
		break;
	}

	osmo_fsm_inst_dispatch(mmctx->gmm_att_req.fsm, E_ATTACH_COMPLETE_RECV, 0);
	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.mm = mmctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_ATTACH, &sig_data);

	return 0;
}

/* Checks if two attach request contain the IEs and IE values
 * return 0 if equal
 * return -1 if error
 * return 1 if unequal
 *
 * Only do a simple memcmp for now.
 */
int gprs_gmm_attach_req_ies(struct msgb *a, struct msgb *b)
{
	struct gsm48_hdr *gh_a = (struct gsm48_hdr *) msgb_gmmh(a);
	struct gsm48_hdr *gh_b = (struct gsm48_hdr *) msgb_gmmh(b);

#define GMM_ATTACH_REQ_LEN 26

	/* there is the LLC FCS behind */
	if (msgb_l3len(a) < GMM_ATTACH_REQ_LEN || msgb_l3len(b) < GMM_ATTACH_REQ_LEN)
		return -1;

	return !!memcmp(gh_a, gh_b, GMM_ATTACH_REQ_LEN);
}

/* 3GPP TS 24.008 § 4.7.4.1 / 9.4.5.2 MO Detach request */
static int gsm48_rx_gmm_det_req(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t detach_type, power_off;
	int rc = 0;

	detach_type = gh->data[0] & 0x7;
	power_off = gh->data[0] & 0x8;

	/* FIXME: In 24.008 there is an optional P-TMSI and P-TMSI signature IE */
	rate_ctr_inc(rate_ctr_group_get_ctr(sgsn->rate_ctrs, CTR_GPRS_DETACH_REQUEST));
	LOGMMCTXP(LOGL_INFO, ctx, "-> GMM DETACH REQUEST TLLI=0x%08x type=%s %s\n",
		msgb_tlli(msg), get_value_string(gprs_det_t_mo_strs, detach_type),
		power_off ? "Power-off" : "");

	/* Only send the Detach Accept (MO) if power off isn't indicated,
	 * see 04.08, 4.7.4.1.2/3 for details */
	if (!power_off) {
		/* force_stby = 0 */
		if (ctx)
			rc = gsm48_tx_gmm_det_ack(ctx, 0);
		else
			rc = gsm48_tx_gmm_det_ack_oldmsg(msg, 0);
	}

	if (ctx) {
		struct sgsn_signal_data sig_data;
		memset(&sig_data, 0, sizeof(sig_data));
		sig_data.mm = ctx;
		osmo_signal_dispatch(SS_SGSN, S_SGSN_DETACH, &sig_data);
		mm_ctx_cleanup_free(ctx, "GMM DETACH REQUEST");
	}

	return rc;
}

/* Chapter 9.4.15: Routing area update accept */
static int gsm48_tx_gmm_ra_upd_ack(struct sgsn_mm_ctx *mm)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 UPD ACK");
	struct gsm48_hdr *gh;
	struct gsm48_ra_upd_ack *rua;
	unsigned long t;
#ifdef PTMSI_ALLOC
	uint8_t *l;
	int rc;
	struct osmo_mobile_identity mi;
#endif

	rate_ctr_inc(rate_ctr_group_get_ctr(sgsn->rate_ctrs, CTR_GPRS_ROUTING_AREA_ACKED));
	LOGMMCTXP(LOGL_INFO, mm, "<- GMM ROUTING AREA UPDATE ACCEPT\n");

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_ACK;

	rua = (struct gsm48_ra_upd_ack *) msgb_put(msg, sizeof(*rua));
	rua->force_stby = 0;	/* not indicated */
	rua->upd_result = 0;	/* RA updated */

	/* Periodic RA update timer */
	t = osmo_tdef_get(sgsn->cfg.T_defs, 3312, OSMO_TDEF_S, -1);
	rua->ra_upd_timer = gprs_secs_to_tmr_floor(t);

	osmo_routing_area_id_encode_buf((uint8_t *)&rua->ra_id, sizeof(struct gsm48_ra_id), &mm->ra);

#if 0
	/* Optional: P-TMSI signature */
	msgb_v_put(msg, GSM48_IE_GMM_PTMSI_SIG);
	ptsig = msgb_put(msg, 3);
	ptsig[0] = mm->p_tmsi_sig >> 16;
	ptsig[1] = mm->p_tmsi_sig >> 8;
	ptsig[2] = mm->p_tmsi_sig & 0xff;
#endif

#ifdef PTMSI_ALLOC
	/* Optional: Allocated P-TMSI */
	mi = (struct osmo_mobile_identity){
		.type = GSM_MI_TYPE_TMSI,
		.tmsi = mm->p_tmsi,
	};
	l = msgb_tl_put(msg, GSM48_IE_GMM_ALLOC_PTMSI);
	rc = osmo_mobile_identity_encode_msgb(msg, &mi, false);
	if (rc < 0) {
		msgb_free(msg);
		return -EINVAL;
	}
	*l = rc;
#endif
	/* MS identity */
	/* List of Received N-PDU */

	/* Optional: Negotiated READY timer value */
	t = osmo_tdef_get(sgsn->cfg.T_defs, 3314, OSMO_TDEF_S, -1);
	msgb_tv_put(msg, GSM48_IE_GMM_TIMER_READY, gprs_secs_to_tmr_floor(t));

	/* GMM cause */
	/* PDP Context Status */
	uint16_t pdp_ctx_status = encode_ms_ctx_status(mm);
	msgb_tlv_put(msg, GSM48_IE_GMM_PDP_CTX_STATUS, 2, (uint8_t *) &pdp_ctx_status);

	/* MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}

/* Chapter 9.4.17: Routing area update reject */
int gsm48_tx_gmm_ra_upd_rej(struct msgb *old_msg, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 RA UPD REJ");
	struct gsm48_hdr *gh;

	LOGP(DMM, LOGL_NOTICE, "<- ROUTING AREA UPDATE REJECT\n");
	rate_ctr_inc(rate_ctr_group_get_ctr(sgsn->rate_ctrs, CTR_GPRS_ROUTING_AREA_REJECT));

	gmm_copy_id(msg, old_msg);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 2);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_REJ;
	gh->data[0] = cause;
	gh->data[1] = 0; /* ? */

	/* Option: P-TMSI signature, allocated P-TMSI, MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0, NULL, false);
}

/* Chapter 9.4.14: Routing area update request */
static int gsm48_rx_gmm_ra_upd_req(struct sgsn_mm_ctx *mmctx, struct msgb *msg,
				   struct gprs_llc_llme *llme)
{
#ifndef PTMSI_ALLOC
	struct sgsn_signal_data sig_data;
#endif
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t *cur = gh->data;
	uint8_t ms_ra_acc_cap_len;
	struct osmo_routing_area_id old_ra_id;
	struct tlv_parsed tp;
	uint8_t upd_type;
	enum gsm48_gmm_cause reject_cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
	int rc;

	/* TODO: In iu mode - handle follow-on request.
	 * The follow-on request can be signaled in an Attach Request on IuPS.
	 * This means the MS/UE asks to keep the PS connection open for further requests
	 * after the Attach Request succeed.
	 * The SGSN can decide if it close the connection or not. Both are spec conform. */

	/* Update Type 10.5.5.18 */
	upd_type = *cur++ & 0x07;

	rate_ctr_inc(rate_ctr_group_get_ctr(sgsn->rate_ctrs, CTR_GPRS_ROUTING_AREA_REQUEST));
	LOGMMCTXP(LOGL_INFO, mmctx, "-> GMM RA UPDATE REQUEST type=\"%s\"\n",
		get_value_string(gprs_upd_t_strs, upd_type));

	/* Old routing area identification 10.5.5.15 */
	osmo_routing_area_id_decode(&old_ra_id, cur, msgb_l3len(msg) - (cur - msgb_gmmh(msg)));
	cur += 6;

	/* MS Radio Access Capability 10.5.5.12a */
	ms_ra_acc_cap_len = *cur++;
	if (ms_ra_acc_cap_len > 52) {
		LOGMMCTXP(LOGL_ERROR, mmctx,
		     "Rejecting GMM RA Update Request: MS Radio Access Capability too long"
		     " (ms_ra_acc_cap_len = %u > 52)\n", ms_ra_acc_cap_len);
		reject_cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
		goto rejected;
	}
	cur += ms_ra_acc_cap_len;

	/* Optional: Old P-TMSI Signature, Requested READY timer, TMSI Status,
	 * DRX parameter, MS network capability */
	tlv_parse(&tp, &gsm48_gmm_att_tlvdef, cur,
			(msg->data + msg->len) - cur, 0, 0);

	switch (upd_type) {
	case GPRS_UPD_T_RA_LA:
	case GPRS_UPD_T_RA_LA_IMSI_ATT:
		LOGMMCTXP(LOGL_NOTICE, mmctx, "Update type %i unsupported in Mode III, is your SI13 corrupt?\n", upd_type);
		reject_cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
		goto rejected;
	case GPRS_UPD_T_RA:
	case GPRS_UPD_T_PERIODIC:
		break;
	}

	if (!mmctx) {
		/* BSSGP doesn't give us an mmctx */

		/* TODO: Check if there is an MM CTX with old_ra_id and
		 * the P-TMSI (if given, reguired for UMTS) or as last resort
		 * if the TLLI matches foreign_tlli (P-TMSI). Note that this
		 * is an optimization to avoid the RA reject (impl detached)
		 * below, which will cause a new attach cycle. */
		/* Look-up the MM context based on old RA-ID and TLLI */
		if (!MSG_IU_UE_CTX(msg)) {
			/* Gb */
			mmctx = sgsn_mm_ctx_by_tlli_and_ptmsi(msgb_tlli(msg), &old_ra_id);
		} else if (TLVP_PRESENT(&tp, GSM48_IE_GMM_ALLOC_PTMSI)) {
#ifdef BUILD_IU
			/* In Iu mode search only for ptmsi */
			struct osmo_mobile_identity mi;
			if (osmo_mobile_identity_decode(&mi, TLVP_VAL(&tp, GSM48_IE_GMM_ALLOC_PTMSI),
							TLVP_LEN(&tp, GSM48_IE_GMM_ALLOC_PTMSI), false)
			    || mi.type != GSM_MI_TYPE_TMSI) {
				LOGIUP(MSG_IU_UE_CTX(msg), LOGL_ERROR, "Cannot decode P-TMSI\n");
				goto rejected;
			}
			mmctx = sgsn_mm_ctx_by_ptmsi(mi.tmsi);
#else
			LOGIUP(MSG_IU_UE_CTX(msg), LOGL_ERROR,
			       "Rejecting GMM RA Update Request: No Iu support\n");
			goto rejected;
#endif
		}
		if (mmctx) {
			LOGMMCTXP(LOGL_INFO, mmctx,
				"Looked up by matching TLLI and P_TMSI. "
				"BSSGP TLLI: %08x, P-TMSI: %08x (%08x), "
				"TLLI: %08x (%08x), RA: %s\n",
				msgb_tlli(msg),
				mmctx->p_tmsi, mmctx->p_tmsi_old,
				mmctx->gb.tlli, mmctx->gb.tlli_new,
				osmo_rai_name2(&mmctx->ra));
			/* A RAT change will trigger the common procedure
			 * below after handling the RAT change. Protect it
			 * here from being called twice */
			if (!mmctx_did_rat_change(mmctx, msg))
				osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_COMMON_PROC_INIT_REQ, NULL);

		}
	} else if (osmo_rai_cmp(&mmctx->ra, &old_ra_id) ||
		mmctx->gmm_fsm->state == ST_GMM_DEREGISTERED)
	{
		/* We've received either a RAU for a MS which isn't registered
		 * or a RAU with an unknown RA ID. As long the SGSN doesn't support
		 * PS handover we treat this as invalid RAU */
		struct osmo_routing_area_id new_ra_id = {};
		char new_ra[32];

		bssgp_parse_cell_id2(&new_ra_id, NULL, msgb_bcid(msg), 8);
		osmo_rai_name2_buf(new_ra, sizeof(new_ra), &new_ra_id);

		if (mmctx->gmm_fsm->state == ST_GMM_DEREGISTERED)
			LOGMMCTXP(LOGL_INFO, mmctx,
				  "Rejecting RAU - GMM state is deregistered. Old RA: %s New RA: %s\n",
				  osmo_rai_name2(&old_ra_id), new_ra);
		else
			LOGMMCTXP(LOGL_INFO, mmctx,
				  "Rejecting RAU - Old RA doesn't match MM. Old RA: %s New RA: %s\n",
				  osmo_rai_name2(&old_ra_id), new_ra);

		reject_cause = GMM_CAUSE_IMPL_DETACHED;
		goto rejected;
	}

	if (!mmctx) {
		if (llme) {
			/* send a XID reset to re-set all LLC sequence numbers
			 * in the MS */
			LOGGBP(llme, DMM, LOGL_NOTICE, "LLC XID RESET\n");
			gprs_llgmm_reset_oldmsg(msg, GPRS_SAPI_GMM, llme);

			/* The RAU didn't come from expected TLLI+RAI, so it's for sure bad and should be rejected.
			 * In any case, before unassigning (freeing) the LLME during the REJECT below, make sure
			 * beforehand that if there's an mmctx relating to that llme it is also freed.
			 * Otherwise it would be kept pointining at a dangling freed llme object.
			 */
			mmctx = sgsn_mm_ctx_by_llme(llme);
			if (mmctx) {
				char old_ra_id_name[32];
				osmo_rai_name2_buf(old_ra_id_name, sizeof(old_ra_id_name), &old_ra_id);
				LOGMMCTXP(LOGL_NOTICE, mmctx,
					  "Rx RA Update Request with unexpected TLLI=%08x Old RA=%s (expected Old RA: %s)!\n",
					  msgb_tlli(msg), old_ra_id_name, osmo_rai_name2(&mmctx->ra));
				/* mmctx will be released (and its llme un assigned) after REJECT below. */
			}
		}
		/* The MS has to perform GPRS attach */
		/* Device is still IMSI attached for CS but initiate GPRS ATTACH,
		 * see GSM 04.08, 4.7.5.1.4 and G.6 */
		LOGGBIUP(llme, msg, LOGL_ERROR, "Rejecting GMM RA Update Request: MS should GMM Attach first\n");
		reject_cause = GMM_CAUSE_IMPL_DETACHED;
		goto rejected;
	}

	if (mmctx_did_rat_change(mmctx, msg)) {
		mmctx_handle_rat_change(mmctx, msg, llme);
		osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_COMMON_PROC_INIT_REQ, NULL);
	}

	/* Store new BVCI/NSEI in MM context (FIXME: delay until we ack?) */
	msgid2mmctx(mmctx, msg);
	/* Bump the statistics of received signalling msgs for this MM context */
	rate_ctr_inc(rate_ctr_group_get_ctr(mmctx->ctrg, GMM_CTR_PKTS_SIG_IN));

	/* Update the MM context with the new RA-ID */
	if (mmctx->ran_type == MM_CTX_T_GERAN_Gb && msgb_bcid(msg)) {
		bssgp_parse_cell_id2(&mmctx->ra, NULL, msgb_bcid(msg), 8);
		/* Update the MM context with the new (i.e. foreign) TLLI */
		mmctx->gb.tlli = msgb_tlli(msg);
	}
	/* Update the MM context with the new DRX params */
	if (TLVP_PRESENT(&tp, GSM48_IE_GMM_DRX_PARAM))
		memcpy(&mmctx->drx_parms, TLVP_VAL(&tp, GSM48_IE_GMM_DRX_PARAM), sizeof(mmctx->drx_parms));

	/* FIXME: Update the MM context with the MS radio acc capabilities */
	/* FIXME: Update the MM context with the MS network capabilities */

	rate_ctr_inc(rate_ctr_group_get_ctr(mmctx->ctrg, GMM_CTR_RA_UPDATE));

#ifdef PTMSI_ALLOC
	ptmsi_update(mmctx);

	/* Start T3350 and re-transmit up to 5 times until ATTACH COMPLETE */
	mmctx->t3350_mode = GMM_T3350_MODE_RAU;
	mmctx_timer_start(mmctx, 3350);
#else
	/* Make sure we are NORMAL (i.e. not SUSPENDED anymore) */
	osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_ATTACH_SUCCESS, NULL);

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.mm = mmctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_UPDATE, &sig_data);
#endif
	if (mmctx->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Even if there is no P-TMSI allocated, the MS will switch from
	 	* foreign TLLI to local TLLI */
		mmctx->gb.tlli_new = gprs_tmsi2tlli(mmctx->p_tmsi, TLLI_LOCAL);

		/* Inform LLC layer about new TLLI but keep accepting the old one during Rx */
		gprs_llgmm_assign(mmctx->gb.llme, mmctx->gb.tlli,
				  mmctx->gb.tlli_new);
	}

	/* Look at PDP Context Status IE and see if MS's view of
	 * activated/deactivated NSAPIs agrees with our view */
	if (TLVP_PRESENT(&tp, GSM48_IE_GMM_PDP_CTX_STATUS)) {
		uint16_t pdp_status = osmo_load16le(TLVP_VAL(&tp, GSM48_IE_GMM_PDP_CTX_STATUS));
		process_ms_ctx_status(mmctx, pdp_status);
	}

	/* Send RA UPDATE ACCEPT. In Iu, the RA upd request can be called from
	 * a new Iu connection, so we might need to re-authenticate the
	 * connection as well as turn on integrity protection. */
	mmctx->pending_req = GSM48_MT_GMM_RA_UPD_REQ;
	return gsm48_gmm_authorize(mmctx);

rejected:
	/* Send RA UPDATE REJECT */
	LOGMMCTXP(LOGL_NOTICE, mmctx,
		  "Rejecting RA Update Request with cause '%s' (%d)\n",
		  get_value_string(gsm48_gmm_cause_names, reject_cause), reject_cause);
	rc = gsm48_tx_gmm_ra_upd_rej(msg, reject_cause);
	if (mmctx)
		mm_ctx_cleanup_free(mmctx, "GMM RA UPDATE REJ");
	else if (llme)
		gprs_llgmm_unassign(llme);
#ifdef BUILD_IU
	else if (MSG_IU_UE_CTX(msg)) {
		unsigned long X1001 = osmo_tdef_get(sgsn->cfg.T_defs, -1001, OSMO_TDEF_S, -1);
		ranap_iu_tx_release_free(MSG_IU_UE_CTX(msg), NULL, (int) X1001);
	}
#endif

	return rc;
}

/* 3GPP TS 24.008 § 9.4.16: Routing area update complete */
static int gsm48_rx_gmm_ra_upd_compl(struct sgsn_mm_ctx *mmctx)
{
	struct sgsn_signal_data sig_data;
	/* only in case SGSN offered new P-TMSI */
	LOGMMCTXP(LOGL_INFO, mmctx, "-> ROUTING AREA UPDATE COMPLETE\n");
	mmctx_timer_stop(mmctx, 3350);
	mmctx->t3350_mode = GMM_T3350_MODE_NONE;
	mmctx->p_tmsi_old = 0;
	mmctx->pending_req = 0;
	osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_COMMON_PROC_SUCCESS, NULL);
	switch(mmctx->ran_type) {
	case MM_CTX_T_UTRAN_Iu:
		osmo_fsm_inst_dispatch(mmctx->iu.mm_state_fsm, E_PMM_RA_UPDATE, NULL);
		break;
	case MM_CTX_T_GERAN_Gb:
		/* Unassign the old TLLI */
		mmctx->gb.tlli = mmctx->gb.tlli_new;
		gprs_llgmm_assign(mmctx->gb.llme, TLLI_UNASSIGNED,
				  mmctx->gb.tlli_new);
		osmo_fsm_inst_dispatch(mmctx->gb.mm_state_fsm, E_MM_RA_UPDATE, NULL);
		break;
	}

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.mm = mmctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_UPDATE, &sig_data);

	return 0;
}

/* 3GPP TS 24.008 § 9.4.8: P-TMSI reallocation complete */
static int gsm48_rx_gmm_ptmsi_reall_compl(struct sgsn_mm_ctx *mmctx)
{
	LOGMMCTXP(LOGL_INFO, mmctx, "-> PTMSI REALLOCATION COMPLETE\n");
	mmctx_timer_stop(mmctx, 3350);
	mmctx->t3350_mode = GMM_T3350_MODE_NONE;
	mmctx->p_tmsi_old = 0;
	mmctx->pending_req = 0;
	if (mmctx->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Unassign the old TLLI */
		mmctx->gb.tlli = mmctx->gb.tlli_new;
		//gprs_llgmm_assign(mmctx->gb.llme, TLLI_UNASSIGNED, mmctx->gb.tlli_new, GPRS_ALGO_GEA0, NULL);
	}
	return 0;
}

/* 3GPP TS 24.008 § 9.4.20 Service request.
 * In Iu, a UE in PMM-IDLE mode can use GSM48_MT_GMM_SERVICE_REQ to switch back
 * to PMM-CONNECTED mode. */
static int gsm48_rx_gmm_service_req(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t *cur = gh->data, *mi_data;
	uint8_t service_type, mi_len;
	struct tlv_parsed tp;
	struct osmo_mobile_identity mi;
	char mi_log_string[32];
	enum gsm48_gmm_cause reject_cause;
	int rc;

	LOGMMCTXP(LOGL_INFO, ctx, "-> GMM SERVICE REQUEST ");

	/* This message is only valid in Iu mode */
	if (!MSG_IU_UE_CTX(msg)) {
		LOGPC(DMM, LOGL_INFO, "Invalid if not in Iu mode\n");
		return -1;
	}

	/* Skip Ciphering key sequence number 10.5.1.2 */
	/* uint8_t ciph_seq_nr = *cur & 0x07; */

	/* Service type 10.5.5.20 */
	service_type = (*cur++ >> 4) & 0x07;

	/* Mobile Identity (P-TMSI or IMSI) 10.5.1.4 */
	mi_len = *cur++;
	mi_data = cur;
	cur += mi_len;
	rc = osmo_mobile_identity_decode(&mi, mi_data, mi_len, false);
	if (rc)
		goto err_inval;
	osmo_mobile_identity_to_str_buf(mi_log_string, sizeof(mi_log_string), &mi);

	DEBUGPC(DMM, "MI(%s) type=\"%s\" ", mi_log_string,
		get_value_string(gprs_service_t_strs, service_type));

	LOGPC(DMM, LOGL_INFO, "\n");

	/* Optional: PDP context status, MBMS context status, Uplink data status, Device properties */
	tlv_parse(&tp, &gsm48_gmm_att_tlvdef, cur, (msg->data + msg->len) - cur, 0, 0);

	switch (mi.type) {
	case GSM_MI_TYPE_IMSI:
		/* Try to find MM context based on IMSI */
		if (!ctx)
			ctx = sgsn_mm_ctx_by_imsi(mi.imsi);
		if (!ctx) {
			/* FIXME: We need to have a context for service request? */
			reject_cause = GMM_CAUSE_IMPL_DETACHED;
			goto rejected;
		}
		msgid2mmctx(ctx, msg);
		break;
	case GSM_MI_TYPE_TMSI:
		/* Try to find MM context based on P-TMSI */
		if (!ctx)
			ctx = sgsn_mm_ctx_by_ptmsi(mi.tmsi);
		if (!ctx) {
			/* FIXME: We need to have a context for service request? */
			reject_cause = GMM_CAUSE_IMPL_DETACHED;
			goto rejected;
		}
		msgid2mmctx(ctx, msg);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, ctx, "Rejecting SERVICE REQUEST with "
			"MI %s\n", mi_log_string);
		reject_cause = GMM_CAUSE_MS_ID_NOT_DERIVED;
		goto rejected;
	}

	osmo_fsm_inst_dispatch(ctx->gmm_fsm, E_GMM_COMMON_PROC_INIT_REQ, NULL);

	ctx->iu.service.type = service_type;

	/* Look at PDP Context Status IE and see if MS's view of
	 * activated/deactivated NSAPIs agrees with our view */
	if (TLVP_PRESENT(&tp, GSM48_IE_GMM_PDP_CTX_STATUS)) {
		uint16_t pdp_status =  tlvp_val16be(&tp, GSM48_IE_GMM_PDP_CTX_STATUS);

		process_ms_ctx_status(ctx, pdp_status);

		/* 3GPP TS 24.008 § 4.7.13.4 Service request procedure not
		 * accepted by the network. Cause #40. If MS has PDP Contexts in
		 * Active state in pdp_status but there is no PDP contexts on
		 * SGSN side then Reject with the cause will force the mobile to
		 * reset PDP contexts */
		if (llist_empty(&ctx->pdp_list) && pdp_status_has_active_nsapis(pdp_status)) {
			reject_cause = GMM_CAUSE_NO_PDP_ACTIVATED;
			goto rejected;
		}
	}


	ctx->pending_req = GSM48_MT_GMM_SERVICE_REQ;
	return gsm48_gmm_authorize(ctx);

err_inval:
	LOGPC(DMM, LOGL_INFO, "\n");
	reject_cause = GMM_CAUSE_SEM_INCORR_MSG;

rejected:
	/* Send SERVICE REJECT */
	LOGMMCTXP(LOGL_NOTICE, ctx,
		  "Rejecting Service Request with cause '%s' (%d)\n",
		  get_value_string(gsm48_gmm_cause_names, reject_cause), reject_cause);
	rc = gsm48_tx_gmm_service_rej_oldmsg(msg, reject_cause);

	return rc;

}


static int gsm48_rx_gmm_status(struct sgsn_mm_ctx *mmctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	LOGMMCTXP(LOGL_INFO, mmctx, "-> GMM STATUS (cause: %s)\n",
		get_value_string(gsm48_gmm_cause_names, gh->data[0]));

	return 0;
}

/* Rx GPRS Mobility Management. MMCTX can be NULL when called. On !Gb (Iu), llme is NULL  */
int gsm0408_rcv_gmm(struct sgsn_mm_ctx *mmctx, struct msgb *msg,
			   struct gprs_llc_llme *llme, bool drop_cipherable)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	int rc;

	if (drop_cipherable && gsm48_hdr_gmm_cipherable(gh)) {
		LOGMMCTXP(LOGL_NOTICE, mmctx, "Dropping cleartext GMM %s which "
			  "is expected to be encrypted for TLLI 0x%08x\n",
			  get_value_string(gprs_msgt_gmm_names, gh->msg_type),
			  llme->tlli);
		return -EBADMSG;
	}

	if (llme && !mmctx &&
	    gh->msg_type != GSM48_MT_GMM_ATTACH_REQ &&
	    gh->msg_type != GSM48_MT_GMM_RA_UPD_REQ) {
		LOGGBP(llme, DMM, LOGL_NOTICE, "Cannot handle GMM for unknown MM CTX\n");
		/* 4.7.10 */
		if (gh->msg_type == GSM48_MT_GMM_STATUS) {
			/* TLLI unassignment */
			gprs_llgmm_unassign(llme);
			return 0;
		}

		/* Don't reply or establish a LLME on DETACH_ACK */
		if (gh->msg_type == GSM48_MT_GMM_DETACH_ACK)
			return gprs_llgmm_unassign(llme);

		/* Don't reply to deatch requests, reason power off */
		if (gh->msg_type == GSM48_MT_GMM_DETACH_REQ &&
			gh->data[0] & 0x8) {
			return 0;
		}


		gprs_llgmm_reset(llme);

		/* Don't force it into re-attachment */
		if (gh->msg_type == GSM48_MT_GMM_DETACH_REQ) {
			/* Handle Detach Request */
			rc = gsm48_rx_gmm_det_req(NULL, msg);

			/* TLLI unassignment */
			gprs_llgmm_unassign(llme);
			return rc;
		}

		/* Force the MS to re-attach */
		rc = gsm0408_gprs_force_reattach_oldmsg(msg, llme);

		/* TLLI unassignment */
		gprs_llgmm_unassign(llme);
		return rc;
	}

	/* A RAT change is only expected/allowed for RAU/Attach Req */
	if (mmctx && mmctx_did_rat_change(mmctx, msg)) {
		switch (gh->msg_type) {
		case GSM48_MT_GMM_RA_UPD_REQ:
		case GSM48_MT_GMM_ATTACH_REQ:
			break;
		default:
			/* This shouldn't happen with other message types and
			 * we need to error out to prevent a crash */
			LOGMMCTXP(LOGL_NOTICE, mmctx, "Dropping GMM %s which was received on different "
				       "RAT (mmctx ran_type=%u, msg_iu_ue_ctx=%p\n",
				       get_value_string(gprs_msgt_gmm_names, gh->msg_type),
				       mmctx->ran_type, MSG_IU_UE_CTX(msg));
			return -EINVAL;
		}
	}

	/*
	 * For a few messages, mmctx may be NULL. For most, we want to ensure a
	 * non-NULL mmctx. At the same time, we want to keep the message
	 * validity check intact, so that all message types appear in the
	 * switch statement and the default case thus means "unknown message".
	 * If we split the switch in two parts to check non-NULL halfway, the
	 * unknown-message check breaks, or we'd need to duplicate the switch
	 * cases in both parts. Just keep one large switch and add some gotos.
	 */
	switch (gh->msg_type) {
	case GSM48_MT_GMM_RA_UPD_REQ:
		rc = gsm48_rx_gmm_ra_upd_req(mmctx, msg, llme);
		break;
	case GSM48_MT_GMM_ATTACH_REQ:
		rc = gsm48_rx_gmm_att_req(mmctx, msg, llme);
		break;
	case GSM48_MT_GMM_SERVICE_REQ:
		rc = gsm48_rx_gmm_service_req(mmctx, msg);
		break;
	/* For all the following types mmctx can not be NULL */
	case GSM48_MT_GMM_ID_RESP:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_id_resp(mmctx, msg);
		break;
	case GSM48_MT_GMM_STATUS:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_status(mmctx, msg);
		break;
	case GSM48_MT_GMM_DETACH_REQ:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_det_req(mmctx, msg);
		break;
	case GSM48_MT_GMM_DETACH_ACK:
		if (!mmctx)
			goto null_mmctx;
		LOGMMCTXP(LOGL_INFO, mmctx, "-> DETACH ACK\n");
		mm_ctx_cleanup_free(mmctx, "GMM DETACH ACK");
		rc = 0;
		break;
	case GSM48_MT_GMM_ATTACH_COMPL:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_att_compl(mmctx);
		break;
	case GSM48_MT_GMM_RA_UPD_COMPL:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_ra_upd_compl(mmctx);
		break;
	case GSM48_MT_GMM_PTMSI_REALL_COMPL:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_ptmsi_reall_compl(mmctx);
		break;
	case GSM48_MT_GMM_AUTH_CIPH_RESP:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_auth_ciph_resp(mmctx, msg);
		break;
	case GSM48_MT_GMM_AUTH_CIPH_FAIL:
		rc = gsm48_rx_gmm_auth_ciph_fail(mmctx, msg);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mmctx, "Unknown GSM 04.08 GMM msg type 0x%02x\n",
			gh->msg_type);
		if (mmctx)
			rc = gsm48_tx_gmm_status(mmctx, GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		else
			rc = -EINVAL;
		break;
	}

	return rc;

null_mmctx:
	LOGGBIUP(llme, msg, LOGL_ERROR,
	     "Received GSM 04.08 message type %s,"
	     " but no MM context available\n",
	     get_value_string(gprs_msgt_gmm_names, gh->msg_type));
	return -EINVAL;
}

static void mmctx_timer_cb(void *_mm)
{
	struct sgsn_mm_ctx *mm = _mm;
	struct gsm_auth_tuple *at;
	int rc;
	unsigned long seconds;

	mm->num_T_exp++;

	switch (mm->T) {
	case 3350:	/* waiting for ATTACH COMPLETE */
		if (mm->num_T_exp >= 5) {
			LOGMMCTXP(LOGL_NOTICE, mm, "T3350 expired >= 5 times\n");
			mm_ctx_cleanup_free(mm, "T3350");
			/* FIXME: should we return some error? */
			break;
		}
		/* re-transmit the respective msg and re-start timer */
		switch (mm->t3350_mode) {
		case GMM_T3350_MODE_ATT:
			gsm48_tx_gmm_att_ack(mm);
			break;
		case GMM_T3350_MODE_RAU:
			gsm48_tx_gmm_ra_upd_ack(mm);
			break;
		case GMM_T3350_MODE_PTMSI_REALL:
			/* FIXME */
			break;
		case GMM_T3350_MODE_NONE:
			LOGMMCTXP(LOGL_NOTICE, mm,
				  "T3350 mode wasn't set, ignoring timeout\n");
			break;
		}
		seconds = osmo_tdef_get(sgsn->cfg.T_defs, 3350, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&mm->timer, seconds, 0);
		break;
	case 3360:	/* waiting for AUTH AND CIPH RESP */
		if (mm->num_T_exp >= 5) {
			LOGMMCTXP(LOGL_NOTICE, mm, "T3360 expired >= 5 times\n");
			mm_ctx_cleanup_free(mm, "T3360");
			break;
		}
		/* Re-transmit the respective msg and re-start timer */
		if (mm->auth_triplet.key_seq == GSM_KEY_SEQ_INVAL) {
			LOGMMCTXP(LOGL_ERROR, mm,
				  "timeout: invalid auth triplet reference\n");
			mm_ctx_cleanup_free(mm, "T3360");
			break;
		}
		at = &mm->auth_triplet;

		rc = gsm48_tx_gmm_auth_ciph_req(mm, &at->vec, at->key_seq, false);
		if (rc < 0) {
			LOGMMCTXP(LOGL_ERROR, mm, "failed sending Auth. & Ciph. Request: %s \n", strerror(-rc));
		} else {
			seconds = osmo_tdef_get(sgsn->cfg.T_defs, 3360, OSMO_TDEF_S, -1);
			osmo_timer_schedule(&mm->timer, seconds, 0);
		}
		break;
	case 3370:	/* waiting for IDENTITY RESPONSE */
		if (mm->num_T_exp >= 5) {
			LOGMMCTXP(LOGL_NOTICE, mm, "T3370 expired >= 5 times\n");
			gsm48_tx_gmm_att_rej(mm, GMM_CAUSE_MS_ID_NOT_DERIVED);
			mm_ctx_cleanup_free(mm, "GMM ATTACH REJECT (T3370)");
			break;
		}
		/* re-tranmit IDENTITY REQUEST and re-start timer */
		gsm48_tx_gmm_id_req(mm, mm->t3370_id_type);
		seconds = osmo_tdef_get(sgsn->cfg.T_defs, 3370, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&mm->timer, seconds, 0);
		break;
	default:
		LOGMMCTXP(LOGL_ERROR, mm, "timer expired in unknown mode %u\n",
			mm->T);
	}
}

int gsm0408_gprs_force_reattach_oldmsg(struct msgb *msg,
				       struct gprs_llc_llme *llme)
{
	int rc;
	if (llme)
		gprs_llgmm_reset_oldmsg(msg, GPRS_SAPI_GMM, llme);

	rc = gsm48_tx_gmm_detach_req_oldmsg(
		msg, GPRS_DET_T_MT_REATT_REQ, GMM_CAUSE_IMPL_DETACHED);

	return rc;
}

int gsm0408_gprs_force_reattach(struct sgsn_mm_ctx *mmctx)
{
	int rc;
	if (mmctx->ran_type == MM_CTX_T_GERAN_Gb)
		gprs_llgmm_reset(mmctx->gb.llme);

	rc = gsm48_tx_gmm_detach_req(
		mmctx, GPRS_DET_T_MT_REATT_REQ, GMM_CAUSE_IMPL_DETACHED);

	mm_ctx_cleanup_free(mmctx, "forced reattach");

	return rc;
}

int gprs_gmm_rx_suspend(struct osmo_routing_area_id *raid, uint32_t tlli)
{
	struct sgsn_mm_ctx *mmctx;

	mmctx = sgsn_mm_ctx_by_tlli(tlli, raid);
	if (!mmctx) {
		LOGP(DMM, LOGL_NOTICE, "SUSPEND request for unknown "
			"TLLI=%08x\n", tlli);
		return -EINVAL;
	}

	if (!gmm_fsm_is_registered(mmctx->gmm_fsm)) {
		LOGMMCTXP(LOGL_NOTICE, mmctx, "SUSPEND request while state "
			"!= REGISTERED (TLLI=%08x)\n", tlli);
		return -EINVAL;
	}

	/* Transition from REGISTERED_NORMAL to REGISTERED_SUSPENDED */
	osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_SUSPEND, NULL);
	return 0;
}

int gprs_gmm_rx_resume(struct osmo_routing_area_id *raid, uint32_t tlli,
		       uint8_t suspend_ref)
{
	struct sgsn_mm_ctx *mmctx;

	/* FIXME: make use of suspend reference? */

	mmctx = sgsn_mm_ctx_by_tlli(tlli, raid);
	if (!mmctx) {
		LOGP(DMM, LOGL_NOTICE, "RESUME request for unknown "
			"TLLI=%08x\n", tlli);
		return -EINVAL;
	}

	if (!gmm_fsm_is_registered(mmctx->gmm_fsm)) {
		LOGMMCTXP(LOGL_NOTICE, mmctx, "RESUME request while state "
			"!= SUSPENDED (TLLI=%08x)\n", tlli);
		/* FIXME: should we not simply ignore it? */
		return -EINVAL;
	}

	/* Transition from SUSPENDED to NORMAL */
	osmo_fsm_inst_dispatch(mmctx->gmm_fsm, E_GMM_RESUME, NULL);
	return 0;
}

/* Has to be called whenever any PDU (signaling, data, ...) has been received */
void gprs_gb_recv_pdu(struct sgsn_mm_ctx *mmctx, const struct msgb *msg)
{
	msgid2mmctx(mmctx, msg);
	if (mmctx->gb.llme)
		osmo_fsm_inst_dispatch(mmctx->gb.mm_state_fsm, E_MM_PDU_RECEPTION, NULL);
}

/* Main entry point for incoming 04.08 GPRS messages from Gb */
int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	struct sgsn_mm_ctx *mmctx;
	struct osmo_routing_area_id ra_id = {};
	int rc = -EINVAL;

	bssgp_parse_cell_id2(&ra_id, NULL, msgb_bcid(msg), 8);
	mmctx = sgsn_mm_ctx_by_tlli(msgb_tlli(msg), &ra_id);
	if (mmctx) {
		rate_ctr_inc(rate_ctr_group_get_ctr(mmctx->ctrg, GMM_CTR_PKTS_SIG_IN));
		mmctx->gb.llme = llme;
		gprs_gb_recv_pdu(mmctx, msg);
	}

	/* MMCTX can be NULL */

	switch (pdisc) {
	case GSM48_PDISC_MM_GPRS:
		rc = gsm0408_rcv_gmm(mmctx, msg, llme, drop_cipherable);
		break;
	case GSM48_PDISC_SM_GPRS:
		rc = gsm0408_rcv_gsm(mmctx, msg, llme);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			"Unknown GSM 04.08 discriminator 0x%02x: %s\n",
			pdisc, osmo_hexdump((uint8_t *)gh, msgb_l3len(msg)));
		/* FIXME: return status message */
		break;
	}

	/* MMCTX can be invalid */

	return rc;
}
