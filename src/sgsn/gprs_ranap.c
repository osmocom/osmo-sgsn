/* Messages on the RANAP interface (Iu mode) */

/* (C) 2009-2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2015 by Holger Hans Peter Freyther
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

#include "config.h"
#include <gtp.h>

#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gprs/gprs_msgb.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_sm.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_ranap.h>
#include <osmocom/sgsn/gprs_gmm_attach.h>
#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>
#include <osmocom/sgsn/gtp_ggsn.h>
#include <osmocom/sgsn/gtp.h>
#include <osmocom/sgsn/pdpctx.h>
#include <osmocom/sgsn/mmctx.h>

#include <osmocom/vlr/vlr.h>

/* Send RAB activation requests for all PDP contexts */
void activate_pdp_rabs(struct sgsn_mm_ctx *ctx)
{
	struct sgsn_pdp_ctx *pdp;
	if (ctx->ran_type != MM_CTX_T_UTRAN_Iu)
		return;
	llist_for_each_entry(pdp, &ctx->pdp_list, list) {
		iu_rab_act_ps(pdp->nsapi, pdp);
	}
}

/* Callback for RAB assignment response */
static int sgsn_ranap_rab_ass_resp(struct sgsn_mm_ctx *ctx, RANAP_RAB_SetupOrModifiedItemIEs_t *setup_ies)
{
	uint8_t rab_id;
	bool require_pdp_update = false;
	struct sgsn_pdp_ctx *pdp = NULL;
	RANAP_RAB_SetupOrModifiedItem_t *item = &setup_ies->raB_SetupOrModifiedItem;
	int rc;

	rab_id = item->rAB_ID.buf[0];

	pdp = sgsn_pdp_ctx_by_nsapi(ctx, rab_id);
	if (!pdp) {
		LOGP(DRANAP, LOGL_ERROR, "RAB Assignment Response for unknown RAB/NSAPI=%u\n", rab_id);
		sgsn_ranap_iu_release_free(ctx, NULL);
		return -1;
	}

	if (item->transportLayerAddress) {
		struct osmo_sockaddr addr;
		LOGPC(DRANAP, LOGL_INFO, " Setup: (%u/%s)", rab_id, osmo_hexdump(item->transportLayerAddress->buf,
								     item->transportLayerAddress->size));
		rc = ranap_transp_layer_addr_decode2(&addr, NULL, item->transportLayerAddress);
		if (rc < 0) {
			LOGP(DRANAP, LOGL_ERROR,
			     "RAB Assignment Resp: Unknown Transport Layer Address (size %u): %s\n",
			     item->transportLayerAddress->size,
			     osmo_hexdump(item->transportLayerAddress->buf, item->transportLayerAddress->size));
			goto ret_error;
		}

		switch (addr.u.sa.sa_family) {
		case AF_INET:
			memcpy(pdp->lib->gsnlu.v, (uint8_t *)&addr.u.sin.sin_addr.s_addr, 4);
			break;
		case AF_INET6:
			/* TODO: Support IPv6 address */
			LOGP(DRANAP, LOGL_ERROR,
			     "RAB Assignment Resp: IPv6 transport layer address not supported!\n");
			goto ret_error;
		default:
			LOGP(DRANAP, LOGL_ERROR,
			     "RAB Assignment Resp: Unexpected transport layer address size %u\n",
			     item->transportLayerAddress->size);
			goto ret_error;
		}
		require_pdp_update = true;
	}

	/* The TEI on the RNC side might have changed, too */
	if (item->iuTransportAssociation &&
	    item->iuTransportAssociation->present == RANAP_IuTransportAssociation_PR_gTP_TEI &&
	    item->iuTransportAssociation->choice.gTP_TEI.buf &&
	    item->iuTransportAssociation->choice.gTP_TEI.size >= 4) {
		uint32_t tei = osmo_load32be(item->iuTransportAssociation->choice.gTP_TEI.buf);
		LOGP(DRANAP, LOGL_DEBUG, "Updating TEID on RNC side from 0x%08x to 0x%08x\n",
			pdp->lib->teid_own, tei);
		pdp->lib->teid_own = tei;
		pdp->lib->dir_tun_flags.l = 1;
		pdp->lib->dir_tun_flags.v[0] = 0x01; /* Set DTI flag in Direct Tunnel Flags */
		require_pdp_update = true;
	}

	if (require_pdp_update)
		gtp_update_context(pdp->ggsn->gsn, pdp->lib, pdp, &pdp->lib->hisaddr0);

	if (pdp->state != PDP_STATE_CR_CONF) {
		send_act_pdp_cont_acc(pdp);
		pdp->state = PDP_STATE_CR_CONF;
	}
	return 0;

ret_error:
	if (pdp->state != PDP_STATE_CR_CONF) {
		gsm48_tx_gsm_act_pdp_rej(ctx, pdp->ti, GSM_CAUSE_NET_FAIL,
					 0, NULL);
		sgsn_delete_pdp_ctx(pdp);
	} else {
		gsm48_tx_gsm_deact_pdp_req(pdp, GSM_CAUSE_NET_FAIL, true);
	}
	return -1;
}

int sgsn_ranap_iu_event(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type, void *data)
{
	struct sgsn_mm_ctx *mm;
	int rc = -1;

	mm = sgsn_mm_ctx_by_ue_ctx(ctx);
	if (!mm) {
		LOGIUP(ctx, LOGL_NOTICE, "Cannot find mm ctx for IU event %s\n",
		       ranap_iu_event_type_str(type));
		ranap_iu_free_ue(ctx);
		return rc;
	}

	switch (type) {
	case RANAP_IU_EVENT_RAB_ASSIGN:
		rc = sgsn_ranap_rab_ass_resp(mm, (RANAP_RAB_SetupOrModifiedItemIEs_t *)data);
		break;
	case RANAP_IU_EVENT_IU_RELEASE:
		/* fall thru */
	case RANAP_IU_EVENT_LINK_INVALIDATED:
		/* Clean up ranap_ue_conn_ctx here */
		LOGMMCTXP(LOGL_INFO, mm, "IU release (cause=%s)\n", ranap_iu_event_type_str(type));
		rc = osmo_fsm_inst_dispatch(mm->iu.mm_state_fsm, E_PMM_PS_CONN_RELEASE, NULL);
		if (rc < 0)
			sgsn_ranap_iu_free(mm);

		if (mm->vsub)
			vlr_subscr_disconnected(mm->vsub);
		rc = 0;
		break;
	case RANAP_IU_EVENT_SECURITY_MODE_COMPLETE:
		/* FIXME: verify that a permitted UEA level was chosen. Compare how osmo-msc does it in
		 * msc_a_ran_dec_from_msc_i(), case RAN_MSG_CIPHER_MODE_COMPLETE.
		 * We should dissolve iu_client.c, it was a design mistake when first implementing Iu support. osmo-msc
		 * has moved away from it a long time ago.
		 */
		/* Continue authentication here */
		mm->iu.ue_ctx->integrity_active = 1;

		if (mm->vsub)
			vlr_subscr_rx_ciph_res(mm->vsub, VLR_CIPH_COMPL);

		rc = 0;
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mm, "Unknown event received: %d\n", type);
		rc = -1;
		break;
	}
	return rc;
}

void sgsn_ranap_iu_free(struct sgsn_mm_ctx *ctx)
{
	if (!ctx)
		return;

	if (!ctx->iu.ue_ctx)
		return;

	ranap_iu_free_ue(ctx->iu.ue_ctx);
	ctx->iu.ue_ctx = NULL;
}

void sgsn_ranap_iu_release_free(struct sgsn_mm_ctx *ctx,
				const struct RANAP_Cause *cause)
{
	unsigned long X1001;

	if (!ctx)
		return;

	if (!ctx->iu.ue_ctx)
		return;

	X1001 = osmo_tdef_get(sgsn->cfg.T_defs, -1001, OSMO_TDEF_S, -1);

	ranap_iu_tx_release_free(ctx->iu.ue_ctx,
				 cause,
				 (int) X1001);
	ctx->iu.ue_ctx = NULL;
}

int iu_rab_act_ps(uint8_t rab_id, struct sgsn_pdp_ctx *pdp)
{
	struct msgb *msg;
	struct sgsn_mm_ctx *mm = pdp->mm;
	struct ranap_ue_conn_ctx *uectx;
	uint32_t ggsn_ip;
	bool use_x213_nsap;

	uectx = mm->iu.ue_ctx;
	use_x213_nsap = (uectx->rab_assign_addr_enc == RANAP_NSAP_ADDR_ENC_X213);

	/* Get the IP address for ggsn user plane */
	memcpy(&ggsn_ip, pdp->lib->gsnru.v, pdp->lib->gsnru.l);
	ggsn_ip = htonl(ggsn_ip);

	LOGP(DRANAP, LOGL_DEBUG, "Assigning RAB: rab_id=%d, ggsn_ip=%x,"
	     " teid_gn=%x, use_x213_nsap=%d\n",
	     rab_id, ggsn_ip, pdp->lib->teid_gn, use_x213_nsap);

	msg = ranap_new_msg_rab_assign_data(rab_id, ggsn_ip,
					    pdp->lib->teid_gn, use_x213_nsap);
	msg->l2h = msg->data;
	return ranap_iu_rab_act(uectx, msg);
}


/* Main entry point for incoming 04.08 GPRS messages from Iu */
int gsm0408_gprs_rcvmsg_iu(struct msgb *msg, struct gprs_ra_id *ra_id,
			   uint16_t *sai)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	struct sgsn_mm_ctx *mmctx;
	int rc = -EINVAL;

	mmctx = sgsn_mm_ctx_by_ue_ctx(MSG_IU_UE_CTX(msg));
	if (mmctx) {
		rate_ctr_inc(rate_ctr_group_get_ctr(mmctx->ctrg, GMM_CTR_PKTS_SIG_IN));
		if (ra_id)
			memcpy(&mmctx->ra, ra_id, sizeof(mmctx->ra));
	}

	/* MMCTX can be NULL */

	switch (pdisc) {
	case GSM48_PDISC_MM_GPRS:
		rc = gsm0408_rcv_gmm(mmctx, msg, NULL, false);
#pragma message "set drop_cipherable arg for gsm0408_rcv_gmm() from IuPS?"
		break;
	case GSM48_PDISC_SM_GPRS:
		rc = gsm0408_rcv_gsm(mmctx, msg, NULL);
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
