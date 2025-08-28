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

#include <asn1c/asn1helpers.h>

#include <osmocom/gtp/gtp.h>

#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gprs/gprs_msgb.h>

#include <osmocom/ranap/ranap_common.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#include <osmocom/ranap/iu_helpers.h>
#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_sm.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_ranap.h>
#include <osmocom/sgsn/gprs_gmm_attach.h>
#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>
#include <osmocom/sgsn/gprs_routing_area.h>
#include <osmocom/sgsn/gtp_ggsn.h>
#include <osmocom/sgsn/gtp.h>
#include <osmocom/sgsn/iu_rnc.h>
#include <osmocom/sgsn/pdpctx.h>
#include <osmocom/sgsn/mmctx.h>

/* Parsed global RNC id. See also struct RANAP_GlobalRNC_ID, and note that the
 * PLMN identity is a BCD representation of the MCC and MNC.
 * See iu_grnc_id_parse(). */
struct iu_grnc_id {
	struct osmo_plmn_id plmn;
	uint16_t rnc_id;
};

static int iu_grnc_id_parse(struct osmo_rnc_id *dst, const struct RANAP_GlobalRNC_ID *src)
{
	/* The size is coming from arbitrary sender, check it gracefully */
	if (src->pLMNidentity.size != 3) {
		LOGP(DRANAP, LOGL_ERROR, "Invalid PLMN Identity size: should be 3, is %d\n",
		     src->pLMNidentity.size);
		return -1;
	}
	osmo_plmn_from_bcd(&src->pLMNidentity.buf[0], &dst->plmn);
	dst->rnc_id = (uint16_t)src->rNC_ID;
	return 0;
}

#if 0
/* not used at present */
static int iu_grnc_id_compose(struct iu_grnc_id *src, struct RANAP_GlobalRNC_ID *dst)
{
	/* The caller must ensure proper size */
	OSMO_ASSERT(dst->pLMNidentity.size == 3);
	gsm48_mcc_mnc_to_bcd(&dst->pLMNidentity.buf[0],
			     src->mcc, src->mnc);
	dst->rNC_ID = src->rnc_id;
	return 0;
}
#endif

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
		sgsn_mm_ctx_iu_ranap_release_free(ctx, NULL);
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

static int sgsn_ranap_iu_event_mmctx(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type, void *data)
{
	struct sgsn_mm_ctx *mm;
	int rc = -1;

	if (!ctx) {
		LOGIUP(ctx, LOGL_ERROR, "NULL ctx given for IU event %s\n",
		       iu_client_event_type_str(type));
		return rc;
	}

	mm = sgsn_mm_ctx_by_ue_ctx(ctx);
	if (!mm) {
		LOGIUP(ctx, LOGL_NOTICE, "Cannot find mm ctx for IU event %s\n",
		       iu_client_event_type_str(type));
		sgsn_ranap_iu_free_ue(ctx);
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
		LOGMMCTXP(LOGL_INFO, mm, "IU release (cause=%s)\n", iu_client_event_type_str(type));
		rc = osmo_fsm_inst_dispatch(mm->iu.mm_state_fsm, E_PMM_PS_CONN_RELEASE, NULL);
		if (rc < 0)
			sgsn_mm_ctx_iu_ranap_free(mm);

		/* TODO: move this into FSM */
		if (mm->ran_type == MM_CTX_T_UTRAN_Iu && mm->gmm_att_req.fsm->state != ST_INIT)
			osmo_fsm_inst_dispatch(mm->gmm_att_req.fsm, E_REJECT, (void *) GMM_DISCARD_MS_WITHOUT_REJECT);
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
		sgsn_ranap_iu_tx_common_id(mm->iu.ue_ctx, mm->imsi);

		/* FIXME: remove gmm_authorize */
		if (mm->pending_req != GSM48_MT_GMM_ATTACH_REQ)
			gsm48_gmm_authorize(mm);
		else
			osmo_fsm_inst_dispatch(mm->gmm_att_req.fsm, E_IU_SECURITY_CMD_COMPLETE, NULL);
		rc = 0;
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mm, "Unknown event received: %d\n", type);
		rc = -1;
		break;
	}
	return rc;
}


int sgsn_ranap_iu_event(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type, void *data)
{
	struct ranap_iu_event_new_area *new_area;

	switch (type) {
	case RANAP_IU_EVENT_RAB_ASSIGN:
	case RANAP_IU_EVENT_IU_RELEASE:
	case RANAP_IU_EVENT_LINK_INVALIDATED:
	case RANAP_IU_EVENT_SECURITY_MODE_COMPLETE:
		return sgsn_ranap_iu_event_mmctx(ctx, type, data);
	case RANAP_IU_EVENT_NEW_AREA:
		/* inform the Routing Area code about a new RA for Iu */
		new_area = data;

		/* Only interesting in Routing Area changes, but not Location Area */
		if (new_area->cell_type != RANAP_IU_NEW_RAC)
			return 0;

		return sgsn_ra_utran_register(new_area->u.rai, new_area->rnc_id);
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Iu: Unknown event received: type: %d\n", type);
		return -1;
	}
}

int sgsn_ranap_iu_tx_rab_ps_ass_req(struct ranap_ue_conn_ctx *ue_ctx,
				    uint8_t rab_id, uint32_t gtp_ip, uint32_t gtp_tei)
{
	struct msgb *msg;
	bool use_x213_nsap = (ue_ctx->rab_assign_addr_enc == RANAP_NSAP_ADDR_ENC_X213);

	LOGP(DRANAP, LOGL_DEBUG,
	     "Assigning RAB: rab_id=%u, ggsn_ip=%x, teid_gn=%x, use_x213_nsap=%d\n",
	     rab_id, gtp_ip, gtp_tei, use_x213_nsap);

	msg = ranap_new_msg_rab_assign_data(rab_id, gtp_ip, gtp_tei, use_x213_nsap);
	return sgsn_scu_iups_tx_data_req(ue_ctx->scu_iups, ue_ctx->conn_id, msg);
}

int sgsn_ranap_iu_tx_sec_mode_cmd(struct ranap_ue_conn_ctx *uectx, struct osmo_auth_vector *vec,
			     int send_ck, int new_key)
{
	struct msgb *msg;

	/* create RANAP message */
	msg = ranap_new_msg_sec_mod_cmd(vec->ik, send_ck ? vec->ck : NULL,
			new_key ? RANAP_KeyStatus_new : RANAP_KeyStatus_old);
	return sgsn_scu_iups_tx_data_req(uectx->scu_iups, uectx->conn_id, msg);
}

int sgsn_ranap_iu_tx_common_id(struct ranap_ue_conn_ctx *uectx, const char *imsi)
{
	struct msgb *msg;

	LOGP(DRANAP, LOGL_INFO, "Transmitting RANAP CommonID (SCCP conn_id %u)\n",
	     uectx->conn_id);

	msg = ranap_new_msg_common_id(imsi);
	return sgsn_scu_iups_tx_data_req(uectx->scu_iups, uectx->conn_id, msg);
}

/* Send a paging command down a given SCCP User. tmsi and paging_cause are
 * optional and may be passed NULL and 0, respectively, to disable their use.
 * See enum RANAP_PagingCause.
 *
 * If TMSI is given, the IMSI is not sent over the air interface. Nevertheless,
 * the IMSI is still required for resolution in the HNB-GW and/or(?) RNC. */
int sgsn_ranap_iu_tx_paging_cmd(struct osmo_sccp_addr *called_addr,
			   const char *imsi, const uint32_t *tmsi,
			   bool is_ps, uint32_t paging_cause)
{
	struct msgb *msg;
	msg = ranap_new_msg_paging_cmd(imsi, tmsi, is_ps ? 1 : 0, paging_cause);
	msg->l2h = msg->data;
	return osmo_sccp_tx_unitdata_msg(sgsn->sccp.scu_iups->scu, &sgsn->sccp.scu_iups->local_sccp_addr, called_addr, msg);
}

int sgsn_ranap_iu_tx(struct msgb *msg_nas, uint8_t sapi)
{
	struct ranap_ue_conn_ctx *uectx = msg_nas->dst;
	struct msgb *msg;

	if (!uectx) {
		LOGP(DRANAP, LOGL_ERROR,
		     "Discarding to-be-transmitted L3 Message as RANAP DT with unset dst SCCP conn_id!\n");
		return -ENOTCONN;
	}

	LOGP(DRANAP, LOGL_INFO, "Transmitting L3 Message as RANAP DT (SCCP conn_id %u)\n",
	     uectx->conn_id);

	msg = ranap_new_msg_dt(sapi, msg_nas->data, msgb_length(msg_nas));
	msgb_free(msg_nas);

	return sgsn_scu_iups_tx_data_req(uectx->scu_iups, uectx->conn_id, msg);
}

/* Send CL RANAP message over SCCP: */
int sgsn_ranap_iu_tx_cl(struct sgsn_sccp_user_iups *scu_iups,
			const struct osmo_sccp_addr *dst_addr,
			struct msgb *msg)
{
	msg->l2h = msg->data;
	return osmo_sccp_tx_unitdata_msg(scu_iups->scu, &scu_iups->local_sccp_addr, dst_addr, msg);
}

/* Send RANAP Error Indication */
int sgsn_ranap_iu_tx_error_ind(struct sgsn_sccp_user_iups *scu_iups,
			       const struct osmo_sccp_addr *dst_addr,
			       const RANAP_Cause_t *cause)
{
	RANAP_CN_DomainIndicator_t domain = RANAP_CN_DomainIndicator_ps_domain;
	struct msgb *ranap_msg;

	ranap_msg = ranap_new_msg_error_ind(cause, NULL, &domain, NULL);
	if (!ranap_msg)
		return -ENOMEM;

	return sgsn_ranap_iu_tx_cl(scu_iups, dst_addr, ranap_msg);
}

/* Send Iu Release for the given UE connection.
 * If cause is NULL, Normal Release cause is sent, otherwise
 * the provided cause. */
int sgsn_ranap_iu_tx_release(struct ranap_ue_conn_ctx *uectx, const struct RANAP_Cause *cause)
{
	struct msgb *msg;
	static const struct RANAP_Cause default_cause = {
		.present = RANAP_Cause_PR_nAS,
		.choice.radioNetwork = RANAP_CauseNAS_normal_release,
	};

	if (!cause)
		cause = &default_cause;

	msg = ranap_new_msg_iu_rel_cmd(cause);
	return sgsn_scu_iups_tx_data_req(uectx->scu_iups, uectx->conn_id, msg);
}

void sgsn_ranap_iu_tx_release_free(struct ranap_ue_conn_ctx *ctx,
				   const struct RANAP_Cause *cause,
				   int timeout)
{
	ctx->notification = false;
	ctx->free_on_release = true;
	int ret = sgsn_ranap_iu_tx_release(ctx, cause);
	/* On Tx failure, trigger timeout immediately, as the response will never arrive */
	if (ret)
		timeout = 0;

	osmo_timer_schedule(&ctx->release_timeout, timeout, 0);
}

static int ranap_handle_co_initial_ue(struct sgsn_sccp_user_iups *scu_iups,
				      const struct osmo_sccp_addr *rem_sccp_addr,
				      uint32_t conn_id,
				      const RANAP_InitialUE_MessageIEs_t *ies)
{
	struct gprs_ra_id ra_id = {};
	struct osmo_routing_area_id ra_id2 = {};
	struct osmo_rnc_id rnc_id = {};
	uint16_t sai;
	struct ranap_ue_conn_ctx *ue;
	struct msgb *msg = msgb_alloc(256, "RANAP->NAS");
	struct ranap_iu_rnc *rnc;

	if (ranap_parse_lai(&ra_id, &ies->lai) != 0) {
		LOGP(DRANAP, LOGL_ERROR, "Failed to parse RANAP LAI IE\n");
		return -1;
	}

	if (!(ies->presenceMask & INITIALUE_MESSAGEIES_RANAP_RAC_PRESENT)) {
		LOGP(DRANAP, LOGL_ERROR, "Rejecting InitialUE msg without RAC IE\n");
		return -1;
	}

	ra_id.rac = asn1str_to_u8(&ies->rac);
	if (ra_id.rac == OSMO_RESERVED_RAC) {
		LOGP(DRANAP, LOGL_ERROR,
		     "Rejecting RNC with invalid/internally used RAC 0x%02x\n", ra_id.rac);
		return -1;
	}

	if (iu_grnc_id_parse(&rnc_id, &ies->globalRNC_ID) != 0) {
		LOGP(DRANAP, LOGL_ERROR,
		     "Failed to parse RANAP Global-RNC-ID IE\n");
		return -1;
	}

	sai = asn1str_to_u16(&ies->sai.sAC);
	msgb_gmmh(msg) = msgb_put(msg, ies->nas_pdu.size);
	memcpy(msgb_gmmh(msg), ies->nas_pdu.buf, ies->nas_pdu.size);

	gprs_rai_to_osmo(&ra_id2, &ra_id);

	/* Make sure we know the RNC Id and LAC+RAC coming in on this connection. */
	rnc = iu_rnc_find_or_create(&rnc_id, rem_sccp_addr);
	OSMO_ASSERT(rnc);
	iu_rnc_update_rai_seen(rnc, &ra_id2);

	ue = ue_conn_ctx_alloc(rnc, scu_iups, conn_id);
	OSMO_ASSERT(ue);
	ue->ra_id = ra_id;

	/* Feed into the MM layer */
	msg->dst = ue;
	gsm0408_gprs_rcvmsg_iu(msg, &ra_id, &sai);

	msgb_free(msg);

	return 0;
}

static void cn_ranap_handle_co_initial(struct sgsn_sccp_user_iups *scu_iups,
				       const struct osmo_sccp_addr *rem_sccp_addr,
				       uint32_t conn_id,
				       const ranap_message *message)
{
	int rc;

	LOGP(DRANAP, LOGL_NOTICE, "handle_co_initial(dir=%u, proc=%u)\n", message->direction, message->procedureCode);

	if (message->direction != RANAP_RANAP_PDU_PR_initiatingMessage
	    || message->procedureCode != RANAP_ProcedureCode_id_InitialUE_Message) {
		LOGP(DRANAP, LOGL_ERROR, "Expected direction 'InitiatingMessage',"
		     " procedureCode 'InitialUE_Message', instead got %u and %u\n",
		     message->direction, message->procedureCode);
		rc = -1;
	} else
		rc = ranap_handle_co_initial_ue(scu_iups, rem_sccp_addr, conn_id, &message->msg.initialUE_MessageIEs);

	if (rc) {
		LOGP(DRANAP, LOGL_ERROR, "Error in %s (%d)\n", __func__, rc);
		/* TODO handling of the error? */
	}
}

int sgsn_ranap_iu_rx_co_initial_msg(struct sgsn_sccp_user_iups *scu_iups,
				    const struct osmo_sccp_addr *rem_sccp_addr,
				    uint32_t conn_id,
				    const uint8_t *data, size_t len)
{
	ranap_message message;
	int rc;

	rc = ranap_cn_rx_co_decode2(&message, data, len);
	if (rc != 0) {
		LOGP(DRANAP, LOGL_ERROR, "Not calling cn_ranap_handle_co_initial() due to rc=%d\n", rc);
		goto free_ret;
	}

	cn_ranap_handle_co_initial(scu_iups, rem_sccp_addr, conn_id, &message);

free_ret:
	/* Free the asn1 structs in message */
	ranap_cn_rx_co_free(&message);
	return rc;
}

static int ranap_handle_co_dt(struct ranap_ue_conn_ctx *ue_ctx, const RANAP_DirectTransferIEs_t *ies)
{
	struct gprs_ra_id _ra_id, *ra_id = NULL;
	uint16_t _sai, *sai = NULL;
	struct msgb *msg = msgb_alloc(256, "RANAP->NAS");

	if (ies->presenceMask & DIRECTTRANSFERIES_RANAP_LAI_PRESENT) {
		if (ranap_parse_lai(&_ra_id, &ies->lai) != 0) {
			LOGP(DRANAP, LOGL_ERROR, "Failed to parse RANAP LAI IE\n");
			return -1;
		}
		ra_id = &_ra_id;
		if (ies->presenceMask & DIRECTTRANSFERIES_RANAP_RAC_PRESENT)
			_ra_id.rac = asn1str_to_u8(&ies->rac);

		if (ies->presenceMask & DIRECTTRANSFERIES_RANAP_SAI_PRESENT) {
			_sai = asn1str_to_u16(&ies->sai.sAC);
			sai = &_sai;
		}
	}

	msgb_gmmh(msg) = msgb_put(msg, ies->nas_pdu.size);
	memcpy(msgb_gmmh(msg), ies->nas_pdu.buf, ies->nas_pdu.size);

	/* Feed into the MM/CC/SMS-CP layer */
	msg->dst = ue_ctx;
	gsm0408_gprs_rcvmsg_iu(msg, ra_id, sai);

	msgb_free(msg);

	return 0;
}

static int ranap_handle_co_err_ind(struct ranap_ue_conn_ctx *ue_ctx, const RANAP_ErrorIndicationIEs_t *ies)
{
	if (ies->presenceMask & ERRORINDICATIONIES_RANAP_CAUSE_PRESENT)
		LOGP(DRANAP, LOGL_ERROR, "Rx Error Indication (%s)\n",
		     ranap_cause_str(&ies->cause));
	else
		LOGP(DRANAP, LOGL_ERROR, "Rx Error Indication\n");

	return 0;
}

static int ranap_handle_co_iu_rel_req(struct ranap_ue_conn_ctx *ue_ctx, const RANAP_Iu_ReleaseRequestIEs_t *ies)
{
	LOGP(DRANAP, LOGL_INFO, "Received Iu Release Request, Sending Release Command\n");
	sgsn_ranap_iu_tx_release(ue_ctx, &ies->cause);
	return 0;
}

static int ranap_handle_co_rab_ass_resp(struct ranap_ue_conn_ctx *ue_ctx, const RANAP_RAB_AssignmentResponseIEs_t *ies)
{
	int rc = -1;

	LOGP(DRANAP, LOGL_INFO,
	       "Rx RAB Assignment Response for UE conn_id %u\n", ue_ctx->conn_id);
	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_SETUPORMODIFIEDLIST_PRESENT) {
		/* TODO: Iterate over list of SetupOrModifiedList IEs and handle each one */
		RANAP_IE_t *ranap_ie = ies->raB_SetupOrModifiedList.raB_SetupOrModifiedList_ies.list.array[0];
		RANAP_RAB_SetupOrModifiedItemIEs_t setup_ies;

		rc = ranap_decode_rab_setupormodifieditemies_fromlist(&setup_ies, &ranap_ie->value);
		if (rc) {
			LOGP(DRANAP, LOGL_ERROR, "Error in ranap_decode_rab_setupormodifieditemies()\n");
			return rc;
		}

		rc = global_iu_event(ue_ctx, RANAP_IU_EVENT_RAB_ASSIGN, &setup_ies);

		ranap_free_rab_setupormodifieditemies(&setup_ies);
	}
	/* FIXME: handle RAB Ass failure? */

	return rc;
}

/* Entry point for connection-oriented RANAP message */
static void cn_ranap_handle_co(struct ranap_ue_conn_ctx *ue_ctx, const ranap_message *message)
{
	int rc;

	LOGP(DRANAP, LOGL_NOTICE, "handle_co(dir=%u, proc=%u)\n", message->direction, message->procedureCode);

	switch (message->direction) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		switch (message->procedureCode) {
		case RANAP_ProcedureCode_id_InitialUE_Message:
			LOGP(DRANAP, LOGL_ERROR, "Got InitialUE_Message but this is not a new conn\n");
			rc = -1;
			break;
		case RANAP_ProcedureCode_id_DirectTransfer:
			rc = ranap_handle_co_dt(ue_ctx, &message->msg.directTransferIEs);
			break;
		case RANAP_ProcedureCode_id_ErrorIndication:
			rc = ranap_handle_co_err_ind(ue_ctx, &message->msg.errorIndicationIEs);
			break;
		case RANAP_ProcedureCode_id_Iu_ReleaseRequest:
			/* Iu Release Request */
			rc = ranap_handle_co_iu_rel_req(ue_ctx, &message->msg.iu_ReleaseRequestIEs);
			break;
		default:
			LOGP(DRANAP, LOGL_ERROR, "Received Initiating Message: unknown Procedure Code %d\n",
			       message->procedureCode);
			rc = -1;
			break;
		}
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		switch (message->procedureCode) {
		case RANAP_ProcedureCode_id_SecurityModeControl:
			/* Security Mode Complete */
			rc = global_iu_event(ue_ctx, RANAP_IU_EVENT_SECURITY_MODE_COMPLETE, NULL);
			break;
		case RANAP_ProcedureCode_id_Iu_Release:
			/* Iu Release Complete */
			rc = global_iu_event(ue_ctx, RANAP_IU_EVENT_IU_RELEASE, NULL);
			if (rc) {
				LOGP(DRANAP, LOGL_ERROR, "Iu Release event: Iu Event callback returned %d\n",
				       rc);
			}
			break;
		default:
			LOGP(DRANAP, LOGL_ERROR, "Received Successful Outcome: unknown Procedure Code %d\n",
			     message->procedureCode);
			rc = -1;
			break;
		}
		break;
	case RANAP_RANAP_PDU_PR_outcome:
		switch (message->procedureCode) {
		case RANAP_ProcedureCode_id_RAB_Assignment:
			/* RAB Assignment Response */
			rc = ranap_handle_co_rab_ass_resp(ue_ctx, &message->msg.raB_AssignmentResponseIEs);
			break;
		default:
			LOGP(DRANAP, LOGL_ERROR, "Received Outcome: unknown Procedure Code %d\n",
			     message->procedureCode);
			rc = -1;
			break;
		}
		break;
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
	default:
		LOGP(DRANAP, LOGL_ERROR, "Received Unsuccessful Outcome: Procedure Code %d\n",
		     message->procedureCode);
		rc = -1;
		break;
	}

	if (rc) {
		LOGP(DRANAP, LOGL_ERROR, "Error in %s (%d)\n", __func__, rc);
		/* TODO handling of the error? */
	}
}

int sgsn_ranap_iu_rx_co_msg(struct ranap_ue_conn_ctx *ue_ctx, const uint8_t *data, size_t len)
{
	ranap_message message;
	int rc;

	rc = ranap_cn_rx_co_decode2(&message, data, len);
	if (rc != 0) {
		LOGP(DRANAP, LOGL_ERROR, "Not calling cn_ranap_handle_co() due to rc=%d\n", rc);
		goto free_ret;
	}

	cn_ranap_handle_co(ue_ctx, &message);

free_ret:
	/* Free the asn1 structs in message */
	ranap_cn_rx_co_free(&message);
	return rc;
}

static int ranap_handle_cl_reset_req(struct sgsn_sccp_user_iups *scu_iups,
				     const struct osmo_scu_unitdata_param *ud_prim,
				     const RANAP_ResetIEs_t *ies)
{
	const RANAP_GlobalRNC_ID_t *grnc_id = NULL;
	RANAP_Cause_t cause;
	struct osmo_rnc_id rnc_id = {};
	struct msgb *resp;

	if (ies->presenceMask & ERRORINDICATIONIES_RANAP_CN_DOMAININDICATOR_PRESENT) {
		if (ies->cN_DomainIndicator != RANAP_CN_DomainIndicator_ps_domain) {
			LOGP(DRANAP, LOGL_ERROR, "Rx RESET: Unexpected CN Domain Indicator %d\n",
			     (int)ies->cN_DomainIndicator);
			cause = (RANAP_Cause_t){
				.present = RANAP_Cause_PR_protocol,
				.choice.protocol = RANAP_CauseProtocol_semantic_error,
			};
			return sgsn_ranap_iu_tx_error_ind(scu_iups, &ud_prim->calling_addr, &cause);
		}
	} /* else: assume PS */

	/* FIXME: support handling Extended RNC-ID instead of Global RNC-ID */

	if (!(ies->presenceMask & RESETIES_RANAP_GLOBALRNC_ID_PRESENT)) {
		LOGP(DRANAP, LOGL_ERROR,
		     "Rx RESET: Missing RANAP Global-RNC-ID IE\n");
		cause = (RANAP_Cause_t){
			.present = RANAP_Cause_PR_protocol,
			.choice.protocol = RANAP_CauseProtocol_transfer_syntax_error,
		};
		return sgsn_ranap_iu_tx_error_ind(scu_iups, &ud_prim->calling_addr, &cause);
	}
	grnc_id = &ies->globalRNC_ID;

	if (iu_grnc_id_parse(&rnc_id, &ies->globalRNC_ID) != 0) {
		LOGP(DRANAP, LOGL_ERROR,
		     "Rx RESET: Failed to parse RANAP Global-RNC-ID IE\n");
		cause = (RANAP_Cause_t){
			.present = RANAP_Cause_PR_protocol,
			.choice.protocol = RANAP_CauseProtocol_transfer_syntax_error,
		};
		return sgsn_ranap_iu_tx_error_ind(scu_iups, &ud_prim->calling_addr, &cause);
	}

	/* send reset response */
	resp = ranap_new_msg_reset_ack(ies->cN_DomainIndicator, grnc_id);
	if (!resp)
		return -ENOMEM;
	return sgsn_ranap_iu_tx_cl(scu_iups, &ud_prim->calling_addr, resp);
}

static int ranap_handle_cl_err_ind(struct sgsn_sccp_user_iups *scu_iups,
				   const struct osmo_scu_unitdata_param *ud_prim,
				   const RANAP_ErrorIndicationIEs_t *ies)
{
	if (ies->presenceMask & ERRORINDICATIONIES_RANAP_CAUSE_PRESENT)
		LOGP(DRANAP, LOGL_ERROR, "Rx Error Indication (%s)\n",
		     ranap_cause_str(&ies->cause));
	else
		LOGP(DRANAP, LOGL_ERROR, "Rx Error Indication\n");

	return 0;
}

/* Entry point for connection-less RANAP message */
static void cn_ranap_handle_cl(struct sgsn_sccp_user_iups *scu_iups,
			       const struct osmo_scu_unitdata_param *ud_prim,
			       const ranap_message *message)
{
	int rc;

	switch (message->direction) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		switch (message->procedureCode) {
		case RANAP_ProcedureCode_id_Reset:
			/* received reset.req, send reset.resp */
			rc = ranap_handle_cl_reset_req(scu_iups, ud_prim, &message->msg.resetIEs);
			break;
		case RANAP_ProcedureCode_id_ErrorIndication:
			rc = ranap_handle_cl_err_ind(scu_iups, ud_prim, &message->msg.errorIndicationIEs);
			break;
		default:
			rc = -1;
			break;
		}
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
	case RANAP_RANAP_PDU_PR_outcome:
	default:
		rc = -1;
		break;
	}

	if (rc) {
		LOGP(DRANAP, LOGL_ERROR, "Error in %s (%d)\n", __func__, rc);
		/* TODO handling of the error? */
	}
}

int sgsn_ranap_iu_rx_cl_msg(struct sgsn_sccp_user_iups *scu_iups,
			    const struct osmo_scu_unitdata_param *ud_prim,
			    const uint8_t *data, size_t len)
{
	ranap_message message;
	int rc;

	rc = ranap_cn_rx_cl_decode2(&message, data, len);
	if (rc != 0) {
		LOGP(DRANAP, LOGL_ERROR, "Not calling cn_ranap_handle_cl() due to rc=%d\n", rc);
		goto free_ret;
	}

	cn_ranap_handle_cl(scu_iups, ud_prim, &message);

free_ret:
	/* Free the asn1 structs in message */
	ranap_cn_rx_cl_free(&message);
	return rc;
}
