/* GPRS SGSN integration with libgtp of OpenGGSN */
/* libgtp implements the GPRS Tunelling Protocol GTP per TS 09.60 / 29.060 */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * (C) 2015 by Holger Hans Peter Freyther
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/gtp/gtp.h>
#include <osmocom/gtp/pdp.h>

#include <osmocom/sgsn/signal.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_ns.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_routing_area.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_sm.h>
#include <osmocom/sgsn/gprs_subscriber.h>
#include <osmocom/sgsn/gprs_sndcp.h>
#include <osmocom/sgsn/gprs_ranap.h>
#include <osmocom/sgsn/gprs_gmm_fsm.h>
#include <osmocom/sgsn/gprs_mm_state_gb_fsm.h>
#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>
#include <osmocom/sgsn/gtp_ggsn.h>
#include <osmocom/sgsn/gtp_mme.h>
#include <osmocom/sgsn/sgsn_rim.h>
#include <osmocom/sgsn/gprs_bssgp.h>
#include <osmocom/sgsn/pdpctx.h>

/* TS 23.003: The MSISDN shall take the dummy MSISDN value composed of
 * 15 digits set to 0 (encoded as an E.164 international number) when
 * the MSISDN is not available in messages in which the presence of the
 * MSISDN parameter */
static const uint8_t dummy_msisdn[] =
	{ 0x91, /* No extension, international, E.164 */
	  0, 0, 0, 0, 0, 0, 0, /* 14 digits of zeroes */
	  0xF0 /* 15th digit of zero + padding */ };

const struct value_string gtp_cause_strs[] = {
	{ GTPCAUSE_REQ_IMSI, "Request IMSI" },
	{ GTPCAUSE_REQ_IMEI, "Request IMEI" },
	{ GTPCAUSE_REQ_IMSI_IMEI, "Request IMSI and IMEI" },
	{ GTPCAUSE_NO_ID_NEEDED, "No identity needed" },
	{ GTPCAUSE_MS_REFUSES_X, "MS refuses" },
	{ GTPCAUSE_MS_NOT_RESP_X, "MS is not GPRS responding" },
	{ GTPCAUSE_ACC_REQ, "Request accepted" },
	{ GTPCAUSE_NON_EXIST, "Non-existent" },
	{ GTPCAUSE_INVALID_MESSAGE, "Invalid message format" },
	{ GTPCAUSE_IMSI_NOT_KNOWN, "IMSI not known" },
	{ GTPCAUSE_MS_DETACHED, "MS is GPRS detached" },
	{ GTPCAUSE_MS_NOT_RESP, "MS is not GPRS responding" },
	{ GTPCAUSE_MS_REFUSES, "MS refuses" },
	{ GTPCAUSE_NO_RESOURCES, "No resources available" },
	{ GTPCAUSE_NOT_SUPPORTED, "Service not supported" },
	{ GTPCAUSE_MAN_IE_INCORRECT, "Mandatory IE incorrect" },
	{ GTPCAUSE_MAN_IE_MISSING, "Mandatory IE missing" },
	{ GTPCAUSE_OPT_IE_INCORRECT, "Optional IE incorrect" },
	{ GTPCAUSE_SYS_FAIL, "System failure" },
	{ GTPCAUSE_ROAMING_REST, "Roaming restrictions" },
	{ GTPCAUSE_PTIMSI_MISMATCH, "P-TMSI Signature mismatch" },
	{ GTPCAUSE_CONN_SUSP, "GPRS connection suspended" },
	{ GTPCAUSE_AUTH_FAIL, "Authentication failure" },
	{ GTPCAUSE_USER_AUTH_FAIL, "User authentication failed" },
	{ GTPCAUSE_CONTEXT_NOT_FOUND, "Context not found" },
	{ GTPCAUSE_ADDR_OCCUPIED, "All dynamic PDP addresses occupied" },
	{ GTPCAUSE_NO_MEMORY, "No memory is available" },
	{ GTPCAUSE_RELOC_FAIL, "Relocation failure" },
	{ GTPCAUSE_UNKNOWN_MAN_EXTHEADER, "Unknown mandatory ext. header" },
	{ GTPCAUSE_SEM_ERR_TFT, "Semantic error in TFT operation" },
	{ GTPCAUSE_SYN_ERR_TFT, "Syntactic error in TFT operation" },
	{ GTPCAUSE_SEM_ERR_FILTER, "Semantic errors in packet filter" },
	{ GTPCAUSE_SYN_ERR_FILTER, "Syntactic errors in packet filter" },
	{ GTPCAUSE_MISSING_APN, "Missing or unknown APN" },
	{ GTPCAUSE_UNKNOWN_PDP, "Unknown PDP address or PDP type" },
	{ 0, NULL }
};

/* Generate the GTP IMSI IE according to 09.60 Section 7.9.2 */
static uint64_t imsi_str2gtp(char *str)
{
	uint64_t imsi64 = 0;
	unsigned int n;
	unsigned int imsi_len = strlen(str);

	if (imsi_len > 16) {
		LOGP(DGPRS, LOGL_NOTICE, "IMSI length > 16 not supported!\n");
		return 0;
	}

	for (n = 0; n < 16; n++) {
		uint64_t val;
		if (n < imsi_len)
			val = (str[n]-'0') & 0xf;
		else
			val = 0xf;
		imsi64 |= (val << (n*4));
	}
	return imsi64;
}

/* generate a PDP context based on the IE's from the 04.08 message,
 * and send the GTP create pdp context request to the GGSN */
struct sgsn_pdp_ctx *sgsn_create_pdp_ctx(struct sgsn_ggsn_ctx *ggsn,
					 struct sgsn_mm_ctx *mmctx,
					 uint16_t nsapi,
					 struct tlv_parsed *tp)
{
	struct osmo_routing_area_id rai = {};
	struct sgsn_pdp_ctx *pctx;
	struct pdp_t *pdp;
	uint64_t imsi_ui64;
	size_t qos_len;
	const uint8_t *qos;
	int rc;

	pctx = sgsn_pdp_ctx_alloc(mmctx, ggsn, nsapi);
	if (!pctx) {
		LOGP(DGPRS, LOGL_ERROR, "Couldn't allocate PDP Ctx\n");
		return NULL;
	}

	imsi_ui64 = imsi_str2gtp(mmctx->imsi);

	rc = gtp_pdp_newpdp(ggsn->gsn, &pdp, imsi_ui64, nsapi, NULL);
	if (rc) {
		LOGP(DGPRS, LOGL_ERROR, "Out of libgtp PDP Contexts\n");
		return NULL;
	}
	pdp->priv = pctx;
	pctx->lib = pdp;

	/* Back up our own local TEID in case we update the library one with RNC TEID when setting up Direct Tunnel: */
	pctx->sgsn_teid_own = pdp->teid_own;

	//pdp->peer =	/* sockaddr_in of GGSN (receive) */
	//pdp->ipif =	/* not used by library */
	pdp->version = ggsn->gtp_version;
	pdp->hisaddr0 =	ggsn->remote_addr;
	pdp->hisaddr1 = ggsn->remote_addr;
	//pdp->cch_pdp = 512;	/* Charging Flat Rate */
	pdp->radio_pri = 0x4;

	/* MS provided APN, subscription was verified by the caller */
	pdp->selmode = 0xFC | 0x00;

	/* IMSI, TEID/TEIC, FLLU/FLLC, TID, NSAPI set in pdp_newpdp */
	LOGPDPCTXP(LOGL_NOTICE, pctx, "Create PDP Context\n");

	/* Put the MSISDN in case we have it */
	if (mmctx->subscr && mmctx->subscr->sgsn_data->msisdn_len) {
		pdp->msisdn.l = OSMO_MIN(mmctx->subscr->sgsn_data->msisdn_len, sizeof(pdp->msisdn.v));
		memcpy(pdp->msisdn.v, mmctx->subscr->sgsn_data->msisdn,
			pdp->msisdn.l);
	} else {
		/* use the dummy 15-digits-zero MSISDN value */
		pdp->msisdn.l = sizeof(dummy_msisdn);
		memcpy(pdp->msisdn.v, dummy_msisdn, pdp->msisdn.l);
	}

	/* End User Address from GMM requested PDP address */
	pdp->eua.l = TLVP_LEN(tp, OSMO_IE_GSM_REQ_PDP_ADDR);
	if (pdp->eua.l > sizeof(pdp->eua.v))
		pdp->eua.l = sizeof(pdp->eua.v);
	memcpy(pdp->eua.v, TLVP_VAL(tp, OSMO_IE_GSM_REQ_PDP_ADDR),
		pdp->eua.l);
	/* Highest 4 bits of first byte need to be set to 1, otherwise
	 * the IE is identical with the 04.08 PDP Address IE */
	pdp->eua.v[0] |= 0xf0;

	/* APN name from GMM */
	if (TLVP_PRESENT(tp, GSM48_IE_GSM_APN)) {
		pdp->apn_use.l = TLVP_LEN(tp, GSM48_IE_GSM_APN);
		if (pdp->apn_use.l > sizeof(pdp->apn_use.v))
			pdp->apn_use.l = sizeof(pdp->apn_use.v);
		memcpy(pdp->apn_use.v, TLVP_VAL(tp, GSM48_IE_GSM_APN), pdp->apn_use.l);
	} else {
		pdp->apn_use.l = 0;
	}

	/* Protocol Configuration Options from GMM */
	if (TLVP_PRESENT(tp, GSM48_IE_GSM_PROTO_CONF_OPT)) {
		pdp->pco_req.l = TLVP_LEN(tp, GSM48_IE_GSM_PROTO_CONF_OPT);
		if (pdp->pco_req.l > sizeof(pdp->pco_req.v))
			pdp->pco_req.l = sizeof(pdp->pco_req.v);
		memcpy(pdp->pco_req.v, TLVP_VAL(tp, GSM48_IE_GSM_PROTO_CONF_OPT),
		       pdp->pco_req.l);
	} else {
		pdp->pco_req.l = 0;
	}

	/* QoS options from GMM or remote */
	if (TLVP_LEN(tp, OSMO_IE_GSM_SUB_QOS) > 0) {
		qos_len = TLVP_LEN(tp, OSMO_IE_GSM_SUB_QOS);
		qos = TLVP_VAL(tp, OSMO_IE_GSM_SUB_QOS);
	} else {
		qos_len = TLVP_LEN(tp, OSMO_IE_GSM_REQ_QOS);
		qos = TLVP_VAL(tp, OSMO_IE_GSM_REQ_QOS);
	}

	pdp->qos_req.l = qos_len + 1;
	if (pdp->qos_req.l > sizeof(pdp->qos_req.v))
		pdp->qos_req.l = sizeof(pdp->qos_req.v);
	pdp->qos_req.v[0] = 0; /* Allocation/Retention policy */
	memcpy(&pdp->qos_req.v[1], qos, pdp->qos_req.l - 1);

	/* charging characteristics if present */
	if (TLVP_LEN(tp, OSMO_IE_GSM_CHARG_CHAR) >= sizeof(pdp->cch_pdp))
		pdp->cch_pdp = tlvp_val16be(tp, OSMO_IE_GSM_CHARG_CHAR);

	/* SGSN address for control plane */
	pdp->gsnlc.l = sizeof(sgsn->cfg.gtp_listenaddr.sin_addr);
	memcpy(pdp->gsnlc.v, &sgsn->cfg.gtp_listenaddr.sin_addr,
		sizeof(sgsn->cfg.gtp_listenaddr.sin_addr));

	/* SGSN address for user plane
	 * Default to the control plane addr for now. If we are connected to a
	 * hnbgw via IuPS we'll need to send a PDP context update with the
	 * correct IP address after the RAB Assignment is complete */
	pdp->gsnlu.l = sizeof(sgsn->cfg.gtp_listenaddr.sin_addr);
	memcpy(pdp->gsnlu.v, &sgsn->cfg.gtp_listenaddr.sin_addr,
		sizeof(sgsn->cfg.gtp_listenaddr.sin_addr));

	/* Encode RAT Type according to TS 29.060 7.7.50 */
	pdp->rattype.l = 1;
	if (mmctx->ran_type == MM_CTX_T_UTRAN_Iu)
		pdp->rattype.v[0] = 1;
	else
		pdp->rattype.v[0] = 2;
	pdp->rattype_given = 1;

	/* Include RAI and ULI all the time */
	pdp->rai_given = 1;
	pdp->rai.l = 6;

	/* Routing Area Identifier with LAC and RAC fixed values, as
	 * requested in 29.006 7.3.1 */
	rai = mmctx->ra;
	rai.lac.lac = 0xFFFE;
	rai.rac = 0xFF;
	osmo_routing_area_id_encode_buf(pdp->rai.v, pdp->rai.l, &rai);

	/* Encode User Location Information accordint to TS 29.060 7.7.51 */
	pdp->userloc_given = 1;
	pdp->userloc.l = 8;
	switch (mmctx->ran_type) {
	case MM_CTX_T_GERAN_Gb:
#if 0
	case MM_CTX_T_GERAN_Iu:
#endif
		pdp->rattype.v[0] = 2;
		/* User Location Information */
		pdp->userloc_given = 1;
		pdp->userloc.l = 8;
		pdp->userloc.v[0] = 0; /* CGI for GERAN */
		bssgp_create_cell_id2(&pdp->userloc.v[1], 8, &mmctx->ra, mmctx->gb.cell_id);
		break;
	case MM_CTX_T_UTRAN_Iu:
		pdp->userloc.v[0] = 1; /* SAI for UTRAN */
		/* SAI is like CGI but with SAC instead of CID, so we can abuse this function */
		bssgp_create_cell_id2(&pdp->userloc.v[1], 8, &mmctx->ra, mmctx->iu.sac);
		break;
	}

	/* optional include the IMEI(SV) */
	if (mmctx->imei[0] != '\0') {
		memset(&pdp->imeisv.v[0], 0, 8);
		pdp->imeisv_given = 1;
		gsm48_encode_bcd_number(&pdp->imeisv.v[0], 8, 0, mmctx->imei);
		pdp->imeisv.l = 8;
		memmove(&pdp->imeisv.v[0], &pdp->imeisv.v[1], 8);
	}

	/* change pdp state to 'requested' */
	pctx->state = PDP_STATE_CR_REQ;

	rc = gtp_create_context_req(ggsn->gsn, pdp, pctx);
	/* FIXME */

	return pctx;
}

/* SGSN wants to delete a PDP context, send first DeleteCtxReq on the GTP side,
   then upon DeleteCtx ACK it will send DeactPdpAcc to the MS if still
   connected. */
int sgsn_delete_pdp_ctx(struct sgsn_pdp_ctx *pctx)
{
	LOGPDPCTXP(LOGL_INFO, pctx, "Delete PDP Context\n");

	OSMO_ASSERT(pctx->ggsn);
	OSMO_ASSERT(pctx->lib);

	/* FIXME: decide if we need teardown or not ! */
	return gtp_delete_context_req2(pctx->ggsn->gsn, pctx->lib, pctx, 1);
}

struct cause_map {
	uint8_t cause_in;
	uint8_t cause_out;
};

static uint8_t cause_map(const struct cause_map *map, uint8_t in, uint8_t deflt)
{
	const struct cause_map *m;

	for (m = map; m->cause_in && m->cause_out; m++) {
		if (m->cause_in == in)
			return m->cause_out;
	}
	return deflt;
}

/* how do we map from gtp cause to SM cause */
static const struct cause_map gtp2sm_cause_map[] = {
	{ GTPCAUSE_NO_RESOURCES, 	GSM_CAUSE_INSUFF_RSRC },
	{ GTPCAUSE_NOT_SUPPORTED,	GSM_CAUSE_SERV_OPT_NOTSUPP },
	{ GTPCAUSE_MAN_IE_INCORRECT,	GSM_CAUSE_INV_MAND_INFO },
	{ GTPCAUSE_MAN_IE_MISSING,	GSM_CAUSE_INV_MAND_INFO },
	{ GTPCAUSE_OPT_IE_INCORRECT,	GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_SYS_FAIL,		GSM_CAUSE_NET_FAIL },
	{ GTPCAUSE_ROAMING_REST,	GSM_CAUSE_REQ_SERV_OPT_NOTSUB },
	{ GTPCAUSE_PTIMSI_MISMATCH,	GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_CONN_SUSP,		GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_AUTH_FAIL,		GSM_CAUSE_AUTH_FAILED },
	{ GTPCAUSE_USER_AUTH_FAIL,	GSM_CAUSE_ACT_REJ_GGSN },
	{ GTPCAUSE_CONTEXT_NOT_FOUND,	GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_ADDR_OCCUPIED,	GSM_CAUSE_INSUFF_RSRC },
	{ GTPCAUSE_NO_MEMORY,		GSM_CAUSE_INSUFF_RSRC },
	{ GTPCAUSE_RELOC_FAIL,		GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_UNKNOWN_MAN_EXTHEADER, GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_MISSING_APN,		GSM_CAUSE_MISSING_APN },
	{ GTPCAUSE_UNKNOWN_PDP,		GSM_CAUSE_UNKNOWN_PDP },
	{ 0, 0 }
};

int send_act_pdp_cont_acc(struct sgsn_pdp_ctx *pctx)
{
	struct sgsn_signal_data sig_data;
	int rc;
	struct gprs_llc_lle *lle;

	/* Inform others about it */
	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.pdp = pctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_PDP_ACT, &sig_data);

	/* Send PDP CTX ACT to MS */
	rc = gsm48_tx_gsm_act_pdp_acc(pctx);
	if (rc < 0)
		return rc;
	pctx->ue_pdp_active = true;

	if (pctx->mm->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Send SNDCP XID to MS */
		lle = &pctx->mm->gb.llme->lle[pctx->sapi];
		rc = sndcp_sn_xid_req(lle,pctx->nsapi);
		if (rc < 0)
			return rc;
	}

	return 0;
}

/* The GGSN has confirmed the creation of a PDP Context */
static int create_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
{
	struct sgsn_pdp_ctx *pctx = cbp;
	uint8_t reject_cause = 0;

	LOGPDPCTXP(LOGL_INFO, pctx, "Received CREATE PDP CTX CONF, cause=%d(%s)\n",
		cause, get_value_string(gtp_cause_strs, cause));

	if (!pctx->mm) {
		goto reject;
	}

	/* Check for cause value if it was really successful */
	if (cause < 0) {
		LOGP(DGPRS, LOGL_NOTICE, "Create PDP ctx req timed out\n");
		if (pdp && pdp->version == 1) {
			pdp->version = 0;
			gtp_create_context_req(sgsn->gsn, pdp, cbp);
			return 0;
		} else {
			reject_cause = GSM_CAUSE_NET_FAIL;
			goto reject;
		}
	}

	/* Check for cause value if it was really successful */
	if (!gtp_cause_successful(cause)) {
		reject_cause = cause_map(gtp2sm_cause_map, cause,
					 GSM_CAUSE_ACT_REJ_GGSN);
		goto reject;
	}

	if (pctx->mm->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Activate the SNDCP layer */
		sndcp_sm_activate_ind(&pctx->mm->gb.llme->lle[pctx->sapi], pctx->nsapi);
		return send_act_pdp_cont_acc(pctx);
	} else if (pctx->mm->ran_type == MM_CTX_T_UTRAN_Iu) {
#ifdef BUILD_IU
		/* Activate a radio bearer */
		iu_rab_act_ps(pdp->nsapi, pctx);
		return 0;
#else
		return -ENOTSUP;
#endif
	}

	LOGP(DGPRS, LOGL_ERROR, "Unknown ran_type %d\n",
	     pctx->mm->ran_type);
	reject_cause = GSM_CAUSE_PROTO_ERR_UNSPEC;

reject:
	/*
	 * In case of a timeout pdp will be NULL but we have a valid pointer
	 * in pctx->lib. For other rejects pctx->lib and pdp might be the
	 * same.
	 */
	pctx->state = PDP_STATE_NONE;
	if (pctx->lib && pctx->lib != pdp)
		pdp_freepdp(pctx->lib);
	pctx->lib = NULL;

	if (pdp)
		pdp_freepdp(pdp);

	/* Send PDP CTX ACT REJ to MS */
	if (pctx->mm)
		gsm48_tx_gsm_act_pdp_rej(pctx->mm, pctx->ti, reject_cause,
					 0, NULL);
	sgsn_pdp_ctx_free(pctx);

	return EOF;
}

void sgsn_ggsn_echo_req(struct sgsn_ggsn_ctx *ggc)
{
	LOGGGSN(ggc, LOGL_INFO, "GTP Tx Echo Request\n");
	gtp_echo_req(ggc->gsn, ggc->gtp_version, ggc, &ggc->remote_addr);
}

int sgsn_mme_ran_info_req(struct sgsn_mme_ctx *mme, const struct bssgp_ran_information_pdu *pdu)
{
	char ri_src_str[64], ri_dest_str[64];
	int ri_len;
	struct msgb *msg;
	struct bssgp_normal_hdr *bgph;
	int rc;
	uint8_t ri_buf[64];
	uint8_t *ri_ptr = &ri_buf[0];
	struct sockaddr_in sk_in = {
		.sin_family = AF_INET,
		.sin_port = htons(GTP1C_PORT),
		.sin_addr = mme->remote_addr,
	};

	msg = bssgp_encode_rim_pdu(pdu);
	if (!msg) {
		LOGMME(mme, DRIM, LOGL_ERROR, "Tx GTP RAN Information Relay: failed to encode pdu\n");
		return -EINVAL;
	}
	bgph = (struct bssgp_normal_hdr *)msgb_bssgph(msg);
	DEBUGP(DLBSSGP, "Tx GTP RAN Information Relay: RIM-PDU:%s, src=%s, dest=%s\n",
	       bssgp_pdu_str(bgph->pdu_type),
	       bssgp_rim_ri_name_buf(ri_src_str, sizeof(ri_src_str), &pdu->routing_info_src),
	       bssgp_rim_ri_name_buf(ri_dest_str, sizeof(ri_dest_str), &pdu->routing_info_dest));

	if ((ri_len = bssgp_create_rim_ri(ri_ptr, &pdu->routing_info_dest)) < 0) {
		ri_ptr = NULL;
		ri_len = 0;
	}

	rc = gtp_ran_info_relay_req(mme->sgsn->gsn,  &sk_in, msgb_data(msg), msgb_length(msg),
				    ri_ptr, ri_len, pdu->routing_info_dest.discr);
	msgb_free(msg);
	return rc;
}

/* Confirmation of a PDP Context Update */
static int update_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
{
	struct sgsn_pdp_ctx *pctx = cbp;
	int rc;

	LOGPDPCTXP(LOGL_INFO, pctx, "Received Update PDP CTX CONF, cause=%d(%s)\n",
		cause, get_value_string(gtp_cause_strs, cause));

	/* 3GPP TS 29.060 "7.3.4":
	 * "If the SGSN receives an Update PDP Context Response with a Cause
	 * value other than "Request accepted", it shall abort the update of the
	 * PDP context.""
	 * "If the SGSN receives an Update PDP Context Response with
	 * a Cause value "Non-existent", it shall delete the PDP Context."
	 */
	if (cause != GTPCAUSE_NON_EXIST)
		 return 0; /* Nothing to do */

	LOGPDPCTXP(LOGL_INFO, pctx, "PDP CTX we tried to update doesn't exist in "
		   "the GGSN anymore, deleting it locally.\n");

	rc = gtp_freepdp(pctx->ggsn->gsn, pctx->lib);
	/* related mmctx is torn down in cb_delete_context called by gtp_freepdp() */
	return rc;
}

/* Confirmation of a PDP Context Delete */
static int delete_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
{
	struct sgsn_signal_data sig_data;
	struct sgsn_pdp_ctx *pctx = cbp;
	int rc = 0;

	LOGPDPCTXP(LOGL_INFO, pctx, "Received DELETE PDP CTX CONF, cause=%d(%s)\n",
		cause, get_value_string(gtp_cause_strs, cause));

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.pdp = pctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_PDP_DEACT, &sig_data);

	if (pctx->mm) {
		if (pctx->mm->ran_type == MM_CTX_T_GERAN_Gb) {
			/* Deactivate the SNDCP layer */
			sndcp_sm_deactivate_ind(&pctx->mm->gb.llme->lle[pctx->sapi], pctx->nsapi);
		} else {
#ifdef BUILD_IU
			/* Deactivate radio bearer */
			ranap_iu_rab_deact(pctx->mm->iu.ue_ctx, 1);
#else
			return -ENOTSUP;
#endif
		}
		if (pctx->ue_pdp_active) {
			/* Confirm deactivation of PDP context to MS */
			rc = gsm48_tx_gsm_deact_pdp_acc(pctx);
			pctx->ue_pdp_active = false;
		}
	} else {
		LOGPDPCTXP(LOGL_NOTICE, pctx,
			   "Not deactivating SNDCP layer since the MM context "
			   "is not available\n");
	}

	sgsn_pdp_ctx_free(pctx);

	return rc;
}

/* Confirmation of an GTP ECHO request */
static int echo_conf(void *cbp, bool timeout)
{
	struct sgsn_ggsn_ctx *ggc = (struct sgsn_ggsn_ctx *)cbp;
	if (timeout) {
		LOGGGSN(ggc, LOGL_NOTICE, "GTP Echo Request timed out\n");
		/* FIXME: if version == 1, retry with version 0 */
		sgsn_ggsn_ctx_drop_all_pdp(ggc);
	} else {
		LOGGGSN(ggc, LOGL_INFO, "GTP Rx Echo Response\n");
	}
	return 0;
}

/* Any message received by GGSN contains a recovery IE */
static int cb_recovery3(struct gsn_t *gsn, struct sockaddr_in *peer, struct pdp_t *pdp, uint8_t recovery)
{
	struct sgsn_ggsn_ctx *ggsn;
	struct sgsn_pdp_ctx *pctx = NULL;

	ggsn = sgsn_ggsn_ctx_by_addr(sgsn, &peer->sin_addr);
	if (!ggsn) {
		LOGP(DGPRS, LOGL_NOTICE, "Received Recovery IE for unknown GGSN\n");
		return -EINVAL;
	}

	if (ggsn->remote_restart_ctr == -1) {
		/* First received ECHO RESPONSE, note the restart ctr */
		ggsn->remote_restart_ctr = recovery;
	} else if (ggsn->remote_restart_ctr != recovery) {
		/* counter has changed (GGSN restart): release all PDP */
		LOGP(DGPRS, LOGL_NOTICE, "GGSN recovery (%u->%u) pdp=%p, "
		     "releasing all%s PDP contexts\n",
		     ggsn->remote_restart_ctr, recovery, pdp, pdp ? " other" : "");
		ggsn->remote_restart_ctr = recovery;
		if (pdp)
			pctx = pdp->priv;
		sgsn_ggsn_ctx_drop_all_pdp_except(ggsn, pctx);
	}
	return 0;
}

/* libgtp callback for confirmations */
static int cb_conf(int type, int cause, struct pdp_t *pdp, void *cbp)
{
	DEBUGP(DGPRS, "libgtp cb_conf(type=%d, cause=%d, pdp=%p, cbp=%p)\n",
		type, cause, pdp, cbp);

	if (cause == EOF)
		LOGP(DGPRS, LOGL_ERROR, "libgtp EOF (type=%u, pdp=%p, cbp=%p)\n",
			type, pdp, cbp);

	switch (type) {
	case GTP_ECHO_REQ:
		/* libgtp hands us the RECOVERY number instead of a cause (EOF on timeout) */
		return echo_conf(cbp, cause == EOF);
	case GTP_CREATE_PDP_REQ:
		return create_pdp_conf(pdp, cbp, cause);
	case GTP_UPDATE_PDP_REQ:
		return update_pdp_conf(pdp, cbp, cause);
	case GTP_DELETE_PDP_REQ:
		return delete_pdp_conf(pdp, cbp, cause);
	default:
		break;
	}
	return 0;
}

/* Called whenever a PDP context is updated from the GGSN for any reason */
static int cb_update_context_ind(struct pdp_t *pdp)
{
	struct sgsn_pdp_ctx *pctx;
	struct sgsn_mm_ctx *mm;
	int rc;

	LOGPDPX(DGPRS, LOGL_INFO, pdp, "Context %p was updated\n", pdp);

	pctx = pdp->priv;
	if (!pctx) {
		LOGP(DGPRS, LOGL_NOTICE,
		     "GTP DATA IND from GGSN for unknown PDP\n");
		return -EIO;
	}
	mm = pctx->mm;
	if (!mm) {
		LOGP(DGPRS, LOGL_ERROR,
		     "PDP context (address=%u) without MM context!\n",
		     pctx->address);
		return -EIO;
	}

	if (mm->ran_type == MM_CTX_T_UTRAN_Iu) {
#ifdef BUILD_IU
		if (pdp->dir_tun_flags.v[0] & 0x04) { /* EI bit set ? */
			/* GGSN informed us that it received an Error Indication when sending DL data to the RNC.
			 * This probably means the RNC lost its state, aka crashed or was rebooted.
			 * Page the UE so it re-creates the state at the RNC. */
			LOGMMCTXP(LOGL_INFO, mm,
				  "GGSN received ErrorInd from RNC while tx DL data. Paging UE in state %s\n",
				  osmo_fsm_inst_state_name(mm->gmm_fsm));
			rc = osmo_fsm_inst_dispatch(mm->iu.mm_state_fsm, E_PMM_RX_GGSN_GTPU_DT_EI, pctx);
			rc = gtp_update_context_resp(sgsn->gsn, pdp,
				 GTPCAUSE_ACC_REQ);
			ranap_iu_page_ps(mm->imsi, &mm->p_tmsi, mm->ra.lac.lac, mm->ra.rac);
			return rc;
		}
#endif
	}

	rc = gtp_update_context_resp(sgsn->gsn, pdp,
				 GTPCAUSE_ACC_REQ);
	return rc;
}

/* Called whenever a PDP context is deleted for any reason */
static int cb_delete_context(struct pdp_t *pdp)
{
	struct sgsn_pdp_ctx *pctx = pdp->priv;

	LOGPDPX(DGPRS, LOGL_INFO, pdp, "Context %p was deleted\n", pdp);

	/* unlink the now non-existing library handle from the pdp context.
	   This way we avoid calling pdp_freepdp() on it, since after returning
	   from cb_delete_context callback, libgtp is already doing so. */
	pctx->lib = NULL;

	sgsn_ggsn_ctx_drop_pdp(pctx);
	return 0;
}

/* Called when we receive a Version Not Supported message */
static int cb_unsup_ind(struct sockaddr_in *peer)
{
	LOGP(DGPRS, LOGL_INFO, "GTP Version not supported Indication "
		"from %s:%u\n", inet_ntoa(peer->sin_addr),
		ntohs(peer->sin_port));
	return 0;
}

/* Called when we receive a Supported Ext Headers Notification */
static int cb_extheader_ind(struct sockaddr_in *peer)
{
	LOGP(DGPRS, LOGL_INFO, "GTP Supported Ext Headers Notification "
		"from %s:%u\n", inet_ntoa(peer->sin_addr),
		ntohs(peer->sin_port));
	return 0;
}

static int cb_gtp_ran_info_relay_ind(struct sockaddr_in *peer, union gtpie_member **ie)
{
	char addrbuf[INET_ADDRSTRLEN];
	struct sgsn_mme_ctx *mme = sgsn_mme_ctx_by_addr(sgsn, &peer->sin_addr);
	if (!mme) {
		LOGP(DGTP, LOGL_NOTICE, "Rx GTP RAN Information Relay from unknown MME %s\n",
		     inet_ntop(AF_INET, &peer->sin_addr, addrbuf, sizeof(addrbuf)));
		return -ECONNREFUSED;
	}

	LOGMME(mme, DGTP, LOGL_INFO, "Rx GTP RAN Information Relay\n");

	int rc;
	unsigned int len = 0;
	struct msgb *msg = bssgp_msgb_alloc();

	uint8_t rim_ra_encoded[256];
	unsigned int rim_ra_encoded_len = 0;
	struct bssgp_rim_routing_info rim_ra;

	unsigned int rim_ra_discr_encoded_len = 0;
	uint8_t rim_ra_discr;

	/* Read RIM Routing Address Discriminator (optional) */
	rc = gtpie_gettlv(ie, GTPIE_RIM_RA_DISCR, 0, &rim_ra_discr_encoded_len, &rim_ra_discr,
			  sizeof(rim_ra_discr));
	if (rc || rim_ra_discr_encoded_len <= 0) {
		LOGMME(mme, DGTP, LOGL_NOTICE, "Rx GTP RAN Information Relay: No RIM Routing Address Discriminator IE found!\n");

		/* It is not an error when the RIM ROUTING ADDRESS DISCRIMINATOR IE is missing. The RIM ROUTING ADDRESS
		 * DISCRIMINATOR IE is an optional IE. When it is missing, the RIM Routing Address shall be processed
		 * as an RNC address ("0001")  See also: 3GPP TS 29.060 */
		rim_ra_discr = BSSGP_RIM_ROUTING_INFO_UTRAN;
	}

	/* Read RIM Routing Address (optional) */
	rc = gtpie_gettlv(ie, GTPIE_RIM_ROUT_ADDR, 0, &rim_ra_encoded_len, rim_ra_encoded, sizeof(rim_ra_encoded));
	if (rc || rim_ra_encoded_len <= 0) {
		LOGMME(mme, DGTP, LOGL_ERROR, "Rx GTP RAN Information Relay: No RIM Routing Address IE found!\n");

		/* TODO: The (usually included) RIM ROUTING ADDRESS field is an optional field. However, we cannot
		 * proceed without a destination address. A possible way to fix this would be a default route that
		 * can be configured via the VTY. */
		goto ret_error;
	} else {
		rc = bssgp_parse_rim_ra(&rim_ra, rim_ra_encoded, rim_ra_encoded_len, rim_ra_discr);
		if (rc < 0) {
			LOGMME(mme, DGTP, LOGL_ERROR,
			       "Rx GTP RAN Information Relay: Failed parsing RIM Routing Address/RIM Routing Address Discriminator IE!\n");
			goto ret_error;
		}
	}

	if (gtpie_gettlv(ie, GTPIE_RAN_T_CONTAIN, 0, &len, msgb_data(msg), 4096) || len <= 0) {
		LOGMME(mme, DGTP, LOGL_ERROR, "Rx GTP RAN Information Relay: No Transparent Container IE found!\n");
		goto ret_error;
	}
	msgb_put(msg, len);
	msgb_bssgph(msg) = msg->data;
	msgb_nsei(msg) = 0;

	return sgsn_rim_rx_from_gtp(msg, &rim_ra);

ret_error:
	msgb_free(msg);
	return -EINVAL;
}

/* Called whenever we receive a DATA packet */
static int cb_data_ind(struct pdp_t *lib, void *packet, unsigned int len)
{
	struct sgsn_pdp_ctx *pdp;
	struct sgsn_mm_ctx *mm;
	struct msgb *msg;
	uint8_t *ud;

	pdp = lib->priv;
	if (!pdp) {
		LOGP(DGPRS, LOGL_NOTICE,
		     "GTP DATA IND from GGSN for unknown PDP\n");
		return -EIO;
	}
	mm = pdp->mm;
	if (!mm) {
		LOGP(DGPRS, LOGL_ERROR,
		     "PDP context (address=%u) without MM context!\n",
		     pdp->address);
		return -EIO;
	}

	DEBUGP(DGPRS, "GTP DATA IND from GGSN for %s, length=%u\n", mm->imsi,
	       len);

	if (mm->ran_type == MM_CTX_T_UTRAN_Iu) {
#ifdef BUILD_IU
		/* Ignore the packet for now and page the UE to get the RAB
		 * reestablished */
		LOGMMCTXP(LOGL_INFO, mm, "Rx GTP for UE in PMM state %s, paging it\n",
			  osmo_fsm_inst_state_name(mm->iu.mm_state_fsm));
		ranap_iu_page_ps(mm->imsi, &mm->p_tmsi, mm->ra.lac.lac, mm->ra.rac);

		return 0;
#else
		return -ENOTSUP;
#endif
	}

	msg = msgb_alloc_headroom(len+256, 128, "GTP->SNDCP");
	ud = msgb_put(msg, len);
	memcpy(ud, packet, len);

	msgb_tlli(msg) = mm->gb.tlli;
	msgb_bvci(msg) = mm->gb.bvci;
	msgb_nsei(msg) = mm->gb.nsei;

	switch (mm->gmm_fsm->state) {
	case ST_GMM_REGISTERED_SUSPENDED:
		LOGMMCTXP(LOGL_INFO, mm, "Dropping DL packet for MS in GMM state %s\n",
			  osmo_fsm_inst_state_name(mm->gmm_fsm));
		msgb_free(msg);
		return -1;
	case ST_GMM_REGISTERED_NORMAL:
		switch (mm->gb.mm_state_fsm->state) {
		case ST_MM_IDLE:
			LOGP(DGPRS, LOGL_ERROR, "Dropping DL packet for MS in MM state %s\n",
			     osmo_fsm_inst_state_name(mm->gb.mm_state_fsm));
			msgb_free(msg);
			return -1;
		case ST_MM_READY:
			/* Go ahead */
			break;
		case ST_MM_STANDBY:
			LOGMMCTXP(LOGL_INFO, mm, "Paging MS in GMM state %s, MM state %s\n",
				  osmo_fsm_inst_state_name(mm->gmm_fsm),
				  osmo_fsm_inst_state_name(mm->gb.mm_state_fsm));
			sgsn_ra_geran_page_ra(&mm->ra, mm);

			/* FIXME: queue the packet we received from GTP */
			break;
		}
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "GTP DATA IND for TLLI %08X in state "
			"%s\n", mm->gb.tlli, osmo_fsm_inst_state_name(mm->gmm_fsm));
		msgb_free(msg);
		return -1;
	}

	rate_ctr_inc(rate_ctr_group_get_ctr(pdp->ctrg, PDP_CTR_PKTS_UDATA_OUT));
	rate_ctr_add(rate_ctr_group_get_ctr(pdp->ctrg, PDP_CTR_BYTES_UDATA_OUT), len);
	rate_ctr_inc(rate_ctr_group_get_ctr(mm->ctrg, GMM_CTR_PKTS_UDATA_OUT));
	rate_ctr_add(rate_ctr_group_get_ctr(mm->ctrg, GMM_CTR_BYTES_UDATA_OUT), len);

	/* It is easier to have a global count */
	pdp->cdr_bytes_out += len;

	return sndcp_sn_unitdata_req(msg, &mm->gb.llme->lle[pdp->sapi],
				  pdp->nsapi, mm);
}

/* Called by SNDCP when it has received/re-assembled a N-PDU */
int sgsn_gtp_data_req(struct osmo_routing_area_id *rai, int32_t tlli, uint8_t nsapi,
			 struct msgb *msg, uint32_t npdu_len, uint8_t *npdu)
{
	struct sgsn_mm_ctx *mmctx;
	struct sgsn_pdp_ctx *pdp;

	/* look-up the MM context for this message */
	mmctx = sgsn_mm_ctx_by_tlli(tlli, rai);
	if (!mmctx) {
		LOGP(DGPRS, LOGL_ERROR,
			"Cannot find MM CTX for TLLI %08x\n", tlli);
		return -EIO;
	}
	/* look-up the PDP context for this message */
	pdp = sgsn_pdp_ctx_by_nsapi(mmctx, nsapi);
	if (!pdp) {
		LOGP(DGPRS, LOGL_ERROR, "Cannot find PDP CTX for "
			"TLLI=%08x, NSAPI=%u\n", tlli, nsapi);
		return -EIO;
	}
	if (!pdp->lib) {
		LOGP(DGPRS, LOGL_ERROR, "PDP CTX without libgtp\n");
		return -EIO;
	}

	rate_ctr_inc(rate_ctr_group_get_ctr(pdp->ctrg, PDP_CTR_PKTS_UDATA_IN));
	rate_ctr_add(rate_ctr_group_get_ctr(pdp->ctrg, PDP_CTR_BYTES_UDATA_IN), npdu_len);
	rate_ctr_inc(rate_ctr_group_get_ctr(mmctx->ctrg, GMM_CTR_PKTS_UDATA_IN));
	rate_ctr_add(rate_ctr_group_get_ctr(mmctx->ctrg, GMM_CTR_BYTES_UDATA_IN), npdu_len);

	/* It is easier to have a global count */
	pdp->cdr_bytes_in += npdu_len;

	return gtp_data_req(pdp->ggsn->gsn, pdp->lib, npdu, npdu_len);
}

/* libgtp select loop integration */
static int sgsn_gtp_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	struct sgsn_instance *sgi = fd->data;
	int rc;

	if (!(what & OSMO_FD_READ))
		return 0;

	switch (fd->priv_nr) {
	case 0:
		rc = gtp_decaps0(sgi->gsn);
		break;
	case 1:
		rc = gtp_decaps1c(sgi->gsn);
		break;
	case 2:
		rc = gtp_decaps1u(sgi->gsn);
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

int sgsn_gtp_init(struct sgsn_instance *sgi)
{
	int rc;
	struct gsn_t *gsn;

	rc = gtp_new(&sgi->gsn, sgi->cfg.gtp_statedir,
		     &sgi->cfg.gtp_listenaddr.sin_addr, GTP_MODE_SGSN);
	if (rc) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to create GTP: %d\n", rc);
		return rc;
	}
	LOGP(DGPRS, LOGL_NOTICE, "Created GTP on %s\n", inet_ntoa(sgi->cfg.gtp_listenaddr.sin_addr));

	gsn = sgi->gsn;

	if (gsn->mode != GTP_MODE_SGSN)
		return -EINVAL;

	osmo_fd_setup(&sgi->gtp_fd0, gsn->fd0, OSMO_FD_READ, sgsn_gtp_fd_cb, sgi, 0);
	rc = osmo_fd_register(&sgi->gtp_fd0);
	if (rc < 0)
		return rc;

	osmo_fd_setup(&sgi->gtp_fd1c, gsn->fd1c, OSMO_FD_READ, sgsn_gtp_fd_cb, sgi, 1);
	rc = osmo_fd_register(&sgi->gtp_fd1c);
	if (rc < 0) {
		osmo_fd_unregister(&sgi->gtp_fd0);
		return rc;
	}

	osmo_fd_setup(&sgi->gtp_fd1u, gsn->fd1u, OSMO_FD_READ, sgsn_gtp_fd_cb, sgi, 2);
	rc = osmo_fd_register(&sgi->gtp_fd1u);
	if (rc < 0) {
		osmo_fd_unregister(&sgi->gtp_fd0);
		osmo_fd_unregister(&sgi->gtp_fd1c);
		return rc;
	}

	/* Register callbackcs with libgtp */
	gtp_set_cb_update_context_ind(gsn, cb_update_context_ind);
	gtp_set_cb_delete_context(gsn, cb_delete_context);
	gtp_set_cb_conf(gsn, cb_conf);
	gtp_set_cb_recovery3(gsn, cb_recovery3);
	gtp_set_cb_data_ind(gsn, cb_data_ind);
	gtp_set_cb_unsup_ind(gsn, cb_unsup_ind);
	gtp_set_cb_extheader_ind(gsn, cb_extheader_ind);
	gtp_set_cb_ran_info_relay_ind(gsn, cb_gtp_ran_info_relay_ind);

	return 0;
}
