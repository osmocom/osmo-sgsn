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

#include <osmocom/core/byteswap.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/gtp/gsn.h>
#include <osmocom/gtp/gtp.h>
#include <osmocom/gtp/gtpie.h>
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
#include <osmocom/sgsn/gprs_rau_fsm.h>

#include <osmocom/vlr/vlr.h>

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

/* Import PDP Context which sent to the SGSN via SGSN Context Response */
struct sgsn_pdp_ctx *sgsn_import_pdp_ctx(
					struct sgsn_mm_ctx *mmctx,
					uint16_t sapi,
					struct pdp_t *pdp)
{
	struct sgsn_pdp_ctx *pctx;
	struct pdp_t *lib_pdp;
	uint64_t imsi_ui64;
	int rc;
	struct sgsn_ggsn_ctx *ggsn = NULL;
	bool ggsn_created = false;
	struct osmo_sockaddr addr = {};

	rc = osmo_sockaddr_from_octets(&addr, pdp->gsnrc.v, pdp->gsnrc.l);
	if (rc < 0 || rc != pdp->gsnrc.l) {
		LOGP(DGPRS, LOGL_ERROR, "Invalid GSN address\n");
		return NULL;
	}

	if (addr.u.sin.sin_family != AF_INET) {
		LOGP(DGPRS, LOGL_ERROR, "SGSN only supports IPv4 towards GGSN\n");
		return NULL;
	}

	ggsn = sgsn_ggsn_ctx_by_addr(sgsn, &addr.u.sin.sin_addr);
	if (!ggsn) {
		/* the ares code is also using UINT32_MAX, which results into multiple GGSN have uint max */
		ggsn = sgsn_ggsn_ctx_alloc(sgsn, UINT32_MAX);
		if (!ggsn) {
			LOGP(DGPRS, LOGL_ERROR, "Couldn't allocate GGSN Ctx\n");
			return NULL;
		}
		ggsn_created = true;
		ggsn->remote_addr = addr.u.sin.sin_addr;
	}

	/* FIXME: why can this NULL for an via vty configured GGSN? */
	if (!ggsn->gsn) {
		ggsn->gsn = sgsn->gsn;
	}

	pctx = sgsn_pdp_ctx_alloc(mmctx, ggsn, pdp->nsapi);
	if (!pctx) {
		LOGP(DGPRS, LOGL_ERROR, "Couldn't allocate PDP Ctx\n");
		goto out;
	}

	imsi_ui64 = imsi_str2gtp(mmctx->imsi);
	rc = gtp_pdp_newpdp(ggsn->gsn, &lib_pdp, imsi_ui64, pdp->nsapi, pdp);
	if (rc) {
		LOGP(DGPRS, LOGL_ERROR, "Out of libgtp PDP Contexts\n");
		return NULL;
	}
	pdp->priv = pctx;
	pctx->nsapi = pdp->nsapi;
	pctx->sapi = sapi;
	pctx->lib = lib_pdp;
	/* FIXME: should the ue pdp active here or not? */
	pctx->ue_pdp_active = true;
	pctx->ti = pdp->ti;
	lib_pdp->priv = pctx;

	/* SGSN address for control plane */
	lib_pdp->gsnlc.l = sizeof(sgsn->cfg.gtp_listenaddr.sin_addr);
	memcpy(lib_pdp->gsnlc.v, &sgsn->cfg.gtp_listenaddr.sin_addr,
	       sizeof(sgsn->cfg.gtp_listenaddr.sin_addr));

	/* SGSN address for user plane */
	lib_pdp->gsnlu.l = sizeof(sgsn->cfg.gtp_listenaddr.sin_addr);
	memcpy(lib_pdp->gsnlu.v, &sgsn->cfg.gtp_listenaddr.sin_addr,
	       sizeof(sgsn->cfg.gtp_listenaddr.sin_addr));



	pctx->state = PDP_STATE_NEED_UPDATE_GSN;

	return pctx;
out:
	if (ggsn && ggsn_created)
		sgsn_ggsn_ctx_free(ggsn);

	return NULL;
}

/* generate a PDP context based on the IE's from the 04.08 message,
 * and send the GTP create pdp context request to the GGSN */
struct sgsn_pdp_ctx *sgsn_create_pdp_ctx(struct sgsn_ggsn_ctx *ggsn,
					 struct sgsn_mm_ctx *mmctx,
					 uint16_t nsapi,
					 struct tlv_parsed *tp)
{
	struct osmo_routing_area_id raid = {};
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
	if (mmctx->vsub && strlen(mmctx->vsub->msisdn)) {
		pdp->msisdn.l = OSMO_MIN(strlen(mmctx->vsub->msisdn), sizeof(pdp->msisdn.v));
		memcpy(pdp->msisdn.v, mmctx->vsub->msisdn,
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
	raid = mmctx->ra;
	raid.lac.lac = 0xFFFE;
	raid.rac = 0xFF;
	osmo_routing_area_id_encode_buf(pdp->rai.v, pdp->rai.l, &raid);

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
	if (cause != GTPCAUSE_NON_EXIST) {
		if (pctx->mm->attach_rau.rau_fsm)
			osmo_fsm_inst_dispatch(pctx->mm->attach_rau.rau_fsm, GMM_RAU_E_GGSN_UPD_RESP, pctx);
		return 0; /* Nothing to do */
	}

	LOGPDPCTXP(LOGL_INFO, pctx, "PDP CTX we tried to update doesn't exist in "
		   "the GGSN anymore, deleting it locally.\n");

	rc = gtp_freepdp(pctx->ggsn->gsn, pctx->lib);
	osmo_fsm_inst_dispatch(pctx->mm->attach_rau.rau_fsm, GMM_RAU_E_GGSN_UPD_RESP, NULL);
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

/* TS 29.060: Encode the MM Ctx TLV (7.7.28) of a SGSN Context Response (7.5.4) */
static int gtp_mm_ctx(uint8_t *buf, unsigned int size, const struct sgsn_mm_ctx *mmctx)
{
	uint8_t length = 0, sec_mode = 0, no_vecs = 0;
	uint32_t tmp32;
	uint16_t tmp16, *len_ptr;
	uint8_t *ptr = buf;
	uint32_t required_auth_type;

#define CHECK_SPACE_ERR(bytes) \
	if (ptr - buf + (bytes) > size) { \
		LOGP(DGPRS, LOGL_ERROR, "Ran out of space encoding mm ctx: %lu, %lu\n", (ptr - buf), (unsigned long) bytes); \
		return -1; \
	}
#define MEMCPY_CHK(dst, src, len) \
	CHECK_SPACE_ERR((len)) \
	memcpy((dst), (uint8_t *)(src), (len)); \
	(dst) += (len);

	// CKSN
	if (mmctx->ran_type != MM_CTX_T_GERAN_Gb) {
		LOGP(DGPRS, LOGL_ERROR, "SGSN Context Request: MM ctx doesn't support Iu/3G yet!"); \
		return -1;
	}

	// FIXME: KSI/CKSN for Iu?;
	*ptr++ = 0xf8 | (mmctx->auth_triplet.key_seq & 0x07);

	// Sec Mode | No Vecs | Used Cipher
	if (mmctx->auth_triplet.vec.auth_types & OSMO_AUTH_TYPE_UMTS) {
		sec_mode = 0;
		required_auth_type = OSMO_AUTH_TYPE_UMTS;
	} else if (mmctx->auth_triplet.vec.auth_types & OSMO_AUTH_TYPE_GSM) {
		sec_mode = 1;
		required_auth_type = OSMO_AUTH_TYPE_GSM;
	} else {
		return -1;
	}

	if (mmctx->vsub) {
		for (int i = 0; i < 5; i++) {
			const struct vlr_auth_tuple *auth = &mmctx->vsub->auth_tuples[i];
			if (auth->use_count == 0 && auth->vec.auth_types & required_auth_type)
				no_vecs++;
		}
	}

	*ptr++ = (sec_mode << 6) | (no_vecs << 3) | (mmctx->ciph_algo & 0x7);
	// Kc or CK/IK
	switch (sec_mode & 0x01) {
	case 0:
		/* UMTS keys */
		MEMCPY_CHK(ptr, mmctx->auth_triplet.vec.ck, sizeof(mmctx->auth_triplet.vec.ck));
		MEMCPY_CHK(ptr, mmctx->auth_triplet.vec.ik, sizeof(mmctx->auth_triplet.vec.ik));
		break;
	case 1:
		/* GSM keys */
		MEMCPY_CHK(ptr, mmctx->auth_triplet.vec.kc, sizeof(mmctx->auth_triplet.vec.kc));
	}

	/* 7.7.35 Authentication Triplet/Quintuplet */
	if (mmctx->vsub) {
		if ((sec_mode & 1) == 1) {
			/* Triplets */
			for (int i = 0; i < 5; i++) {
				const struct vlr_auth_tuple *auth = &mmctx->vsub->auth_tuples[i];
				if (!(auth->use_count == 0 && auth->vec.auth_types & required_auth_type))
					continue;
				MEMCPY_CHK(ptr, auth->vec.rand, sizeof(auth->vec.rand));
				MEMCPY_CHK(ptr, auth->vec.sres, 4);
				MEMCPY_CHK(ptr, auth->vec.kc, 8);
			}
		} else {
			/* Quintuplets */
			CHECK_SPACE_ERR(2);
			len_ptr = (uint16_t *)ptr; /* size will be filled later */
			ptr += 2;

			for (int i = 0; i < 5; i++) {
				const struct vlr_auth_tuple *auth = &mmctx->vsub->auth_tuples[i];
				if (!(auth->use_count == 0 && auth->vec.auth_types & required_auth_type))
					continue;
				MEMCPY_CHK(ptr, auth->vec.rand, sizeof(auth->vec.rand));
				*ptr++ = auth->vec.res_len;
				MEMCPY_CHK(ptr, auth->vec.res, (unsigned long) auth->vec.res_len);

				MEMCPY_CHK(ptr, auth->vec.ck, sizeof(auth->vec.ck));
				MEMCPY_CHK(ptr, auth->vec.ik, sizeof(auth->vec.ik));

				*ptr++ = sizeof(auth->vec.autn);
				MEMCPY_CHK(ptr, auth->vec.autn, sizeof(auth->vec.autn));
			}
			*len_ptr = htobe16(ptr - (((uint8_t *)len_ptr) + 2));
		}
	}


	// DRX
	MEMCPY_CHK(ptr, &mmctx->drx_parms, sizeof(mmctx->drx_parms));

	// MS Network Cap Len
	*ptr++ = mmctx->ms_network_capa.len;
	// MS Network Cap
	MEMCPY_CHK(ptr, mmctx->ms_network_capa.buf, (unsigned long) mmctx->ms_network_capa.len);

	// Container Len
	*ptr++ = 0;
	*ptr++ = 0;
	// Container
	// FIXME: Container

	// Access Restriction Data Len
	*ptr++ = 0;
	// FIXME: NRSRA

	return ptr - buf;
#undef CHECK_SPACE_ERR
#undef MEMCPY_CHK
}

#define GSM_MI_TYPE_TLLI 126
#define RESP_MAX_IES 10

static int cb_gtp_sgsn_context_request_ind(struct gsn_t *gsn, struct sockaddr_in *peer, uint32_t local_ref, union gtpie_member **ie, unsigned int ie_size)
{
	struct sgsn_mm_ctx *mmctx = NULL;
	struct sgsn_pdp_ctx *pdp;
	struct osmo_mobile_identity mi = {};
	struct osmo_routing_area_id rai = {};
	uint8_t raiv[6];
	uint8_t buf[512];
	int buf_len;

	char mi_str[40];
	char rai_str[40];
	uint64_t imsi;
	unsigned int length = 0;
	union gtpie_member *resp_ie[GTPIE_SIZE] = {};
	union gtpie_member resp_ie_elem[RESP_MAX_IES] = {};
	unsigned resp_it = 0;
	int rc;

	if (gtpie_gettv0(ie, GTPIE_RAI, 0, &raiv, 6)) {
		//goto missing_ie;
		return -1;
	}

	if (osmo_routing_area_id_decode(&rai, raiv, 6) < 0) {
		rate_ctr_inc2(gsn->ctrg, GSN_CTR_PKT_INVALID);
		//GTP_LOGPKG(LOGL_ERROR, peer, pack, len,
		//	   "Invalid RAI\n");
	}

	/* parse get the TMSI, IMSI, TMSI_SIG */
	if (!gtpie_gettv4(ie, GTPIE_P_TMSI, 0, &mi.tmsi)) {
		mi.type = GSM_MI_TYPE_TMSI;
	} else if (!gtpie_gettv8(ie, GTPIE_IMSI, 0, &imsi)) {
		mi.type = GSM_MI_TYPE_IMSI;
		/* NOTE: gtpie_gettv8 already converts to host byte order, but imsi_gtp2str seems to prefer big endian */
		imsi = ntoh64(imsi);
		const char *imsi_str = imsi_gtp2str(&imsi);
		memcpy(mi.imsi, imsi_str, sizeof(mi.imsi));
	} else if (!gtpie_gettv4(ie, GTPIE_TLLI, 0, &mi.tmsi)) {
		mi.type = GSM_MI_TYPE_TLLI;
	}

	osmo_mobile_identity_to_str_buf(mi_str, sizeof(mi_str), &mi);
	osmo_rai_name2_buf(rai_str, sizeof(rai_str), &rai);

	/* check if the subscribe is known to us */
	LOGP(DGPRS, LOGL_NOTICE, "RAI: %s MI: %s\n", rai_str, mi_str);
	if (mi.type == GSM_MI_TYPE_IMSI)
		mmctx = sgsn_mm_ctx_by_imsi(mi.imsi);
	else if (mi.type == GSM_MI_TYPE_TMSI)
		mmctx = sgsn_mm_ctx_by_ptmsi(mi.tmsi);
	else if (mi.type == GSM_MI_TYPE_TLLI)
		mmctx = sgsn_mm_ctx_by_tlli(mi.tmsi, &rai);

	if (!mmctx) {
		LOGP(DGPRS, LOGL_NOTICE, "No context found\n");
		return gtp_sgsn_context_resp_error(gsn, local_ref, GTPCAUSE_IMSI_NOT_KNOWN);
	}

	LOGMMCTXP(LOGL_INFO, mmctx, "Ctx will be transfered to another SGSN/MME\n");

	mmctx->gtp_local_ref = local_ref;
	mmctx->gtp_local_ref_valid = true;

	/* 7.7.1: Cause Code */
	resp_ie_elem[resp_it].tv1.t = GTPIE_CAUSE;
	resp_ie_elem[resp_it].tv1.v = GTPCAUSE_ACC_REQ;
	resp_ie[GTPIE_CAUSE] = &resp_ie_elem[resp_it];
	resp_it++;

	/* 7.7.2: IMSI */
	imsi = imsi_str2gtp(mmctx->imsi);
	resp_ie_elem[resp_it].tv8.t = GTPIE_IMSI;
	resp_ie_elem[resp_it].tv8.v = imsi;
	resp_ie[GTPIE_IMSI] = &resp_ie_elem[resp_it];
	resp_it++;

	/* 7.7.28: MM Context */
	buf_len = gtp_mm_ctx(buf, sizeof(buf), mmctx);
	if (buf_len <= 0)
		return gtp_sgsn_context_resp_error(gsn, local_ref, GTPCAUSE_SYS_FAIL);

	resp_ie_elem[resp_it].tlv.t = GTPIE_MM_CONTEXT;
	resp_ie_elem[resp_it].tlv.l = htons(buf_len);
	memcpy(&resp_ie_elem[resp_it].tlv.v[0], buf, buf_len);
	resp_ie[GTPIE_MM_CONTEXT] = &resp_ie_elem[resp_it];
	resp_it++;

	// /* 7.7.99: UE network capability */
	// resp_ie_elem[resp_it].tlv.t = GTPIE_UE_NET_CAPA;
	// resp_ie_elem[resp_it].tlv.l = htons(sizeof(mmctx->ms_network_capa.len));
	// memcpy(&resp_ie_elem[resp_it].tlv.v[0], mmctx->ms_network_capa.buf, mmctx->ms_network_capa.len);
	// resp_ie[resp_it] = &resp_ie_elem[resp_it];
	// resp_it++;

	/* 7.7.29: PDP Context */
	llist_for_each_entry(pdp, &mmctx->pdp_list, list) {
		// use talloc here?
		buf_len = gtp_encode_pdp_ctx(buf, sizeof(buf), pdp->lib, pdp->sapi);
		if (buf_len <= 0) {
			return gtp_sgsn_context_resp_error(gsn, local_ref, GTPCAUSE_SYS_FAIL);
		}

		resp_ie_elem[resp_it].tlv.t = GTPIE_PDP_CONTEXT;
		resp_ie_elem[resp_it].tlv.l = htons(buf_len);
		resp_ie[GTPIE_PDP_CONTEXT] = &resp_ie_elem[resp_it];
		memcpy(&resp_ie_elem[resp_it].tlv.v[0], buf, buf_len);

		resp_it++;
		/* TODO: fix the duplicated PDP Context */
		break;

		// if (resp_it >= RESP_MAX_IES)
		// 	break;
	}

	return gtp_sgsn_context_resp(gsn, local_ref, resp_ie, GTPIE_SIZE);
}

#define GTP_SEC_MODE_GSM_TRIPLETS 1
#define GTP_SEC_MODE_GSM_QUINTLETS 3
#define GTP_SEC_MODE_UMTS_QUINTLETS 2
#define GTP_SEC_MODE_CIPHER_UMTS_QUINTLETS 0

/*! validate the length of the quintlets, because of the variable AUTS */
static int validate_quintlets(uint8_t *buf, unsigned int buf_len)
{
	uint8_t xres_len, autn_len;
	unsigned int i = 0;
	/* buf = Rand, XRes length, XRes, CK, IK, AUTN length, AUTN */

	/* RAND */
	i += 16;

	if (buf_len <= i)
		return -ENOMEM;

	xres_len = buf[i];
	i++;

	/* XRES */
	i += xres_len;

	/* CK */
	i += 16;

	/* IK */
	i += 16;

	if (buf_len <= i)
		return -ENOMEM;

	autn_len = buf[i];
	i++;

	/* AUTN */
	i += autn_len;

	if (i != buf_len)
		return -EINVAL;

	return 0;
}

/*! parse the GTP IE MM Context IE and save it into the local MM Ctx. TS 29.060 7.7.28
 *  @param[inout] mmctx The MM Context to save the GTP values into
 *  @param[in] buf A pointer to the GTP IE value octet 4 TS 29.060 7.7.28
 *  @param[in] buf_len The length of \a buf
 *  @return 0 on success, -ENOMEM when to short, -EINVAL for invalid encoding */
static int gtp_mmctx_ie_to_mmctx(struct sgsn_mm_ctx *mmctx, uint8_t *buf, unsigned int buf_len)
{
	/* octet 4 */
	uint8_t cksn_more;
	/* octet 5 */
	uint8_t sec_mode, no_vec, used_cipher;
	/* octet 6.. */
	uint8_t *kc = NULL, *ck = NULL, *ik = NULL;
	uint8_t *quintlet = NULL, *triplet = NULL;
	uint16_t quintlet_len = 0;

	uint8_t *ms_net_cap = NULL;
	uint8_t ms_net_cap_len = 0;

	uint8_t *container = NULL;
	uint16_t container_len = 0;
	uint16_t length_access_restr = 0;
	unsigned int i;

	if (buf_len <= 5)
		return -ENOMEM;

	/* validate length of mm ctx */
	cksn_more = buf[0];
	sec_mode = buf[1] >> 6;
	no_vec = (buf[1] >> 3) & 0x7;
	used_cipher = buf[1] & 0x7;
	i = 2;

	if (no_vec > 5)
		return -EINVAL;

	switch (sec_mode) {
	case GTP_SEC_MODE_GSM_TRIPLETS:
		/* Kc */
		kc = &buf[i];
		i += 8;
		if (buf_len <= i)
			return -ENOMEM;

		/* triplet length is: 28 = 16 rand + 4 sres + 8 kc */
		triplet = &buf[i];
		i += 28 * no_vec;
		if (buf_len <= i)
			return -ENOMEM;
		break;
	case GTP_SEC_MODE_GSM_QUINTLETS:
		/* Kc */
		kc = &buf[i];
		i += 8;
		if (buf_len <= i)
			return -ENOMEM;

		quintlet_len = osmo_load16be(&buf[i]);
		i += 2;
		if (quintlet_len) {
			quintlet = &buf[i];
			i += quintlet_len;
		}

		if (buf_len <= i)
			return -ENOMEM;
		break;
	case GTP_SEC_MODE_CIPHER_UMTS_QUINTLETS:
	case GTP_SEC_MODE_UMTS_QUINTLETS:
		/* CK, IK */
		ck = &buf[i];
		i += 16;
		ik = &buf[i];
		i += 16;

		if (buf_len <= i)
			return -ENOMEM;

		quintlet_len = osmo_load16be(&buf[i]);
		i += 2;
		if (quintlet_len) {
			quintlet = &buf[i];
			i += quintlet_len;
		}

		if (buf_len <= i)
			return -ENOMEM;

		break;
	}

	/* DRX */
	i += 2;
	if (buf_len <= i)
		return -ENOMEM;

	/* MS Network Capability */
	ms_net_cap_len = buf[i];
	i++;
	i += ms_net_cap_len;
	if (buf_len <= i)
		return -ENOMEM;

	/* Container */
	container_len = osmo_load16be(&buf[i]);
	i += 2;

	i += container_len;
	if (buf_len <= i)
		return -ENOMEM;

	switch (sec_mode) {
	case GTP_SEC_MODE_GSM_QUINTLETS:
	case GTP_SEC_MODE_UMTS_QUINTLETS:
	case GTP_SEC_MODE_CIPHER_UMTS_QUINTLETS:
		if (validate_quintlets(quintlet, quintlet_len)) {
			LOGMMCTXP(LOGL_ERROR, mmctx, "SGSN Context resp: invalid quintlets length\n");
			return -EINVAL;
		}
		break;
	case GTP_SEC_MODE_GSM_TRIPLETS:
		break;
	}

	/* TODO: parse Length of Access Restriction Data + following field */

	/* Save data into the mmctx */
	memset(&mmctx->auth_triplet, 0, sizeof(mmctx->auth_triplet));
	mmctx->auth_triplet.key_seq = cksn_more & 0x7;
	switch (sec_mode) {
	case GTP_SEC_MODE_GSM_QUINTLETS:
	case GTP_SEC_MODE_GSM_TRIPLETS:
		memcpy(&mmctx->auth_triplet.vec.kc, kc, 8);
		break;
	case GTP_SEC_MODE_UMTS_QUINTLETS:
	case GTP_SEC_MODE_CIPHER_UMTS_QUINTLETS:
		memcpy(&mmctx->auth_triplet.vec.ck, ck, 16);
		memcpy(&mmctx->auth_triplet.vec.ik, ik, 16);
		break;
	}

	// check for vsub
	/* TODO: optional: pass triplets + quintlets to the VLR. */
	// collect gtp sessions + Update PDP Context Request

	return 0;
}

static int cb_gtp_sgsn_context_response_ind(struct gsn_t *gsn, struct sockaddr_in *peer, uint32_t local_ref, union gtpie_member **ie, unsigned int ie_size)
{
	struct sgsn_mm_ctx *mmctx = NULL;
	uint64_t imsi;
	uint8_t buf[512];
	unsigned int buf_len;
	uint8_t cause;
	int rc;

	mmctx = sgsn_mm_ctx_by_gtp_local_ref(local_ref);
	if (!mmctx) {
		/* How can we loose the local reference? Most likely only when we release the whole subscriber. */
		return gtp_sgsn_context_ack_error(gsn, local_ref, GTPCAUSE_NO_RESOURCES);
	}

	/* Check cause */
	if (gtpie_gettv1(ie, GTPIE_CAUSE, 0, &cause)) {
		mmctx->gtp_local_ref_valid = false;
		LOGMMCTXP(LOGL_ERROR, mmctx, "SGSN Context resp: Mandatory Cause IE not found\n");
		return gtp_sgsn_context_ack_error(gsn, local_ref, GTPCAUSE_MAN_IE_MISSING);
	}

	if (!mmctx->vsub) {
		LOGMMCTXP(LOGL_ERROR, mmctx, "SGSN Context resp: Mandatory Cause IE not found\n");
		/* TODO: check if need to inform the other SGSN/MME with a different cause code */
		return gtp_sgsn_context_ack_error(gsn, local_ref, GTPCAUSE_MS_NOT_RESP);
	}

	if (cause != GTPCAUSE_ACC_REQ) {
		mmctx->gtp_local_ref_valid = false;
		LOGMMCTXP(LOGL_ERROR, mmctx, "SGSN Context resp: Cause %d\n", cause);
		vlr_subscr_rx_pvlr_id_nack(mmctx->vsub);
		/* FIXME: inform FSM */
		return -1;
	}

	if (gtpie_gettv8(ie, GTPIE_IMSI, 0, &imsi)) {
		LOGMMCTXP(LOGL_ERROR, mmctx, "SGSN Context resp: Mandatory IMSI IE not found\n");
		vlr_subscr_rx_pvlr_id_nack(mmctx->vsub);
		return gtp_sgsn_context_ack_error(gsn, local_ref, GTPCAUSE_MAN_IE_MISSING);
	}
	imsi = ntoh64(imsi);
	const char *imsi_str = imsi_gtp2str(&imsi);
	/* move this into a different function? */
	strncpy(mmctx->imsi, imsi_str, sizeof(mmctx->imsi));
	if (mmctx->vsub)
		vlr_subscr_set_imsi(mmctx->vsub, imsi_str);

	if (gtpie_gettlv(ie, GTPIE_MM_CONTEXT, 0, &buf_len, buf, sizeof(buf))) {
		LOGMMCTXP(LOGL_ERROR, mmctx, "SGSN Context resp: Mandatory MM context IE not found\n");
		return gtp_sgsn_context_ack_error(gsn, local_ref, GTPCAUSE_MAN_IE_MISSING);
	}

	// parse MMCTX
	// what do we need?
	// keys
	rc = gtpie_gettlv(ie, GTPIE_PDP_CONTEXT, 0, &buf_len, buf, sizeof(buf));
	if (rc) {
		LOGMMCTXP(LOGL_ERROR, mmctx, "PDP Context resp: Mandatory MM context IE not found\n");
		return gtp_sgsn_context_ack_error(gsn, local_ref, GTPCAUSE_MAN_IE_MISSING);
	}

	uint16_t sapi;
	struct pdp_t new_pdp;

	rc = gtp_decode_pdp_ctx(buf, buf_len, &new_pdp, &sapi);
	if (rc) {
		/* Ignore the failure and continue to work without taken the PDP context over.
		 * This way we communicate an Ack towards the SGSN/MME. The remote is responsible to close the PDP context not
		 * mentioned in the ack */
	}

	/* we save the pdps into the mmctx and inform the GGSN after we authenticated the client */
	struct sgsn_pdp_ctx *pctx = sgsn_import_pdp_ctx(mmctx, sapi, &new_pdp);
	if (!pctx) {
		/* Ignore the failure and continue to work without taken the PDP context over.
		 * This way we communicate an Ack towards the SGSN/MME. The remote is responsible to close the PDP context not
		 * mentioned in the ack */
	}

	vlr_subscr_rx_pvlr_id_ack(mmctx->vsub);

	return 0;
}

int sgsn_context_ack(struct gsn_t *gsn, struct sgsn_mm_ctx *mmctx, uint8_t cause)
{
	int rc;

	if (!mmctx->gtp_local_ref_valid)
		return -EINVAL;

	if (!mmctx->gtp_local_ref)
		return -EINVAL;

	rc = gtp_sgsn_context_ack_error(gsn, mmctx->gtp_local_ref, cause);
	mmctx->gtp_local_ref_valid = false;

	return rc;
}

static int cb_gtp_sgsn_context_ack_ind(struct gsn_t *gsn, struct sockaddr_in *peer, uint32_t local_ref, union gtpie_member **ie, unsigned int ie_size)
{
	/* The remote peer has verified/established a connection to the UE,
	 * Release local GGSN connection */

	struct sgsn_mm_ctx *mmctx = NULL;
	struct sgsn_pdp_ctx *pdp, *pdp2;

	mmctx = sgsn_mm_ctx_by_gtp_local_ref(local_ref);
	if (!mmctx) {
		/* Can't do anything here. The Ack is the last message anyway. */
		return 0;
	}
	mmctx->gtp_local_ref_valid = false;
	/* FIXME: drop HLR relation? */
	/* FIXME: drop local VLR relation? */
	/* FIXME: Parse Tunnel Endpoint Identifier Data II IE */
	llist_for_each_entry_safe(pdp, pdp2, &mmctx->pdp_list, list) {
		sgsn_pdp_ctx_free(pdp);
	}

	return 0;
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
int sgsn_gtp_data_req(struct osmo_routing_area_id *ra_id, int32_t tlli, uint8_t nsapi,
			 struct msgb *msg, uint32_t npdu_len, uint8_t *npdu)
{
	struct sgsn_mm_ctx *mmctx;
	struct sgsn_pdp_ctx *pdp;

	/* look-up the MM context for this message */
	mmctx = sgsn_mm_ctx_by_tlli(tlli, ra_id);
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
	gtp_set_cb_sgsn_context_request_ind(gsn, cb_gtp_sgsn_context_request_ind);
	gtp_set_cb_sgsn_context_response_ind(gsn, cb_gtp_sgsn_context_response_ind);
	gtp_set_cb_sgsn_context_ack_ind(gsn, cb_gtp_sgsn_context_ack_ind);

	return 0;
}
