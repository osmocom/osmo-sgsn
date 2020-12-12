/* NS-over-IP proxy */

/* (C) 2010-2020 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2013 by On-Waves
 * (C) 2013 by Holger Hans Peter Freyther
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
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <time.h>

#include <osmocom/core/hashtable.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>

#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_bss.h>
#include <osmocom/gprs/bssgp_bvc_fsm.h>

#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/sgsn/signal.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_gb_parse.h>
#include <osmocom/sgsn/gb_proxy.h>

#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/sgsn/gprs_utils.h>

extern void *tall_sgsn_ctx;

static const struct rate_ctr_desc global_ctr_description[] = {
	{ "inv-bvci",	    "Invalid BVC Identifier          " },
	{ "inv-lai",	    "Invalid Location Area Identifier" },
	{ "inv-rai",	    "Invalid Routing Area Identifier " },
	{ "inv-nsei",	    "No BVC established for NSEI     " },
	{ "proto-err:bss",  "BSSGP protocol error      (BSS )" },
	{ "proto-err:sgsn", "BSSGP protocol error      (SGSN)" },
	{ "not-supp:bss",   "Feature not supported     (BSS )" },
	{ "not-supp:sgsn",  "Feature not supported     (SGSN)" },
	{ "restart:sgsn",   "Restarted RESET procedure (SGSN)" },
	{ "tx-err:sgsn",    "NS Transmission error     (SGSN)" },
	{ "error",          "Other error                     " },
	{ "mod-peer-err",   "Patch error: no peer            " },
};

static const struct rate_ctr_group_desc global_ctrg_desc = {
	.group_name_prefix = "gbproxy:global",
	.group_description = "GBProxy Global Statistics",
	.num_ctr = ARRAY_SIZE(global_ctr_description),
	.ctr_desc = global_ctr_description,
	.class_id = OSMO_STATS_CLASS_GLOBAL,
};

static int gbprox_relay2peer(struct msgb *old_msg, struct gbproxy_bvc *bvc,
			     uint16_t ns_bvci);


/* generate BVC-STATUS message with cause value derived from TLV-parser error */
static int tx_status_from_tlvp(enum osmo_tlv_parser_error tlv_p_err, struct msgb *orig_msg)
{
	uint8_t bssgp_cause;
	switch (tlv_p_err) {
	case OSMO_TLVP_ERR_MAND_IE_MISSING:
		bssgp_cause = BSSGP_CAUSE_MISSING_MAND_IE;
		break;
	default:
		bssgp_cause = BSSGP_CAUSE_PROTO_ERR_UNSPEC;
	}
	return bssgp_tx_status(bssgp_cause, NULL, orig_msg);
}

/* strip off the NS header */
static void strip_ns_hdr(struct msgb *msg)
{
	int strip_len = msgb_bssgph(msg) - msg->data;
	msgb_pull(msg, strip_len);
}

#if 0
/* feed a message down the NS-VC associated with the specified bvc */
static int gbprox_relay2sgsn(struct gbproxy_config *cfg, struct msgb *old_msg,
			     uint16_t ns_bvci, uint16_t sgsn_nsei)
{
	/* create a copy of the message so the old one can
	 * be free()d safely when we return from gbprox_rcvmsg() */
	struct gprs_ns2_inst *nsi = cfg->nsi;
	struct osmo_gprs_ns2_prim nsp = {};
	struct msgb *msg = bssgp_msgb_copy(old_msg, "msgb_relay2sgsn");
	int rc;

	DEBUGP(DGPRS, "NSE(%05u/BSS)-BVC(%05u) proxying BTS->SGSN  NSE(%05u/SGSN)\n",
		msgb_nsei(msg), ns_bvci, sgsn_nsei);

	nsp.bvci = ns_bvci;
	nsp.nsei = sgsn_nsei;

	strip_ns_hdr(msg);
	osmo_prim_init(&nsp.oph, SAP_NS, PRIM_NS_UNIT_DATA,
		       PRIM_OP_REQUEST, msg);
	rc = gprs_ns2_recv_prim(nsi, &nsp.oph);
	if (rc < 0)
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_TX_ERR_SGSN]);
	return rc;
}
#endif

/* feed a message down the NSE */
static int gbprox_relay2nse(struct msgb *old_msg, struct gbproxy_nse *nse,
			     uint16_t ns_bvci)
{
	OSMO_ASSERT(nse);
	OSMO_ASSERT(nse->cfg);

	/* create a copy of the message so the old one can
	 * be free()d safely when we return from gbprox_rcvmsg() */
	struct gprs_ns2_inst *nsi = nse->cfg->nsi;
	struct osmo_gprs_ns2_prim nsp = {};
	struct msgb *msg = bssgp_msgb_copy(old_msg, "msgb_relay2nse");
	uint32_t tlli;
	int rc;

	DEBUGP(DGPRS, "NSE(%05u/SGSN)-BVC(%05u) proxying SGSN->BSS NSE(%05u/BSS)\n",
		msgb_nsei(msg), ns_bvci, nse->nsei);

	nsp.bvci = ns_bvci;
	nsp.nsei = nse->nsei;

	/* Strip the old NS header, it will be replaced with a new one */
	strip_ns_hdr(msg);

	/* TS 48.018 Section 5.4.2: The link selector parameter is
	 * defined in 3GPP TS 48.016. At one side of the Gb interface,
	 * all BSSGP UNITDATA PDUs related to an MS shall be passed with
	 * the same LSP, e.g. the LSP contains the MS's TLLI, to the
	 * underlying network service. */
	if (gprs_gb_parse_tlli(msgb_data(msg), msgb_length(msg), &tlli) == 1)
		nsp.u.unitdata.link_selector = tlli;

	osmo_prim_init(&nsp.oph, SAP_NS, PRIM_NS_UNIT_DATA,
		       PRIM_OP_REQUEST, msg);
	rc = gprs_ns2_recv_prim(nsi, &nsp.oph);
	/* FIXME: We need a counter group for gbproxy_nse */
	//if (rc < 0)
	//	rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_TX_ERR]);

	return rc;
}

/* feed a message down the NS-VC associated with the specified bvc */
static int gbprox_relay2peer(struct msgb *old_msg, struct gbproxy_bvc *bvc,
			     uint16_t ns_bvci)
{
	int rc;
	struct gbproxy_nse *nse = bvc->nse;
	OSMO_ASSERT(nse);

	rc = gbprox_relay2nse(old_msg, nse, ns_bvci);
	if (rc < 0)
		rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_TX_ERR]);

	return rc;
}

int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	return 0;
}


/***********************************************************************
 * PTP BVC handling
 ***********************************************************************/

/* route an uplink message on a PTP-BVC to a SGSN using the TLLI */
static int gbprox_bss2sgsn_tlli(struct gbproxy_cell *cell, struct msgb *msg, uint32_t tlli,
				bool sig_bvci)
{
	struct gbproxy_bvc *sgsn_bvc;
	unsigned int i;

	/* FIXME: derive NRI from TLLI */
	/* FIXME: find the SGSN for that NRI */

	/* HACK: we currently simply pick the first SGSN we find */
	for (i = 0; i < ARRAY_SIZE(cell->sgsn_bvc); i++) {
		sgsn_bvc = cell->sgsn_bvc[i];
		if (sgsn_bvc)
			return gbprox_relay2peer(msg, sgsn_bvc, sig_bvci ? 0 : sgsn_bvc->bvci);
	}
	return 0;
}

static int gbprox_bss2sgsn_null_nri(struct gbproxy_cell *cell, struct msgb *msg)
{
	struct gbproxy_bvc *sgsn_bvc;
	unsigned int i;

	/* FIXME: find the SGSN for that NRI */

	/* HACK: we currently simply pick the first SGSN we find */
	for (i = 0; i < ARRAY_SIZE(cell->sgsn_bvc); i++) {
		sgsn_bvc = cell->sgsn_bvc[i];
		if (sgsn_bvc)
			return gbprox_relay2peer(msg, sgsn_bvc, sgsn_bvc->bvci);
	}
	return 0;
}


/* Receive an incoming PTP message from a BSS-side NS-VC */
static int gbprox_rx_ptp_from_bss(struct gbproxy_nse *nse, struct msgb *msg, uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	const char *pdut_name = osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type);
	struct gbproxy_bvc *bss_bvc;
	struct tlv_parsed tp;
	char log_pfx[32];
	uint32_t tlli;
	int rc;

	snprintf(log_pfx, sizeof(log_pfx), "NSE(%05u/BSS)-BVC(%05u/??)", nse->nsei, ns_bvci);

	LOGP(DGPRS, LOGL_DEBUG, "%s Rx %s\n", log_pfx, pdut_name);

	if (ns_bvci == 0 || ns_bvci == 1) {
		LOGP(DGPRS, LOGL_NOTICE, "%s BVCI=%05u is not PTP\n", log_pfx, ns_bvci);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(bgph->pdu_type) & BSSGP_PDUF_PTP)) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s not allowed in PTP BVC\n", log_pfx, pdut_name);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(bgph->pdu_type) & BSSGP_PDUF_UL)) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s not allowed in uplink direction\n", log_pfx, pdut_name);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	bss_bvc = gbproxy_bvc_by_bvci(nse, ns_bvci);
	if (!bss_bvc) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s - Didn't find BVC for PTP message, discarding\n",
		     log_pfx, pdut_name);
		return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, &ns_bvci, msg);
	}

	/* UL_UNITDATA has a different header than all other uplink PDUs */
	if (bgph->pdu_type == BSSGP_PDUT_UL_UNITDATA) {
		const struct bssgp_ud_hdr *budh = (struct bssgp_ud_hdr *) msgb_bssgph(msg);
		if (msgb_bssgp_len(msg) < sizeof(*budh))
			return bssgp_tx_status(BSSGP_CAUSE_INV_MAND_INF, NULL, msg);
		rc = osmo_tlv_prot_parse(&osmo_pdef_bssgp, &tp, 1, bgph->pdu_type, budh->data,
					 msgb_bssgp_len(msg) - sizeof(*budh), 0, 0, DGPRS, log_pfx);
		/* populate TLLI from the fixed headser into the TLV-parsed array so later code
		 * doesn't have to worry where the TLLI came from */
		tp.lv[BSSGP_IE_TLLI].len = 4;
		tp.lv[BSSGP_IE_TLLI].val = (const uint8_t *) &budh->tlli;
	} else {
		rc = osmo_tlv_prot_parse(&osmo_pdef_bssgp, &tp, 1, bgph->pdu_type, bgph->data,
					 msgb_bssgp_len(msg) - sizeof(*bgph), 0, 0, DGPRS, log_pfx);
	}
	if (rc < 0) {
		rate_ctr_inc(&nse->cfg->ctrg->ctr[GBPROX_GLOB_CTR_PROTO_ERR_BSS]);
		return tx_status_from_tlvp(rc, msg);
	}
	/* hack to get both msg + tlv_parsed passed via osmo_fsm_inst_dispatch */
	msgb_bcid(msg) = (void *)&tp;

	switch (bgph->pdu_type) {
	case BSSGP_PDUT_UL_UNITDATA:
	case BSSGP_PDUT_RA_CAPA_UPDATE:
	case BSSGP_PDUT_FLOW_CONTROL_MS:
	case BSSGP_PDUT_DOWNLOAD_BSS_PFC:
	case BSSGP_PDUT_CREATE_BSS_PFC_ACK:
	case BSSGP_PDUT_CREATE_BSS_PFC_NACK:
	case BSSGP_PDUT_MODIFY_BSS_PFC_ACK:
	case BSSGP_PDUT_DELETE_BSS_PFC_ACK:
	case BSSGP_PDUT_FLOW_CONTROL_PFC:
	case BSSGP_PDUT_DELETE_BSS_PFC_REQ:
	case BSSGP_PDUT_PS_HO_REQUIRED:
	case BSSGP_PDUT_PS_HO_REQUEST_ACK:
	case BSSGP_PDUT_PS_HO_REQUEST_NACK:
	case BSSGP_PDUT_PS_HO_COMPLETE:
	case BSSGP_PDUT_PS_HO_CANCEL:
		/* We can route based on TLLI-NRI */
		tlli = osmo_load32be(TLVP_VAL(&tp, BSSGP_IE_TLLI));
		rc = gbprox_bss2sgsn_tlli(bss_bvc->cell, msg, tlli, false);
		break;
	case BSSGP_PDUT_RADIO_STATUS:
		if (TLVP_PRESENT(&tp, BSSGP_IE_TLLI)) {
			tlli = osmo_load32be(TLVP_VAL(&tp, BSSGP_IE_TLLI));
			rc = gbprox_bss2sgsn_tlli(bss_bvc->cell, msg, tlli, false);
		} else if (TLVP_PRESENT(&tp, BSSGP_IE_TMSI)) {
			/* we treat the TMSI like a TLLI and extract the NRI from it */
			tlli = osmo_load32be(TLVP_VAL(&tp, BSSGP_IE_TMSI));
			rc = gbprox_bss2sgsn_tlli(bss_bvc->cell, msg, tlli, false);
		} else if (TLVP_PRESENT(&tp, BSSGP_IE_IMSI)) {
			rc = gbprox_bss2sgsn_null_nri(bss_bvc->cell, msg);
		} else
			LOGPBVC(bss_bvc, LOGL_ERROR, "Rx RADIO-STATUS without any of the conditional IEs\n");
		break;
	case BSSGP_PDUT_DUMMY_PAGING_PS_RESP:
	case BSSGP_PDUT_PAGING_PS_REJECT:
		/* TODO: Implement via state tracking of PAGING-PS + DUMMY_PAGING_PS */
		LOGPBVC(bss_bvc, LOGL_ERROR, "Rx %s: Implementation missing\n", pdut_name);
		break;
	case BSSGP_PDUT_FLOW_CONTROL_BVC:
		osmo_fsm_inst_dispatch(bss_bvc->fi, BSSGP_BVCFSM_E_RX_FC_BVC, msg);
		break;
	case BSSGP_PDUT_STATUS:
		/* TODO: Implement by inspecting the contained PDU */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_PDU_IN_ERROR))
			break;
		LOGPBVC(bss_bvc, LOGL_ERROR, "Rx %s: Implementation missing\n", pdut_name);
		break;
	}

	return 0;
}

/* Receive an incoming PTP message from a SGSN-side NS-VC */
static int gbprox_rx_ptp_from_sgsn(struct gbproxy_nse *nse, struct msgb *msg, uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	const char *pdut_name = osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type);
	struct gbproxy_bvc *sgsn_bvc, *bss_bvc;
	struct tlv_parsed tp;
	char log_pfx[32];
	int rc;

	snprintf(log_pfx, sizeof(log_pfx), "NSE(%05u/SGSN)-BVC(%05u/??)", nse->nsei, ns_bvci);

	LOGP(DGPRS, LOGL_DEBUG, "%s Rx %s\n", log_pfx, pdut_name);

	if (ns_bvci == 0 || ns_bvci == 1) {
		LOGP(DGPRS, LOGL_NOTICE, "%s BVCI is not PTP\n", log_pfx);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(bgph->pdu_type) & BSSGP_PDUF_PTP)) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s not allowed in PTP BVC\n", log_pfx, pdut_name);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(bgph->pdu_type) & BSSGP_PDUF_DL)) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s not allowed in downlink direction\n", log_pfx, pdut_name);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	sgsn_bvc = gbproxy_bvc_by_bvci(nse, ns_bvci);
	if (!sgsn_bvc) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s - Didn't find BVC for for PTP message, discarding\n",
		     log_pfx, pdut_name);
		rate_ctr_inc(&nse->cfg->ctrg-> ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, &ns_bvci, msg);
	}

	if (!bssgp_bvc_fsm_is_unblocked(sgsn_bvc->fi)) {
		LOGPBVC(sgsn_bvc, LOGL_NOTICE, "Rx %s: Dropping on blocked BVC\n", pdut_name);
		rate_ctr_inc(&sgsn_bvc->ctrg->ctr[GBPROX_PEER_CTR_DROPPED]);
		return bssgp_tx_status(BSSGP_CAUSE_BVCI_BLOCKED, &ns_bvci, msg);
	}

	/* DL_UNITDATA has a different header than all other uplink PDUs */
	if (bgph->pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		const struct bssgp_ud_hdr *budh = (struct bssgp_ud_hdr *) msgb_bssgph(msg);
		if (msgb_bssgp_len(msg) < sizeof(*budh))
			return bssgp_tx_status(BSSGP_CAUSE_INV_MAND_INF, NULL, msg);
		rc = osmo_tlv_prot_parse(&osmo_pdef_bssgp, &tp, 1, bgph->pdu_type, budh->data,
					 msgb_bssgp_len(msg) - sizeof(*budh), 0, 0, DGPRS, log_pfx);
		/* populate TLLI from the fixed headser into the TLV-parsed array so later code
		 * doesn't have to worry where the TLLI came from */
		tp.lv[BSSGP_IE_TLLI].len = 4;
		tp.lv[BSSGP_IE_TLLI].val = (const uint8_t *) &budh->tlli;
	} else {
		rc = osmo_tlv_prot_parse(&osmo_pdef_bssgp, &tp, 1, bgph->pdu_type, bgph->data,
					 msgb_bssgp_len(msg) - sizeof(*bgph), 0, 0, DGPRS, log_pfx);
	}
	if (rc < 0) {
		rate_ctr_inc(&nse->cfg->ctrg->ctr[GBPROX_GLOB_CTR_PROTO_ERR_BSS]);
		return tx_status_from_tlvp(rc, msg);
	}
	/* hack to get both msg + tlv_parsed passed via osmo_fsm_inst_dispatch */
	msgb_bcid(msg) = (void *)&tp;

	OSMO_ASSERT(sgsn_bvc->cell);
	bss_bvc = sgsn_bvc->cell->bss_bvc;

	switch (bgph->pdu_type) {
	case BSSGP_PDUT_FLOW_CONTROL_BVC_ACK:
		return osmo_fsm_inst_dispatch(sgsn_bvc->fi, BSSGP_BVCFSM_E_RX_FC_BVC_ACK, msg);
	default:
		return gbprox_relay2peer(msg, bss_bvc, bss_bvc->bvci);
	}

}

/***********************************************************************
 * BVC FSM call-backs
 ***********************************************************************/

/* helper function to dispatch a FSM event to all SGSN-side BVC FSMs of a cell */
static void dispatch_to_all_sgsn_bvc(struct gbproxy_cell *cell, uint32_t event, void *priv)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cell->sgsn_bvc); i++) {
		struct gbproxy_bvc *sgsn_bvc = cell->sgsn_bvc[i];
		if (!sgsn_bvc)
			continue;
		osmo_fsm_inst_dispatch(sgsn_bvc->fi, event, priv);
	}
}

/* BVC FSM informs us about a BSS-side reset of the signaling BVC */
static void bss_sig_bvc_reset_notif(uint16_t nsei, uint16_t bvci, const struct gprs_ra_id *ra_id,
				    uint16_t cell_id, uint8_t cause, void *priv)
{
	struct gbproxy_bvc *sig_bvc = priv;
	struct gbproxy_nse *nse = sig_bvc->nse;
	struct gbproxy_bvc *ptp_bvc;
	unsigned int i;

	/* BLOCK all SGSN-side PTP BVC within this NSE */
	hash_for_each(nse->bvcs, i, ptp_bvc, list) {
		if (ptp_bvc == sig_bvc)
			continue;
		OSMO_ASSERT(ptp_bvc->cell);

		dispatch_to_all_sgsn_bvc(ptp_bvc->cell, BSSGP_BVCFSM_E_REQ_BLOCK, &cause);
	}

	/* Delete all BSS-side PTP BVC within this NSE */
	gbproxy_cleanup_bvcs(nse, 0);

	/* TODO: we keep the "CELL" around for now, re-connecting it to
	 * any (later) new PTP-BVC for that BVCI. Not sure if that's the
	 * best idea ? */
}

/* forward declaration */
static const struct bssgp_bvc_fsm_ops sgsn_ptp_bvc_fsm_ops;

static const struct bssgp_bvc_fsm_ops bss_sig_bvc_fsm_ops = {
	.reset_notification = bss_sig_bvc_reset_notif,
};

/* BVC FSM informs us about a BSS-side reset of a PTP BVC */
static void bss_ptp_bvc_reset_notif(uint16_t nsei, uint16_t bvci, const struct gprs_ra_id *ra_id,
				    uint16_t cell_id, uint8_t cause, void *priv)
{
	struct gbproxy_bvc *bvc = priv;
	struct gbproxy_config *cfg = bvc->nse->cfg;
	struct gbproxy_nse *sgsn_nse;
	unsigned int i;

	OSMO_ASSERT(bvci != 0);

	if (!bvc->cell) {
		/* see if we have a CELL dangling around */
		bvc->cell = gbproxy_cell_by_bvci(cfg, bvci);
		if (bvc->cell) {
			/* the CELL already exists. This means either it * was created before at an
			 * earlier PTP BVC-RESET, or that there are non-unique BVCIs and hence a
			 * malconfiguration */
			if (bvc->cell->bss_bvc) {
				LOGPBVC(bvc, LOGL_NOTICE, "Rx BVC-RESET via this NSE, but CELL already "
					"has BVC on NSEI=%05u\n", bvc->cell->bss_bvc->nse->nsei);
				LOGPBVC(bvc->cell->bss_bvc, LOGL_NOTICE, "Destroying due to conflicting "
					"BVCI configuration (new NSEI=%05u)!\n", bvc->nse->nsei);
				gbproxy_bvc_free(bvc->cell->bss_bvc);
			}
			bvc->cell->bss_bvc = bvc;
		}
	}

	if (!bvc->cell) {
		/* if we end up here, it means this is the first time we received a BVC-RESET
		 * for this BVC.  We need to create the 'cell' data structure and the SGSN-side
		 * BVC counterparts */

		bvc->cell = gbproxy_cell_alloc(cfg, bvci);
		OSMO_ASSERT(bvc->cell);
		memcpy(bvc->cell->ra, bvc->ra, sizeof(bvc->cell->ra));

		/* link us to the cell and vice-versa */
		bvc->cell->bss_bvc = bvc;
	}

	/* allocate (any missing) SGSN-side BVCs within the cell, and reset them */
	hash_for_each(cfg->sgsn_nses, i, sgsn_nse, list) {
		struct gbproxy_bvc *sgsn_bvc = gbproxy_bvc_by_bvci(sgsn_nse, bvci);
		if (sgsn_bvc)
			OSMO_ASSERT(sgsn_bvc->cell == bvc->cell || !sgsn_bvc->cell);

		if (!sgsn_bvc) {
			sgsn_bvc = gbproxy_bvc_alloc(sgsn_nse, bvci);
			OSMO_ASSERT(sgsn_bvc);

			sgsn_bvc->cell = bvc->cell;
			memcpy(sgsn_bvc->ra, bvc->cell->ra, sizeof(sgsn_bvc->ra));
			sgsn_bvc->fi = bssgp_bvc_fsm_alloc_ptp_bss(sgsn_bvc, cfg->nsi, sgsn_nse->nsei,
								   bvci, ra_id, cell_id);
			OSMO_ASSERT(sgsn_bvc->fi);
			bssgp_bvc_fsm_set_ops(sgsn_bvc->fi, &sgsn_ptp_bvc_fsm_ops, sgsn_bvc);

			gbproxy_cell_add_sgsn_bvc(bvc->cell, sgsn_bvc);
		}
	}

	/* Trigger outbound BVC-RESET procedure toward each SGSN */
	dispatch_to_all_sgsn_bvc(bvc->cell, BSSGP_BVCFSM_E_REQ_RESET, &cause);
}

/* BVC FSM informs us about a BSS-side FSM state change */
static void bss_ptp_bvc_state_chg_notif(uint16_t nsei, uint16_t bvci, int old_state, int state, void *priv)
{
	struct gbproxy_bvc *bvc = priv;
	struct gbproxy_cell *cell = bvc->cell;
	uint8_t cause = bssgp_bvc_fsm_get_block_cause(bvc->fi);

	/* we have just been created but due to callback ordering the cell is not associated */
	if (!cell)
		return;

	switch (state) {
	case BSSGP_BVCFSM_S_BLOCKED:
		/* block the corresponding SGSN-side PTP BVCs */
		dispatch_to_all_sgsn_bvc(cell, BSSGP_BVCFSM_E_REQ_BLOCK, &cause);
		break;
	case BSSGP_BVCFSM_S_UNBLOCKED:
		/* unblock the corresponding SGSN-side PTP BVCs */
		dispatch_to_all_sgsn_bvc(cell, BSSGP_BVCFSM_E_REQ_UNBLOCK, NULL);
		break;
	}
}

/* BVC FSM informs us about BVC-FC PDU receive */
static void bss_ptp_bvc_fc_bvc(uint16_t nsei, uint16_t bvci, const struct bssgp2_flow_ctrl *fc, void *priv)
{
	struct gbproxy_bvc *bss_bvc = priv;
	struct gbproxy_cell *cell = bss_bvc->cell;

	if (!cell)
		return;

	/* FIXME: actually split the bandwidth among the SGSNs! */

	dispatch_to_all_sgsn_bvc(cell, BSSGP_BVCFSM_E_REQ_FC_BVC, (void *) fc);
}

static const struct bssgp_bvc_fsm_ops bss_ptp_bvc_fsm_ops = {
	.reset_notification = bss_ptp_bvc_reset_notif,
	.state_chg_notification = bss_ptp_bvc_state_chg_notif,
	.rx_fc_bvc = bss_ptp_bvc_fc_bvc,
};

/* BVC FSM informs us about a SGSN-side reset of a PTP BVC */
static void sgsn_ptp_bvc_reset_notif(uint16_t nsei, uint16_t bvci, const struct gprs_ra_id *ra_id,
				     uint16_t cell_id, uint8_t cause, void *priv)
{
	struct gbproxy_bvc *bvc = priv;

	if (!bvc->cell) {
		LOGPBVC(bvc, LOGL_ERROR, "RESET of PTP BVC on SGSN side for which we have no BSS?\n");
		return;
	}

	OSMO_ASSERT(bvc->cell->bss_bvc);

	/* request reset of BSS-facing PTP-BVC */
	osmo_fsm_inst_dispatch(bvc->cell->bss_bvc->fi, BSSGP_BVCFSM_E_REQ_RESET, &cause);
}

static const struct bssgp_bvc_fsm_ops sgsn_ptp_bvc_fsm_ops = {
	.reset_notification = sgsn_ptp_bvc_reset_notif,
};

/* BVC FSM informs us about a SGSN-side reset of the signaling BVC */
static void sgsn_sig_bvc_reset_notif(uint16_t nsei, uint16_t bvci, const struct gprs_ra_id *ra_id,
				     uint16_t cell_id, uint8_t cause, void *priv)
{
	struct gbproxy_bvc *bvc = priv;
	struct gbproxy_config *cfg = bvc->nse->cfg;
	struct gbproxy_nse *bss_nse;
	unsigned int i;

	/* delete all SGSN-side PTP BVC for this SGSN */
	gbproxy_cleanup_bvcs(bvc->nse, 0);
	/* FIXME: what to do about the cells? */
	/* FIXME: do we really want to RESET all signaling BVC on the BSS and affect all other SGSN? */

	/* we need to trigger generating a reset procedure towards each BSS side signaling BVC */
	hash_for_each(cfg->bss_nses, i, bss_nse, list) {
		struct gbproxy_bvc *bss_bvc = gbproxy_bvc_by_bvci(bss_nse, 0);
		if (!bss_bvc) {
			LOGPNSE(bss_nse, LOGL_ERROR, "Doesn't have BVC with BVCI=0 ?!?\n");
			continue;
		}
		osmo_fsm_inst_dispatch(bss_bvc->fi, BSSGP_BVCFSM_E_REQ_RESET, &cause);
	}
}

const struct bssgp_bvc_fsm_ops sgsn_sig_bvc_fsm_ops = {
	.reset_notification = sgsn_sig_bvc_reset_notif,
};

/***********************************************************************
 * Signaling BVC handling
 ***********************************************************************/

/* process a BVC-RESET message from the BSS side */
static int rx_bvc_reset_from_bss(struct gbproxy_nse *nse, struct msgb *msg, struct tlv_parsed *tp)
{
	struct gbproxy_bvc *from_bvc = NULL;
	uint16_t bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
	uint32_t features = 0; // FIXME: make configurable

	LOGPNSE(nse, LOGL_INFO, "Rx BVC-RESET (BVCI=%05u)\n", bvci);

	if (bvci == 0) {
		/* If we receive a BVC reset on the signalling endpoint, we
		 * don't want the SGSN to reset, as the signalling endpoint
		 * is common for all point-to-point BVCs (and thus all BTS) */

		from_bvc = gbproxy_bvc_by_bvci(nse, 0);
		if (!from_bvc) {
			from_bvc = gbproxy_bvc_alloc(nse, 0);
			OSMO_ASSERT(from_bvc);
			from_bvc->fi = bssgp_bvc_fsm_alloc_sig_sgsn(from_bvc, nse->cfg->nsi, nse->nsei, features);
			if (!from_bvc->fi) {
				LOGPNSE(nse, LOGL_ERROR, "Cannot allocate SIG-BVC FSM\n");
				gbproxy_bvc_free(from_bvc);
				return -ENOMEM;
			}
			bssgp_bvc_fsm_set_ops(from_bvc->fi, &bss_sig_bvc_fsm_ops, from_bvc);
		}
	} else {
		from_bvc = gbproxy_bvc_by_bvci(nse, bvci);
		if (!from_bvc) {
			/* if a PTP-BVC is reset, and we don't know that
			 * PTP-BVCI yet, we should allocate a new bvc */
			from_bvc = gbproxy_bvc_alloc(nse, bvci);
			OSMO_ASSERT(from_bvc);
			from_bvc->fi = bssgp_bvc_fsm_alloc_ptp_sgsn(from_bvc, nse->cfg->nsi,
								    nse->nsei, bvci);
			if (!from_bvc->fi) {
				LOGPNSE(nse, LOGL_ERROR, "Cannot allocate SIG-BVC FSM\n");
				gbproxy_bvc_free(from_bvc);
				return -ENOMEM;
			}
			bssgp_bvc_fsm_set_ops(from_bvc->fi, &bss_ptp_bvc_fsm_ops, from_bvc);
		}
#if 0
		/* Could have moved to a different NSE */
		if (!check_bvc_nsei(from_bvc, nsei)) {
			LOGPBVC(from_bvc, LOGL_NOTICE, "moving bvc to NSE(%05u)\n", nsei);

			struct gbproxy_nse *nse_new = gbproxy_nse_by_nsei(cfg, nsei, false);
			if (!nse_new) {
				LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u) Got PtP BVC reset before signalling reset for "
					"BVCI=%05u\n", bvci, nsei);
				bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_STATE, NULL, msg);
				return 0;
			}

			/* Move bvc to different NSE */
			gbproxy_bvc_move(from_bvc, nse_new);
		}
#endif
		/* FIXME: do we need this, if it happens within FSM? */
		if (TLVP_PRES_LEN(tp, BSSGP_IE_CELL_ID, 8)) {
			struct gprs_ra_id raid;
			/* We have a Cell Identifier present in this
			 * PDU, this means we can extend our local
			 * state information about this particular cell
			 * */
			memcpy(from_bvc->ra, TLVP_VAL(tp, BSSGP_IE_CELL_ID), sizeof(from_bvc->ra));
			gsm48_parse_ra(&raid, from_bvc->ra);
			LOGPBVC(from_bvc, LOGL_INFO, "Cell ID %s\n", osmo_rai_name(&raid));
		}
	}
	/* hand into FSM for further processing */
	osmo_fsm_inst_dispatch(from_bvc->fi, BSSGP_BVCFSM_E_RX_RESET, msg);
	return 0;
}

/* Receive an incoming signalling message from a BSS-side NS-VC */
static int gbprox_rx_sig_from_bss(struct gbproxy_nse *nse, struct msgb *msg, uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	uint8_t pdu_type = bgph->pdu_type;
	const char *pdut_name = osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type);
	struct tlv_parsed tp;
	int data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
	struct gbproxy_bvc *from_bvc = NULL;
	char log_pfx[32];
	uint16_t ptp_bvci;
	uint32_t tlli;
	int rc;

	snprintf(log_pfx, sizeof(log_pfx), "NSE(%05u/BSS)-BVC(%05u/??)", nse->nsei, ns_bvci);

	LOGP(DGPRS, LOGL_DEBUG, "%s Rx %s\n", log_pfx, pdut_name);

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s BVCI=%05u is not signalling\n", log_pfx, pdut_name, ns_bvci);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(pdu_type) & BSSGP_PDUF_SIG)) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s not allowed in signalling BVC\n", log_pfx, pdut_name);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(pdu_type) & BSSGP_PDUF_UL)) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s not allowed in uplink direction\n", log_pfx, pdut_name);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	rc = osmo_tlv_prot_parse(&osmo_pdef_bssgp, &tp, 1, pdu_type, bgph->data, data_len, 0, 0,
				 DGPRS, log_pfx);
	if (rc < 0) {
		rate_ctr_inc(&nse->cfg->ctrg->ctr[GBPROX_GLOB_CTR_PROTO_ERR_BSS]);
		return tx_status_from_tlvp(rc, msg);
	}
	/* hack to get both msg + tlv_parsed passed via osmo_fsm_inst_dispatch */
	msgb_bcid(msg) = (void *)&tp;

	/* special case handling for some PDU types */
	switch (pdu_type) {
	case BSSGP_PDUT_BVC_RESET:
		/* resolve or create gbproxy_bvc + handlei n BVC-FSM */
		ptp_bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		return rx_bvc_reset_from_bss(nse, msg, &tp);
	case BSSGP_PDUT_BVC_RESET_ACK:
		ptp_bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		from_bvc = gbproxy_bvc_by_bvci(nse, ptp_bvci);
		if (!from_bvc)
			goto err_no_bvc;
		return osmo_fsm_inst_dispatch(from_bvc->fi, BSSGP_BVCFSM_E_RX_RESET_ACK, msg);
	case BSSGP_PDUT_BVC_BLOCK:
		ptp_bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		from_bvc = gbproxy_bvc_by_bvci(nse, ptp_bvci);
		if (!from_bvc)
			goto err_no_bvc;
		return osmo_fsm_inst_dispatch(from_bvc->fi, BSSGP_BVCFSM_E_RX_BLOCK, msg);
	case BSSGP_PDUT_BVC_UNBLOCK:
		ptp_bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		from_bvc = gbproxy_bvc_by_bvci(nse, ptp_bvci);
		if (!from_bvc)
			goto err_no_bvc;
		return osmo_fsm_inst_dispatch(from_bvc->fi, BSSGP_BVCFSM_E_RX_UNBLOCK, msg);
	case BSSGP_PDUT_SUSPEND:
	case BSSGP_PDUT_RESUME:
		/* FIXME: Implement TLLI Cache.  Every SUSPEND/RESUME we must
		 * take record of the TLLI->BVC mapping so we can map
		 * back from TLLI->BVC when the SUSPEND/RESUME-ACK
		 * arrives.  Cache should have a timeout of 1-3 seconds
		 * and the ACK should explicitly delete entries. */
#if 0
		/* TODO: Validate the RAI for consistency with the RAI
		 * we expect for any of the BVC within this BSS side NSE */
		memcpy(ra, TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA), sizeof(from_bvc->ra));
		gsm48_parse_ra(&raid, from_bvc->ra);
#endif
		break;
	case BSSGP_PDUT_STATUS:
		/* FIXME: inspect the erroneous PDU IE (if any) and check
		 * if we can extract a TLLI/RNI to route it to the correct SGSN */
		break;
	case BSSGP_PDUT_RAN_INFO:
	case BSSGP_PDUT_RAN_INFO_REQ:
	case BSSGP_PDUT_RAN_INFO_ACK:
	case BSSGP_PDUT_RAN_INFO_ERROR:
	case BSSGP_PDUT_RAN_INFO_APP_ERROR:
		/* FIXME: route based in RIM Routing IE */
		rc = bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_FEAT, NULL, msg);
		break;
	case BSSGP_PDUT_LLC_DISCARD:
	case BSSGP_PDUT_FLUSH_LL_ACK:
		/* route based on BVCI + TLLI */
		ptp_bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		tlli = osmo_load32be(TLVP_VAL(&tp, BSSGP_IE_TLLI));
		from_bvc = gbproxy_bvc_by_bvci(nse, ptp_bvci);
		if (!from_bvc)
			goto err_no_bvc;
		gbprox_bss2sgsn_tlli(from_bvc->cell, msg, tlli, true);
		break;
	default:
		LOGPNSE(nse, LOGL_ERROR, "Rx %s: Implementation missing\n", pdut_name);
		break;
	}

	return rc;
err_no_bvc:
	LOGPNSE(nse, LOGL_ERROR, "Rx %s: cannot find BVC for BVCI=%05u\n", pdut_name, ptp_bvci);
	rate_ctr_inc(&nse->cfg->ctrg->ctr[GBPROX_GLOB_CTR_INV_NSEI]);
	return bssgp_tx_status(BSSGP_CAUSE_INV_MAND_INF, NULL, msg);
}

/* Receive paging request from SGSN, we need to relay to proper BSS */
static int gbprox_rx_paging(struct gbproxy_nse *sgsn_nse, struct msgb *msg, const char *pdut_name,
			    struct tlv_parsed *tp, uint16_t ns_bvci)
{
	struct gbproxy_config *cfg = sgsn_nse->cfg;
	struct gbproxy_bvc *sgsn_bvc, *bss_bvc;
	struct gbproxy_nse *nse;
	unsigned int n_nses = 0;
	int errctr = GBPROX_GLOB_CTR_PROTO_ERR_SGSN;
	int i, j;

	/* FIXME: Handle paging logic to only page each matching NSE */

	if (TLVP_PRES_LEN(tp, BSSGP_IE_BVCI, 2)) {
		uint16_t bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
		errctr = GBPROX_GLOB_CTR_OTHER_ERR;
		sgsn_bvc = gbproxy_bvc_by_bvci(sgsn_nse, bvci);
		if (!sgsn_bvc) {
			LOGPNSE(sgsn_nse, LOGL_NOTICE, "Rx %s: unable to route: BVCI=%05u unknown\n",
				pdut_name, bvci);
			rate_ctr_inc(&cfg->ctrg->ctr[errctr]);
			return -EINVAL;
		}
		LOGPBVC(sgsn_bvc, LOGL_INFO, "Rx %s: routing by BVCI\n", pdut_name);
		return gbprox_relay2peer(msg, sgsn_bvc->cell->bss_bvc, ns_bvci);
	} else if (TLVP_PRES_LEN(tp, BSSGP_IE_ROUTEING_AREA, 6)) {
		errctr = GBPROX_GLOB_CTR_INV_RAI;
		/* iterate over all bvcs and dispatch the paging to each matching one */
		hash_for_each(cfg->bss_nses, i, nse, list) {
			hash_for_each(nse->bvcs, j, bss_bvc, list) {
				if (!memcmp(bss_bvc->ra, TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA), 6)) {
					LOGPNSE(nse, LOGL_INFO, "Rx %s: routing to NSE (RAI match)\n",
						pdut_name);
					gbprox_relay2peer(msg, bss_bvc, ns_bvci);
					n_nses++;
					/* Only send it once to each NSE */
					break;
				}
			}
		}
	} else if (TLVP_PRES_LEN(tp, BSSGP_IE_LOCATION_AREA, 5)) {
		errctr = GBPROX_GLOB_CTR_INV_LAI;
		/* iterate over all bvcs and dispatch the paging to each matching one */
		hash_for_each(cfg->bss_nses, i, nse, list) {
			hash_for_each(nse->bvcs, j, bss_bvc, list) {
				if (!memcmp(bss_bvc->ra, TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA), 5)) {
					LOGPNSE(nse, LOGL_INFO, "Rx %s: routing to NSE (LAI match)\n",
						pdut_name);
					gbprox_relay2peer(msg, bss_bvc, ns_bvci);
					n_nses++;
					/* Only send it once to each NSE */
					break;
				}
			}
		}
	} else if (TLVP_PRES_LEN(tp, BSSGP_IE_BSS_AREA_ID, 1)) {
		/* iterate over all bvcs and dispatch the paging to each matching one */
		hash_for_each(cfg->bss_nses, i, nse, list) {
			hash_for_each(nse->bvcs, j, bss_bvc, list) {
				LOGPNSE(nse, LOGL_INFO, "Rx %s:routing to NSE (broadcast)\n", pdut_name);
				gbprox_relay2peer(msg, bss_bvc, ns_bvci);
				n_nses++;
				/* Only send it once to each NSE */
				break;
			}
		}
	} else {
		LOGPNSE(sgsn_nse, LOGL_ERROR, "BSSGP PAGING: unable to route, missing IE\n");
		rate_ctr_inc(&cfg->ctrg->ctr[errctr]);
	}

	if (n_nses == 0) {
		LOGPNSE(sgsn_nse, LOGL_ERROR, "BSSGP PAGING: unable to route, no destination found\n");
		rate_ctr_inc(&cfg->ctrg->ctr[errctr]);
		return -EINVAL;
	}
	return 0;
}

/* Receive an incoming BVC-RESET message from the SGSN */
static int rx_bvc_reset_from_sgsn(struct gbproxy_nse *nse, struct msgb *msg, struct tlv_parsed *tp,
			uint16_t ns_bvci)
{
	uint16_t ptp_bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
	struct gbproxy_bvc *from_bvc;

	LOGPNSE(nse, LOGL_INFO, "Rx BVC-RESET (BVCI=%05u)\n", ptp_bvci);

	if (ptp_bvci == 0) {
		from_bvc = gbproxy_bvc_by_bvci(nse, 0);
		OSMO_ASSERT(from_bvc);
		osmo_fsm_inst_dispatch(from_bvc->fi, BSSGP_BVCFSM_E_RX_RESET, msg);
	} else {
		from_bvc = gbproxy_bvc_by_bvci(nse, ptp_bvci);
		if (!from_bvc) {
			LOGPNSE(nse, LOGL_ERROR, "Rx BVC-RESET BVCI=%05u: Cannot find BVC\n", ptp_bvci);
			rate_ctr_inc(&nse->cfg->ctrg->ctr[GBPROX_GLOB_CTR_INV_BVCI]);
			return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, &ptp_bvci, msg);
		}
		osmo_fsm_inst_dispatch(from_bvc->fi, BSSGP_BVCFSM_E_RX_RESET, msg);
	}

	return 0;
}

/* Receive an incoming signalling message from the SGSN-side NS-VC */
static int gbprox_rx_sig_from_sgsn(struct gbproxy_nse *nse, struct msgb *msg, uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	uint8_t pdu_type = bgph->pdu_type;
	const char *pdut_name = osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type);
	struct gbproxy_config *cfg = nse->cfg;
	struct gbproxy_bvc *sgsn_bvc;
	struct tlv_parsed tp;
	int data_len;
	uint16_t bvci;
	char log_pfx[32];
	int rc = 0;
	int cause;
	int i;

	snprintf(log_pfx, sizeof(log_pfx), "NSE(%05u/SGSN)-BVC(%05u/??)", nse->nsei, ns_bvci);

	LOGP(DGPRS, LOGL_DEBUG, "%s Rx %s\n", log_pfx, pdut_name);

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "%s BVCI=%05u is not signalling\n", log_pfx, ns_bvci);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(pdu_type) & BSSGP_PDUF_SIG)) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s not allowed in signalling BVC\n", log_pfx, pdut_name);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(pdu_type) & BSSGP_PDUF_DL)) {
		LOGP(DGPRS, LOGL_NOTICE, "%s %s not allowed in downlink direction\n", log_pfx, pdut_name);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	data_len = msgb_bssgp_len(msg) - sizeof(*bgph);

	rc = osmo_tlv_prot_parse(&osmo_pdef_bssgp, &tp, 1, pdu_type, bgph->data, data_len, 0, 0,
				 DGPRS, log_pfx);
	if (rc < 0) {
		rc = tx_status_from_tlvp(rc, msg);
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
		return rc;
	}
	/* hack to get both msg + tlv_parsed passed via osmo_fsm_inst_dispatch */
	msgb_bcid(msg) = (void *)&tp;

	switch (pdu_type) {
	case BSSGP_PDUT_BVC_RESET:
		/* resolve or create ggbproxy_bvc + handle in BVC-FSM */
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		rc = rx_bvc_reset_from_sgsn(nse, msg, &tp, ns_bvci);
		break;
	case BSSGP_PDUT_BVC_RESET_ACK:
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		sgsn_bvc = gbproxy_bvc_by_bvci(nse, bvci);
		if (!sgsn_bvc)
			goto err_no_bvc;
		rc = osmo_fsm_inst_dispatch(sgsn_bvc->fi, BSSGP_BVCFSM_E_RX_RESET_ACK, msg);
		break;
	case BSSGP_PDUT_BVC_BLOCK_ACK:
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		sgsn_bvc = gbproxy_bvc_by_bvci(nse, bvci);
		if (!sgsn_bvc)
			goto err_no_bvc;
		rc = osmo_fsm_inst_dispatch(sgsn_bvc->fi, BSSGP_BVCFSM_E_RX_BLOCK_ACK, msg);
		break;
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		sgsn_bvc = gbproxy_bvc_by_bvci(nse, bvci);
		if (!sgsn_bvc)
			goto err_no_bvc;
		rc = osmo_fsm_inst_dispatch(sgsn_bvc->fi, BSSGP_BVCFSM_E_RX_UNBLOCK_ACK, msg);
		break;
	case BSSGP_PDUT_FLUSH_LL:
		/* simple case: BVCI IE is mandatory */
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		sgsn_bvc = gbproxy_bvc_by_bvci(nse, bvci);
		if (!sgsn_bvc)
			goto err_no_bvc;
		if (sgsn_bvc->cell && sgsn_bvc->cell->bss_bvc)
			rc = gbprox_relay2peer(msg, sgsn_bvc->cell->bss_bvc, ns_bvci);
		break;
	case BSSGP_PDUT_PAGING_PS:
	case BSSGP_PDUT_PAGING_CS:
		/* process the paging request (LAI/RAI lookup) */
		rc = gbprox_rx_paging(nse, msg, pdut_name, &tp, ns_bvci);
		break;
	case BSSGP_PDUT_STATUS:
		/* Some exception has occurred */
		cause = *TLVP_VAL(&tp, BSSGP_IE_CAUSE);
		LOGPNSE(nse, LOGL_NOTICE, "Rx STATUS cause=0x%02x(%s) ", cause,
			bssgp_cause_str(cause));
		if (TLVP_PRES_LEN(&tp, BSSGP_IE_BVCI, 2)) {
			bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
			LOGPC(DGPRS, LOGL_NOTICE, "BVCI=%05u\n", bvci);
			sgsn_bvc = gbproxy_bvc_by_bvci(nse, bvci);
			/* don't send STATUS in response to STATUS if !bvc */
			if (sgsn_bvc && sgsn_bvc->cell && sgsn_bvc->cell->bss_bvc)
				rc = gbprox_relay2peer(msg, sgsn_bvc->cell->bss_bvc, ns_bvci);
		} else
			LOGPC(DGPRS, LOGL_NOTICE, "\n");
		break;
	/* those only exist in the SGSN -> BSS direction */
	case BSSGP_PDUT_SUSPEND_ACK:
	case BSSGP_PDUT_SUSPEND_NACK:
	case BSSGP_PDUT_RESUME_ACK:
	case BSSGP_PDUT_RESUME_NACK:
		/* FIXME: handle based on TLLI cache. The RA-ID is not a unique
		 * criterion, so we have to rely on the TLLI->BVC state created
		 * while processing the SUSPEND/RESUME in uplink */
		/* FIXME: route to SGSN baed on NRI derived from TLLI */
		break;
	case BSSGP_PDUT_SGSN_INVOKE_TRACE:
	case BSSGP_PDUT_OVERLOAD:
		LOGPNSE(nse, LOGL_DEBUG, "Rx %s: broadcasting\n", pdut_name);
		/* broadcast to all BSS-side bvcs */
		hash_for_each(cfg->bss_nses, i, nse, list) {
			gbprox_relay2nse(msg, nse, 0);
		}
		break;
	case BSSGP_PDUT_RAN_INFO:
	case BSSGP_PDUT_RAN_INFO_REQ:
	case BSSGP_PDUT_RAN_INFO_ACK:
	case BSSGP_PDUT_RAN_INFO_ERROR:
	case BSSGP_PDUT_RAN_INFO_APP_ERROR:
		/* FIXME: route based in RIM Routing IE */
		rc = bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_FEAT, NULL, msg);
		break;
	default:
		LOGPNSE(nse, LOGL_NOTICE, "Rx %s: Not supported\n", pdut_name);
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
		break;
	}

	return rc;

err_no_bvc:
	LOGPNSE(nse, LOGL_ERROR, "Rx %s: Cannot find BVC\n", pdut_name);
	rate_ctr_inc(&cfg->ctrg-> ctr[GBPROX_GLOB_CTR_INV_RAI]);
	return bssgp_tx_status(BSSGP_CAUSE_INV_MAND_INF, NULL, msg);
}


/***********************************************************************
 * libosmogb NS/BSSGP integration
 ***********************************************************************/

int gbprox_bssgp_send_cb(void *ctx, struct msgb *msg)
{
	int rc;
	struct gbproxy_config *cfg = (struct gbproxy_config *) ctx;
	struct gprs_ns2_inst *nsi = cfg->nsi;
	struct osmo_gprs_ns2_prim nsp = {};

	nsp.bvci = msgb_bvci(msg);
	nsp.nsei = msgb_nsei(msg);

	osmo_prim_init(&nsp.oph, SAP_NS, PRIM_NS_UNIT_DATA, PRIM_OP_REQUEST, msg);
	rc = gprs_ns2_recv_prim(nsi, &nsp.oph);

	return rc;
}

/* Main input function for Gb proxy */
int gbprox_rcvmsg(void *ctx, struct msgb *msg)
{
	struct gbproxy_config *cfg = (struct gbproxy_config *) ctx;
	uint16_t ns_bvci = msgb_bvci(msg);
	uint16_t nsei = msgb_nsei(msg);
	struct gbproxy_nse *nse;

	/* ensure minimum length to decode PCU type */
	if (msgb_bssgp_len(msg) < sizeof(struct bssgp_normal_hdr))
		return bssgp_tx_status(BSSGP_CAUSE_SEM_INCORR_PDU, NULL, msg);

	nse = gbproxy_nse_by_nsei(cfg, nsei, NSE_F_SGSN);
	if (nse) {
		if (ns_bvci == 0 || ns_bvci == 1)
			return gbprox_rx_sig_from_sgsn(nse, msg, ns_bvci);
		else
			return gbprox_rx_ptp_from_sgsn(nse, msg, ns_bvci);
	}

	nse = gbproxy_nse_by_nsei(cfg, nsei, NSE_F_BSS);
	if (!nse) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/BSS) not known -> allocating\n", nsei);
		nse = gbproxy_nse_alloc(cfg, nsei, false);
	}
	if (nse) {
		if (ns_bvci == 0 || ns_bvci == 1)
			return gbprox_rx_sig_from_bss(nse, msg, ns_bvci);
		else
			return gbprox_rx_ptp_from_bss(nse, msg, ns_bvci);
	}

	return 0;
}

/*  TODO: What about handling:
 * 	NS_AFF_CAUSE_VC_FAILURE,
	NS_AFF_CAUSE_VC_RECOVERY,
	NS_AFF_CAUSE_FAILURE,
	NS_AFF_CAUSE_RECOVERY,
	osmocom own causes
	NS_AFF_CAUSE_SNS_CONFIGURED,
	NS_AFF_CAUSE_SNS_FAILURE,
	*/

void gprs_ns_prim_status_cb(struct gbproxy_config *cfg, struct osmo_gprs_ns2_prim *nsp)
{
	/* TODO: bss nsei available/unavailable  bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_BLOCK, nsvc->nsei, bvc->bvci, 0);
	 * TODO: sgsn nsei available/unavailable
	 */

	struct gbproxy_bvc *bvc;
	struct gbproxy_nse *sgsn_nse;

	switch (nsp->u.status.cause) {
	case NS_AFF_CAUSE_SNS_FAILURE:
	case NS_AFF_CAUSE_SNS_CONFIGURED:
		break;

	case NS_AFF_CAUSE_RECOVERY:
		LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d became available\n", nsp->nsei);
		sgsn_nse = gbproxy_nse_by_nsei(cfg, nsp->nsei, NSE_F_SGSN);
		if (sgsn_nse) {
			uint8_t cause = BSSGP_CAUSE_OML_INTERV;
			bvc = gbproxy_bvc_by_bvci(sgsn_nse, 0);
			if (bvc)
				osmo_fsm_inst_dispatch(bvc->fi, BSSGP_BVCFSM_E_REQ_RESET, &cause); 
		}
		break;
	case NS_AFF_CAUSE_FAILURE:
#if 0
		if (gbproxy_is_sgsn_nsei(cfg, nsp->nsei)) {
			/* sgsn */
			/* TODO: BSVC: block all PtP towards bss */
			rate_ctr_inc(&cfg->ctrg->
				     ctr[GBPROX_GLOB_CTR_RESTART_RESET_SGSN]);
		} else {
			/* bss became unavailable
			 * TODO: Block all BVC belonging to that NSE */
			bvc = gbproxy_bvc_by_nsei(cfg, nsp->nsei);
			if (!bvc) {
				/* TODO: use primitive name + status cause name */
				LOGP(DGPRS, LOGL_NOTICE, "Received ns2 primitive %d for unknown bvc NSEI=%u\n",
				     nsp->u.status.cause, nsp->nsei);
				break;
			}

			if (!bvc->blocked)
				break;
			hash_for_each(cfg->sgsn_nses, _sgsn, sgsn_nse, list) {
				bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_BLOCK, sgsn_nse->nsei, bvc->bvci, 0);
			}
		}
#endif
		LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d became unavailable\n", nsp->nsei);
		break;
	default:
		LOGP(DPCU, LOGL_NOTICE, "NS: Unknown NS-STATUS.ind cause=%s from NS\n",
		     gprs_ns2_aff_cause_prim_str(nsp->u.status.cause));
		break;
	}
}

/* called by the ns layer */
int gprs_ns2_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_gprs_ns2_prim *nsp;
	struct gbproxy_config *cfg = (struct gbproxy_config *) ctx;
	uintptr_t bvci;
	int rc = 0;

	if (oph->sap != SAP_NS)
		return 0;

	nsp = container_of(oph, struct osmo_gprs_ns2_prim, oph);

	if (oph->operation != PRIM_OP_INDICATION) {
		LOGP(DPCU, LOGL_NOTICE, "NS: Unexpected primitive operation %s from NS\n",
		     get_value_string(osmo_prim_op_names, oph->operation));
		return 0;
	}

	switch (oph->primitive) {
	case PRIM_NS_UNIT_DATA:

		/* hand the message into the BSSGP implementation */
		msgb_bssgph(oph->msg) = oph->msg->l3h;
		msgb_bvci(oph->msg) = nsp->bvci;
		msgb_nsei(oph->msg) = nsp->nsei;
		bvci = nsp->bvci | BVC_LOG_CTX_FLAG;

		log_set_context(LOG_CTX_GB_BVC, (void *)bvci);
		rc = gbprox_rcvmsg(cfg, oph->msg);
		msgb_free(oph->msg);
		break;
	case PRIM_NS_STATUS:
		gprs_ns_prim_status_cb(cfg, nsp);
		break;
	default:
		LOGP(DPCU, LOGL_NOTICE, "NS: Unknown prim %s %s from NS\n",
		     gprs_ns2_prim_str(oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation));
		break;
	}

	return rc;
}

void gbprox_reset(struct gbproxy_config *cfg)
{
	struct gbproxy_nse *nse;
	struct hlist_node *ntmp;
	int i, j;

	hash_for_each_safe(cfg->bss_nses, i, ntmp, nse, list) {
		struct gbproxy_bvc *bvc;
		struct hlist_node *tmp;
		hash_for_each_safe(nse->bvcs, j, tmp, bvc, list)
			gbproxy_bvc_free(bvc);

		gbproxy_nse_free(nse);
	}
	/* FIXME: cells */
	/* FIXME: SGSN side BVCs (except signaling) */

	rate_ctr_group_free(cfg->ctrg);
	gbproxy_init_config(cfg);
}

int gbproxy_init_config(struct gbproxy_config *cfg)
{
	struct timespec tp;

	hash_init(cfg->bss_nses);
	cfg->ctrg = rate_ctr_group_alloc(tall_sgsn_ctx, &global_ctrg_desc, 0);
	if (!cfg->ctrg) {
		LOGP(DGPRS, LOGL_ERROR, "Cannot allocate global counter group!\n");
		return -1;
	}
	osmo_clock_gettime(CLOCK_REALTIME, &tp);
	osmo_fsm_log_timeouts(true);

	return 0;
}
