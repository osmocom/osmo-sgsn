/* NS-over-IP proxy */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
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
static int gbprox_relay2sgsn(struct gbproxy_config *cfg, struct msgb *old_msg,
			     uint16_t ns_bvci, uint16_t sgsn_nsei);


static int gbproxy_is_sgsn_nsei(struct gbproxy_config *cfg, uint16_t nsei)
{
	return nsei == cfg->nsip_sgsn_nsei;
}

static int check_bvc_nsei(struct gbproxy_bvc *bvc, uint16_t nsei)
{
	OSMO_ASSERT(bvc);
	OSMO_ASSERT(bvc->nse);

	if (bvc->nse->nsei != nsei) {
		LOGPBVC(bvc, LOGL_NOTICE, "Peer entry doesn't match current NSEI "
		     "via NSE(%05u/BSS)\n", nsei);
		rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_INV_NSEI]);
		return 0;
	}

	return 1;
}

/* strip off the NS header */
static void strip_ns_hdr(struct msgb *msg)
{
	int strip_len = msgb_bssgph(msg) - msg->data;
	msgb_pull(msg, strip_len);
}

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

static int block_unblock_bvc(struct gbproxy_config *cfg, uint16_t ptp_bvci, uint8_t pdu_type)
{
	struct gbproxy_bvc *bvc;

	bvc = gbproxy_bvc_by_bvci(cfg, ptp_bvci);
	if (!bvc) {
		LOGP(DGPRS, LOGL_ERROR, "BVC(%05u/??) Cannot find BSS\n",
			ptp_bvci);
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		return -ENOENT;
	}

	switch (pdu_type) {
	case BSSGP_PDUT_BVC_BLOCK_ACK:
		bvc->blocked = true;
		rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_BLOCKED]);
		break;
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
		bvc->blocked = false;
		rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_UNBLOCKED]);
		break;
	default:
		break;
	}
	return 0;
}

/* Send a message to a bvc identified by ptp_bvci but using ns_bvci
 * in the NS hdr */
static int gbprox_relay2bvci(struct gbproxy_config *cfg, struct msgb *msg, uint16_t ptp_bvci,
			  uint16_t ns_bvci)
{
	struct gbproxy_bvc *bvc;

	bvc = gbproxy_bvc_by_bvci(cfg, ptp_bvci);
	if (!bvc) {
		LOGP(DGPRS, LOGL_ERROR, "BVC(%05u/??) Cannot find BSS\n",
			ptp_bvci);
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		return -ENOENT;
	}

	return gbprox_relay2peer(msg, bvc, ns_bvci);
}

int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	return 0;
}

/* Receive an incoming PTP message from a BSS-side NS-VC */
static int gbprox_rx_ptp_from_bss(struct gbproxy_config *cfg,
				  struct msgb *msg, uint16_t nsei,
				  uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct gbproxy_bvc *bvc;

	if (ns_bvci == 0 && ns_bvci == 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/BSS) BVCI=%05u is not PTP\n", nsei, ns_bvci);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(bgph->pdu_type) & BSSGP_PDUF_PTP)) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/%05u) %s not allowed in PTP BVC\n",
		     nsei, ns_bvci, osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type));
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(bgph->pdu_type) & BSSGP_PDUF_UL)) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/%05u) %s not allowed in uplink direction\n",
		     nsei, ns_bvci, osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type));
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	bvc = gbproxy_bvc_by_bvci(cfg, ns_bvci);
	if (!bvc) {
		LOGP(DGPRS, LOGL_NOTICE, "BVC(%05u/??) Didn't find bvc "
		     "for PTP message from NSE(%05u/BSS), "
		     "discarding message\n",
		     ns_bvci, nsei);
		return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI,
				       &ns_bvci, msg);
	}

	/* TODO: Should we discard this message if the check fails */
	check_bvc_nsei(bvc, nsei);

	return gbprox_relay2sgsn(cfg, msg, ns_bvci, cfg->nsip_sgsn_nsei);
}

/* Receive an incoming PTP message from a SGSN-side NS-VC */
static int gbprox_rx_ptp_from_sgsn(struct gbproxy_config *cfg,
				   struct msgb *msg, uint16_t nsei,
				   uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct gbproxy_bvc *bvc;

	if (ns_bvci == 0 && ns_bvci == 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/BSS) BVCI=%05u is not PTP\n", nsei, ns_bvci);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(bgph->pdu_type) & BSSGP_PDUF_PTP)) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/%05u) %s not allowed in PTP BVC\n",
		     nsei, ns_bvci, osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type));
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(bgph->pdu_type) & BSSGP_PDUF_DL)) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/%05u) %s not allowed in downlink direction\n",
		     nsei, ns_bvci, osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, bgph->pdu_type));
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	bvc = gbproxy_bvc_by_bvci(cfg, ns_bvci);
	if (!bvc) {
		LOGP(DGPRS, LOGL_INFO, "BVC(%05u/??) Didn't find bvc for "
		     "for message from NSE(%05u/SGSN)\n",
		     ns_bvci, nsei);
		rate_ctr_inc(&cfg->ctrg->
			     ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI,
				       &ns_bvci, msg);
	}

	if (bvc->blocked) {
		LOGPBVC(bvc, LOGL_NOTICE, "Dropping PDU for "
		     "blocked BVC via NSE(%05u/SGSN)\n", nsei);
		rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_DROPPED]);
		return bssgp_tx_status(BSSGP_CAUSE_BVCI_BLOCKED, &ns_bvci, msg);
	}

	return gbprox_relay2peer(msg, bvc, ns_bvci);
}

/* process a BVC-RESET message from the BSS side */
static int gbprox_rx_bvc_reset_from_bss(struct gbproxy_config *cfg, struct msgb *msg,
					uint16_t nsei, struct tlv_parsed *tp)
{
	struct gbproxy_bvc *from_bvc = NULL;
	uint16_t bvci;

	if (!TLVP_PRES_LEN(tp, BSSGP_IE_BVCI, 2) || !TLVP_PRES_LEN(tp, BSSGP_IE_CAUSE, 1)) {
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_PROTO_ERR_BSS]);
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
	}

	bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
	LOGP(DGPRS, LOGL_INFO, "NSE(%05u) Rx BVC RESET (BVCI=%05u)\n", nsei, bvci);
	if (bvci == 0) {
		/* If we receive a BVC reset on the signalling endpoint, we
		 * don't want the SGSN to reset, as the signalling endpoint
		 * is common for all point-to-point BVCs (and thus all BTS) */

		/* Ensure the NSE bvc is there and clear all PtP BVCs */
		struct gbproxy_nse *nse = gbproxy_nse_by_nsei_or_new(cfg, nsei);
		if (!nse) {
			LOGP(DGPRS, LOGL_ERROR, "Could not create NSE(%05u)\n", nsei);
			bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, 0, msg);
			return 0;
		}

		gbproxy_cleanup_bvcs(cfg, nsei, 0);

		/* FIXME: only do this if SGSN is alive! */
		LOGPNSE(nse, LOGL_INFO, "Tx fake BVC RESET ACK of BVCI=0\n");
		bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_RESET_ACK, nsei, 0, 0);
		return 0;
	} else {
		from_bvc = gbproxy_bvc_by_bvci(cfg, bvci);
		if (!from_bvc) {
			struct gbproxy_nse *nse = gbproxy_nse_by_nsei(cfg, nsei);
			if (!nse) {
				LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u) Got PtP BVC reset before signalling reset for "
					"BVCI=%05u\n", nsei, bvci);
				bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_STATE, NULL, msg);
				return 0;
			}
			/* if a PTP-BVC is reset, and we don't know that
			 * PTP-BVCI yet, we should allocate a new bvc */
			from_bvc = gbproxy_bvc_alloc(nse, bvci);
			OSMO_ASSERT(from_bvc);
			LOGPBVC(from_bvc, LOGL_INFO, "Allocated new bvc\n");
		}

		/* Could have moved to a different NSE */
		if (!check_bvc_nsei(from_bvc, nsei)) {
			LOGPBVC(from_bvc, LOGL_NOTICE, "moving bvc to NSE(%05u)\n", nsei);

			struct gbproxy_nse *nse_new = gbproxy_nse_by_nsei(cfg, nsei);
			if (!nse_new) {
				LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u) Got PtP BVC reset before signalling reset for "
					"BVCI=%05u\n", bvci, nsei);
				bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_STATE, NULL, msg);
				return 0;
			}

			/* Move bvc to different NSE */
			gbproxy_bvc_move(from_bvc, nse_new);
		}

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
	/* continue processing / relaying to SGSN[s] */
	return 1;
}

/* Receive an incoming signalling message from a BSS-side NS-VC */
static int gbprox_rx_sig_from_bss(struct gbproxy_config *cfg,
				  struct msgb *msg, uint16_t nsei,
				  uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
	struct gbproxy_bvc *from_bvc = NULL;
	struct gprs_ra_id raid;
	int rc;

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/BSS) BVCI=%05u is not signalling\n", nsei, ns_bvci);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(pdu_type) & BSSGP_PDUF_SIG)) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/BSS) %s not allowed in signalling BVC\n",
		     nsei, osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, pdu_type));
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	if (!(bssgp_pdu_type_flags(pdu_type) & BSSGP_PDUF_UL)) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/BSS) %s not allowed in uplink direction\n",
		     nsei, osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, pdu_type));
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_SUSPEND:
	case BSSGP_PDUT_RESUME:
		/* We implement RAI snooping during SUSPEND/RESUME, since it
		 * establishes a relationsip between BVCI/bvc and the routeing
		 * area identification.  The snooped information is then used
		 * for routing the {SUSPEND,RESUME}_[N]ACK back to the correct
		 * BSSGP */
		if (!TLVP_PRES_LEN(&tp, BSSGP_IE_ROUTEING_AREA, 6))
			goto err_mand_ie;
		from_bvc = gbproxy_bvc_by_nsei(cfg, nsei);
		if (!from_bvc)
			goto err_no_bvc;
		memcpy(from_bvc->ra, TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA),
			sizeof(from_bvc->ra));
		gsm48_parse_ra(&raid, from_bvc->ra);
		LOGPBVC(from_bvc, LOGL_INFO, "BSSGP SUSPEND/RESUME "
			"RAI snooping: RAI %s\n",
			osmo_rai_name(&raid));
		/* FIXME: This only supports one BSS per RA */
		break;
	case BSSGP_PDUT_BVC_RESET:
		rc = gbprox_rx_bvc_reset_from_bss(cfg, msg, nsei, &tp);
		/* if function retruns 0, we terminate processing here */
		if (rc == 0)
			return 0;
		break;
	}

	return gbprox_relay2sgsn(cfg, msg, ns_bvci, cfg->nsip_sgsn_nsei);
err_no_bvc:
	LOGP(DGPRS, LOGL_ERROR, "NSE(%05u/BSS) cannot find bvc based on NSEI\n",
		nsei);
	rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_INV_NSEI]);
	return bssgp_tx_status(BSSGP_CAUSE_INV_MAND_INF, NULL, msg);
err_mand_ie:
	LOGP(DGPRS, LOGL_ERROR, "NSE(%05u/BSS) missing mandatory RA IE\n",
		nsei);
	rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_PROTO_ERR_BSS]);
	return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
}

/* Receive paging request from SGSN, we need to relay to proper BSS */
static int gbprox_rx_paging(struct gbproxy_config *cfg, struct msgb *msg, struct tlv_parsed *tp,
			    uint32_t nsei, uint16_t ns_bvci)
{
	struct gbproxy_nse *nse;
	struct gbproxy_bvc *bvc;
	unsigned int n_nses = 0;
	int errctr = GBPROX_GLOB_CTR_PROTO_ERR_SGSN;
	int i, j;

	/* FIXME: Handle paging logic to only page each matching NSE */

	LOGP(DGPRS, LOGL_INFO, "NSE(%05u/SGSN) BSSGP PAGING\n",
		nsei);
	if (TLVP_PRES_LEN(tp, BSSGP_IE_BVCI, 2)) {
		uint16_t bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
		errctr = GBPROX_GLOB_CTR_OTHER_ERR;
		bvc = gbproxy_bvc_by_bvci(cfg, bvci);
		if (!bvc) {
			LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/SGSN) BSSGP PAGING: "
				"unable to route: BVCI=%05u unknown\n", nsei, bvci);
			rate_ctr_inc(&cfg->ctrg->ctr[errctr]);
			return -EINVAL;
		}
		LOGPBVC(bvc, LOGL_INFO, "routing by BVCI\n");
		return gbprox_relay2peer(msg, bvc, ns_bvci);
	} else if (TLVP_PRES_LEN(tp, BSSGP_IE_ROUTEING_AREA, 6)) {
		errctr = GBPROX_GLOB_CTR_INV_RAI;
		/* iterate over all bvcs and dispatch the paging to each matching one */
		hash_for_each(cfg->bss_nses, i, nse, list) {
			hash_for_each(nse->bvcs, j, bvc, list) {
				if (!memcmp(bvc->ra, TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA), 6)) {
					LOGPNSE(nse, LOGL_INFO, "routing to NSE (RAI match)\n");
					gbprox_relay2peer(msg, bvc, ns_bvci);
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
			hash_for_each(nse->bvcs, j, bvc, list) {
				if (!memcmp(bvc->ra, TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA), 5)) {
					LOGPNSE(nse, LOGL_INFO, "routing to NSE (LAI match)\n");
					gbprox_relay2peer(msg, bvc, ns_bvci);
					n_nses++;
					/* Only send it once to each NSE */
					break;
				}
			}
		}
	} else if (TLVP_PRES_LEN(tp, BSSGP_IE_BSS_AREA_ID, 1)) {
		/* iterate over all bvcs and dispatch the paging to each matching one */
		hash_for_each(cfg->bss_nses, i, nse, list) {
			hash_for_each(nse->bvcs, j, bvc, list) {
				LOGPNSE(nse, LOGL_INFO, "routing to NSE (broadcast)\n");
				gbprox_relay2peer(msg, bvc, ns_bvci);
				n_nses++;
				/* Only send it once to each NSE */
				break;
			}
		}
	} else {
		LOGP(DGPRS, LOGL_ERROR, "NSE(%05u/SGSN) BSSGP PAGING: "
			"unable to route, missing IE\n", nsei);
		rate_ctr_inc(&cfg->ctrg->ctr[errctr]);
	}

	if (n_nses == 0) {
		LOGP(DGPRS, LOGL_ERROR, "NSE(%05u/SGSN) BSSGP PAGING: "
			"unable to route, no destination found\n", nsei);
		rate_ctr_inc(&cfg->ctrg->ctr[errctr]);
		return -EINVAL;
	}
	return 0;
}

/* Receive an incoming BVC-RESET message from the SGSN */
static int rx_reset_from_sgsn(struct gbproxy_config *cfg,
			struct msgb *orig_msg,
			struct msgb *msg, struct tlv_parsed *tp,
			uint32_t nsei, uint16_t ns_bvci)
{
	struct gbproxy_nse *nse;
	struct gbproxy_bvc *bvc;
	uint16_t ptp_bvci;
	int i, j;

	if (!TLVP_PRES_LEN(tp, BSSGP_IE_BVCI, 2)) {
		rate_ctr_inc(&cfg->ctrg->
			     ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE,
				       NULL, orig_msg);
	}
	ptp_bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));

	if (ptp_bvci >= 2) {
		/* A reset for a PTP BVC was received, forward it to its
		 * respective bvc */
		bvc = gbproxy_bvc_by_bvci(cfg, ptp_bvci);
		if (!bvc) {
			LOGP(DGPRS, LOGL_ERROR, "NSE(%05u/SGSN) BVCI=%05u: Cannot find BSS\n",
				nsei, ptp_bvci);
			rate_ctr_inc(&cfg->ctrg->
				     ctr[GBPROX_GLOB_CTR_INV_BVCI]);
			return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI,
					       &ptp_bvci, orig_msg);
		}
		return gbprox_relay2peer(msg, bvc, ns_bvci);
	}

	/* A reset for the Signalling entity has been received
	 * from the SGSN.  As the signalling BVCI is shared
	 * among all the BSS's that we multiplex, it needs to
	 * be relayed  */
	hash_for_each(cfg->bss_nses, i, nse, list) {
		hash_for_each(nse->bvcs, j, bvc, list)
			gbprox_relay2peer(msg, bvc, ns_bvci);
	}

	return 0;
}

/* Receive an incoming signalling message from the SGSN-side NS-VC */
static int gbprox_rx_sig_from_sgsn(struct gbproxy_config *cfg,
				struct msgb *orig_msg, uint32_t nsei,
				uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph =
		(struct bssgp_normal_hdr *) msgb_bssgph(orig_msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len;
	struct gbproxy_nse *nse;
	struct gbproxy_bvc *bvc;
	uint16_t bvci;
	struct msgb *msg;
	int rc = 0;
	int cause;
	int i;

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/SGSN) BVCI=%05u is not signalling\n", nsei, ns_bvci);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, orig_msg);
	}

	if (!(bssgp_pdu_type_flags(pdu_type) & BSSGP_PDUF_SIG)) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/SGSN) %s not allowed in signalling BVC\n",
		     nsei, osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, pdu_type));
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, orig_msg);
	}

	if (!(bssgp_pdu_type_flags(pdu_type) & BSSGP_PDUF_DL)) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/SGSN) %s not allowed in downlink direction\n",
		     nsei, osmo_tlv_prot_msg_name(&osmo_pdef_bssgp, pdu_type));
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, orig_msg);
	}

	msg = bssgp_msgb_copy(orig_msg, "rx_sig_from_sgsn");
	/* Update message info */
	bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	data_len = msgb_bssgp_len(orig_msg) - sizeof(*bgph);
	rc = bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_BVC_RESET:
		rc = rx_reset_from_sgsn(cfg, msg, orig_msg, &tp, nsei, ns_bvci);
		break;
	case BSSGP_PDUT_BVC_RESET_ACK:
		/* simple case: BVCI IE is mandatory */
		if (!TLVP_PRES_LEN(&tp, BSSGP_IE_BVCI, 2))
			goto err_mand_ie;
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		if (bvci == BVCI_SIGNALLING) {
			/* TODO: Reset all PTP BVCIs */
		} else {
			rc = gbprox_relay2bvci(cfg, msg, bvci, ns_bvci);
		}
		break;
	case BSSGP_PDUT_FLUSH_LL:
		/* simple case: BVCI IE is mandatory */
		if (!TLVP_PRES_LEN(&tp, BSSGP_IE_BVCI, 2))
			goto err_mand_ie;
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		rc = gbprox_relay2bvci(cfg, msg, bvci, ns_bvci);
		break;
	case BSSGP_PDUT_PAGING_PS:
	case BSSGP_PDUT_PAGING_CS:
		/* process the paging request (LAI/RAI lookup) */
		rc = gbprox_rx_paging(cfg, msg, &tp, nsei, ns_bvci);
		break;
	case BSSGP_PDUT_STATUS:
		/* Some exception has occurred */
		LOGP(DGPRS, LOGL_NOTICE,
			"NSE(%05u/SGSN) BSSGP STATUS ", nsei);
		if (!TLVP_PRES_LEN(&tp, BSSGP_IE_CAUSE, 1)) {
			LOGPC(DGPRS, LOGL_NOTICE, "\n");
			goto err_mand_ie;
		}
		cause = *TLVP_VAL(&tp, BSSGP_IE_CAUSE);
		LOGPC(DGPRS, LOGL_NOTICE,
			"cause=0x%02x(%s) ", *TLVP_VAL(&tp, BSSGP_IE_CAUSE),
			bssgp_cause_str(cause));
		if (TLVP_PRES_LEN(&tp, BSSGP_IE_BVCI, 2)) {
			bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
			LOGPC(DGPRS, LOGL_NOTICE, "BVCI=%05u\n", bvci);

			if (cause == BSSGP_CAUSE_UNKNOWN_BVCI)
				rc = gbprox_relay2bvci(cfg, msg, bvci, ns_bvci);
		} else
			LOGPC(DGPRS, LOGL_NOTICE, "\n");
		break;
	/* those only exist in the SGSN -> BSS direction */
	case BSSGP_PDUT_SUSPEND_ACK:
	case BSSGP_PDUT_SUSPEND_NACK:
	case BSSGP_PDUT_RESUME_ACK:
	case BSSGP_PDUT_RESUME_NACK:
		/* RAI IE is mandatory */
		if (!TLVP_PRES_LEN(&tp, BSSGP_IE_ROUTEING_AREA, 6))
			goto err_mand_ie;
		bvc = gbproxy_bvc_by_rai(cfg, TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA));
		if (!bvc)
			goto err_no_bvc;
		rc = gbprox_relay2peer(msg, bvc, ns_bvci);
		break;
	case BSSGP_PDUT_BVC_BLOCK_ACK:
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
		if (!TLVP_PRES_LEN(&tp, BSSGP_IE_BVCI, 2))
			goto err_mand_ie;
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		if (bvci == 0) {
			LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/SGSN) BSSGP "
			     "%sBLOCK_ACK for signalling BVCI ?!?\n", nsei,
			     pdu_type == BSSGP_PDUT_BVC_UNBLOCK_ACK ? "UN":"");
			/* TODO: should we send STATUS ? */
			rate_ctr_inc(&cfg->ctrg->
				     ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		} else {
			/* Mark BVC as (un)blocked */
			block_unblock_bvc(cfg, bvci, pdu_type);
		}
		rc = gbprox_relay2bvci(cfg, msg, bvci, ns_bvci);
		break;
	case BSSGP_PDUT_SGSN_INVOKE_TRACE:
	case BSSGP_PDUT_OVERLOAD:
		LOGP(DGPRS, LOGL_DEBUG,
			"NSE(%05u/SGSN) BSSGP %s: broadcasting\n", nsei, bssgp_pdu_str(pdu_type));
		/* broadcast to all BSS-side bvcs */
		hash_for_each(cfg->bss_nses, i, nse, list) {
			gbprox_relay2nse(msg, nse, 0);
		}
		break;
	default:
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/SGSN) BSSGP PDU type %s not supported\n", nsei,
		     bssgp_pdu_str(pdu_type));
		rate_ctr_inc(&cfg->ctrg->
			     ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, orig_msg);
		break;
	}

	msgb_free(msg);

	return rc;
err_mand_ie:
	LOGP(DGPRS, LOGL_ERROR, "NSE(%05u/SGSN) missing mandatory IE\n",
		nsei);
	rate_ctr_inc(&cfg->ctrg->
		     ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
	msgb_free(msg);
	return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, orig_msg);
err_no_bvc:
	LOGP(DGPRS, LOGL_ERROR, "NSE(%05u/SGSN) cannot find bvc based on RAI\n",
		nsei);
	rate_ctr_inc(&cfg->ctrg-> ctr[GBPROX_GLOB_CTR_INV_RAI]);
	msgb_free(msg);
	return bssgp_tx_status(BSSGP_CAUSE_INV_MAND_INF, NULL, orig_msg);
}

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
	int rc;
	uint16_t nsei = msgb_nsei(msg);
	uint16_t ns_bvci = msgb_bvci(msg);
	struct gbproxy_config *cfg = (struct gbproxy_config *) ctx;

	int remote_end_is_sgsn = gbproxy_is_sgsn_nsei(cfg, nsei);

	/* ensure minimum length to decode PCU type */
	if (msgb_bssgp_len(msg) < sizeof(struct bssgp_normal_hdr))
		return bssgp_tx_status(BSSGP_CAUSE_SEM_INCORR_PDU, NULL, msg);

	/* Only BVCI=0 messages need special treatment */
	if (ns_bvci == 0 || ns_bvci == 1) {
		if (remote_end_is_sgsn)
			rc = gbprox_rx_sig_from_sgsn(cfg, msg, nsei, ns_bvci);
		else
			rc = gbprox_rx_sig_from_bss(cfg, msg, nsei, ns_bvci);
	} else {
		/* All other BVCI are PTP */
		if (remote_end_is_sgsn)
			rc = gbprox_rx_ptp_from_sgsn(cfg, msg, nsei,
						     ns_bvci);
		else
			rc = gbprox_rx_ptp_from_bss(cfg, msg, nsei,
						    ns_bvci);
	}

	return rc;
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

	switch (nsp->u.status.cause) {
	case NS_AFF_CAUSE_SNS_FAILURE:
	case NS_AFF_CAUSE_SNS_CONFIGURED:
		break;

	case NS_AFF_CAUSE_RECOVERY:
		LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d became available\n", nsp->nsei);
		if (gbproxy_is_sgsn_nsei(cfg, nsp->nsei)) {
			/* look-up or create the BTS context for this BVC */
			struct bssgp_bvc_ctx *bctx = btsctx_by_bvci_nsei(nsp->bvci, nsp->nsei);
			if (!bctx)
				bctx = btsctx_alloc(nsp->bvci, nsp->nsei);

			bssgp_tx_bvc_reset_nsei_bvci(cfg->nsip_sgsn_nsei, 0, BSSGP_CAUSE_OML_INTERV, NULL, 0);
		}
		break;
	case NS_AFF_CAUSE_FAILURE:
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
			bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_BLOCK, cfg->nsip_sgsn_nsei,
					     bvc->bvci, 0);
		}
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

	return 0;
}
