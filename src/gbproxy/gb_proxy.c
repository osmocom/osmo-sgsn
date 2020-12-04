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
static void gbproxy_reset_imsi_acquisition(struct gbproxy_link_info* link_info);

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

/* Transmit Chapter 9.2.10 Identity Request */
static void gprs_put_identity_req(struct msgb *msg, uint8_t id_type)
{
	struct gsm48_hdr *gh;

	id_type &= GSM_MI_TYPE_MASK;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ID_REQ;
	gh->data[0] = id_type;
}

/* Transmit Chapter 9.4.6.2 Detach Accept (mobile originated detach) */
static void gprs_put_mo_detach_acc(struct msgb *msg)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_DETACH_ACK;
	gh->data[0] = 0; /* no force to standby */
}

static void gprs_push_llc_ui(struct msgb *msg,
			     int is_uplink, unsigned sapi, unsigned nu)
{
	const uint8_t e_bit = 0;
	const uint8_t pm_bit = 1;
	const uint8_t cr_bit = is_uplink ? 0 : 1;
	uint8_t *llc;
	uint8_t *fcs_field;
	uint32_t fcs;

	nu &= 0x01ff; /* 9 Bit */

	llc = msgb_push(msg, 3);
	llc[0] = (cr_bit << 6) | (sapi & 0x0f);
	llc[1] = 0xc0 | (nu >> 6); /* UI frame */
	llc[2] = (nu << 2) | ((e_bit & 1) << 1) | (pm_bit & 1);

	fcs = gprs_llc_fcs(llc, msgb_length(msg));
	fcs_field = msgb_put(msg, 3);
	fcs_field[0] = (uint8_t)(fcs >> 0);
	fcs_field[1] = (uint8_t)(fcs >> 8);
	fcs_field[2] = (uint8_t)(fcs >> 16);
}

static void gprs_push_bssgp_dl_unitdata(struct msgb *msg,
					uint32_t tlli)
{
	struct bssgp_ud_hdr *budh;
	uint8_t *llc = msgb_data(msg);
	size_t llc_size = msgb_length(msg);
	const size_t llc_ie_hdr_size = 3;
	const uint8_t qos_profile[] = {0x00, 0x50, 0x20}; /* hard-coded */
	const uint8_t lifetime[] = {0x02, 0x58}; /* 6s hard-coded */

	const size_t bssgp_overhead = sizeof(*budh) +
		TVLV_GROSS_LEN(sizeof(lifetime)) + llc_ie_hdr_size;
	uint8_t *ie;
	uint32_t tlli_be = htonl(tlli);

	budh = (struct bssgp_ud_hdr *)msgb_push(msg, bssgp_overhead);

	budh->pdu_type = BSSGP_PDUT_DL_UNITDATA;
	memcpy(&budh->tlli, &tlli_be, sizeof(budh->tlli));
	memcpy(&budh->qos_profile, qos_profile, sizeof(budh->qos_profile));

	ie = budh->data;
	tvlv_put(ie, BSSGP_IE_PDU_LIFETIME, sizeof(lifetime), lifetime);
	ie += TVLV_GROSS_LEN(sizeof(lifetime));

	/* Note: Add alignment before the LLC IE if inserting other IE */

	*(ie++) = BSSGP_IE_LLC_PDU;
	*(ie++) = llc_size / 256;
	*(ie++) = llc_size % 256;

	OSMO_ASSERT(ie == llc);

	msgb_bssgph(msg) = (uint8_t *)budh;
	msgb_tlli(msg) = tlli;
}

/* update bvc according to the BSS message */
static void gbprox_update_current_raid(uint8_t *raid_enc,
				       struct gbproxy_bvc *bvc,
				       const char *log_text)
{
	struct gbproxy_patch_state *state = &bvc->patch_state;
	const struct osmo_plmn_id old_plmn = state->local_plmn;
	struct gprs_ra_id raid;
	OSMO_ASSERT(bvc->nse);
	struct gbproxy_config *cfg = bvc->nse->cfg;
	OSMO_ASSERT(cfg);

	if (!raid_enc)
		return;

	gsm48_parse_ra(&raid, raid_enc);

	/* save source side MCC/MNC */
	if (!cfg->core_plmn.mcc || raid.mcc == cfg->core_plmn.mcc) {
		state->local_plmn.mcc = 0;
	} else {
		state->local_plmn.mcc = raid.mcc;
	}

	if (!cfg->core_plmn.mnc
	    || !osmo_mnc_cmp(raid.mnc, raid.mnc_3_digits,
			     cfg->core_plmn.mnc, cfg->core_plmn.mnc_3_digits)) {
		state->local_plmn.mnc = 0;
		state->local_plmn.mnc_3_digits = false;
	} else {
		state->local_plmn.mnc = raid.mnc;
		state->local_plmn.mnc_3_digits = raid.mnc_3_digits;
	}

	if (osmo_plmn_cmp(&old_plmn, &state->local_plmn))
		LOGPBVC(bvc, LOGL_NOTICE,
		     "Patching RAID %sactivated, msg: %s, "
		     "local: %s, core: %s\n",
		     state->local_plmn.mcc || state->local_plmn.mnc ?
		     "" : "de",
		     log_text,
		     osmo_plmn_name(&state->local_plmn),
		     osmo_plmn_name2(&cfg->core_plmn));
}

uint32_t gbproxy_make_bss_ptmsi(struct gbproxy_bvc *bvc,
				uint32_t sgsn_ptmsi)
{
	uint32_t bss_ptmsi;
	int max_retries = 23, rc = 0;
	if (!bvc->nse->cfg->patch_ptmsi) {
		bss_ptmsi = sgsn_ptmsi;
	} else {
		do {
			rc = osmo_get_rand_id((uint8_t *) &bss_ptmsi, sizeof(bss_ptmsi));
			if (rc < 0) {
				bss_ptmsi = GSM_RESERVED_TMSI;
				break;
			}

			bss_ptmsi = bss_ptmsi | GSM23003_TMSI_SGSN_MASK;

			if (gbproxy_link_info_by_ptmsi(bvc, bss_ptmsi))
				bss_ptmsi = GSM_RESERVED_TMSI;
		} while (bss_ptmsi == GSM_RESERVED_TMSI && max_retries--);
	}

	if (bss_ptmsi == GSM_RESERVED_TMSI)
		LOGPBVC(bvc, LOGL_ERROR, "Failed to allocate a BSS P-TMSI: %d (%s)\n", rc, strerror(-rc));

	return bss_ptmsi;
}

uint32_t gbproxy_make_sgsn_tlli(struct gbproxy_bvc *bvc,
				struct gbproxy_link_info *link_info,
				uint32_t bss_tlli)
{
	uint32_t sgsn_tlli;
	int max_retries = 23, rc = 0;
	if (!bvc->nse->cfg->patch_ptmsi) {
		sgsn_tlli = bss_tlli;
	} else if (link_info->sgsn_tlli.ptmsi != GSM_RESERVED_TMSI &&
		   gprs_tlli_type(bss_tlli) == TLLI_FOREIGN) {
		sgsn_tlli = gprs_tmsi2tlli(link_info->sgsn_tlli.ptmsi,
					   TLLI_FOREIGN);
	} else if (link_info->sgsn_tlli.ptmsi != GSM_RESERVED_TMSI &&
		   gprs_tlli_type(bss_tlli) == TLLI_LOCAL) {
		sgsn_tlli = gprs_tmsi2tlli(link_info->sgsn_tlli.ptmsi,
					   TLLI_LOCAL);
	} else {
		do {
			/* create random TLLI, 0b01111xxx... */
			rc = osmo_get_rand_id((uint8_t *) &sgsn_tlli, sizeof(sgsn_tlli));
			if (rc < 0) {
				sgsn_tlli = 0;
				break;
			}

			sgsn_tlli = (sgsn_tlli & 0x7fffffff) | 0x78000000;

			if (gbproxy_link_info_by_any_sgsn_tlli(bvc, sgsn_tlli))
				sgsn_tlli = 0;
		} while (!sgsn_tlli && max_retries--);
	}

	if (!sgsn_tlli)
		LOGPBVC(bvc, LOGL_ERROR, "Failed to allocate an SGSN TLLI: %d (%s)\n", rc, strerror(-rc));

	return sgsn_tlli;
}

void gbproxy_reset_link(struct gbproxy_link_info *link_info)
{
	gbproxy_reset_imsi_acquisition(link_info);
}

/* Returns != 0 iff IMSI acquisition was in progress */
static int gbproxy_restart_imsi_acquisition(struct gbproxy_link_info* link_info)
{
	int in_progress = 0;
	if (!link_info)
		return 0;

	if (link_info->imsi_acq_pending)
		in_progress = 1;

	gbproxy_link_info_discard_messages(link_info);
	link_info->imsi_acq_pending = false;

	return in_progress;
}

static void gbproxy_reset_imsi_acquisition(struct gbproxy_link_info* link_info)
{
	gbproxy_restart_imsi_acquisition(link_info);
	link_info->vu_gen_tx_bss = GBPROXY_INIT_VU_GEN_TX;
}

/* Got identity response with IMSI, assuming the request had
 * been generated by the gbproxy */
static int gbproxy_flush_stored_messages(struct gbproxy_bvc *bvc,
					  time_t now,
					  struct gbproxy_link_info* link_info)
{
	int rc;
	struct msgb *stored_msg;
	OSMO_ASSERT(bvc);
	OSMO_ASSERT(bvc->nse);
	struct gbproxy_config *cfg = bvc->nse->cfg;
	OSMO_ASSERT(cfg);

	/* Patch and flush stored messages towards the SGSN */
	while ((stored_msg = msgb_dequeue_count(&link_info->stored_msgs,
						&link_info->stored_msgs_len))) {
		struct gprs_gb_parse_context tmp_parse_ctx = {0};
		tmp_parse_ctx.to_bss = 0;
		tmp_parse_ctx.peer_nsei = msgb_nsei(stored_msg);
		int len_change = 0;

		gprs_gb_parse_bssgp(msgb_bssgph(stored_msg),
				    msgb_bssgp_len(stored_msg),
				    &tmp_parse_ctx);
		gbproxy_patch_bssgp(stored_msg, msgb_bssgph(stored_msg),
				    msgb_bssgp_len(stored_msg),
				    bvc, link_info, &len_change,
				    &tmp_parse_ctx);

		rc = gbproxy_update_link_state_after(bvc, link_info, now,
				&tmp_parse_ctx);
		if (rc == 1) {
			LOGPBVC_CAT(bvc, DLLC, LOGL_NOTICE, "link_info deleted while flushing stored messages\n");
			msgb_free(stored_msg);
			return -1;
		}

		rc = gbprox_relay2sgsn(cfg, stored_msg,
				       msgb_bvci(stored_msg), link_info->sgsn_nsei);

		if (rc < 0)
			LOGPBVC_CAT(bvc, DLLC, LOGL_ERROR,
			     "failed to send stored message "
			     "(%s)\n",
			     tmp_parse_ctx.llc_msg_name ?
			     tmp_parse_ctx.llc_msg_name : "BSSGP");
		msgb_free(stored_msg);
	}

	return 0;
}

static int gbproxy_gsm48_to_bvc(struct gbproxy_bvc *bvc,
				 struct gbproxy_link_info* link_info,
				 uint16_t bvci,
				 struct msgb *msg /* Takes msg ownership */)
{
	int rc;

	/* Workaround to avoid N(U) collisions and to enable a restart
	 * of the IMSI acquisition procedure. This will work unless the
	 * SGSN has an initial V(UT) within [256-32, 256+n_retries]
	 * (see GSM 04.64, 8.4.2). */
	gprs_push_llc_ui(msg, 0, GPRS_SAPI_GMM, link_info->vu_gen_tx_bss);
	link_info->vu_gen_tx_bss = (link_info->vu_gen_tx_bss + 1) % 512;

	gprs_push_bssgp_dl_unitdata(msg, link_info->tlli.current);
	msg->l3h = msg->data;

	rc = gbprox_relay2peer(msg, bvc, bvci);
	msgb_free(msg);
	return rc;
}

static void gbproxy_acquire_imsi(struct gbproxy_bvc *bvc,
				 struct gbproxy_link_info* link_info,
				 uint16_t bvci)
{
	struct msgb *idreq_msg;

	/* Send IDENT REQ */
	idreq_msg = gsm48_msgb_alloc_name("GSM 04.08 ACQ IMSI");
	gprs_put_identity_req(idreq_msg, GSM_MI_TYPE_IMSI);
	gbproxy_gsm48_to_bvc(bvc, link_info, bvci, idreq_msg);
}

static void gbproxy_tx_detach_acc(struct gbproxy_bvc *bvc,
				  struct gbproxy_link_info* link_info,
				  uint16_t bvci)
{
	struct msgb *detacc_msg;

	/* Send DETACH ACC */
	detacc_msg = gsm48_msgb_alloc_name("GSM 04.08 DET ACC");
	gprs_put_mo_detach_acc(detacc_msg);
	gbproxy_gsm48_to_bvc(bvc, link_info, bvci, detacc_msg);
}

/* Return != 0 iff msg still needs to be processed */
static int gbproxy_imsi_acquisition(struct gbproxy_bvc *bvc,
				    struct msgb *msg,
				    time_t now,
				    struct gbproxy_link_info* link_info,
				    struct gprs_gb_parse_context *parse_ctx)
{
	struct msgb *stored_msg;
	OSMO_ASSERT(bvc);
	OSMO_ASSERT(bvc->nse);
	struct gbproxy_config *cfg = bvc->nse->cfg;
	OSMO_ASSERT(cfg);

	if (!link_info)
		return 1;

	if (!link_info->imsi_acq_pending && link_info->imsi_len > 0)
		return 1;

	if (parse_ctx->g48_hdr)
		switch (parse_ctx->g48_hdr->msg_type)
		{
		case GSM48_MT_GMM_RA_UPD_REQ:
		case GSM48_MT_GMM_ATTACH_REQ:
			if (gbproxy_restart_imsi_acquisition(link_info)) {
				LOGPBVC_CAT(bvc, DLLC, LOGL_INFO,
				     " IMSI acquisition was in progress "
				     "when receiving an %s.\n",
				     parse_ctx->llc_msg_name);
			}
			break;
		case GSM48_MT_GMM_DETACH_REQ:
			/* Nothing has been sent to the SGSN yet */
			if (link_info->imsi_acq_pending) {
				LOGPBVC_CAT(bvc, DLLC, LOGL_INFO,
				     "IMSI acquisition was in progress "
				     "when receiving a DETACH_REQ.\n");
			}
			if (!parse_ctx->invalidate_tlli) {
				LOGPBVC_CAT(bvc, DLLC, LOGL_INFO,
				     "IMSI not yet acquired, "
				     "faking a DETACH_ACC.\n");
				gbproxy_tx_detach_acc(bvc, link_info, msgb_bvci(msg));
				parse_ctx->invalidate_tlli = 1;
			}
			gbproxy_reset_imsi_acquisition(link_info);
			gbproxy_update_link_state_after(bvc, link_info, now,
							parse_ctx);
			return 0;
		}

	if (link_info->imsi_acq_pending && link_info->imsi_len > 0) {
		int is_ident_resp =
			parse_ctx->g48_hdr &&
			gsm48_hdr_pdisc(parse_ctx->g48_hdr) == GSM48_PDISC_MM_GPRS &&
			gsm48_hdr_msg_type(parse_ctx->g48_hdr) == GSM48_MT_GMM_ID_RESP;

		LOGPBVC_CAT(bvc, DLLC, LOGL_DEBUG,
		     "IMSI acquisition succeeded, "
		     "flushing stored messages\n");
		/* The IMSI is now available. If flushing the messages fails,
		 * then link_info has been deleted and we should return
		 * immediately. */
		if (gbproxy_flush_stored_messages(bvc, now, link_info) < 0)
			return 0;

		gbproxy_reset_imsi_acquisition(link_info);

		/* This message is most probably the response to the ident
		 * request sent by gbproxy_acquire_imsi(). Don't forward it to
		 * the SGSN. */
		return !is_ident_resp;
	}

	/* The message cannot be processed since the IMSI is still missing */

	/* If queue is getting too large, drop oldest msgb before adding new one */
	if (cfg->stored_msgs_max_len > 0) {
		int exceeded_max_len = link_info->stored_msgs_len
				   + 1 - cfg->stored_msgs_max_len;

		for (; exceeded_max_len > 0; exceeded_max_len--) {
			struct msgb *msgb_drop;
			msgb_drop = msgb_dequeue_count(&link_info->stored_msgs,
						       &link_info->stored_msgs_len);
			LOGPBVC_CAT(bvc, DLLC, LOGL_INFO,
			     "Dropping stored msgb from list "
			     "(!acq imsi, length %d, max_len exceeded)\n",
			     link_info->stored_msgs_len);

			msgb_free(msgb_drop);
		}
	}

	/* Enqueue unpatched messages */
	LOGPBVC_CAT(bvc, DLLC, LOGL_INFO,
	     "IMSI acquisition in progress, "
	     "storing message (%s)\n",
	     parse_ctx->llc_msg_name ? parse_ctx->llc_msg_name : "BSSGP");

	stored_msg = bssgp_msgb_copy(msg, "process_bssgp_ul");
	msgb_enqueue_count(&link_info->stored_msgs, stored_msg,
			   &link_info->stored_msgs_len);

	if (!link_info->imsi_acq_pending) {
		LOGPBVC_CAT(bvc, DLLC, LOGL_INFO,
		     "IMSI is required but not available, "
		     "initiating identification procedure (%s)\n",
		     parse_ctx->llc_msg_name ? parse_ctx->llc_msg_name : "BSSGP");

		gbproxy_acquire_imsi(bvc, link_info, msgb_bvci(msg));

		/* There is no explicit retransmission handling, the
		 * implementation relies on the MS doing proper retransmissions
		 * of the triggering message instead */

		link_info->imsi_acq_pending = true;
	}

	return 0;
}

struct gbproxy_bvc *gbproxy_find_bvc(struct gbproxy_config *cfg,
				       struct msgb *msg,
				       struct gprs_gb_parse_context *parse_ctx)
{
	struct gbproxy_bvc *bvc = NULL;

	if (msgb_bvci(msg) >= 2)
		bvc = gbproxy_bvc_by_bvci(cfg, msgb_bvci(msg));

	if (!bvc && !parse_ctx->to_bss)
		bvc = gbproxy_bvc_by_nsei(cfg, msgb_nsei(msg));

	if (!bvc)
		bvc = gbproxy_bvc_by_bssgp_tlv(cfg, &parse_ctx->bssgp_tp);

	if (!bvc) {
		LOGP(DLLC, LOGL_INFO,
		     "NSE(%05u/%s) patching: didn't find bvc for message, "
		     "PDU %d\n",
		     msgb_nsei(msg), parse_ctx->to_bss ? "BSS" : "SGSN",
		     parse_ctx->pdu_type);
		/* Increment counter */
		rate_ctr_inc(&cfg->ctrg->ctr[GBPROX_GLOB_CTR_PATCH_PEER_ERR]);
	}
	return bvc;
}

/* patch BSSGP message */
static int gbprox_process_bssgp_ul(struct gbproxy_config *cfg,
				   struct msgb *msg,
				   struct gbproxy_bvc *bvc)
{
	struct gprs_gb_parse_context parse_ctx = {0};
	int rc;
	int len_change = 0;
	time_t now;
	struct timespec ts = {0,};
	struct gbproxy_link_info *link_info = NULL;
	uint32_t sgsn_nsei = cfg->nsip_sgsn_nsei;

	if (!cfg->core_plmn.mcc && !cfg->core_plmn.mnc && !cfg->core_apn &&
	    !cfg->acquire_imsi && !cfg->patch_ptmsi && !cfg->route_to_sgsn2)
		return 1;

	parse_ctx.to_bss = 0;
	parse_ctx.peer_nsei = msgb_nsei(msg);

	/* Parse BSSGP/LLC */
	rc = gprs_gb_parse_bssgp(msgb_bssgph(msg), msgb_bssgp_len(msg),
				 &parse_ctx);

	if (!rc && !parse_ctx.need_decryption) {
		LOGP(DGPRS, LOGL_ERROR,
		     "NSE(%05u/BSS) patching: failed to parse invalid %s message\n",
		     msgb_nsei(msg), gprs_gb_message_name(&parse_ctx, "NS_UNITDATA"));
		gprs_gb_log_parse_context(LOGL_NOTICE, &parse_ctx, "NS_UNITDATA");
		LOGP(DGPRS, LOGL_NOTICE,
		     "NSE(%05u/BSS) invalid message was: %s\n",
		     msgb_nsei(msg), msgb_hexdump(msg));
		return 0;
	}

	/* Get bvc */
	if (!bvc)
		bvc = gbproxy_find_bvc(cfg, msg, &parse_ctx);

	if (!bvc)
		return 0;


	osmo_clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	gbprox_update_current_raid(parse_ctx.bssgp_raid_enc, bvc,
				   parse_ctx.llc_msg_name);

	gprs_gb_log_parse_context(LOGL_DEBUG, &parse_ctx, "NS_UNITDATA");

	link_info = gbproxy_update_link_state_ul(bvc, now, &parse_ctx);

	if (parse_ctx.g48_hdr) {
		switch (parse_ctx.g48_hdr->msg_type) {
		case GSM48_MT_GMM_ATTACH_REQ:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_ATTACH_REQS]);
			break;
		case GSM48_MT_GMM_DETACH_REQ:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_DETACH_REQS]);
			break;
		case GSM48_MT_GMM_ATTACH_COMPL:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_ATTACH_COMPLS]);
			break;
		case GSM48_MT_GMM_RA_UPD_REQ:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_RA_UPD_REQS]);
			break;
		case GSM48_MT_GMM_RA_UPD_COMPL:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_RA_UPD_COMPLS]);
			break;
		case GSM48_MT_GMM_STATUS:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_GMM_STATUS_BSS]);
			break;
		case GSM48_MT_GSM_ACT_PDP_REQ:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_PDP_ACT_REQS]);
			break;
		case GSM48_MT_GSM_DEACT_PDP_REQ:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_PDP_DEACT_REQS]);
			break;

		default:
			break;
		}
	}

	if (link_info && cfg->route_to_sgsn2) {
		if (cfg->acquire_imsi && link_info->imsi_len == 0)
			sgsn_nsei = 0xffff;
		else if (gbproxy_imsi_matches(cfg, GBPROX_MATCH_ROUTING,
					      link_info))
			sgsn_nsei = cfg->nsip_sgsn2_nsei;
	}

	if (link_info)
		link_info->sgsn_nsei = sgsn_nsei;

	/* Handle IMSI acquisition */
	if (cfg->acquire_imsi) {
		rc = gbproxy_imsi_acquisition(bvc, msg, now, link_info,
					      &parse_ctx);
		if (rc <= 0)
			return rc;
	}

	gbproxy_patch_bssgp(msg, msgb_bssgph(msg), msgb_bssgp_len(msg),
			    bvc, link_info, &len_change, &parse_ctx);

	gbproxy_update_link_state_after(bvc, link_info, now, &parse_ctx);

	if (sgsn_nsei != cfg->nsip_sgsn_nsei) {
		/* Send message directly to the selected SGSN */
		rc = gbprox_relay2sgsn(cfg, msg, msgb_bvci(msg), sgsn_nsei);
		/* Don't let the calling code handle the transmission */
		return 0;
	}

	return 1;
}

/* patch BSSGP message to use core_plmn.mcc/mnc on the SGSN side */
static void gbprox_process_bssgp_dl(struct gbproxy_config *cfg,
				    struct msgb *msg,
				    struct gbproxy_bvc *bvc)
{
	struct gprs_gb_parse_context parse_ctx = {0};
	int rc;
	int len_change = 0;
	time_t now;
	struct timespec ts = {0,};
	struct gbproxy_link_info *link_info = NULL;

	if (!cfg->core_plmn.mcc && !cfg->core_plmn.mnc && !cfg->core_apn &&
	    !cfg->acquire_imsi && !cfg->patch_ptmsi && !cfg->route_to_sgsn2)
		return;

	parse_ctx.to_bss = 1;
	parse_ctx.peer_nsei = msgb_nsei(msg);

	rc = gprs_gb_parse_bssgp(msgb_bssgph(msg), msgb_bssgp_len(msg),
				 &parse_ctx);

	if (!rc && !parse_ctx.need_decryption) {
		LOGP(DGPRS, LOGL_ERROR,
		     "NSE(%05u/SGSN) patching: failed to parse invalid %s message\n",
		     msgb_nsei(msg), gprs_gb_message_name(&parse_ctx, "NS_UNITDATA"));
		gprs_gb_log_parse_context(LOGL_NOTICE, &parse_ctx, "NS_UNITDATA");
		LOGP(DGPRS, LOGL_NOTICE,
		     "NSE(%05u/SGSN) invalid message was: %s\n",
		     msgb_nsei(msg), msgb_hexdump(msg));
		return;
	}

	/* Get bvc */
	if (!bvc)
		bvc = gbproxy_find_bvc(cfg, msg, &parse_ctx);

	if (!bvc)
		return;

	osmo_clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	if (parse_ctx.g48_hdr) {
		switch (parse_ctx.g48_hdr->msg_type) {
		case GSM48_MT_GMM_ATTACH_ACK:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_ATTACH_ACKS]);
			break;
		case GSM48_MT_GMM_ATTACH_REJ:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_ATTACH_REJS]);
			break;
		case GSM48_MT_GMM_DETACH_ACK:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_DETACH_ACKS]);
			break;
		case GSM48_MT_GMM_RA_UPD_ACK:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_RA_UPD_ACKS]);
			break;
		case GSM48_MT_GMM_RA_UPD_REJ:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_RA_UPD_REJS]);
			break;
		case GSM48_MT_GMM_STATUS:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_GMM_STATUS_SGSN]);
			break;
		case GSM48_MT_GSM_ACT_PDP_ACK:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_PDP_ACT_ACKS]);
			break;
		case GSM48_MT_GSM_ACT_PDP_REJ:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_PDP_ACT_REJS]);
			break;
		case GSM48_MT_GSM_DEACT_PDP_ACK:
			rate_ctr_inc(&bvc->ctrg->ctr[GBPROX_PEER_CTR_PDP_DEACT_ACKS]);
			break;

		default:
			break;
		}
	}

	gprs_gb_log_parse_context(LOGL_DEBUG, &parse_ctx, "NS_UNITDATA");

	link_info = gbproxy_update_link_state_dl(bvc, now, &parse_ctx);

	gbproxy_patch_bssgp(msg, msgb_bssgph(msg), msgb_bssgp_len(msg),
			    bvc, link_info, &len_change, &parse_ctx);

	gbproxy_update_link_state_after(bvc, link_info, now, &parse_ctx);

	return;
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
	struct gbproxy_bvc *bvc;
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	uint8_t pdu_type = bgph->pdu_type;
	int rc;

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

	rc = gbprox_process_bssgp_ul(cfg, msg, bvc);
	if (!rc)
		return 0;

	switch (pdu_type) {
	case BSSGP_PDUT_FLOW_CONTROL_BVC:
		if (!cfg->route_to_sgsn2)
			break;

		/* Send a copy to the secondary SGSN */
		gbprox_relay2sgsn(cfg, msg, ns_bvci, cfg->nsip_sgsn2_nsei);
		break;
	default:
		break;
	}


	return gbprox_relay2sgsn(cfg, msg, ns_bvci, cfg->nsip_sgsn_nsei);
}

/* Receive an incoming PTP message from a SGSN-side NS-VC */
static int gbprox_rx_ptp_from_sgsn(struct gbproxy_config *cfg,
				   struct msgb *msg, uint16_t nsei,
				   uint16_t ns_bvci)
{
	struct gbproxy_bvc *bvc;
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	uint8_t pdu_type = bgph->pdu_type;

	bvc = gbproxy_bvc_by_bvci(cfg, ns_bvci);

	/* Send status messages before patching */

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

	switch (pdu_type) {
	case BSSGP_PDUT_FLOW_CONTROL_BVC_ACK:
	case BSSGP_PDUT_BVC_BLOCK_ACK:
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
		if (cfg->route_to_sgsn2 && nsei == cfg->nsip_sgsn2_nsei)
			/* Hide ACKs from the secondary SGSN, the primary SGSN
			 * is responsible to send them. */
			return 0;
		break;
	default:
		break;
	}

	/* Optionally patch the message */
	gbprox_process_bssgp_dl(cfg, msg, bvc);

	return gbprox_relay2peer(msg, bvc, ns_bvci);
}

/* process a BVC-RESET message from the BSS side */
static int gbprox_rx_bvc_reset_from_bss(struct gbproxy_config *cfg, struct msgb *msg,
					uint16_t nsei, struct tlv_parsed *tp,
					int *copy_to_sgsn2)
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
		if (cfg->route_to_sgsn2)
			*copy_to_sgsn2 = 1;
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
	int copy_to_sgsn2 = 0;
	int rc;

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u) BVCI=%05u is not signalling\n",
			nsei, ns_bvci);
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u) UNITDATA not allowed in "
			"signalling\n", nsei);
		return -EINVAL;
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
		rc = gbprox_rx_bvc_reset_from_bss(cfg, msg, nsei, &tp, &copy_to_sgsn2);
		/* if function retruns 0, we terminate processing here */
		if (rc == 0)
			return 0;
		break;
	}

	/* Normally, we can simply pass on all signalling messages from BSS to
	 * SGSN */
	rc = gbprox_process_bssgp_ul(cfg, msg, from_bvc);
	if (!rc)
		return 0;

	if (copy_to_sgsn2)
		gbprox_relay2sgsn(cfg, msg, ns_bvci, cfg->nsip_sgsn2_nsei);

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
		llist_for_each_entry(nse, &cfg->bss_nses, list) {
			llist_for_each_entry(bvc, &nse->bvcs, list) {
				if (!memcmp(bvc->ra, TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA), 6)) {
					LOGPNSE(nse, LOGL_INFO, "routing to NSE (RAI match)\n");
					gbprox_relay2nse(msg, nse, ns_bvci);
					n_nses++;
					/* Only send it once to each NSE */
					break;
				}
			}
		}
	} else if (TLVP_PRES_LEN(tp, BSSGP_IE_LOCATION_AREA, 5)) {
		errctr = GBPROX_GLOB_CTR_INV_LAI;
		/* iterate over all bvcs and dispatch the paging to each matching one */
		llist_for_each_entry(nse, &cfg->bss_nses, list) {
			llist_for_each_entry(bvc, &nse->bvcs, list) {
				if (!memcmp(bvc->ra, TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA), 5)) {
					LOGPNSE(nse, LOGL_INFO, "routing to NSE (LAI match)\n");
					gbprox_relay2nse(msg, nse, ns_bvci);
					n_nses++;
					/* Only send it once to each NSE */
					break;
				}
			}
		}
	} else if (TLVP_PRES_LEN(tp, BSSGP_IE_BSS_AREA_ID, 1)) {
		/* iterate over all bvcs and dispatch the paging to each matching one */
		llist_for_each_entry(nse, &cfg->bss_nses, list) {
			llist_for_each_entry(bvc, &nse->bvcs, list) {
				LOGPNSE(nse, LOGL_INFO, "routing to NSE (broadcast)\n");
				gbprox_relay2nse(msg, nse, ns_bvci);
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
	llist_for_each_entry(nse, &cfg->bss_nses, list) {
		llist_for_each_entry(bvc, &nse->bvcs, list)
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

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/SGSN) BVCI=%05u is not "
			"signalling\n", nsei, ns_bvci);
		/* FIXME: Send proper error message */
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "NSE(%05u/SGSN) UNITDATA not allowed in "
			"signalling\n", nsei);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, orig_msg);
	}

	msg = bssgp_msgb_copy(orig_msg, "rx_sig_from_sgsn");
	gbprox_process_bssgp_dl(cfg, msg, NULL);
	/* Update message info */
	bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	data_len = msgb_bssgp_len(orig_msg) - sizeof(*bgph);
	rc = bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_BVC_RESET:
		rc = rx_reset_from_sgsn(cfg, msg, orig_msg, &tp, nsei, ns_bvci);
		break;
	case BSSGP_PDUT_BVC_RESET_ACK:
		if (cfg->route_to_sgsn2 && nsei == cfg->nsip_sgsn2_nsei)
			break;
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
		llist_for_each_entry(nse, &cfg->bss_nses, list) {
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

static int gbproxy_is_sgsn_nsei(struct gbproxy_config *cfg, uint16_t nsei)
{
	return nsei == cfg->nsip_sgsn_nsei ||
		(cfg->route_to_sgsn2 && nsei == cfg->nsip_sgsn2_nsei);
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
		if (nsp->nsei == cfg->nsip_sgsn_nsei) {
			/* look-up or create the BTS context for this BVC */
			struct bssgp_bvc_ctx *bctx = btsctx_by_bvci_nsei(nsp->bvci, nsp->nsei);
			if (!bctx)
				bctx = btsctx_alloc(nsp->bvci, nsp->nsei);

			bssgp_tx_bvc_reset_nsei_bvci(cfg->nsip_sgsn_nsei, 0, BSSGP_CAUSE_OML_INTERV, NULL, 0);
		}
		break;
	case NS_AFF_CAUSE_FAILURE:
		if (nsp->nsei == cfg->nsip_sgsn_nsei) {
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
	struct gbproxy_nse *nse, *ntmp;

	llist_for_each_entry_safe(nse, ntmp, &cfg->bss_nses, list) {
		struct gbproxy_bvc *bvc, *tmp;
		llist_for_each_entry_safe(bvc, tmp, &nse->bvcs, list)
			gbproxy_bvc_free(bvc);

		gbproxy_nse_free(nse);
	}

	rate_ctr_group_free(cfg->ctrg);
	gbproxy_init_config(cfg);
}

int gbproxy_init_config(struct gbproxy_config *cfg)
{
	struct timespec tp;

	INIT_LLIST_HEAD(&cfg->bss_nses);
	cfg->ctrg = rate_ctr_group_alloc(tall_sgsn_ctx, &global_ctrg_desc, 0);
	if (!cfg->ctrg) {
		LOGP(DGPRS, LOGL_ERROR, "Cannot allocate global counter group!\n");
		return -1;
	}
	osmo_clock_gettime(CLOCK_REALTIME, &tp);

	return 0;
}
