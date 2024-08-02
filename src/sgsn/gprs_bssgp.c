/* GPRS BSSGP protocol implementation as per 3GPP TS 08.18 */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#include "osmocom/core/hashtable.h"
#include <osmocom/core/prim.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns2.h>

#include <osmocom/gprs/llc/llc_prim.h>

#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/sgsn_rim.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/mmctx.h>

static uint64_t time_now_usec(void)
{
	struct timespec tp;
	if (osmo_clock_gettime(CLOCK_MONOTONIC, &tp))
		return 0;
	return (uint64_t)tp.tv_sec * 1000000 + tp.tv_nsec / 1000;
}

static struct bssgp_tlli *tlli_cache_get(struct bssgp_state *state, uint32_t tlli)
{
	struct bssgp_tlli *cache_entry;

	hash_for_each_possible(state->tlli_cache.entries, cache_entry, list, tlli) {
		if (cache_entry->tlli == tlli)
			return cache_entry;
	}
	return NULL;
}

static int tlli_cache_update(struct bssgp_state *state, uint32_t tlli, uint16_t nsei, uint16_t bvci)
{
	struct bssgp_tlli *cache_entry;

	cache_entry = tlli_cache_get(state, tlli);
	if (!cache_entry) {
		cache_entry = talloc_zero(sgsn, struct bssgp_tlli);
		if (!cache_entry)
			return -ENOMEM;

		cache_entry->tlli = tlli;
		hash_add(state->tlli_cache.entries, &cache_entry->list, tlli);
	}

	cache_entry->bvci = bvci;
	cache_entry->nsei = nsei;
	cache_entry->last_seen = time_now_usec();

	return 0;
}

static int tlli_cache_cleanup(struct bssgp_state *state)
{
	int i, count = 0;
	struct bssgp_tlli *cache_entry;
	struct hlist_node *tmp;
	uint64_t expiry = time_now_usec() - (state->tlli_cache.timeout * 1000000);

	hash_for_each_safe(state->tlli_cache.entries, i, tmp, cache_entry, list) {
		if (cache_entry->last_seen < expiry) {
			count++;
			LOGP(DGPRS, LOGL_NOTICE, "Cache entry for TLLI %08x expired, removing\n", cache_entry->tlli);
			hash_del(&cache_entry->list);
			talloc_free(cache_entry);
		}
	}
	return count;
}

static void tlli_cache_cleanup_cb(void *data)
{
	struct bssgp_state *state = data;

	tlli_cache_cleanup(state);
	osmo_timer_schedule(&state->tlli_cache.timer, 2, 0);
}

/* Entry function from upper level (LLC), asking us to transmit a BSSGP PDU
 * to a remote MS (identified by TLLI) at a BTS identified by its BVCI and NSEI */
int sgsn_bssgp_tx_dl_unitdata(struct osmo_gprs_llc_prim *llc_prim)
{
	struct msgb *msg;
	struct sgsn_mm_ctx *mmctx;
	struct bssgp_dl_ud_par dup;
	struct bssgp_tlli *cache_entry;
	const uint8_t qos_profile_default[3] = { 0x00, 0x00, 0x20 };
	int rc;

	memset(&dup, 0, sizeof(dup));

	cache_entry = tlli_cache_get(&sgsn->bssgp, llc_prim->bssgp.tlli);
	if (!cache_entry) {
		LOGP(DGPRS, LOGL_ERROR, "Can't find BSSGP link for TLLI %02x\n", llc_prim->bssgp.tlli);
		return -ENOENT;
	}

	/* before we have received some identity from the MS, we might
	 * not yet have a MMC context (e.g. XID negotiation of primarly
	 * LLC connection from GMM sapi). */
	mmctx = sgsn_mm_ctx_by_tlli(llc_prim->bssgp.tlli);
	if (mmctx) {
		/* In rare cases the LLME is NULL in those cases don't
		 * use the mm radio capabilities */
		dup.imsi = mmctx->imsi;
		dup.drx_parms = mmctx->drx_parms;
		dup.ms_ra_cap.len = mmctx->ms_radio_access_capa.len;
		dup.ms_ra_cap.v = mmctx->ms_radio_access_capa.buf;
	}

	/* FIXME: use QoS from primitive */
	memcpy(&dup.qos_profile, qos_profile_default,
	       sizeof(qos_profile_default));

	msg = msgb_alloc_headroom(4096, 128, "llc2bssgp");
	msgb_tlli(msg) = llc_prim->bssgp.tlli;
	msgb_bvci(msg) = cache_entry->bvci;
	msgb_nsei(msg) = cache_entry->nsei;
	msgb_gmmh(msg) = msgb_put(msg, llc_prim->bssgp.ll_pdu_len);
	if (llc_prim->bssgp.ll_pdu_len > 0) {
		memcpy(msgb_gmmh(msg), llc_prim->bssgp.ll_pdu, llc_prim->bssgp.ll_pdu_len);
	}

	rc = bssgp_tx_dl_ud(msg, 1000, &dup);
	//TODO: free msg?
	return rc;
}

/* receive an incoming LLC PDU (BSSGP-UL-UNITDATA-IND, 7.2.4.2) */
static int sgsn_bssgp_rx_ul_unitdata(struct osmo_bssgp_prim *bp)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct gprs_ra_id ra_id;

	uint8_t *llc_pdu =(uint8_t *)TLVP_VAL(bp->tp, BSSGP_IE_LLC_PDU);
	size_t llc_pdu_len = TLVP_LEN(bp->tp, BSSGP_IE_LLC_PDU);

	switch (gprs_tlli_type(bp->tlli)) {
	case TLLI_LOCAL:
	case TLLI_FOREIGN:
	case TLLI_RANDOM:
	case TLLI_AUXILIARY:
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR,
			"Discarding frame with strange TLLI type\n");
		return -EINVAL;
	}

	rc = tlli_cache_update(&sgsn->bssgp, bp->tlli, bp->nsei, bp->bvci);
	if (rc < 0)
		return rc;

	if (!TLVP_PRES_LEN(bp->tp, BSSGP_IE_CELL_ID, 8)) {
		LOGP(DGPRS, LOGL_ERROR,
		     "Discarding BSSGP without IE CELL_ID\n");
		return -EINVAL;
	}
	bssgp_parse_cell_id(&ra_id, TLVP_VAL(bp->tp, BSSGP_IE_CELL_ID));

	llc_prim = osmo_gprs_llc_prim_alloc_bssgp_ul_unitdata_ind(bp->tlli, llc_pdu, llc_pdu_len);
	OSMO_ASSERT(llc_prim);
	llc_prim->bssgp.ul_unitdata_ind.cell_id.ci =
			bssgp_parse_cell_id(&llc_prim->bssgp.ul_unitdata_ind.cell_id.rai,
					    TLVP_VAL(bp->tp, BSSGP_IE_CELL_ID));
	rc = osmo_gprs_llc_prim_lower_up(llc_prim);

	return rc;
}

/* call-back function for the BSSGP protocol */
int sgsn_bssgp_rx_prim(struct osmo_prim_hdr *oph)
{
	struct osmo_bssgp_prim *bp;
	bp = container_of(oph, struct osmo_bssgp_prim, oph);

	switch (oph->sap) {
	case SAP_BSSGP_LL:
		switch (oph->primitive) {
		case PRIM_BSSGP_UL_UD:
			return sgsn_bssgp_rx_ul_unitdata(bp);
		}
		break;
	case SAP_BSSGP_GMM:
		switch (oph->primitive) {
		case PRIM_BSSGP_GMM_SUSPEND:
			return gprs_gmm_rx_suspend(bp->ra_id, bp->tlli);
		case PRIM_BSSGP_GMM_RESUME:
			return gprs_gmm_rx_resume(bp->ra_id, bp->tlli,
						  bp->u.resume.suspend_ref);
		}
		break;
	case SAP_BSSGP_NM:
		break;
	case SAP_BSSGP_RIM:
		return sgsn_rim_rx_from_gb(bp, oph->msg);
	}
	return 0;
}

int sgsn_bssgp_page_ps_ra(struct sgsn_mm_ctx *mmctx)
{
	struct bssgp_paging_info pinfo;
	struct bssgp_tlli *cache_entry;
	int rc;
	uint32_t tlli;

	/*
	 * FIXME: page whole routing area, not only the last known cell
	 * FIXME: use routing area, lookup all matching cells and use it to find the right cell.
	 */
	tlli = gprs_tmsi2tlli(mmctx->p_tmsi, TLLI_LOCAL);
	if (tlli == GSM_RESERVED_TMSI || tlli == 0) {
		LOGMMCTXP(LOGL_ERROR, mmctx, "Can't convert P-TMSI (%08x) to TLLI to find the cell for MS\n",
			  mmctx->p_tmsi);
		return -ENOENT;
	}
	cache_entry = tlli_cache_get(&sgsn->bssgp, mmctx->p_tmsi);
	if (!cache_entry) {
		LOGP(DGPRS, LOGL_ERROR, "Can't find BSSGP link for TLLI %02x\n", tlli);
		return -ENOENT;
	}

	/* initiate PS PAGING procedure */
	memset(&pinfo, 0, sizeof(pinfo));
	pinfo.mode = BSSGP_PAGING_PS;
	pinfo.scope = BSSGP_PAGING_BVCI;
	pinfo.bvci = cache_entry->bvci;
	pinfo.imsi = mmctx->imsi;
	pinfo.ptmsi = &mmctx->p_tmsi;
	pinfo.drx_params = mmctx->drx_parms;
	pinfo.qos[0] = 0; // FIXME

	rc = bssgp_tx_paging(cache_entry->nsei, 0, &pinfo);
	rate_ctr_inc(rate_ctr_group_get_ctr(mmctx->ctrg, GMM_CTR_PAGING_PS));

	return rc;
}

/* called by the bssgp layer to send NS PDUs */
int sgsn_bssgp_dispatch_ns_unitdata_req_cb(void *ctx, struct msgb *msg)
{
	struct gprs_ns2_inst *nsi = (struct gprs_ns2_inst *) ctx;
	struct osmo_gprs_ns2_prim nsp = {};
	nsp.nsei = msgb_nsei(msg);
	nsp.bvci = msgb_bvci(msg);
	osmo_prim_init(&nsp.oph, SAP_NS, GPRS_NS2_PRIM_UNIT_DATA, PRIM_OP_REQUEST, msg);
	return gprs_ns2_recv_prim(nsi, &nsp.oph);
}

int sgsn_bssgp_init(void)
{
	hash_init(sgsn->bssgp.tlli_cache.entries);
	sgsn->bssgp.tlli_cache.timeout = 10;
	osmo_timer_setup(&sgsn->bssgp.tlli_cache.timer, tlli_cache_cleanup_cb, &sgsn->bssgp);
	osmo_timer_schedule(&sgsn->bssgp.tlli_cache.timer, 2, 0);

	return 0;
}
