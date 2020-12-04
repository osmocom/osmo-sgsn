/* Gb proxy peer handling */

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

#include <osmocom/sgsn/gb_proxy.h>

#include <osmocom/sgsn/debug.h>

#include <osmocom/gprs/protocol/gsm_08_18.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/tlv.h>

#include <string.h>

extern void *tall_sgsn_ctx;

static const struct rate_ctr_desc bvc_ctr_description[] = {
	{ "blocked",	   "BVC Block                       " },
	{ "unblocked",	   "BVC Unblock                     " },
	{ "dropped",	   "BVC blocked, dropped packet     " },
	{ "inv-nsei",	   "NSEI mismatch                   " },
	{ "tx-err",	   "NS Transmission error           " },
	{ "raid-mod:bss",  "RAID patched              (BSS )" },
	{ "raid-mod:sgsn", "RAID patched              (SGSN)" },
	{ "apn-mod:sgsn",  "APN patched                     " },
	{ "tlli-mod:bss",  "TLLI patched              (BSS )" },
	{ "tlli-mod:sgsn", "TLLI patched              (SGSN)" },
	{ "ptmsi-mod:bss", "P-TMSI patched            (BSS )" },
	{ "ptmsi-mod:sgsn","P-TMSI patched            (SGSN)" },
	{ "mod-crypt-err", "Patch error: encrypted          " },
	{ "mod-err",	   "Patch error: other              " },
	{ "attach-reqs",   "Attach Request count            " },
	{ "attach-rejs",   "Attach Reject count             " },
	{ "attach-acks",   "Attach Accept count             " },
	{ "attach-cpls",   "Attach Completed count          " },
	{ "ra-upd-reqs",   "RoutingArea Update Request count" },
	{ "ra-upd-rejs",   "RoutingArea Update Reject count " },
	{ "ra-upd-acks",   "RoutingArea Update Accept count " },
	{ "ra-upd-cpls",   "RoutingArea Update Compltd count" },
	{ "gmm-status",    "GMM Status count           (BSS)" },
	{ "gmm-status",    "GMM Status count          (SGSN)" },
	{ "detach-reqs",   "Detach Request count            " },
	{ "detach-acks",   "Detach Accept count             " },
	{ "pdp-act-reqs",  "PDP Activation Request count    " },
	{ "pdp-act-rejs",  "PDP Activation Reject count     " },
	{ "pdp-act-acks",  "PDP Activation Accept count     " },
	{ "pdp-deact-reqs","PDP Deactivation Request count  " },
	{ "pdp-deact-acks","PDP Deactivation Accept count   " },
	{ "tlli-unknown",  "TLLI from SGSN unknown          " },
	{ "tlli-cache",    "TLLI cache size                 " },
};

osmo_static_assert(ARRAY_SIZE(bvc_ctr_description) == GBPROX_PEER_CTR_LAST, everything_described);

static const struct rate_ctr_group_desc bvc_ctrg_desc = {
	.group_name_prefix = "gbproxy:peer",
	.group_description = "GBProxy Peer Statistics",
	.num_ctr = ARRAY_SIZE(bvc_ctr_description),
	.ctr_desc = bvc_ctr_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};


/* Find the gbproxy_bvc by its BVCI. There can only be one match */
struct gbproxy_bvc *gbproxy_bvc_by_bvci(struct gbproxy_config *cfg, uint16_t bvci)
{
	struct gbproxy_nse *nse;

	llist_for_each_entry(nse, &cfg->nses, list) {
		struct gbproxy_bvc *bvc;
		llist_for_each_entry(bvc, &nse->bvcs, list) {
			if (bvc->bvci == bvci)
				return bvc;
		}
	}
	return NULL;
}

/* Find the gbproxy_bvc by its NSEI */
/* FIXME: Only returns the first bvc, but we could have multiple on this nsei */
struct gbproxy_bvc *gbproxy_bvc_by_nsei(struct gbproxy_config *cfg,
					  uint16_t nsei)
{
	struct gbproxy_nse *nse;
	llist_for_each_entry(nse, &cfg->nses, list) {
		if (nse->nsei == nsei && !llist_empty(&nse->bvcs))
			return llist_first_entry(&nse->bvcs, struct gbproxy_bvc, list);
	}
	return NULL;
}

/* look-up a bvc by its Routeing Area Identification (RAI) */
/* FIXME: this doesn't make sense, as RA can span multiple bvcs! */
struct gbproxy_bvc *gbproxy_bvc_by_rai(struct gbproxy_config *cfg,
					 const uint8_t *ra)
{
	struct gbproxy_nse *nse;

	llist_for_each_entry(nse, &cfg->nses, list) {
		struct gbproxy_bvc *bvc;
		llist_for_each_entry(bvc, &nse->bvcs, list) {
			if (!memcmp(bvc->ra, ra, 6))
				return bvc;
		}
	}

	return NULL;
}

/* look-up a bvc by its Location Area Identification (LAI) */
/* FIXME: this doesn't make sense, as LA can span multiple bvcs! */
struct gbproxy_bvc *gbproxy_bvc_by_lai(struct gbproxy_config *cfg,
					 const uint8_t *la)
{
	struct gbproxy_nse *nse;

	llist_for_each_entry(nse, &cfg->nses, list) {
		struct gbproxy_bvc *bvc;
		llist_for_each_entry(bvc, &nse->bvcs, list) {
			if (!memcmp(bvc->ra, la, 5))
				return bvc;
		}
	}
	return NULL;
}

/* look-up a bvc by its Location Area Code (LAC) */
/* FIXME: this doesn't make sense, as LAC can span multiple bvcs! */
struct gbproxy_bvc *gbproxy_bvc_by_lac(struct gbproxy_config *cfg,
					 const uint8_t *la)
{
	struct gbproxy_nse *nse;

	llist_for_each_entry(nse, &cfg->nses, list) {
		struct gbproxy_bvc *bvc;
		llist_for_each_entry(bvc, &nse->bvcs, list) {
			if (!memcmp(bvc->ra + 3, la + 3, 2))
				return bvc;
		}
	}
	return NULL;
}

struct gbproxy_bvc *gbproxy_bvc_by_bssgp_tlv(struct gbproxy_config *cfg,
					       struct tlv_parsed *tp)
{
	if (TLVP_PRES_LEN(tp, BSSGP_IE_BVCI, 2)) {
		uint16_t bvci;

		bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
		if (bvci >= 2)
			return gbproxy_bvc_by_bvci(cfg, bvci);
	}

	/* FIXME: this doesn't make sense, as RA can span multiple bvcs! */
	if (TLVP_PRES_LEN(tp, BSSGP_IE_ROUTEING_AREA, 6)) {
		uint8_t *rai = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA);
		/* Only compare LAC part, since MCC/MNC are possibly patched.
		 * Since the LAC of different BSS must be different when
		 * MCC/MNC are patched, collisions shouldn't happen. */
		return gbproxy_bvc_by_lac(cfg, rai);
	}

	/* FIXME: this doesn't make sense, as LA can span multiple bvcs! */
	if (TLVP_PRES_LEN(tp, BSSGP_IE_LOCATION_AREA, 5)) {
		uint8_t *lai = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA);
		return gbproxy_bvc_by_lac(cfg, lai);
	}

	return NULL;
}

static void clean_stale_timer_cb(void *data)
{
	time_t now;
	struct timespec ts = {0,};
	struct gbproxy_bvc *bvc = (struct gbproxy_bvc *) data;
	OSMO_ASSERT(bvc);
	OSMO_ASSERT(bvc->nse);
	struct gbproxy_config *cfg = bvc->nse->cfg;
	OSMO_ASSERT(cfg);

	osmo_clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;
	gbproxy_remove_stale_link_infos(bvc, now);
	if (cfg->clean_stale_timer_freq != 0)
		osmo_timer_schedule(&bvc->clean_stale_timer,
					cfg->clean_stale_timer_freq, 0);
}

struct gbproxy_bvc *gbproxy_bvc_alloc(struct gbproxy_nse *nse, uint16_t bvci)
{
	struct gbproxy_bvc *bvc;
	OSMO_ASSERT(nse);
	struct gbproxy_config *cfg = nse->cfg;
	OSMO_ASSERT(cfg);

	bvc = talloc_zero(tall_sgsn_ctx, struct gbproxy_bvc);
	if (!bvc)
		return NULL;

	bvc->bvci = bvci;
	bvc->ctrg = rate_ctr_group_alloc(bvc, &bvc_ctrg_desc, bvci);
	if (!bvc->ctrg) {
		talloc_free(bvc);
		return NULL;
	}
	bvc->nse = nse;

	llist_add(&bvc->list, &nse->bvcs);

	INIT_LLIST_HEAD(&bvc->patch_state.logical_links);

	osmo_timer_setup(&bvc->clean_stale_timer, clean_stale_timer_cb, bvc);
	if (cfg->clean_stale_timer_freq != 0)
		osmo_timer_schedule(&bvc->clean_stale_timer,
					cfg->clean_stale_timer_freq, 0);

	return bvc;
}

void gbproxy_bvc_free(struct gbproxy_bvc *bvc)
{
	if (!bvc)
		return;

	llist_del(&bvc->list);
	osmo_timer_del(&bvc->clean_stale_timer);
	gbproxy_delete_link_infos(bvc);

	rate_ctr_group_free(bvc->ctrg);
	bvc->ctrg = NULL;

	talloc_free(bvc);
}

void gbproxy_bvc_move(struct gbproxy_bvc *bvc, struct gbproxy_nse *nse)
{
	llist_del(&bvc->list);
	llist_add(&bvc->list, &nse->bvcs);
	bvc->nse = nse;
}

/*! remove bvcs (BVCs) on NSE specified by NSEI.
 *  \param[in] cfg proxy in which we operate
 *  \param[in] nsei NS entity in which we should clean up
 *  \param[in] bvci if 0: remove all BVCs; if != 0: BVCI of the single BVC to clean up */
int gbproxy_cleanup_bvcs(struct gbproxy_config *cfg, uint16_t nsei, uint16_t bvci)
{
	int counter = 0;
	struct gbproxy_nse *nse, *ntmp;
	OSMO_ASSERT(cfg);

	llist_for_each_entry_safe(nse, ntmp, &cfg->nses, list) {
		struct gbproxy_bvc *bvc, *tmp;
		if (nse->nsei != nsei)
			continue;
		llist_for_each_entry_safe(bvc, tmp, &nse->bvcs, list) {
			if (bvci && bvc->bvci != bvci)
				continue;

			gbproxy_bvc_free(bvc);
			counter += 1;
		}
	}

	return counter;
}

struct gbproxy_nse *gbproxy_nse_alloc(struct gbproxy_config *cfg, uint16_t nsei)
{
	struct gbproxy_nse *nse;
	OSMO_ASSERT(cfg);

	nse = talloc_zero(tall_sgsn_ctx, struct gbproxy_nse);
	if (!nse)
		return NULL;

	nse->nsei = nsei;
	nse->cfg = cfg;

	llist_add(&nse->list, &cfg->nses);

	INIT_LLIST_HEAD(&nse->bvcs);

	return nse;
}

void gbproxy_nse_free(struct gbproxy_nse *nse)
{
	struct gbproxy_bvc *bvc, *tmp;
	if (!nse)
		return;

	llist_del(&nse->list);

	llist_for_each_entry_safe(bvc, tmp, &nse->bvcs, list)
		gbproxy_bvc_free(bvc);

	talloc_free(nse);
}

struct gbproxy_nse *gbproxy_nse_by_nsei(struct gbproxy_config *cfg, uint16_t nsei)
{
	struct gbproxy_nse *nse;
	OSMO_ASSERT(cfg);

	llist_for_each_entry(nse, &cfg->nses, list) {
		if (nse->nsei == nsei)
			return nse;
	}

	return NULL;
}

struct gbproxy_nse *gbproxy_nse_by_nsei_or_new(struct gbproxy_config *cfg, uint16_t nsei)
{
	struct gbproxy_nse *nse;
	OSMO_ASSERT(cfg);

	nse = gbproxy_nse_by_nsei(cfg, nsei);
	if (!nse)
		nse = gbproxy_nse_alloc(cfg, nsei);

	return nse;
}
