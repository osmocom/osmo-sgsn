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
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/tlv.h>

#include <string.h>

extern void *tall_sgsn_ctx;

static const struct rate_ctr_desc peer_ctr_description[] = {
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

osmo_static_assert(ARRAY_SIZE(peer_ctr_description) == GBPROX_PEER_CTR_LAST, everything_described);

static const struct rate_ctr_group_desc peer_ctrg_desc = {
	.group_name_prefix = "gbproxy:peer",
	.group_description = "GBProxy Peer Statistics",
	.num_ctr = ARRAY_SIZE(peer_ctr_description),
	.ctr_desc = peer_ctr_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};


/* Find the gbproxy_peer by its BVCI. There can only be one match */
struct gbproxy_peer *gbproxy_peer_by_bvci(struct gbproxy_config *cfg, uint16_t bvci)
{
	struct gbproxy_nse *nse;

	llist_for_each_entry(nse, &cfg->nse_peers, list) {
		struct gbproxy_peer *peer;
		llist_for_each_entry(peer, &nse->bts_peers, list) {
			if (peer->bvci == bvci)
				return peer;
		}
	}
	return NULL;
}

/* Find the gbproxy_peer by its NSEI */
/* FIXME: Only returns the first peer, but we could have multiple on this nsei */
struct gbproxy_peer *gbproxy_peer_by_nsei(struct gbproxy_config *cfg,
					  uint16_t nsei)
{
	struct gbproxy_nse *nse;
	llist_for_each_entry(nse, &cfg->nse_peers, list) {
		if (nse->nsei == nsei && !llist_empty(&nse->bts_peers))
			return llist_first_entry(&nse->bts_peers, struct gbproxy_peer, list);
	}
	return NULL;
}

/* look-up a peer by its Routeing Area Identification (RAI) */
/* FIXME: this doesn't make sense, as RA can span multiple peers! */
struct gbproxy_peer *gbproxy_peer_by_rai(struct gbproxy_config *cfg,
					 const uint8_t *ra)
{
	struct gbproxy_nse *nse;

	llist_for_each_entry(nse, &cfg->nse_peers, list) {
		struct gbproxy_peer *peer;
		llist_for_each_entry(peer, &nse->bts_peers, list) {
			if (!memcmp(peer->ra, ra, 6))
				return peer;
		}
	}

	return NULL;
}

/* look-up a peer by its Location Area Identification (LAI) */
/* FIXME: this doesn't make sense, as LA can span multiple peers! */
struct gbproxy_peer *gbproxy_peer_by_lai(struct gbproxy_config *cfg,
					 const uint8_t *la)
{
	struct gbproxy_nse *nse;

	llist_for_each_entry(nse, &cfg->nse_peers, list) {
		struct gbproxy_peer *peer;
		llist_for_each_entry(peer, &nse->bts_peers, list) {
			if (!memcmp(peer->ra, la, 5))
				return peer;
		}
	}
	return NULL;
}

/* look-up a peer by its Location Area Code (LAC) */
/* FIXME: this doesn't make sense, as LAC can span multiple peers! */
struct gbproxy_peer *gbproxy_peer_by_lac(struct gbproxy_config *cfg,
					 const uint8_t *la)
{
	struct gbproxy_nse *nse;

	llist_for_each_entry(nse, &cfg->nse_peers, list) {
		struct gbproxy_peer *peer;
		llist_for_each_entry(peer, &nse->bts_peers, list) {
			if (!memcmp(peer->ra + 3, la + 3, 2))
				return peer;
		}
	}
	return NULL;
}

struct gbproxy_peer *gbproxy_peer_by_bssgp_tlv(struct gbproxy_config *cfg,
					       struct tlv_parsed *tp)
{
	if (TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		uint16_t bvci;

		bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
		if (bvci >= 2)
			return gbproxy_peer_by_bvci(cfg, bvci);
	}

	/* FIXME: this doesn't make sense, as RA can span multiple peers! */
	if (TLVP_PRESENT(tp, BSSGP_IE_ROUTEING_AREA)) {
		uint8_t *rai = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA);
		/* Only compare LAC part, since MCC/MNC are possibly patched.
		 * Since the LAC of different BSS must be different when
		 * MCC/MNC are patched, collisions shouldn't happen. */
		return gbproxy_peer_by_lac(cfg, rai);
	}

	/* FIXME: this doesn't make sense, as LA can span multiple peers! */
	if (TLVP_PRESENT(tp, BSSGP_IE_LOCATION_AREA)) {
		uint8_t *lai = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA);
		return gbproxy_peer_by_lac(cfg, lai);
	}

	return NULL;
}

static void clean_stale_timer_cb(void *data)
{
	time_t now;
	struct timespec ts = {0,};
	struct gbproxy_peer *peer = (struct gbproxy_peer *) data;
	OSMO_ASSERT(peer);
	OSMO_ASSERT(peer->nse);
	struct gbproxy_config *cfg = peer->nse->cfg;
	OSMO_ASSERT(cfg);

	osmo_clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;
	gbproxy_remove_stale_link_infos(peer, now);
	if (cfg->clean_stale_timer_freq != 0)
		osmo_timer_schedule(&peer->clean_stale_timer,
					cfg->clean_stale_timer_freq, 0);
}

struct gbproxy_peer *gbproxy_peer_alloc(struct gbproxy_nse *nse, uint16_t bvci)
{
	struct gbproxy_peer *peer;
	OSMO_ASSERT(nse);
	struct gbproxy_config *cfg = nse->cfg;
	OSMO_ASSERT(cfg);

	peer = talloc_zero(tall_sgsn_ctx, struct gbproxy_peer);
	if (!peer)
		return NULL;

	peer->bvci = bvci;
	peer->ctrg = rate_ctr_group_alloc(peer, &peer_ctrg_desc, bvci);
	if (!peer->ctrg) {
		talloc_free(peer);
		return NULL;
	}
	peer->nse = nse;

	llist_add(&peer->list, &nse->bts_peers);

	INIT_LLIST_HEAD(&peer->patch_state.logical_links);

	osmo_timer_setup(&peer->clean_stale_timer, clean_stale_timer_cb, peer);
	if (cfg->clean_stale_timer_freq != 0)
		osmo_timer_schedule(&peer->clean_stale_timer,
					cfg->clean_stale_timer_freq, 0);

	return peer;
}

void gbproxy_peer_free(struct gbproxy_peer *peer)
{
	OSMO_ASSERT(peer);

	llist_del(&peer->list);
	osmo_timer_del(&peer->clean_stale_timer);
	gbproxy_delete_link_infos(peer);

	rate_ctr_group_free(peer->ctrg);
	peer->ctrg = NULL;

	talloc_free(peer);
}

void gbproxy_peer_move(struct gbproxy_peer *peer, struct gbproxy_nse *nse)
{
	llist_del(&peer->list);
	llist_add(&peer->list, &nse->bts_peers);
	peer->nse = nse;
}

int gbproxy_cleanup_peers(struct gbproxy_config *cfg, uint16_t nsei, uint16_t bvci)
{
	int counter = 0;
	struct gbproxy_nse *nse, *ntmp;
	OSMO_ASSERT(cfg);

	llist_for_each_entry_safe(nse, ntmp, &cfg->nse_peers, list) {
		struct gbproxy_peer *peer, *tmp;
		if (nse->nsei != nsei)
			continue;
		llist_for_each_entry_safe(peer, tmp, &nse->bts_peers, list) {
			if (bvci && peer->bvci != bvci)
				continue;

			gbproxy_peer_free(peer);
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

	llist_add(&nse->list, &cfg->nse_peers);

	INIT_LLIST_HEAD(&nse->bts_peers);

	return nse;
}

void gbproxy_nse_free(struct gbproxy_nse *nse)
{
	struct gbproxy_peer *peer, *tmp;
	OSMO_ASSERT(nse);

	llist_del(&nse->list);

	llist_for_each_entry_safe(peer, tmp, &nse->bts_peers, list)
		gbproxy_peer_free(peer);

	talloc_free(nse);
}

struct gbproxy_nse *gbproxy_nse_by_nsei(struct gbproxy_config *cfg, uint16_t nsei)
{
	struct gbproxy_nse *nse;
	OSMO_ASSERT(cfg);

	llist_for_each_entry(nse, &cfg->nse_peers, list) {
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