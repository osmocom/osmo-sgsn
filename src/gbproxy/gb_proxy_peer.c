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
struct gbproxy_bvc *gbproxy_bvc_by_bvci(struct gbproxy_nse *nse, uint16_t bvci)
{
	struct gbproxy_bvc *bvc;
	hash_for_each_possible(nse->bvcs, bvc, list, bvci) {
		if (bvc->bvci == bvci)
			return bvc;
	}
	return NULL;
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

	hash_add(nse->bvcs, &bvc->list, bvc->bvci);

        return bvc;
}

void gbproxy_bvc_free(struct gbproxy_bvc *bvc)
{
	struct gbproxy_cell *cell;

	if (!bvc)
		return;

	hash_del(&bvc->list);

	rate_ctr_group_free(bvc->ctrg);
	bvc->ctrg = NULL;

	osmo_fsm_inst_free(bvc->fi);

	cell = bvc->cell;
	if (cell) {
		int i;

		if (cell->bss_bvc == bvc)
			cell->bss_bvc = NULL;

		/* we could also be a SGSN-side BVC */
		for (i = 0; i < ARRAY_SIZE(cell->sgsn_bvc); i++) {
			if (cell->sgsn_bvc[i] == bvc)
				cell->sgsn_bvc[i] = NULL;
		}
		bvc->cell = NULL;
	}

	talloc_free(bvc);
}

/*! remove BVCs on NSE specified by NSEI.
 *  \param[in] cfg proxy in which we operate
 *  \param[in] nsei NS entity in which we should clean up
 *  \param[in] bvci if 0: remove all PTP BVCs; if != 0: BVCI of the single BVC to clean up */
int gbproxy_cleanup_bvcs(struct gbproxy_nse *nse, uint16_t bvci)
{
	struct hlist_node *btmp;
	struct gbproxy_bvc *bvc;
	int j, counter = 0;

	if (!nse)
		return 0;

	hash_for_each_safe(nse->bvcs, j, btmp, bvc, list) {
		if (bvci && bvc->bvci != bvci)
			continue;
		if (bvci == 0 && bvc->bvci == 0)
			continue;

		gbproxy_bvc_free(bvc);
		counter += 1;
	}

	return counter;
}


/***********************************************************************
 * CELL
 ***********************************************************************/

/* Allocate a new 'cell' object */
struct gbproxy_cell *gbproxy_cell_alloc(struct gbproxy_config *cfg, uint16_t bvci)
{
	struct gbproxy_cell *cell;
	OSMO_ASSERT(cfg);

	cell = talloc_zero(cfg, struct gbproxy_cell);
	if (!cell)
		return NULL;

	cell->cfg = cfg;
	cell->bvci = bvci;

	hash_add(cfg->cells, &cell->list, cell->bvci);

	return cell;
}

/* Find cell by BVCI */
struct gbproxy_cell *gbproxy_cell_by_bvci(struct gbproxy_config *cfg, uint16_t bvci)
{
	struct gbproxy_cell *cell;

	hash_for_each_possible(cfg->cells, cell, list, bvci) {
		if (cell->bvci == bvci)
			return cell;
	}
	return NULL;
}

struct gbproxy_cell *gbproxy_cell_by_bvci_or_new(struct gbproxy_config *cfg, uint16_t bvci)
{
	struct gbproxy_cell *cell;
	OSMO_ASSERT(cfg);

	cell = gbproxy_cell_by_bvci(cfg, bvci);
	if (!cell)
		cell = gbproxy_cell_alloc(cfg, bvci);

	return cell;
}

void gbproxy_cell_free(struct gbproxy_cell *cell)
{
	unsigned int i;

	if (!cell)
		return;

	/* remove from cfg.cells */
	hash_del(&cell->list);

	/* remove back-pointers from the BSS side */
	if (cell->bss_bvc && cell->bss_bvc->cell)
		cell->bss_bvc->cell = NULL;

	/* remove back-pointers from the SGSN side */
	for (i = 0; i < ARRAY_SIZE(cell->sgsn_bvc); i++) {
		if (!cell->sgsn_bvc[i])
			continue;
		if (cell->sgsn_bvc[i]->cell)
			cell->sgsn_bvc[i]->cell = NULL;
	}

	talloc_free(cell);
}

bool gbproxy_cell_add_sgsn_bvc(struct gbproxy_cell *cell, struct gbproxy_bvc *bvc)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(cell->sgsn_bvc); i++) {
		if (!cell->sgsn_bvc[i]) {
			cell->sgsn_bvc[i] = bvc;
			return true;
		}
	}
	return false;
}

/***********************************************************************
 * NSE - NS Entity
 ***********************************************************************/

struct gbproxy_nse *gbproxy_nse_alloc(struct gbproxy_config *cfg, uint16_t nsei, bool sgsn_facing)
{
	struct gbproxy_nse *nse;
	OSMO_ASSERT(cfg);

	nse = talloc_zero(tall_sgsn_ctx, struct gbproxy_nse);
	if (!nse)
		return NULL;

	nse->nsei = nsei;
	nse->cfg = cfg;
	nse->sgsn_facing = sgsn_facing;

	if (sgsn_facing)
		hash_add(cfg->sgsn_nses, &nse->list, nsei);
	else
		hash_add(cfg->bss_nses, &nse->list, nsei);

	hash_init(nse->bvcs);

	return nse;
}

void gbproxy_nse_free(struct gbproxy_nse *nse)
{
	struct gbproxy_bvc *bvc;
	struct hlist_node *tmp;
	int i;

	if (!nse)
		return;

	hash_del(&nse->list);

	hash_for_each_safe(nse->bvcs, i, tmp, bvc, list)
		gbproxy_bvc_free(bvc);

	talloc_free(nse);
}

struct gbproxy_nse *gbproxy_nse_by_nsei(struct gbproxy_config *cfg, uint16_t nsei, uint32_t flags)
{
	struct gbproxy_nse *nse;
	OSMO_ASSERT(cfg);

	if (flags & NSE_F_SGSN) {
		hash_for_each_possible(cfg->sgsn_nses, nse, list, nsei) {
			if (nse->nsei == nsei)
				return nse;
		}
	}

	if (flags & NSE_F_BSS) {
		hash_for_each_possible(cfg->bss_nses, nse, list, nsei) {
			if (nse->nsei == nsei)
				return nse;
		}
	}

	return NULL;
}

struct gbproxy_nse *gbproxy_nse_by_nsei_or_new(struct gbproxy_config *cfg, uint16_t nsei, bool sgsn_facing)
{
	struct gbproxy_nse *nse;
	OSMO_ASSERT(cfg);

	nse = gbproxy_nse_by_nsei(cfg, nsei, sgsn_facing ? NSE_F_SGSN : NSE_F_BSS);
	if (!nse)
		nse = gbproxy_nse_alloc(cfg, nsei, sgsn_facing);

	return nse;
}
