/* SGSN Routing Area for 2G */

/* (C) 2024 sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Alexander Couzens <lynxis@fe80.eu>
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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_bssgp.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/sgsn.h>

#include <osmocom/sgsn/gprs_routing_area.h>

const struct value_string sgsn_ra_ran_type_names[] = {
	{ RA_TYPE_GERAN_Gb,	"GERAN_Gb" },
	{ RA_TYPE_UTRAN_Iu,	"UTRAN_Iu" },
	{ 0,                    NULL },
};

static void _sgsn_ra_cell_free(struct sgsn_ra_cell *cell, bool drop_empty_ra)
{
	struct sgsn_ra *ra;

	if (!cell)
		return;

	llist_del(&cell->list);
	/* to prevent double free of the Cell when freeing a Routing Area */
	if (!drop_empty_ra) {
		talloc_free(cell);
		return;
	}

	ra = cell->ra;
	talloc_free(cell);

	if (llist_empty(&ra->cells_alive_list))
		sgsn_ra_free(ra);
}

void sgsn_ra_cell_free(struct sgsn_ra_cell *cell)
{
	_sgsn_ra_cell_free(cell, true);
}

void sgsn_ra_free(struct sgsn_ra *ra)
{
	struct sgsn_ra_cell *cell, *cell2;

	if (!ra)
		return;

	llist_for_each_entry_safe(cell, cell2, &ra->cells_alive_list, list) {
		_sgsn_ra_cell_free(cell, false);
	}

	llist_del(&ra->list);
	talloc_free(ra);
}

struct sgsn_ra *sgsn_ra_alloc(const struct osmo_routing_area_id *rai, enum sgsn_ra_ran_type ran_type)
{
	struct sgsn_ra *ra;
	ra = talloc_zero(sgsn->routing_area, struct sgsn_ra);
	if (!ra)
		return NULL;

	INIT_LLIST_HEAD(&ra->cells_alive_list);
	ra->rai = *rai;
	ra->ran_type = ran_type;
	llist_add(&ra->list, &sgsn->routing_area->ra_list);
	return ra;
}

struct sgsn_ra_cell *sgsn_ra_cell_alloc_geran(struct sgsn_ra *ra, uint16_t cell_id, uint16_t nsei, uint16_t bvci)
{
	struct sgsn_ra_cell *cell;

	cell = talloc_zero(ra, struct sgsn_ra_cell);
	if (!cell)
		return NULL;

	cell->ra = ra;
	cell->cell_id = cell_id;
	cell->ran_type = RA_TYPE_GERAN_Gb;
	cell->u.geran.bvci = bvci;
	cell->u.geran.nsei = nsei;

	llist_add(&cell->list, &ra->cells_alive_list);

	return cell;
}

struct sgsn_ra *sgsn_ra_get_ra(const struct osmo_routing_area_id *rai)
{
	struct sgsn_ra *ra;

	llist_for_each_entry(ra, &sgsn->routing_area->ra_list, list)
		if (osmo_rai_cmp(&ra->rai, rai) == 0)
			return ra;

	return NULL;
}

struct sgsn_ra *sgsn_ra_get_ra_geran(const struct osmo_routing_area_id *rai)
{
	struct sgsn_ra *ra = sgsn_ra_get_ra(rai);

	if (!ra)
		return ra;

	if (ra->ran_type == RA_TYPE_GERAN_Gb)
		return ra;

	return NULL;
}

struct sgsn_ra_cell *sgsn_ra_get_cell_by_gb(uint16_t nsei, uint16_t bvci)
{
	struct sgsn_ra *ra;
	struct sgsn_ra_cell *cell;

	/* BVCI = 0 is invalid, only valid for signalling within the BSSGP, not for a single cell */
	if (bvci == 0)
		return NULL;

	llist_for_each_entry(ra, &sgsn->routing_area->ra_list, list) {
		if (ra->ran_type != RA_TYPE_GERAN_Gb)
			continue;

		llist_for_each_entry(cell, &ra->cells_alive_list, list) {
			if (cell->ran_type != RA_TYPE_GERAN_Gb)
				continue;

			if (cell->u.geran.bvci == bvci && cell->u.geran.nsei == nsei)
				return cell;
		}
	}

	return NULL;
}

int sgsn_ra_foreach_cell(struct sgsn_ra *ra, sgsn_ra_cb_t *cb, void *cb_data)
{
	struct sgsn_ra_cell *cell, *tmp;
	int ret = -ENOENT;

	OSMO_ASSERT(cb);

	llist_for_each_entry_safe(cell, tmp, &ra->cells_alive_list, list) {
		ret = cb(cell, cb_data);
		switch (ret) {
		case SGSN_RA_CB_CONT:
			continue;
		case SGSN_RA_CB_STOP:
			return 0;
		case SGSN_RA_CB_ERROR:
			return -1;
		default:
			OSMO_ASSERT(0);
		}
	}

	return ret;
}

int sgsn_ra_foreach_cell2(struct osmo_routing_area_id *rai, sgsn_ra_cb_t *cb, void *cb_data)
{
	struct sgsn_ra *ra;
	OSMO_ASSERT(rai);
	OSMO_ASSERT(cb);

	ra = sgsn_ra_get_ra(rai);
	if (!ra)
		return -ENOENT;

	return sgsn_ra_foreach_cell(ra, cb, cb_data);
}

/* valid for GERAN */
struct sgsn_ra_cell *sgsn_ra_get_cell_by_ra(const struct sgsn_ra *ra, uint16_t cell_id)
{
	struct sgsn_ra_cell *cell;

	if (ra->ran_type != RA_TYPE_GERAN_Gb)
		return NULL;

	llist_for_each_entry(cell, &ra->cells_alive_list, list) {
		if (cell->cell_id == cell_id)
			return cell;
	}

	return NULL;
}

/* valid for GERAN */
struct sgsn_ra_cell *sgsn_ra_get_cell_by_lai(const struct osmo_location_area_id *lai, uint16_t cell_id)
{
	struct sgsn_ra *ra;
	struct sgsn_ra_cell *cell;

	/* This is a little bit in-efficient. A more performance way, but more complex would
	 * adding a llist for LAC on top of the routing areas */
	llist_for_each_entry(ra, &sgsn->routing_area->ra_list, list) {
		if (ra->ran_type != RA_TYPE_GERAN_Gb)
			continue;

		if (osmo_lai_cmp(&ra->rai.lac, lai) != 0)
			continue;

		llist_for_each_entry(cell, &ra->cells_alive_list, list) {
			if (cell->cell_id == cell_id)
				return cell;
		}
	}

	return NULL;
}

/*! Return the GERAN cell by searching for the RA, when found, search the cell within the RA
 *
 * \param cgi_ps
 * \return the cell or NULL if not found
 */
struct sgsn_ra_cell *sgsn_ra_get_cell_by_cgi_ps(const struct osmo_cell_global_id_ps *cgi_ps)
{
	struct sgsn_ra *ra;

	OSMO_ASSERT(cgi_ps);

	ra = sgsn_ra_get_ra_geran(&cgi_ps->rai);
	if (!ra)
		return NULL;

	return sgsn_ra_get_cell_by_ra(ra, cgi_ps->cell_identity);
}

struct sgsn_ra_cell *sgsn_ra_get_cell_by_cgi(const struct osmo_cell_global_id *cgi)
{
	OSMO_ASSERT(cgi);

	return sgsn_ra_get_cell_by_lai(&cgi->lai, cgi->cell_identity);
}

/*! Callback from the BSSGP layer on NM RESET IND
 *
 * \param nsei
 * \param bvci
 * \param cgi_ps
 * \return 0 on success or -ENOMEM
 */
int sgsn_ra_bvc_reset_ind(uint16_t nsei, uint16_t bvci, struct osmo_cell_global_id_ps *cgi_ps)
{
	struct sgsn_ra *ra;
	struct sgsn_ra_cell *cell;
	bool ra_created = false;
	OSMO_ASSERT(cgi_ps);

	/* TODO: do we have to move all MS to GMM IDLE state when this happens for a alive cell which got reseted? */
	ra = sgsn_ra_get_ra_geran(&cgi_ps->rai);
	if (!ra) {
		/* TODO: check for UTRAN rai when introducing UTRAN support */
		ra = sgsn_ra_alloc(&cgi_ps->rai, RA_TYPE_GERAN_Gb);
		if (!ra)
			return -ENOMEM;
		ra_created = true;
	}

	if (!ra_created) {
		cell = sgsn_ra_get_cell_by_ra(ra, cgi_ps->cell_identity);
		if (cell && cell->ran_type == RA_TYPE_GERAN_Gb) {
			/* Cell already exist, update NSEI/BVCI */
			if (cell->u.geran.bvci != bvci || cell->u.geran.nsei != nsei) {
				LOGP(DRA, LOGL_INFO, "GERAN Cell changed DLCI. Old: nsei/bvci %05u/%05u New: nsei/bvci %05u/%05u\n",
				     cell->u.geran.nsei, cell->u.geran.bvci, nsei, bvci);
				cell->u.geran.bvci = bvci;
				cell->u.geran.nsei = nsei;
			}
			return 0;
		}

		if (cell && cell->ran_type != RA_TYPE_GERAN_Gb) {
			/* How can we have here a RA change? Must be a configuration error. */
			LOGP(DRA, LOGL_INFO, "CGI %s: RAN change detected to GERAN!", osmo_cgi_ps_name(cgi_ps));
			_sgsn_ra_cell_free(cell, false);
			cell = NULL;
		}

		if (!cell) {
			char old_ra[32];
			char new_ra[32];
			/* check for the same cell id within the location area. The cell id is also unique for the cell within the LAC
			 * This should only happen when a Cell is changing routing areas */
			cell = sgsn_ra_get_cell_by_lai(&cgi_ps->rai.lac, cgi_ps->cell_identity);
			if (cell) {
				LOGP(DRA, LOGL_INFO, "CGI %s: changed Routing Area. Old: %s, New: %s\n",
				     osmo_cgi_ps_name(cgi_ps),
				     osmo_rai_name2_buf(old_ra, sizeof(old_ra), &cell->ra->rai),
				     osmo_rai_name2_buf(new_ra, sizeof(new_ra), &cgi_ps->rai));

				OSMO_ASSERT(cell->ra != ra);

				/* the old RA is definitive not our ra! Drop the old ra */
				_sgsn_ra_cell_free(cell, true);
				cell = NULL;
			}
		}
	}

	cell = sgsn_ra_cell_alloc_geran(ra, cgi_ps->cell_identity, nsei, bvci);
	if (!cell)
		return -ENOMEM;

	LOGP(DRA, LOGL_INFO, "New cell registered %s via nsei/bvci %05u/%05u\n", osmo_cgi_ps_name(cgi_ps), nsei, bvci);

	return 0;
}

/* FIXME: call it on BSSGP BLOCK + unavailable with BVCI */
int sgsn_ra_nsei_failure_ind(uint16_t nsei)
{
	struct sgsn_ra *ra, *ra2;
	struct sgsn_ra_cell *cell, *cell2;
	bool found = false;

	llist_for_each_entry_safe(ra, ra2, &sgsn->routing_area->ra_list, list) {
		if (ra->ran_type != RA_TYPE_GERAN_Gb)
			continue;

		llist_for_each_entry_safe(cell, cell2, &ra->cells_alive_list, list) {
			if (cell->ran_type != RA_TYPE_GERAN_Gb)
				continue;

			if (cell->u.geran.nsei == nsei) {
				found = true;
				_sgsn_ra_cell_free(cell, false);
			}
		}

		if (llist_empty(&ra->cells_alive_list))
			sgsn_ra_free(ra);
	}

	return found ? 0 : -ENOENT;
}

int sgsn_ra_geran_page_ra(struct osmo_routing_area_id *rai, struct sgsn_mm_ctx *mmctx)
{
	struct sgsn_ra *ra;
	struct sgsn_ra_cell *cell;
	int ret = -ENOENT;

	rate_ctr_inc(rate_ctr_group_get_ctr(mmctx->ctrg, GMM_CTR_PAGING_PS));

	ra = sgsn_ra_get_ra_geran(rai);
	if (!ra)
		return -ENOENT;

	llist_for_each_entry(cell, &ra->cells_alive_list, list) {
		if (cell->ran_type == RA_TYPE_GERAN_Gb) {
			sgsn_bssgp_page_ps_bvci(mmctx, cell->u.geran.nsei, cell->u.geran.bvci);
			ret = 0;
		}
	}


	return ret;
}

void sgsn_ra_init(struct sgsn_instance *inst)
{
	inst->routing_area = talloc_zero(inst, struct sgsn_ra_global);
	OSMO_ASSERT(inst->routing_area);

	INIT_LLIST_HEAD(&inst->routing_area->ra_list);
}
