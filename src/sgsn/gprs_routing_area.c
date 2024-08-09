/* SGSN Routing Area for 2G */

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/sgsn/debug.h>


#include <osmocom/gsm/gsm48.h>

#include <osmocom/sgsn/sgsn.h>

#include <osmocom/sgsn/gprs_routing_area.h>

struct sgsn_ra_global {
	/* FIXME: move to sgsn global context */
	struct llist_head ras;
};

struct sgsn_ra_global *sgsn_ra_ctx;

/* TODO: do we need a location area level here? */
/* TOOD: is the cell id unique in GERAN or only unique within a LAC? */
/* TODO: check for cell id within a LAC */

void sgsn_ra_free(struct sgsn_ra *ra)
{
	struct sgsn_ra_cell *cell, *cell2;

	if (!llist_empty(&ra->cells)) {
		llist_for_each_entry_safe(cell, cell2, &ra->cells, list) {
			sgsn_ra_cell_free(cell, false);
		}
	}

	llist_del(&ra->list);
	talloc_free(ra);
}

void sgsn_ra_cell_free(struct sgsn_ra_cell *cell, bool drop_empty_ra)
{
	struct sgsn_ra *ra;

	OSMO_ASSERT(cell);
	llist_del(&cell->list);
	if (!drop_empty_ra) {
		talloc_free(cell);
		return;
	}

	/* FIXME: change state of the Routing Area? */
	ra = cell->ra;
	talloc_free(cell);

	if (llist_empty(&ra->cells)) {
		sgsn_ra_free(ra);
	}
}

struct sgsn_ra *sgsn_ra_alloc(const struct osmo_routing_area_id *rai)
{
	struct sgsn_ra *ra;
	ra = talloc_zero(sgsn_ra_ctx, struct sgsn_ra);
	if (!ra)
		return NULL;

	INIT_LLIST_HEAD(&ra->cells);

	ra->ra = *rai;
	llist_add(&ra->list, &sgsn_ra_ctx->ras);
	return ra;
}

static struct sgsn_ra_cell *sgsn_ra_cell_alloc_geran(struct sgsn_ra *ra, uint16_t cell_id, uint16_t nsei, uint16_t bvci)
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

	llist_add(&cell->list, &ra->cells);

	return cell;
}

struct sgsn_ra *sgsn_ra_get_ra(const struct osmo_routing_area_id *rai)
{
	struct sgsn_ra *ra;

	llist_for_each_entry(ra, &sgsn_ra_ctx->ras, list) {
		if (osmo_rai_cmp(&ra->ra, rai) == 0) {
			return ra;
		}
	}

	return NULL;
}

struct sgsn_ra_cell *sgsn_ra_get_cell_by_gb(uint16_t nsei, uint16_t bvci)
{
	struct sgsn_ra *ra;
	struct sgsn_ra_cell *cell;

	/* BVCI = 0 is invalid, only valid for signalling within the BSSGP, not for a single cell */
	if (bvci == 0)
		return NULL;

	llist_for_each_entry(ra, &sgsn_ra_ctx->ras, list) {
		llist_for_each_entry(cell, &ra->cells, list) {
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

	llist_for_each_entry_safe(cell, tmp, &ra->cells, list) {
		ret = cb(cell, cb_data);
		switch (ret) {
		case SGSN_RA_CB_CONT:
			continue;
		case SGSN_RA_CB_STOP:
			return 0;
		case SGSN_RA_CB_ERROR:
		default:
			return -1;
		}
	}

	return ret;
}

int sgsn_ra_foreach_cell2(struct osmo_routing_area_id *ra_id, sgsn_ra_cb_t *cb, void *cb_data)
{
	struct sgsn_ra *ra;
	OSMO_ASSERT(ra_id);
	OSMO_ASSERT(cb);

	ra = sgsn_ra_get_ra(ra_id);
	if (!ra)
		return -ENOENT;

	return sgsn_ra_foreach_cell(ra, cb, cb_data);
}

struct sgsn_ra_cell *sgsn_ra_get_cell_by_ra(const struct sgsn_ra *ra, uint16_t cell_id)
{
	struct sgsn_ra_cell *cell;

	llist_for_each_entry(cell, &ra->cells, list) {
		if (cell->cell_id == cell_id)
			return cell;
	}

	return NULL;
}

struct sgsn_ra_cell *sgsn_ra_get_cell_by_lai(const struct osmo_location_area_id *lai, uint16_t cell_identity)
{
	struct sgsn_ra *ra;
	struct sgsn_ra_cell *cell;

	/* This is a little bit in-efficient. A more performance way, but more complex would
	 * adding a llist for LAC on top of the routing areas */
	llist_for_each_entry(ra, &sgsn_ra_ctx->ras, list) {
		if (osmo_lai_cmp(&ra->ra.lac, lai) != 0)
			continue;

		llist_for_each_entry(cell, &ra->cells, list) {
			if (cell->cell_id == cell_identity)
				return cell;
		}
	}

	return NULL;
}

/*! Return the cell by searching for the RA, when found, search the cell within the RA
 *
 * \param cgi_ps
 * \return the cell or NULL if not found
 */
struct sgsn_ra_cell *sgsn_ra_get_cell_by_cgi_ps(const struct osmo_cell_global_id_ps *cgi_ps)
{
	struct sgsn_ra *ra;

	OSMO_ASSERT(cgi_ps);

	ra = sgsn_ra_get_ra(&cgi_ps->rai);
	if (!ra)
		return NULL;

	return sgsn_ra_get_cell_by_ra(ra, cgi_ps->cell_identity);
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

	ra = sgsn_ra_get_ra(&cgi_ps->rai);
	if (!ra) {
		ra = sgsn_ra_alloc(&cgi_ps->rai);
		if (!ra)
			return -ENOMEM;
		ra_created = true;
	}

	if (!ra_created) {
		cell = sgsn_ra_get_cell_by_ra(ra, cgi_ps->cell_identity);
		if (cell && cell->ran_type == RA_TYPE_GERAN_Gb) {
			/* Cell already exist, update NSEI/BVCI */
			/* FIXME: drop old BVCI? How to handle the same RAI/CellId via different BVCIs? */
			if (cell->u.geran.bvci != bvci || cell->u.geran.nsei != nsei) {
				LOGP(DRA, LOGL_INFO, "GERAN Cell changed DLCI. Old: nsei/bvci 0x%04x/0x%04x New: nsei/bvci 0x%04x/0x%04x\n",
				     cell->u.geran.nsei, cell->u.geran.bvci, nsei, bvci);
				cell->u.geran.bvci = bvci;
				cell->u.geran.nsei = nsei;
			}
			return 0;
		} else if (cell && cell->ran_type != RA_TYPE_GERAN_Gb) {
			/* How can we have here a RA change? Must be a configuration error */
			LOGP(DRA, LOGL_INFO, "CGI %s: RAN change detected to GERAN!", osmo_cgi_ps_name(cgi_ps));
			sgsn_ra_cell_free(cell, false);
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
				     osmo_rai_name2_buf(old_ra, sizeof(old_ra), &cell->ra->ra),
				     osmo_rai_name2_buf(new_ra, sizeof(new_ra), &cgi_ps->rai));

				OSMO_ASSERT(cell->ra != ra);

				/* the old RA is definitive not our ra! Drop the old ra */
				sgsn_ra_cell_free(cell, true);
				cell = NULL;
			}
		}
	}

	cell = sgsn_ra_cell_alloc_geran(ra, cgi_ps->cell_identity, nsei, bvci);
	if (!cell)
		return -ENOMEM;

	LOGP(DRA, LOGL_INFO, "New cell registered %s via nsei/bvci %04x/%04x\n", osmo_cgi_ps_name(cgi_ps), nsei, bvci);

	return 0;
}

/* All Cells using this NSEI become unavailable */
void sgsn_ra_nsei_unavailable_ind(uint16_t nsei)
{
	struct sgsn_ra *ra, *ra2;
	struct sgsn_ra_cell *cell, *cell2;

	llist_for_each_entry_safe(ra, ra2, &sgsn_ra_ctx->ras, list) {
		llist_for_each_entry_safe(cell, cell2, &ra->cells, list) {
			if (cell->ran_type == RA_TYPE_GERAN_Gb && cell->u.geran.nsei == nsei) {
				/* TODO: we need to take care of all MS in this cell.
				 * What happens if a MS has an active data connection?
				 * Delete Bearer towards GGSN? */
				LOGP(DRA, LOGL_INFO, "Rau %s: Cell %d went offline because NSE (%d) failed\n",
				     osmo_rai_name2(&ra->ra), cell->cell_id, nsei);
				sgsn_ra_cell_free(cell, false);
			}
		}
		/* Check if RA is empty */
		if (llist_empty(&ra->cells)) {
			sgsn_ra_free(ra);
		}
	}
}

void sgsn_ra_init()
{
	sgsn_ra_ctx = talloc_zero(sgsn, struct sgsn_ra_global);
	OSMO_ASSERT(sgsn_ra_ctx);

	INIT_LLIST_HEAD(&sgsn_ra_ctx->ras);
}
