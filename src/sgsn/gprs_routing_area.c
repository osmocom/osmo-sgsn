/* SGSN Routing Area for 2G */

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/sgsn/debug.h>


#include <osmocom/gsm/gsm48.h>

#include <osmocom/sgsn/gprs_routing_area.h>
#include <osmocom/sgsn/sgsn.h>

struct sgsn_rau_global {
	/* FIXME: move to sgsn global context */
	struct llist_head raus;
};

struct sgsn_rau_global *sgsn_rau_ctx;

/* TODO: do we need a location area level here? */
/* TOOD: is the cell id unique in GERAN or only unique within a LAC? */
/* TODO: check for cell id within a LAC */

struct sgsn_rau {
	struct llist_head list;

	struct osmo_routing_area_id rau;
	struct llist_head cells;
};

enum sgsn_rau_ran_type {
	RAU_TYPE_GERAN_Gb,
	RAU_TYPE_UTRAN_Iu,
};

struct sgsn_rau_cell {
	/* contains cells which are in BVC_UNBLOCKED */
	struct llist_head list;

	/*! link back to the parent */
	struct sgsn_rau *rau;

	enum sgsn_rau_ran_type ran_type;

	uint16_t cell_id;
	union {
		struct {
			uint16_t nsei;
			uint16_t bvci;
		} geran;
		struct {
			/* TODO: unused */
			uint16_t rncid;
			uint16_t sac;
		} utran;
	} u;
};

void sgsn_rau_free(struct sgsn_rau *rau)
{
	llist_del(&rau->list);
	talloc_free(rau);
}

void sgsn_rau_cell_free(struct sgsn_rau_cell *cell, bool drop_empty_rau)
{
	struct sgsn_rau *rau;

	OSMO_ASSERT(cell);
	llist_del(&cell->list);
	if (!drop_empty_rau) {
		talloc_free(cell);
		return;
	}

	/* FIXME: change state of the Routing Area? */
	rau = cell->rau;
	if (llist_empty(&rau->cells)) {
		sgsn_rau_free(rau);
	}
}

struct sgsn_rau *sgsn_rau_alloc(const struct osmo_routing_area_id *rai)
{
	struct sgsn_rau *rau;
	rau = talloc_zero(sgsn_rau_ctx, struct sgsn_rau);
	if (!rau)
		return NULL;

	INIT_LLIST_HEAD(&rau->cells);

	rau->rau = *rai;
	llist_add(&rau->list, &sgsn_rau_ctx->raus);
	return rau;
}

struct sgsn_rau_cell *sgsn_rau_cell_alloc_geran(struct sgsn_rau *rau, uint16_t cell_id, uint16_t nsei, uint16_t bvci)
{
	struct sgsn_rau_cell *cell;

	cell = talloc_zero(rau, struct sgsn_rau_cell);
	if (!cell)
		return NULL;

	cell->rau = rau;
	cell->cell_id = cell_id;
	cell->ran_type = RAU_TYPE_GERAN_Gb;
	cell->u.geran.bvci = bvci;
	cell->u.geran.nsei = nsei;

	return cell;
}

struct sgsn_rau *sgsn_rau_get_rau(const struct osmo_routing_area_id *rai)
{
	struct sgsn_rau *rau;

	llist_for_each_entry(rau, &sgsn_rau_ctx->raus, list) {
		if (osmo_rai_cmp(&rau->rau, rai) == 0) {
			return rau;
		}
	}

	return NULL;
}

struct sgsn_rau_cell *sgsn_rau_get_cell_by_gb(uint16_t nsei, uint16_t bvci)
{
	struct sgsn_rau *rau;
	struct sgsn_rau_cell *cell;

	/* BVCI = 0 is invalid, only valid for signalling within the BSSGP, not for a single cell */
	if (bvci == 0)
		return NULL;

	llist_for_each_entry(rau, &sgsn_rau_ctx->raus, list) {
		llist_for_each_entry(cell, &rau->cells, list) {
			if (cell->ran_type != RAU_TYPE_GERAN_Gb)
				continue;
			if (cell->u.geran.bvci == bvci && cell->u.geran.nsei == nsei)
				return cell;
		}
	}

	return NULL;
}

typedef int (sgsn_rau_cb_t)(struct sgsn_rau_cell *rau_cell, void *cb_data);

/*
 * return value for callbacks.
 * STOP: stop calling the callback for the remaining cells, sgsn_rau_foreach_rau() returns 0
 * CONT: call the callback for remaining cells
 * ABORT: stop calling the callback for the remaining cells, sgsn_rau_foreach_rau() returns -1
 */
#define SGSN_RAU_CB_STOP 1
#define SGSN_RAU_CB_CONT 0
#define SGSN_RAU_CB_ERROR -1

int sgsn_rau_foreach_cell(struct sgsn_rau *rau, sgsn_rau_cb_t *cb, void *cb_data)
{
	struct sgsn_rau_cell *cell, *tmp;
	int ret = -ENOENT;

	OSMO_ASSERT(cb);

	llist_for_each_entry_safe(cell, tmp, &rau->cells, list) {
		ret = cb(cell, cb_data);
		switch (ret) {
		case SGSN_RAU_CB_CONT:
			continue;
		case SGSN_RAU_CB_STOP:
			return 0;
		case SGSN_RAU_CB_ERROR:
		default:
			return -1;
		}
	}

	return ret;
}


int sgsn_rau_foreach_cell2(struct osmo_routing_area_id *ra_id, sgsn_rau_cb_t *cb, void *cb_data)
{
	struct sgsn_rau *rau;
	OSMO_ASSERT(ra_id);
	OSMO_ASSERT(cb);

	rau = sgsn_rau_get_rau(ra_id);
	if (!rau)
		return -ENOENT;

	return sgsn_rau_foreach_cell(rau, cb, cb_data);
}

struct sgsn_rau_cell *sgsn_rau_get_cell_by_rau(const struct sgsn_rau *rau, uint16_t cell_id)
{
	struct sgsn_rau_cell *cell;

	llist_for_each_entry(cell, &rau->cells, list) {
		if (cell->cell_id == cell_id)
			return cell;
	}

	return NULL;
}

struct sgsn_rau_cell *sgsn_rau_get_cell_by_lai(const struct osmo_location_area_id *lai, uint16_t cell_identity)
{
	struct sgsn_rau *rau;
	struct sgsn_rau_cell *cell;

	/* This is a little bit in-efficient. A more performance way, but more complex would
	 * adding a llist for LAC on top of the routing areas */
	llist_for_each_entry(rau, &sgsn_rau_ctx->raus, list) {
		if (osmo_lai_cmp(&rau->rau.lac, lai) != 0)
			continue;

		llist_for_each_entry(cell, &rau->cells, list) {
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
struct sgsn_rau_cell *sgsn_rau_get_cell_by_cgi_ps(const struct osmo_cell_global_id_ps *cgi_ps)
{
	struct sgsn_rau *rau;

	OSMO_ASSERT(cgi_ps);

	rau = sgsn_rau_get_rau(&cgi_ps->rai);
	if (!rau)
		return NULL;

	return sgsn_rau_get_cell_by_rau(rau, cgi_ps->cell_identity);
}

/*! Callback from the BSSGP layer on NM RESET IND
 *
 * \param nsei
 * \param bvci
 * \param cgi_ps
 * \return 0 on success or -ENOMEM
 */
int sgsn_rau_bvc_reset_ind(uint16_t nsei, uint16_t bvci, struct osmo_cell_global_id_ps *cgi_ps)
{
	struct sgsn_rau *rau;
	struct sgsn_rau_cell *cell;
	bool rau_created = false;
	OSMO_ASSERT(cgi_ps);

	/* TODO: do we have to move all MS to GMM IDLE state when this happens for a alive cell which got reseted? */

	rau = sgsn_rau_get_rau(&cgi_ps->rai);
	if (!rau) {
		rau = sgsn_rau_alloc(&cgi_ps->rai);
		if (!rau)
			return -ENOMEM;
		rau_created = true;
	}

	if (!rau_created) {
		cell = sgsn_rau_get_cell_by_rau(rau, cgi_ps->cell_identity);
		if (cell && cell->ran_type == RAU_TYPE_GERAN_Gb) {
			/* Cell already exist, update NSEI/BVCI */
			/* FIXME: drop old BVCI? How to handle the same RAI/CellId via different BVCIs? */
			if (cell->u.geran.bvci != bvci || cell->u.geran.nsei != nsei) {
				LOGP(DRAU, LOGL_INFO, "GERAN Cell changed DLCI. Old: nsei/bvci %04x%04x New: nsei/bvci %04x/%04x",
				     cell->u.geran.nsei, cell->u.geran.bvci, nsei, bvci);
				cell->u.geran.bvci = bvci;
				cell->u.geran.nsei = nsei;
			}
			return 0;
		} else if (cell && cell->ran_type != RAU_TYPE_GERAN_Gb) {
			/* How can we have here a RAU change? Must be a configuration error */
			LOGP(DRAU, LOGL_ERROR, "CGI %s: RAN change detected to GERAN!", osmo_cgi_ps_name(cgi_ps));
			sgsn_rau_cell_free(cell, false);
			cell = NULL;
		}

		if (!cell) {
			char old_ra[32];
			char new_ra[32];
			/* check for the same cell id within the location area. The cell id is also unique for the cell within the LAC
			 * This should only happen when a Cell is changing routing areas */
			cell = sgsn_rau_get_cell_by_lai(&cgi_ps->rai.lac, cgi_ps->cell_identity);
			if (cell) {
				LOGP(DRAU, LOGL_ERROR, "CGI %s: changed Routing Area. Old: %s, New: %s",
				     osmo_cgi_ps_name(cgi_ps),
				     osmo_rai_name2_buf(old_ra, sizeof(old_ra), &cell->rau->rau),
				     osmo_rai_name2_buf(new_ra, sizeof(new_ra), &cgi_ps->rai));

				OSMO_ASSERT(cell->rau != rau);

				/* the old RAU is definitive not our rau! Drop the old rau */
				sgsn_rau_cell_free(cell, true);
				cell = NULL;
			}
		}
	}

	cell = sgsn_rau_cell_alloc_geran(rau, cgi_ps->cell_identity, nsei, bvci);
	if (!cell)
		return -ENOMEM;

	LOGP(DRAU, LOGL_INFO, "New cell registered %s via nsei/bvci %04x/%04x", osmo_cgi_ps_name(cgi_ps), nsei, bvci);

	return 0;
}

/* TODO: use vty to configure allowed 2G RAUs */
bool sgsn_rau_valid_rau(struct osmo_routing_area_id *ra_id)
{
	return true;
}

void sgsn_rau_init()
{
	sgsn_rau_ctx = talloc_zero(sgsn, struct sgsn_rau_global);
	OSMO_ASSERT(sgsn_rau_ctx);

	INIT_LLIST_HEAD(&sgsn_rau_ctx->raus);
}
