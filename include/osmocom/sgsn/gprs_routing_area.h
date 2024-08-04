/*! \file gprs_routing_area.h */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm23003.h>

struct sgsn_instance;

struct sgsn_ra_global {
	/* list of struct sgsn_ra */
	struct llist_head ra_list;
};

struct sgsn_ra {
	/* Entry in sgsn_ra_global->ra_list */
	struct llist_head list;

	struct osmo_routing_area_id rai;
	/* cells contains a list of sgsn_ra_cells which are alive */
	struct llist_head cells;
};

enum sgsn_ra_ran_type {
	RA_TYPE_GERAN_Gb,
	RA_TYPE_UTRAN_Iu,
};

struct sgsn_ra_cell {
	/* Entry in sgsn_ra->cells */
	struct llist_head list;

	/*! link back to the parent */
	struct sgsn_ra *ra;

	enum sgsn_ra_ran_type ran_type;

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

void sgsn_ra_init(struct sgsn_instance *inst);

struct sgsn_ra *sgsn_ra_alloc(const struct osmo_routing_area_id *rai);
void sgsn_ra_free(struct sgsn_ra *ra);
struct sgsn_ra_cell *sgsn_ra_cell_alloc_geran(struct sgsn_ra *ra, uint16_t cell_id, uint16_t nsei, uint16_t bvci);
void sgsn_ra_cell_free(struct sgsn_ra_cell *cell);

/* Called by BSSGP layer to inform about a reset on a BVCI */
int sgsn_ra_bvc_reset_ind(uint16_t nsei, uint16_t bvci, struct osmo_cell_global_id_ps *cgi_ps);
/* FIXME: handle BVC BLOCK/UNBLOCK/UNAVAILABLE */
/* Called by NS-VC layer to inform about an unavailable NSEI (and all BVCI on them) */
int sgsn_ra_nsei_failure_ind(uint16_t nsei);

struct sgsn_ra_cell *sgsn_ra_get_cell_by_cgi_ps(const struct osmo_cell_global_id_ps *cgi_ps);
struct sgsn_ra_cell *sgsn_ra_get_cell_by_lai(const struct osmo_location_area_id *lai, uint16_t cell_id);
struct sgsn_ra_cell *sgsn_ra_get_cell_by_cgi(const struct osmo_cell_global_id *cgi);
struct sgsn_ra_cell *sgsn_ra_get_cell_by_ra(const struct sgsn_ra *ra, uint16_t cell_id);
struct sgsn_ra_cell *sgsn_ra_get_cell_by_gb(uint16_t nsei, uint16_t bvci);
struct sgsn_ra *sgsn_ra_get_ra(const struct osmo_routing_area_id *ra_id);


/*
 * return value for callbacks.
 * STOP: stop calling the callback for the remaining cells, sgsn_ra_foreach_ra() returns 0
 * CONT: continue to call the callback for remaining cells
 * ABORT: stop calling the callback for the remaining cells, sgsn_ra_foreach_ra() returns -1
 */
#define SGSN_RA_CB_STOP 1
#define SGSN_RA_CB_CONT 0
#define SGSN_RA_CB_ERROR -1

typedef int (sgsn_ra_cb_t)(struct sgsn_ra_cell *ra_cell, void *cb_data);
int sgsn_ra_foreach_cell(struct sgsn_ra *ra, sgsn_ra_cb_t *cb, void *cb_data);
int sgsn_ra_foreach_cell2(struct osmo_routing_area_id *rai, sgsn_ra_cb_t *cb, void *cb_data);
