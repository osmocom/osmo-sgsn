/*! \file gprs_routing_area.h */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm23003.h>

/* rai -> struct osmo_routing_area_id * */
#define LOGRAI(level, rai, fmt, args...) \
	do {\
		char __log_rai_buf[32]; \
		LOGP(DRA, level, "RA(%s) " fmt, \
		     osmo_rai_name2_buf(__log_rai_buf, sizeof(__log_rai_buf), rai), \
		     ## args); \
	} while (0)

/* ra -> struct sgsn_ra * */
#define LOGRA(level, ra, fmt, args...) \
	LOGRAI(level, (&(ra)->rai), fmt, ## args)

struct sgsn_instance;
struct sgsn_mm_ctx;

struct sgsn_ra_global {
	/* list of struct sgsn_ra */
	struct llist_head ra_list;
};

enum sgsn_ra_ran_type {
	RA_TYPE_GERAN_Gb,
	RA_TYPE_UTRAN_Iu,
};

extern const struct value_string sgsn_ra_ran_type_names[];

struct sgsn_ra {
	/* Entry in sgsn_ra_global->ra_list */
	struct llist_head list;

	struct osmo_routing_area_id rai;

	/* For GERAN: every PCU is connected to the SGSN. It allows the SGSN to know every single cell.
	 * For routing, the SGSN must know to which PCU a given cell is connected.
	 * It is possible that more than one PCU serves the same Routing Area.
	 *
	 * For UTRAN: only the RNC (HNB via HNBGW) is communicating with the SGSN.
	 * The SGSN doesn't know every cell, because they aren't accepted individually by the SGSN.
	 * The SGSN only "knows" RAI/SAI if they have been used. In the future it would be a good idea to
	 * allow configuring RA in the vty/config as well.
	 * Similar to the GERAN Cell, but iu_client doesn't notify us for every given SAI, only for RAC.
	 * Further the SGSN doesn't get informed about Service Area and can't relate the SAI to a given UE.
	 * For UTRAN only do a LAC/RAC <> RNC relation and don't have a specific cell relation.
	 */
	enum sgsn_ra_ran_type ran_type;
	union {
		struct {
			/* the RNC id must be the same for a given Routing Area */
			struct osmo_rnc_id rnc_id;
		} utran;
	} u;

	/* GERAN/UTRAN: cells contains a list of sgsn_ra_cells which are alive */
	struct llist_head cells_alive_list;
};

struct sgsn_ra_cell {
	/* Entry in sgsn_ra->cells */
	struct llist_head list;

	/*! link back to the parent */
	struct sgsn_ra *ra;

	enum sgsn_ra_ran_type ran_type;
	union {
		struct {
			uint16_t nsei;
			uint16_t bvci;
			uint16_t cell_id;
		} geran;

		struct {
			/* the RNC id must be the same for a given Routing Area */
			uint16_t sac;
		} utran;
	} u;
};

void sgsn_ra_init(struct sgsn_instance *inst);

struct sgsn_ra *sgsn_ra_alloc(const struct osmo_routing_area_id *rai, enum sgsn_ra_ran_type ran_type);
struct sgsn_ra *sgsn_ra_find_or_create(const struct osmo_routing_area_id *rai, enum sgsn_ra_ran_type ran_type);
struct sgsn_ra *sgsn_ra_get_ra(const struct osmo_routing_area_id *rai);
void sgsn_ra_free(struct sgsn_ra *ra);
struct sgsn_ra_cell *sgsn_ra_cell_alloc_geran(struct sgsn_ra *ra, uint16_t cell_id, uint16_t nsei, uint16_t bvci);
void sgsn_ra_cell_free(struct sgsn_ra_cell *cell);

/* GERAN */
/* Called by BSSGP layer to inform about a reset on a PtP BVCI */
int sgsn_ra_geran_bvc_cell_reset_ind(uint16_t nsei, uint16_t bvci, struct osmo_cell_global_id_ps *cgi_ps);
/* Called by BSSGP layer to inform about a reset on a Signal BVCI */
void sgsn_ra_geran_bvc_sign_reset_ind(uint16_t nsei);
/* FIXME: handle BVC BLOCK/UNBLOCK/UNAVAILABLE */
/* Called by NS-VC layer to inform about an unavailable NSEI (and all BVCI on them) */
int sgsn_ra_geran_nsei_failure_ind(uint16_t nsei);

struct sgsn_ra_cell *sgsn_ra_geran_get_cell_by_cgi_ps(const struct osmo_cell_global_id_ps *cgi_ps);
struct sgsn_ra_cell *sgsn_ra_geran_get_cell_by_lai(const struct osmo_location_area_id *lai, uint16_t cell_id);
struct sgsn_ra_cell *sgsn_ra_geran_get_cell_by_cgi(const struct osmo_cell_global_id *cgi);
struct sgsn_ra_cell *sgsn_ra_geran_get_cell_by_ra(const struct sgsn_ra *ra, uint16_t cell_id);
struct sgsn_ra_cell *sgsn_ra_geran_get_cell_by_gb(uint16_t nsei, uint16_t bvci);

/* UTRAN */
int sgsn_ra_utran_register(const struct osmo_routing_area_id *rai, const struct osmo_rnc_id *rnc_id);

struct sgsn_ra *sgsn_ra_geran_get_ra(const struct osmo_routing_area_id *rai);

/* Page the whole routing area for this mmctx */
int sgsn_ra_geran_page_ra(const struct osmo_routing_area_id *rai, struct sgsn_mm_ctx *mmctx);
struct sgsn_ra *sgsn_ra_utran_get_ra(const struct osmo_routing_area_id *rai);

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

/* Page the whole routing area for this mmctx */
int sgsn_ra_utran_page_ra(const struct osmo_routing_area_id *rai, const struct sgsn_mm_ctx *mmctx);
