/* Test the SGSN routing ares */
/*
 * (C) 2024 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 * Author: Alexander Couzens <lynxis@fe80.eu>
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

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/vty/vty.h>

#include <osmocom/gsupclient/gsup_client.h>

#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_routing_area.h>

#include <stdio.h>


void *tall_sgsn_ctx;
struct sgsn_instance *sgsn;

static void cleanup_test(void)
{
	TALLOC_FREE(sgsn);
}

/* Create RA, free RA */
static void test_routing_area_create(void)
{
	struct sgsn_ra *ra;
	struct osmo_routing_area_id raid = {
		.lac = {
			.plmn = { .mcc = 262, .mnc = 42, .mnc_3_digits = false },
			.lac = 23
		},
		.rac = 42
	};

	printf("Testing Routing Area create/free\n");

	sgsn = sgsn_instance_alloc(tall_sgsn_ctx);
	ra = sgsn_ra_alloc(&raid);
	OSMO_ASSERT(ra);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);

	sgsn_ra_free(ra);
	OSMO_ASSERT(llist_empty(&sgsn->routing_area->ra_list));

	/* Cleanup */
	cleanup_test();
}

static void test_routing_area_free_empty(void)
{

	struct sgsn_ra *ra;
	struct sgsn_ra_cell *cell_a;
	struct osmo_routing_area_id raid = {
		.lac = {
			.plmn = { .mcc = 262, .mnc = 42, .mnc_3_digits = false },
			.lac = 24
		},
		.rac = 43
	};

	uint16_t cell_id = 9999;
	uint16_t nsei = 2, bvci = 3;

	printf("Testing Routing Area create/free\n");

	sgsn = sgsn_instance_alloc(tall_sgsn_ctx);
	ra = sgsn_ra_alloc(&raid);
	OSMO_ASSERT(ra);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);

	cell_a = sgsn_ra_cell_alloc_geran(ra, cell_id, nsei, bvci);
	OSMO_ASSERT(cell_a);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);
	OSMO_ASSERT(llist_count(&ra->cells) == 1);

	sgsn_ra_free(ra);
	OSMO_ASSERT(llist_empty(&sgsn->routing_area->ra_list));

	ra = sgsn_ra_alloc(&raid);
	OSMO_ASSERT(ra);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);

	cell_a = sgsn_ra_cell_alloc_geran(ra, cell_id, nsei, bvci);
	OSMO_ASSERT(cell_a);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);
	OSMO_ASSERT(llist_count(&ra->cells) == 1);

	sgsn_ra_free(ra);
	OSMO_ASSERT(llist_empty(&sgsn->routing_area->ra_list));

	cleanup_test();
}

/* Create RA, use different find functiosn, free RA */
static void test_routing_area_find(void)
{
	struct sgsn_ra *ra_a, *ra_b;
	struct sgsn_ra_cell *cell_a, *cell_b;
	struct osmo_routing_area_id ra_id = {
		.lac = {
			.plmn = { .mcc = 262, .mnc = 42, .mnc_3_digits = false },
			.lac = 24
		},
		.rac = 43
	};

	uint16_t cell_id = 9999, cell_id_not_found = 44;
	struct osmo_cell_global_id_ps cgi_ps = {
		.rai = ra_id,
		.cell_identity = cell_id,
	};
	struct osmo_cell_global_id cgi = {
		.lai = ra_id.lac,
		.cell_identity = cell_id
	};

	uint16_t nsei = 2, bvci = 3;

	printf("Testing Routing Area find\n");

	sgsn = sgsn_instance_alloc(tall_sgsn_ctx);
	ra_a = sgsn_ra_alloc(&ra_id);
	OSMO_ASSERT(ra_a);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);

	ra_b = sgsn_ra_get_ra(&ra_id);
	OSMO_ASSERT(ra_a == ra_b);

	cell_a = sgsn_ra_cell_alloc_geran(ra_a, cell_id, nsei, bvci);
	OSMO_ASSERT(cell_a);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);

	cell_b = sgsn_ra_get_cell_by_cgi_ps(&cgi_ps);
	OSMO_ASSERT(cell_b);
	OSMO_ASSERT(cell_b == cell_a);

	cell_b = sgsn_ra_get_cell_by_ra(ra_a, cgi.cell_identity);
	OSMO_ASSERT(cell_b);
	OSMO_ASSERT(cell_b == cell_a);

	cell_b = sgsn_ra_get_cell_by_cgi(&cgi);
	OSMO_ASSERT(cell_b);
	OSMO_ASSERT(cell_b == cell_a);

	cell_b = sgsn_ra_get_cell_by_lai(&cgi.lai, cgi.cell_identity);
	OSMO_ASSERT(cell_b);
	OSMO_ASSERT(cell_b == cell_a);

	sgsn_ra_free(ra_a);
	OSMO_ASSERT(llist_empty(&sgsn->routing_area->ra_list));

	/* try to search for a cell id which isn't present */
	cgi.cell_identity = cell_id_not_found;
	cgi_ps.cell_identity = cell_id_not_found;

	ra_a = sgsn_ra_alloc(&ra_id);
	OSMO_ASSERT(ra_a);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);

	cell_a = sgsn_ra_cell_alloc_geran(ra_a, cell_id, nsei, bvci);
	OSMO_ASSERT(cell_a);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);

	cell_b = sgsn_ra_get_cell_by_cgi_ps(&cgi_ps);
	OSMO_ASSERT(!cell_b);

	cell_b = sgsn_ra_get_cell_by_ra(ra_a, cgi_ps.cell_identity);
	OSMO_ASSERT(!cell_b);

	cell_b = sgsn_ra_get_cell_by_cgi(&cgi);
	OSMO_ASSERT(!cell_b);

	cell_b = sgsn_ra_get_cell_by_lai(&cgi.lai, cgi.cell_identity);
	OSMO_ASSERT(!cell_b);

	/* try to find for a different RAC */
	cgi_ps.rai.rac = 45;
	ra_id.rac = 46;

	cell_b = sgsn_ra_get_cell_by_cgi_ps(&cgi_ps);
	OSMO_ASSERT(!cell_b);

	ra_b = sgsn_ra_get_ra(&ra_id);
	OSMO_ASSERT(!ra_b);

	/* try to find for different LAC */
	cgi.lai.lac = 46;
	cell_b = sgsn_ra_get_cell_by_cgi(&cgi);
	OSMO_ASSERT(!cell_b);

	sgsn_ra_free(ra_a);
	OSMO_ASSERT(llist_empty(&sgsn->routing_area->ra_list));

	cleanup_test();
}

static void test_routing_area_reset_ind(void)
{
	struct sgsn_ra *ra_a;
	struct sgsn_ra_cell *cell_a, *cell_b;
	struct osmo_routing_area_id ra_id = {
		.lac = {
			.plmn = { .mcc = 262, .mnc = 42, .mnc_3_digits = false },
			.lac = 24
		},
		.rac = 43
	};

	uint16_t cell_id = 9999;
	struct osmo_cell_global_id_ps cgi_ps = {
		.rai = ra_id,
		.cell_identity = cell_id,
	};
	struct osmo_cell_global_id cgi = {
		.lai = ra_id.lac,
		.cell_identity = cell_id
	};

	uint16_t nsei = 2, bvci = 3;
	int rc;

	printf("Testing Routing Area BSSGP BVC RESET IND\n");

	sgsn = sgsn_instance_alloc(tall_sgsn_ctx);
	ra_a = sgsn_ra_alloc(&ra_id);
	OSMO_ASSERT(ra_a);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);
	OSMO_ASSERT(llist_count(&ra_a->cells) == 0);

	rc = sgsn_ra_bvc_reset_ind(nsei, bvci, &cgi_ps);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(llist_count(&ra_a->cells) == 1);

	cell_a = sgsn_ra_get_cell_by_cgi(&cgi);
	OSMO_ASSERT(cell_a);

	rc = sgsn_ra_bvc_reset_ind(nsei, bvci, &cgi_ps);
	OSMO_ASSERT(rc == 0);

	cell_b = sgsn_ra_get_cell_by_cgi(&cgi);
	OSMO_ASSERT(cell_b);
	OSMO_ASSERT(cell_a == cell_b);

	sgsn_ra_free(ra_a);
	OSMO_ASSERT(llist_empty(&sgsn->routing_area->ra_list));

	rc = sgsn_ra_bvc_reset_ind(nsei, bvci, &cgi_ps);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(llist_count(&sgsn->routing_area->ra_list) == 1);

	ra_a = sgsn_ra_get_ra(&cgi_ps.rai);
	sgsn_ra_free(ra_a);
	OSMO_ASSERT(llist_empty(&sgsn->routing_area->ra_list));

	cleanup_test();
}

void test_routing_area_nsei_free(void)
{
	struct sgsn_ra *ra_a;
	struct osmo_routing_area_id ra_id = {
		.lac = {
			.plmn = { .mcc = 262, .mnc = 42, .mnc_3_digits = false },
			.lac = 24
		},
		.rac = 43
	};

	uint16_t cell_id = 9999;
	struct osmo_cell_global_id_ps cgi_ps = {
		.rai = ra_id,
		.cell_identity = cell_id,
	};

	uint16_t nsei = 2, bvci = 3;
	int rc;

	printf("Testing Routing Area nsei failure\n");

	sgsn = sgsn_instance_alloc(tall_sgsn_ctx);

	rc = sgsn_ra_bvc_reset_ind(nsei, bvci, &cgi_ps);
	OSMO_ASSERT(rc == 0);

	ra_a = sgsn_ra_get_ra(&cgi_ps.rai);
	OSMO_ASSERT(llist_count(&ra_a->cells) == 1);

	rc = sgsn_ra_nsei_failure_ind(nsei);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(llist_empty(&sgsn->routing_area->ra_list));

	rc = sgsn_ra_nsei_failure_ind(nsei);
	OSMO_ASSERT(rc == -ENOENT);
	OSMO_ASSERT(llist_empty(&sgsn->routing_area->ra_list));

	cleanup_test();
}

static struct log_info_cat gprs_categories[] = {
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DPAG]	= {
		.name = "DPAG",
		.description = "Paging Subsystem",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DLLC] = {
		.name = "DLLC",
		.description = "GPRS Logical Link Control Protocol (LLC)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DRA] = {
		.name = "DRA",
		.description = "Routing Area",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

static struct vty_app_info vty_info = {
	.name = "testSGSN",
};

int main(int argc, char **argv)
{
	void *osmo_sgsn_ctx;
	void *msgb_ctx;

	osmo_sgsn_ctx = talloc_named_const(NULL, 0, "osmo_sgsn");
	osmo_init_logging2(osmo_sgsn_ctx, &info);
	tall_sgsn_ctx = talloc_named_const(osmo_sgsn_ctx, 0, "sgsn");
	msgb_ctx = msgb_talloc_ctx_init(osmo_sgsn_ctx, 0);

	vty_init(&vty_info);

	test_routing_area_create();
	test_routing_area_find();
	test_routing_area_free_empty();
	test_routing_area_reset_ind();
	test_routing_area_nsei_free();
	printf("Done\n");

	talloc_report_full(osmo_sgsn_ctx, stderr);
	OSMO_ASSERT(talloc_total_blocks(msgb_ctx) == 1);
	OSMO_ASSERT(talloc_total_blocks(tall_sgsn_ctx) == 1);
	return 0;
}


/* stubs */
struct osmo_prim_hdr;
int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	abort();
}
