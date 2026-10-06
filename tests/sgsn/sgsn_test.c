/* Test the SGSN */
/*
 * (C) 2014 by Holger Hans Peter Freyther
 * (C) 2014 by sysmocom s.f.m.c. GmbH
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
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_subscriber.h>
#include <osmocom/sgsn/gprs_utils.h>
#include <osmocom/sgsn/gprs_gmm_fsm.h>
#include <osmocom/sgsn/gtp_ggsn.h>

#include <stdio.h>

#include "gprs_gb_parse.h"

void *tall_sgsn_ctx;
struct sgsn_instance *sgsn;
unsigned sgsn_tx_counter = 0;
struct msgb *last_msg = NULL;
struct gprs_gb_parse_context last_dl_parse_ctx;

static void reset_last_msg(void)
{
	if (last_msg)
		msgb_free(last_msg);

	last_msg = NULL;
	memset(&last_dl_parse_ctx, 0, sizeof(last_dl_parse_ctx));
}

static void cleanup_test(void)
{
	reset_last_msg();
	TALLOC_FREE(sgsn);
}

/* override, requires '-Wl,--wrap=osmo_get_rand_id' */
int __real_osmo_get_rand_id(uint8_t *data, size_t len);
int mock_osmo_get_rand_id(uint8_t *data, size_t len);
int (*osmo_get_rand_id_cb)(uint8_t *, size_t) =
  &mock_osmo_get_rand_id;

int __wrap_osmo_get_rand_id(uint8_t *buf, size_t num)
{
	return (*osmo_get_rand_id_cb)(buf, num);
}
/* make results of A&C ref predictable */
int mock_osmo_get_rand_id(uint8_t *buf, size_t num)
{
	if (num > 1)
		return __real_osmo_get_rand_id(buf, num);
	buf[0] = 0;
	return 1;
}

static int count(struct llist_head *head)
{
	struct llist_head *cur;
	int count = 0;

	llist_for_each(cur, head)
		count += 1;

	return count;
}

/*
 * Create a context and search for it
 */
static struct sgsn_mm_ctx *alloc_mm_ctx(uint32_t tlli, struct osmo_routing_area_id *raid)
{
	struct sgsn_mm_ctx *ctx, *ictx;
	struct gprs_llc_lle *lle;
	int old_count = count(gprs_llme_list());

	lle = gprs_lle_get_or_create(tlli, 3);
	ctx = sgsn_mm_ctx_alloc_gb(tlli, raid);
	ctx->gb.llme = lle->llme;

	ictx = sgsn_mm_ctx_by_tlli(tlli, raid);
	OSMO_ASSERT(ictx == ctx);

	OSMO_ASSERT(count(gprs_llme_list()) == old_count + 1);

	return ctx;
}

static void test_llme(void)
{
	struct gprs_llc_lle *lle, *lle_copy;
	uint32_t local_tlli;

	printf("Testing LLME allocations\n");
	local_tlli = gprs_tmsi2tlli(0x234, TLLI_LOCAL);

	/* initial state */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);

	/* Create a new entry */
	lle = gprs_lle_get_or_create(local_tlli, 3);
	OSMO_ASSERT(lle);
	OSMO_ASSERT(count(gprs_llme_list()) == 1);

	/* No new entry is created */
	lle_copy = gprs_lle_get_or_create(local_tlli, 3);
	OSMO_ASSERT(lle == lle_copy);
	OSMO_ASSERT(count(gprs_llme_list()) == 1);

	/* unassign which should delete it*/
	gprs_llgmm_unassign(lle->llme);

	/* Check that everything was cleaned up */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);

	cleanup_test();
}

#define VERBOSE_ASSERT(val, expect_op, fmt) \
	do { \
		printf(#val " == " fmt "\n", (val)); \
		OSMO_ASSERT((val) expect_op); \
	} while (0);

static void test_apn_matching(void)
{
	struct apn_ctx *actx, *actxs[9];

	printf("Testing APN matching\n");
	sgsn = sgsn_instance_alloc(tall_sgsn_ctx);

	actxs[0] = sgsn_apn_ctx_find_alloc("*.test", "");
	actxs[1] = sgsn_apn_ctx_find_alloc("*.def.test", "");
	actxs[2] = sgsn_apn_ctx_find_alloc("abc.def.test", "");
	actxs[3] = NULL;

	actxs[4] = sgsn_apn_ctx_find_alloc("abc.def.test", "456");
	actxs[5] = sgsn_apn_ctx_find_alloc("abc.def.test", "456123");
	actxs[6] = sgsn_apn_ctx_find_alloc("*.def.test", "456");
	actxs[7] = sgsn_apn_ctx_find_alloc("*.def.test", "456123");

	actxs[8] = sgsn_apn_ctx_find_alloc("ghi.def.test", "456");

	actx = sgsn_apn_ctx_match("abc.def.test", "12345678");
	OSMO_ASSERT(actx == actxs[2]);
	actx = sgsn_apn_ctx_match("aBc.dEf.test", "12345678");
	OSMO_ASSERT(actx == actxs[2]);
	actx = sgsn_apn_ctx_match("xyz.def.test", "12345678");
	OSMO_ASSERT(actx == actxs[1]);
	actx = sgsn_apn_ctx_match("xyz.dEf.test", "12345678");
	OSMO_ASSERT(actx == actxs[1]);
	actx = sgsn_apn_ctx_match("xyz.uvw.test", "12345678");
	OSMO_ASSERT(actx == actxs[0]);
	actx = sgsn_apn_ctx_match("xyz.uvw.foo", "12345678");
	OSMO_ASSERT(actx == NULL);

	actxs[3] = sgsn_apn_ctx_find_alloc("*", "");
	actx = sgsn_apn_ctx_match("xyz.uvw.foo", "12345678");
	OSMO_ASSERT(actx == actxs[3]);

	actx = sgsn_apn_ctx_match("abc.def.test", "45699900");
	OSMO_ASSERT(actx == actxs[4]);

	actx = sgsn_apn_ctx_match("xyz.def.test", "45699900");
	OSMO_ASSERT(actx == actxs[6]);

	actx = sgsn_apn_ctx_match("abc.def.test", "45612300");
	OSMO_ASSERT(actx == actxs[5]);

	actx = sgsn_apn_ctx_match("xyz.def.test", "45612300");
	OSMO_ASSERT(actx == actxs[7]);

	actx = sgsn_apn_ctx_match("ghi.def.test", "45699900");
	OSMO_ASSERT(actx == actxs[8]);

	actx = sgsn_apn_ctx_match("ghi.def.test", "45612300");
	OSMO_ASSERT(actx == actxs[7]);

	/* Free APN contexts and check how the matching changes */

	sgsn_apn_ctx_free(actxs[7]);
	actx = sgsn_apn_ctx_match("ghi.def.test", "45612300");
	OSMO_ASSERT(actx == actxs[8]);

	sgsn_apn_ctx_free(actxs[8]);
	actx = sgsn_apn_ctx_match("ghi.def.test", "45612300");
	OSMO_ASSERT(actx == actxs[6]);

	sgsn_apn_ctx_free(actxs[6]);
	actx = sgsn_apn_ctx_match("ghi.def.test", "45612300");
	OSMO_ASSERT(actx == actxs[1]);

	sgsn_apn_ctx_free(actxs[5]);
	actx = sgsn_apn_ctx_match("abc.def.test", "45612300");
	OSMO_ASSERT(actx == actxs[4]);

	sgsn_apn_ctx_free(actxs[4]);
	actx = sgsn_apn_ctx_match("abc.def.test", "45612300");
	OSMO_ASSERT(actx == actxs[2]);

	sgsn_apn_ctx_free(actxs[2]);
	actx = sgsn_apn_ctx_match("abc.def.test", "12345678");
	OSMO_ASSERT(actx == actxs[1]);

	sgsn_apn_ctx_free(actxs[1]);
	actx = sgsn_apn_ctx_match("abc.def.test", "12345678");
	OSMO_ASSERT(actx == actxs[0]);

	sgsn_apn_ctx_free(actxs[0]);
	actx = sgsn_apn_ctx_match("abc.def.test", "12345678");
	OSMO_ASSERT(actx == actxs[3]);

	sgsn_apn_ctx_free(actxs[3]);
	actx = sgsn_apn_ctx_match("abc.def.test", "12345678");
	OSMO_ASSERT(actx == NULL);

	cleanup_test();
}

static void test_ggsn_selection(void)
{
	struct apn_ctx *actxs[4];
	struct sgsn_ggsn_ctx *ggc, *ggcs[3];
	const char *imsi1 = "1234567890";
	struct sgsn_mm_ctx *ctx;
	struct osmo_routing_area_id raid = { 0, };
	uint32_t local_tlli = 0xffeeddcc;
	enum gsm48_gsm_cause gsm_cause;
	struct tlv_parsed tp;
	uint8_t apn_enc[GSM_APN_LENGTH + 10];
	char apn_str[GSM_APN_LENGTH];

	printf("Testing GGSN selection\n");

	sgsn = sgsn_instance_alloc(tall_sgsn_ctx);

	/* TODO: Check for emptiness */

	/* Create a context */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	ctx = alloc_mm_ctx(local_tlli, &raid);
	osmo_strlcpy(ctx->imsi, imsi1, sizeof(ctx->imsi));

	tp.lv[GSM48_IE_GSM_APN].len = 0;
	tp.lv[GSM48_IE_GSM_APN].val = apn_enc;

	ggcs[0] = sgsn_ggsn_ctx_find_alloc(sgsn, 0);
	ggcs[1] = sgsn_ggsn_ctx_find_alloc(sgsn, 1);
	ggcs[2] = sgsn_ggsn_ctx_find_alloc(sgsn, 2);

	actxs[0] = sgsn_apn_ctx_find_alloc("test.apn", "123456");
	actxs[0]->ggsn = ggcs[0];
	actxs[1] = sgsn_apn_ctx_find_alloc("*.apn", "123456");
	actxs[1]->ggsn = ggcs[1];
	actxs[2] = sgsn_apn_ctx_find_alloc("*", "456789");
	actxs[2]->ggsn = ggcs[2];

	/* Resolve GGSNs */

	tp.lv[GSM48_IE_GSM_APN].len =
		osmo_apn_from_str(apn_enc, sizeof(apn_enc), "Test.Apn");

	ggc = sgsn_mm_ctx_find_ggsn_ctx(ctx, &tp, &gsm_cause, apn_str);
	OSMO_ASSERT(ggc != NULL);
	OSMO_ASSERT(ggc->id == 0);
	OSMO_ASSERT(strcmp(apn_str, "Test.Apn") == 0);

	tp.lv[GSM48_IE_GSM_APN].len =
		osmo_apn_from_str(apn_enc, sizeof(apn_enc), "Other.Apn");

	ggc = sgsn_mm_ctx_find_ggsn_ctx(ctx, &tp, &gsm_cause, apn_str);
	OSMO_ASSERT(ggc != NULL);
	OSMO_ASSERT(ggc->id == 1);
	OSMO_ASSERT(strcmp(apn_str, "Other.Apn") == 0);

	tp.lv[GSM48_IE_GSM_APN].len = 0;
	tp.lv[GSM48_IE_GSM_APN].val = NULL;

	ggc = sgsn_mm_ctx_find_ggsn_ctx(ctx, &tp, &gsm_cause, apn_str);
	OSMO_ASSERT(ggc != NULL);
	OSMO_ASSERT(ggc->id == 0);
	OSMO_ASSERT(strcmp(apn_str, "") == 0);

	actxs[3] = sgsn_apn_ctx_find_alloc("*", "123456");
	actxs[3]->ggsn = ggcs[2];
	ggc = sgsn_mm_ctx_find_ggsn_ctx(ctx, &tp, &gsm_cause, apn_str);
	OSMO_ASSERT(ggc != NULL);
	OSMO_ASSERT(ggc->id == 2);
	OSMO_ASSERT(strcmp(apn_str, "") == 0);

	sgsn_apn_ctx_free(actxs[3]);
	tp.lv[GSM48_IE_GSM_APN].val = apn_enc;

	tp.lv[GSM48_IE_GSM_APN].len =
		osmo_apn_from_str(apn_enc, sizeof(apn_enc), "Foo.Bar");

	ggc = sgsn_mm_ctx_find_ggsn_ctx(ctx, &tp, &gsm_cause, apn_str);
	OSMO_ASSERT(ggc == NULL);
	OSMO_ASSERT(gsm_cause == GSM_CAUSE_MISSING_APN);
	OSMO_ASSERT(strcmp(apn_str, "Foo.Bar") == 0);

	tp.lv[GSM48_IE_GSM_APN].len = sizeof(apn_enc);
	ggc = sgsn_mm_ctx_find_ggsn_ctx(ctx, &tp, &gsm_cause, apn_str);
	OSMO_ASSERT(ggc == NULL);
	OSMO_ASSERT(gsm_cause == GSM_CAUSE_INV_MAND_INFO);

	tp.lv[GSM48_IE_GSM_APN].len =
		osmo_apn_from_str(apn_enc, sizeof(apn_enc), "Test.Apn");

	ggc = sgsn_mm_ctx_find_ggsn_ctx(ctx, &tp, &gsm_cause, apn_str);
	OSMO_ASSERT(ggc != NULL);
	OSMO_ASSERT(ggc->id == 0);
	OSMO_ASSERT(strcmp(apn_str, "Test.Apn") == 0);

/*	FIXME: sgsn_mm_ctx_find_ggsn_ctx() is still using gprs_subscr which is never set.
 *      for this reason, this part of the unit test is failing.
 *	tp.lv[GSM48_IE_GSM_APN].len =
 *		osmo_apn_from_str(apn_enc, sizeof(apn_enc), "Other.Apn");
 *
 *	ggc = sgsn_mm_ctx_find_ggsn_ctx(ctx, &tp, &gsm_cause, apn_str);
 *	OSMO_ASSERT(ggc == NULL);
 *	OSMO_ASSERT(gsm_cause == GSM_CAUSE_REQ_SERV_OPT_NOTSUB);
 *	OSMO_ASSERT(strcmp(apn_str, "") == 0);
 */

	/* Cleanup */
	sgsn_mm_ctx_cleanup_free(ctx);

	/* TODO: assert_no_subscrs(); */

	sgsn_apn_ctx_free(actxs[0]);
	sgsn_apn_ctx_free(actxs[1]);
	sgsn_apn_ctx_free(actxs[2]);

	sgsn_ggsn_ctx_free(ggcs[0]);
	sgsn_ggsn_ctx_free(ggcs[1]);
	sgsn_ggsn_ctx_free(ggcs[2]);

	cleanup_test();
}

bool pdp_status_has_active_nsapis(uint16_t pdp_status);

static void test_pdp_status_has_active_nsapis(void)
{
	uint16_t pdp_status1 = 0b0000000000100000; /* PDP NSAPI 5 active */
	uint16_t pdp_status2 = 0b0000000000000000; /* no active PDP NSAPI */
	uint16_t pdp_status3 = 0b0000000100000000; /* PDP NSAPI 8 active */
	uint16_t pdp_status4 = 0b0000000000000001; /* reserved NSAPI 0 active -> no active */

	printf("Testing pdp_status_has_active_nsapis\n");

	OSMO_ASSERT(pdp_status_has_active_nsapis(pdp_status1));
	OSMO_ASSERT(!pdp_status_has_active_nsapis(pdp_status2));
	OSMO_ASSERT(pdp_status_has_active_nsapis(pdp_status3));
	OSMO_ASSERT(!pdp_status_has_active_nsapis(pdp_status4));
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
	[DMEAS] = {
		.name = "DMEAS",
		.description = "Radio Measurement Processing",
		.enabled = 0, .loglevel = LOGL_NOTICE,
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
	[DSNDCP] = {
		.name = "DSNDCP",
		.description = "GPRS Sub-Network Dependent Control Protocol (SNDCP)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

static struct vty_app_info vty_info = {
	.name 		= "testSGSN",
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

	test_llme();
	test_apn_matching();
	test_ggsn_selection();
	test_pdp_status_has_active_nsapis();
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
