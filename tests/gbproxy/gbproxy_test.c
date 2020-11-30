/* test routines for gbproxy
 * send NS messages to the gbproxy and dumps what happens
 * (C) 2013-2020 by sysmocom s.f.m.c. GmbH
 * Author: Jacob Erlbeck <jerlbeck@sysmocom.de>
 */
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/core/prim.h>
#include <osmocom/vty/command.h>
#include <osmocom/sgsn/gb_proxy.h>
#include <osmocom/sgsn/gprs_utils.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_gb_parse.h>
#include <osmocom/sgsn/debug.h>

#define REMOTE_BSS_ADDR 0x01020304
#define REMOTE_SGSN_ADDR 0x05060708

#define SGSN_NSEI 0x0100

#define REMOTE_SGSN2_ADDR 0x15161718
#define SGSN2_NSEI 0x0102

#define MATCH_ANY (-1)

void *tall_sgsn_ctx = NULL;

struct gbproxy_config gbcfg = {0};

struct llist_head *received_messages = NULL;

/* override, requires '-Wl,--wrap=osmo_get_rand_id' */
int __real_osmo_get_rand_id(uint8_t *data, size_t len);
int mock_osmo_get_rand_id(uint8_t *data, size_t len);
int (*osmo_get_rand_id_cb)(uint8_t *, size_t) =
  &mock_osmo_get_rand_id;

int __wrap_osmo_get_rand_id(uint8_t *buf, size_t num)
{
	return (*osmo_get_rand_id_cb)(buf, num);
}

static int rand_seq_num = 0;
int mock_osmo_get_rand_id(uint8_t *buf, size_t num)
{
	uint32_t val;

	OSMO_ASSERT(num == sizeof(val));

	val = 0x00dead00 + rand_seq_num;

	rand_seq_num++;

	memcpy(buf, &val, num);

	return 1;
}

static void cleanup_test()
{
	rand_seq_num = 0;
}

static int dump_global(FILE *stream, int indent)
{
	unsigned int i;
	const struct rate_ctr_group_desc *desc;
	int rc;

	rc = fprintf(stream, "%*sGbproxy global:\n", indent, "");
	if (rc < 0)
		return rc;

	desc = gbcfg.ctrg->desc;

	for (i = 0; i < desc->num_ctr; i++) {
		struct rate_ctr *ctr = &gbcfg.ctrg->ctr[i];
		if (ctr->current) {
			rc = fprintf(stream, "%*s    %s: %llu\n",
				     indent, "",
				     desc->ctr_desc[i].description,
				     (long long)ctr->current);

			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

static int dump_peers(FILE *stream, int indent, time_t now,
		      struct gbproxy_config *cfg)
{
	struct gbproxy_peer *peer;
	struct gprs_ra_id raid;
	unsigned int i;
	const struct rate_ctr_group_desc *desc;
	int rc;

	rc = fprintf(stream, "%*sPeers:\n", indent, "");
	if (rc < 0)
		return rc;

	llist_for_each_entry(peer, &cfg->bts_peers, list) {
		struct gbproxy_link_info *link_info;
		struct gbproxy_patch_state *state = &peer->patch_state;
		gsm48_parse_ra(&raid, peer->ra);

		rc = fprintf(stream, "%*s  NSEI %u, BVCI %u, %sblocked, RAI %s\n",
			     indent, "",
			     peer->nsei, peer->bvci,
			     peer->blocked ? "" : "not ",
			     osmo_rai_name(&raid));

		if (rc < 0)
			return rc;

		desc = peer->ctrg->desc;

		for (i = 0; i < desc->num_ctr; i++) {
			struct rate_ctr *ctr = &peer->ctrg->ctr[i];
			if (ctr->current) {
				rc = fprintf(stream, "%*s    %s: %llu\n",
					     indent, "",
					     desc->ctr_desc[i].description,
					     (long long)ctr->current);

				if (rc < 0)
					return rc;
			}
		}

		fprintf(stream, "%*s    TLLI-Cache: %d\n",
			indent, "", state->logical_link_count);
		llist_for_each_entry(link_info, &state->logical_links, list) {
			struct osmo_mobile_identity mi;
			const char *imsi_str;
			time_t age = now ? now - link_info->timestamp : 0;
			int stored_msgs = 0;
			struct llist_head *iter;
			enum gbproxy_match_id match_id;
			llist_for_each(iter, &link_info->stored_msgs)
				stored_msgs++;

			if (link_info->imsi > 0) {
				if (osmo_mobile_identity_decode(&mi, link_info->imsi, link_info->imsi_len, false)
				    || mi.type != GSM_MI_TYPE_IMSI)
					imsi_str = "(invalid)";
				else
					imsi_str = mi.imsi;
			} else {
				imsi_str = "(none)";
			}
			fprintf(stream, "%*s      TLLI %08x",
				     indent, "", link_info->tlli.current);
			if (link_info->tlli.assigned)
				fprintf(stream, "/%08x", link_info->tlli.assigned);
			if (link_info->sgsn_tlli.current) {
				fprintf(stream, " -> %08x",
					link_info->sgsn_tlli.current);
				if (link_info->sgsn_tlli.assigned)
					fprintf(stream, "/%08x",
						link_info->sgsn_tlli.assigned);
			}
			fprintf(stream, ", IMSI %s, AGE %d",
				imsi_str, (int)age);

			if (stored_msgs)
				fprintf(stream, ", STORED %d", stored_msgs);

			for (match_id = 0; match_id < ARRAY_SIZE(cfg->matches);
			     ++match_id) {
				if (cfg->matches[match_id].enable &&
				    link_info->is_matching[match_id]) {
					fprintf(stream, ", IMSI matches");
					break;
				}
			}

			if (link_info->imsi_acq_pending)
				fprintf(stream, ", IMSI acquisition in progress");

			if (cfg->route_to_sgsn2)
				fprintf(stream, ", SGSN NSEI %d",
					link_info->sgsn_nsei);

			if (link_info->is_deregistered)
				fprintf(stream, ", DE-REGISTERED");

			rc = fprintf(stream, "\n");
			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

const uint8_t *convert_ra(struct gprs_ra_id *raid)
{
	static struct gsm48_ra_id r;
	gsm48_encode_ra(&r, raid);
	return (const uint8_t *)&r;
}

/* DTAP - Attach Request */
static const unsigned char dtap_attach_req[] = {
	0x08, 0x01, 0x02, 0xf5, 0xe0, 0x21, 0x08, 0x02,
	0x05, 0xf4, 0xfb, 0xc5, 0x46, 0x79, 0x11, 0x22,
	0x33, 0x40, 0x50, 0x60, 0x19, 0x18, 0xb3, 0x43,
	0x2b, 0x25, 0x96, 0x62, 0x00, 0x60, 0x80, 0x9a,
	0xc2, 0xc6, 0x62, 0x00, 0x60, 0x80, 0xba, 0xc8,
	0xc6, 0x62, 0x00, 0x60, 0x80, 0x00,
};

/* DTAP - Attach Request (invalid RAI) */
static const unsigned char dtap_attach_req2[] = {
	0x08, 0x01, 0x02, 0xf5, 0xe0, 0x21, 0x08, 0x02,
	0x05, 0xf4, 0xfb, 0x00, 0xbe, 0xef, 0x99, 0x99,
	0x99, 0x40, 0x50, 0x60, 0x19, 0x18, 0xb3, 0x43,
	0x2b, 0x25, 0x96, 0x62, 0x00, 0x60, 0x80, 0x9a,
	0xc2, 0xc6, 0x62, 0x00, 0x60, 0x80, 0xba, 0xc8,
	0xc6, 0x62, 0x00, 0x60, 0x80, 0x00,
};

/* DTAP - Attach Request (P-TMSI 0x3f32b700) */
static const unsigned char dtap_attach_req3[] = {
	0x08, 0x01, 0x02, 0xf5, 0xe0, 0x21, 0x08, 0x02,
	0x05, 0xf4, 0xef, 0xe2, 0xb7, 0x00, 0x11, 0x22,
	0x33, 0x40, 0x50, 0x60, 0x19, 0x18, 0xb3, 0x43,
	0x2b, 0x25, 0x96, 0x62, 0x00, 0x60, 0x80, 0x9a,
	0xc2, 0xc6, 0x62, 0x00, 0x60, 0x80, 0xba, 0xc8,
	0xc6, 0x62, 0x00, 0x60, 0x80, 0x00,
};

/* DTAP - Attach Request (IMSI 12131415161718) */
static const unsigned char dtap_attach_req4[] = {
	0x08, 0x01, 0x02, 0xf5, 0xe0, 0x21, 0x08, 0x02,
	0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0xf8, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60, 0x19,
	0x18, 0xb3, 0x43, 0x2b, 0x25, 0x96, 0x62, 0x00,
	0x60, 0x80, 0x9a, 0xc2, 0xc6, 0x62, 0x00, 0x60,
	0x80, 0xba, 0xc8, 0xc6, 0x62, 0x00, 0x60, 0x80,
	0x00,
};

/* DTAP - Identity Request */
static const unsigned char dtap_identity_req[] = {
	0x08, 0x15, 0x01
};

/* DTAP - Identity Response */
static const unsigned char dtap_identity_resp[] = {
	0x08, 0x16, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0xf8
};

/* DTAP - Identity Response, IMSI 2 */
static const unsigned char dtap_identity2_resp[] = {
	0x08, 0x16, 0x08, 0x11, 0x12, 0x99, 0x99, 0x99,
	0x16, 0x17, 0xf8
};

/* DTAP - Identity Response, IMSI 3 */
static const unsigned char dtap_identity3_resp[] = {
	0x08, 0x16, 0x08, 0x11, 0x12, 0x99, 0x99, 0x99,
	0x26, 0x27, 0xf8
};

/* DTAP - Attach Accept */
static const unsigned char dtap_attach_acc[] = {
	0x08, 0x02, 0x01, 0x49, 0x04, 0x21, 0x63, 0x54,
	0x40, 0x50, 0x60, 0x19, 0xcd, 0xd7, 0x08, 0x17,
	0x16, 0x18, 0x05, 0xf4, 0xef, 0xe2, 0xb7, 0x00
};

/* DTAP - Attach Accept, P-TMSI 2 */
static const unsigned char dtap_attach_acc2[] = {
	0x08, 0x02, 0x01, 0x49, 0x04, 0x21, 0x63, 0x54,
	0x40, 0x50, 0x60, 0x19, 0xcd, 0xd7, 0x08, 0x17,
	0x16, 0x18, 0x05, 0xf4, 0xe0, 0x98, 0x76, 0x54
};

/* DTAP - Attach Complete */
static const unsigned char dtap_attach_complete[] = {
	0x08, 0x03
};

/* DTAP - Attach Reject (GPRS services not allowed) */
static const unsigned char dtap_attach_rej7[] = {
	0x08, 0x04, 0x07
};

/* DTAP - GMM Information */
static const unsigned char dtap_gmm_information[] = {
	0x08, 0x21
};

/* DTAP - Routing Area Update Request */
static const unsigned char dtap_ra_upd_req[] = {
	0x08, 0x08, 0x10, 0x11, 0x22, 0x33, 0x40, 0x50,
	0x60, 0x1d, 0x19, 0x13, 0x42, 0x33, 0x57, 0x2b,
	0xf7, 0xc8, 0x48, 0x02, 0x13, 0x48, 0x50, 0xc8,
	0x48, 0x02, 0x14, 0x48, 0x50, 0xc8, 0x48, 0x02,
	0x17, 0x49, 0x10, 0xc8, 0x48, 0x02, 0x00, 0x19,
	0x8b, 0xb2, 0x92, 0x17, 0x16, 0x27, 0x07, 0x04,
	0x31, 0x02, 0xe5, 0xe0, 0x32, 0x02, 0x20, 0x00
};

/* DTAP - Routing Area Update Accept */
static const unsigned char dtap_ra_upd_acc[] = {
	0x08, 0x09, 0x00, 0x49, 0x21, 0x63, 0x54,
	0x40, 0x50, 0x60, 0x19, 0x54, 0xab, 0xb3, 0x18,
	0x05, 0xf4, 0xef, 0xe2, 0xb7, 0x00, 0x17, 0x16,
};

/* DTAP - Routing Area Update Accept, P-TMSI 2 */
static const unsigned char dtap_ra_upd_acc2[] = {
	0x08, 0x09, 0x00, 0x49, 0x21, 0x63, 0x54,
	0x40, 0x50, 0x60, 0x19, 0x54, 0xab, 0xb3, 0x18,
	0x05, 0xf4, 0xe0, 0x98, 0x76, 0x54, 0x17, 0x16,
};

/* DTAP - Routing Area Update Accept, P-TMSI 3 */
static const unsigned char dtap_ra_upd_acc3[] = {
	0x08, 0x09, 0x00, 0x49, 0x21, 0x63, 0x54,
	0x40, 0x50, 0x60, 0x19, 0x54, 0xab, 0xb3, 0x18,
	0x05, 0xf4, 0xe0, 0x54, 0x32, 0x10, 0x17, 0x16,
};

/* DTAP - Routing Area Update Complete */
static const unsigned char dtap_ra_upd_complete[] = {
	0x08, 0x0a
};

/* DTAP - Routing Area Update Reject */
/* cause = 10 ("Implicitly detached"), force_standby = 0 */
static const unsigned char dtap_ra_upd_rej[] = {
	0x08, 0x0b, 0x0a, 0x00,
};

/* DTAP - Activate PDP Context Request */
static const unsigned char dtap_act_pdp_ctx_req[] = {
	0x0a, 0x41, 0x05, 0x03, 0x0c, 0x00,
	0x00, 0x1f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x02, 0x01, 0x21, 0x28, 0x03,
	0x02, 0x61, 0x62, 0x27, 0x14, 0x80, 0x80, 0x21,
	0x10, 0x01, 0x00, 0x00, 0x10, 0x81, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x83, 0x06, 0x00, 0x00, 0x00,
	0x00
};

/* DTAP - Detach Request (MO) */
/* normal detach, power_off = 1 */
static const unsigned char dtap_detach_po_req[] = {
	0x08, 0x05, 0x09, 0x18, 0x05, 0xf4, 0xef, 0xe2,
	0xb7, 0x00, 0x19, 0x03, 0xb9, 0x97, 0xcb
};

/* DTAP - Detach Request (MO) */
/* normal detach, power_off = 0 */
static const unsigned char dtap_detach_req[] = {
	0x08, 0x05, 0x01, 0x18, 0x05, 0xf4, 0xef, 0xe2,
	0xb7, 0x00, 0x19, 0x03, 0xb9, 0x97, 0xcb
};

/* DTAP - Detach Accept (MO) */
static const unsigned char dtap_detach_acc[] = {
	0x08, 0x06, 0x00
};

/* DTAP - Detach Request (MT) */
/* normal detach, reattach required, implicitly detached */
static const unsigned char dtap_mt_detach_rea_req[] = {
	0x08, 0x05, 0x01, 0x25, 0x0a
};

/* DTAP - Detach Request (MT) */
/* normal detach, reattach not required, implicitly detached */
static const unsigned char dtap_mt_detach_req[] = {
	0x08, 0x05, 0x02, 0x25, 0x0a
};

/* DTAP - Detach Accept (MT) */
static const unsigned char dtap_mt_detach_acc[] = {
	0x08, 0x06
};

/* GPRS-LLC - SAPI: LLGMM, U, XID */
static const unsigned char llc_u_xid_ul[] = {
	0x41, 0xfb, 0x01, 0x00, 0x0e, 0x00, 0x64, 0x11,
	0x05, 0x16, 0x01, 0x90, 0x66, 0xb3, 0x28
};

/* GPRS-LLC - SAPI: LLGMM, U, XID */
static const unsigned char llc_u_xid_dl[] = {
	0x41, 0xfb, 0x30, 0x84, 0x10, 0x61, 0xb6, 0x64,
	0xe4, 0xa9, 0x1a, 0x9e
};

/* GPRS-LLC - SAPI: LL11, UI, NSAPI 5, DNS query */
static const unsigned char llc_ui_ll11_dns_query_ul[] = {
	0x0b, 0xc0, 0x01, 0x65, 0x00, 0x00, 0x00, 0x45,
	0x00, 0x00, 0x38, 0x95, 0x72, 0x00, 0x00, 0x45,
	0x11, 0x20, 0x85, 0x0a, 0xc0, 0x07, 0xe4, 0xac,
	0x10, 0x01, 0x0a, 0xad, 0xab, 0x00, 0x35, 0x00,
	0x24, 0x0e, 0x1c, 0x3b, 0xe0, 0x01, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x6d, 0x05, 0x68, 0x65, 0x69, 0x73, 0x65, 0x02,
	0x64, 0x65, 0x00, 0x00, 0x01, 0x00, 0x01, 0x47,
	0x8f, 0x07
};

/* GPRS-LLC - SAPI: LL11, UI, NSAPI 5, DNS query */
static const unsigned char llc_ui_ll11_dns_resp_dl[] = {
	0x4b, 0xc0, 0x01, 0x65, 0x00, 0x00, 0x00, 0x45,
	0x00, 0x00, 0xc6, 0x00, 0x00, 0x40, 0x00, 0x3e,
	0x11, 0x7c, 0x69, 0xac, 0x10, 0x01, 0x0a, 0x0a,
	0xc0, 0x07, 0xe4, 0x00, 0x35, 0xad, 0xab, 0x00,
	0xb2, 0x74, 0x4e, 0x3b, 0xe0, 0x81, 0x80, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x01,
	0x6d, 0x05, 0x68, 0x65, 0x69, 0x73, 0x65, 0x02,
	0x64, 0x65, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
	0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e,
	0x10, 0x00, 0x04, 0xc1, 0x63, 0x90, 0x58, 0xc0,
	0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0e,
	0x10, 0x00, 0x16, 0x03, 0x6e, 0x73, 0x32, 0x0c,
	0x70, 0x6f, 0x70, 0x2d, 0x68, 0x61, 0x6e, 0x6e,
	0x6f, 0x76, 0x65, 0x72, 0x03, 0x6e, 0x65, 0x74,
	0x00, 0xc0, 0x0e, 0x00, 0x02, 0x00, 0x01, 0x00,
	0x00, 0x0e, 0x10, 0x00, 0x10, 0x02, 0x6e, 0x73,
	0x01, 0x73, 0x08, 0x70, 0x6c, 0x75, 0x73, 0x6c,
	0x69, 0x6e, 0x65, 0xc0, 0x14, 0xc0, 0x0e, 0x00,
	0x02, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00,
	0x05, 0x02, 0x6e, 0x73, 0xc0, 0x0e, 0xc0, 0x0e,
	0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10,
	0x00, 0x05, 0x02, 0x6e, 0x73, 0xc0, 0x5f, 0xc0,
	0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0e,
	0x10, 0x00, 0x12, 0x02, 0x6e, 0x73, 0x0c, 0x70,
	0x6f, 0x70, 0x2d, 0x68, 0x61, 0x6e, 0x6e, 0x6f,
	0x76, 0x65, 0x72, 0xc0, 0x14, 0xaa, 0xdf, 0x31
};

#define NS_ALLOC_HEADROOM	128
#define NS_ALLOC_SIZE	3072
static int gprs_ns2_callback(struct osmo_prim_hdr *oph, void *ctx);
static void send_ns_unitdata(struct gprs_ns2_inst *nsi, const char *text,
			     uint16_t nsei, uint16_t nsbvci,
			     const unsigned char *bssgp_msg, size_t bssgp_msg_size)
{
	struct msgb *msg;
	struct osmo_gprs_ns2_prim nsp = {};
	nsp.nsei = nsei;
	nsp.bvci = nsbvci;
	//nsp.u.unitdata.change

	if (bssgp_msg_size > NS_ALLOC_SIZE - NS_ALLOC_HEADROOM) {
		fprintf(stderr, "message too long: %zu\n", bssgp_msg_size);
		return;
	}

	msg = msgb_alloc_headroom(NS_ALLOC_SIZE, NS_ALLOC_HEADROOM,
					       "GPRS/NS");
	OSMO_ASSERT(msg);
	memmove(msg->data, bssgp_msg, bssgp_msg_size);
	msgb_bssgph(msg) = msg->data;
	msg->l2h = msg->data;
	msg->l3h = msg->data;
	msgb_put(msg, bssgp_msg_size);

	printf("PROCESSING %s from NSEI %d\n%s\n\n",
	       text, nsei,
	       osmo_hexdump(bssgp_msg, bssgp_msg_size));


	//gprs_process_message(nsi, text ? text : "UNITDATA", nsei, msg, bssgp_msg_size + 4);
	osmo_prim_init(&nsp.oph, SAP_NS, PRIM_NS_UNIT_DATA,
			PRIM_OP_INDICATION, msg);

	gprs_ns2_callback(&nsp.oph, &gbcfg);
}
static int gbprox_test_bssgp_send_cb(void *ctx, struct msgb *msg);

/* wrap */
int gprs_ns2_recv_prim(struct gprs_ns2_inst *nsi, struct osmo_prim_hdr *oph)
{
	struct osmo_gprs_ns2_prim *nsp;

	if (oph->sap != SAP_NS)
		return 0;

	nsp = container_of(oph, struct osmo_gprs_ns2_prim, oph);

	if (oph->operation != PRIM_OP_REQUEST) {
		LOGP(DPCU, LOGL_NOTICE, "NS: %s Unknown prim %d from NS\n",
		     get_value_string(osmo_prim_op_names, oph->operation),
		     oph->operation);
		return 0;
	}

	switch (oph->primitive) {
	case PRIM_NS_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		msgb_bssgph(oph->msg) = oph->msg->l3h;
		msgb_bvci(oph->msg) = nsp->bvci;
		msgb_nsei(oph->msg) = nsp->nsei;
		printf("NS2 UD REQUEST, prim %d, msg length %zu, bvci 0x%04x\n%s\n\n",
			oph->primitive, msgb_bssgp_len(oph->msg), nsp->bvci,
			osmo_hexdump(msgb_l3(oph->msg), msgb_l3len(oph->msg)));
		return gbprox_test_bssgp_send_cb(&gbcfg, oph->msg);
		break;
	default:
		printf("NS2 REQUEST, prim %d, bvci 0x%04x\n\n",
			oph->primitive, nsp->bvci);

		break;
	}
	return 0;
}

static void send_bssgp_ul_unitdata(
	struct gprs_ns2_inst *nsi, const char *text,
	uint16_t nsei, uint16_t nsbvci, uint32_t tlli,
	struct gprs_ra_id *raid, uint16_t cell_id,
	const uint8_t *llc_msg, size_t llc_msg_size)
{
	/* GPRS Network Service, PDU type: NS_UNITDATA */
	/* Base Station Subsystem GPRS Protocol: UL_UNITDATA */
	unsigned char msg[4096] = {
		0x01, /* TLLI */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
		0x08, 0x88, /* RAI */ 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
		/* CELL ID */ 0x00, 0x00, 0x00, 0x80, 0x0e, /* LLC LEN */ 0x00, 0x00,
	};

	size_t bssgp_msg_size = 23 + llc_msg_size;

	OSMO_ASSERT(bssgp_msg_size <= sizeof(msg));

	gsm48_encode_ra((struct gsm48_ra_id *)(msg + 10), raid);
	msg[1] = (uint8_t)(tlli >> 24);
	msg[2] = (uint8_t)(tlli >> 16);
	msg[3] = (uint8_t)(tlli >> 8);
	msg[4] = (uint8_t)(tlli >> 0);
	msg[16] = cell_id / 256;
	msg[17] = cell_id % 256;
	msg[21] = llc_msg_size / 256;
	msg[22] = llc_msg_size % 256;
	memcpy(msg + 23, llc_msg, llc_msg_size);

	send_ns_unitdata(nsi, text ? text : "BSSGP UL UNITDATA",
			 nsei, nsbvci, msg, bssgp_msg_size);
}

static void send_bssgp_dl_unitdata(
	struct gprs_ns2_inst *nsi, const char *text,
	uint16_t nsei, uint16_t nsbvci, uint32_t tlli,
	int with_racap_drx, const uint8_t *imsi, size_t imsi_size,
	const uint8_t *llc_msg, size_t llc_msg_size)
{
	/* Base Station Subsystem GPRS Protocol: DL_UNITDATA */
	unsigned char msg[4096] = {
		0x00, /* TLLI */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x20,
		0x16, 0x82, 0x02, 0x58,
	};
	unsigned char racap_drx[] = {
		0x13, 0x99, 0x18, 0xb3, 0x43, 0x2b, 0x25, 0x96,
		0x62, 0x00, 0x60, 0x80, 0x9a, 0xc2, 0xc6, 0x62,
		0x00, 0x60, 0x80, 0xba, 0xc8, 0xc6, 0x62, 0x00,
		0x60, 0x80, 0x00, 0x0a, 0x82, 0x08, 0x02
	};

	size_t bssgp_msg_size = 0;

	OSMO_ASSERT(51 + imsi_size + llc_msg_size <= sizeof(msg));

	msg[1] = (uint8_t)(tlli >> 24);
	msg[2] = (uint8_t)(tlli >> 16);
	msg[3] = (uint8_t)(tlli >> 8);
	msg[4] = (uint8_t)(tlli >> 0);

	bssgp_msg_size = 12;

	if (with_racap_drx) {
		memcpy(msg + bssgp_msg_size, racap_drx, sizeof(racap_drx));
		bssgp_msg_size += sizeof(racap_drx);
	}

	if (imsi) {
		OSMO_ASSERT(imsi_size <= 127);
		msg[bssgp_msg_size] = BSSGP_IE_IMSI;
		msg[bssgp_msg_size + 1] = 0x80 | imsi_size;
		memcpy(msg + bssgp_msg_size + 2, imsi, imsi_size);
		bssgp_msg_size += 2 + imsi_size;
	}

	if ((bssgp_msg_size % 4) != 0) {
		size_t abytes = (4 - (bssgp_msg_size + 2) % 4) % 4;
		msg[bssgp_msg_size] = BSSGP_IE_ALIGNMENT;
		msg[bssgp_msg_size + 1] = 0x80 | abytes;
		memset(msg + bssgp_msg_size + 2, 0, abytes);
		bssgp_msg_size += 2 + abytes;
	}

	msg[bssgp_msg_size] = BSSGP_IE_LLC_PDU;
	if (llc_msg_size < 128) {
		msg[bssgp_msg_size + 1] = 0x80 | llc_msg_size;
		bssgp_msg_size += 2;
	} else {
		msg[bssgp_msg_size + 1] = llc_msg_size / 256;
		msg[bssgp_msg_size + 2] = llc_msg_size % 256;
		bssgp_msg_size += 3;
	}
	memcpy(msg + bssgp_msg_size, llc_msg, llc_msg_size);
	bssgp_msg_size += llc_msg_size;


	send_ns_unitdata(nsi, text ? text : "BSSGP DL UNITDATA",
			 nsei, nsbvci, msg, bssgp_msg_size);
}

static void send_bssgp_reset(struct gprs_ns2_inst *nsi,
			     uint16_t nsei, uint16_t bvci)
{
	/* GPRS Network Service, PDU type: NS_UNITDATA, BVCI 0
	 * BSSGP RESET */
	unsigned char msg[18] = {
		0x22, 0x04, 0x82, 0x4a,
		0x2e, 0x07, 0x81, 0x08, 0x08, 0x88, 0x11, 0x22,
		0x33, 0x40, 0x50, 0x60, 0x10, 0x00
	};

	msg[3] = bvci / 256;
	msg[4] = bvci % 256;

	send_ns_unitdata(nsi, "BVC_RESET", nsei, 0, msg, sizeof(msg));
}

static void send_bssgp_reset_ack(struct gprs_ns2_inst *nsi,
				 uint16_t nsei, uint16_t bvci)
{
	/* GPRS Network Service, PDU type: NS_UNITDATA, BVCI 0
	 * BSSGP RESET_ACK */
	static unsigned char msg[5] = {
		0x23, 0x04, 0x82, 0x00,
		0x00
	};

	msg[3] = bvci / 256;
	msg[4] = bvci % 256;

	send_ns_unitdata(nsi, "BVC_RESET_ACK", nsei, 0, msg, sizeof(msg));
}

static void send_bssgp_suspend(struct gprs_ns2_inst *nsi,
			       uint16_t nsei,
			       uint32_t tlli,
			       struct gprs_ra_id *raid)
{
	/* Base Station Subsystem GPRS Protocol, BSSGP SUSPEND */
	unsigned char msg[15] = {
		0x0b, 0x1f, 0x84, /* TLLI */ 0xff, 0xff, 0xff, 0xff, 0x1b,
		0x86, /* RAI */ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	msg[3] = (uint8_t)(tlli >> 24);
	msg[4] = (uint8_t)(tlli >> 16);
	msg[5] = (uint8_t)(tlli >> 8);
	msg[6] = (uint8_t)(tlli >> 0);

	gsm48_encode_ra((struct gsm48_ra_id *)(msg + 9), raid);

	send_ns_unitdata(nsi, "BVC_SUSPEND", nsei, 0, msg, sizeof(msg));
}

static void send_bssgp_suspend_ack(struct gprs_ns2_inst *nsi,
				   uint16_t nsei,
				   uint32_t tlli,
				   struct gprs_ra_id *raid)
{
	/* Base Station Subsystem GPRS Protocol, BSSGP SUSPEND ACK */
	unsigned char msg[18] = {
		0x0c, 0x1f, 0x84, /* TLLI */ 0xff, 0xff, 0xff, 0xff, 0x1b,
		0x86, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1d,
		0x81, 0x01
	};

	msg[3] = (uint8_t)(tlli >> 24);
	msg[4] = (uint8_t)(tlli >> 16);
	msg[5] = (uint8_t)(tlli >> 8);
	msg[6] = (uint8_t)(tlli >> 0);

	gsm48_encode_ra((struct gsm48_ra_id *)(msg + 9), raid);

	send_ns_unitdata(nsi, "BVC_SUSPEND_ACK", nsei, 0, msg, sizeof(msg));
}

static void send_bssgp_llc_discarded(struct gprs_ns2_inst *nsi,
				     uint16_t nsei,
				     uint16_t bvci, uint32_t tlli,
				     unsigned n_frames, unsigned n_octets)
{
	/* Base Station Subsystem GPRS Protocol: LLC-DISCARDED (0x2c) */
	unsigned char msg[] = {
		0x2c, 0x1f, 0x84, /* TLLI */ 0xff, 0xff, 0xff, 0xff, 0x0f,
		0x81, /* n frames */ 0xff, 0x04, 0x82, /* BVCI */ 0xff, 0xff, 0x25, 0x83,
		/* n octets */ 0xff, 0xff, 0xff
	};

	msg[3] = (uint8_t)(tlli >> 24);
	msg[4] = (uint8_t)(tlli >> 16);
	msg[5] = (uint8_t)(tlli >> 8);
	msg[6] = (uint8_t)(tlli >> 0);
	msg[9] = (uint8_t)(n_frames);
	msg[12] = (uint8_t)(bvci >> 8);
	msg[13] = (uint8_t)(bvci >> 0);
	msg[16] = (uint8_t)(n_octets >> 16);
	msg[17] = (uint8_t)(n_octets >> 8);
	msg[18] = (uint8_t)(n_octets >> 0);

	send_ns_unitdata(nsi, "LLC_DISCARDED", nsei, 0, msg, sizeof(msg));
}

static void send_bssgp_paging(struct gprs_ns2_inst *nsi,
			      uint16_t nsei,
			      const uint8_t *imsi, size_t imsi_size,
			      struct gprs_ra_id *raid, uint32_t ptmsi)
{
	/* Base Station Subsystem GPRS Protocol, BSSGP SUSPEND */
	unsigned char msg[100] = {
		0x06,
	};

	const unsigned char drx_ie[] = {0x0a, 0x82, 0x07, 0x04};
	const unsigned char qos_ie[] = {0x18, 0x83, 0x00, 0x00, 0x00};

	size_t bssgp_msg_size = 1;

	if (imsi) {
		OSMO_ASSERT(imsi_size <= 127);
		msg[bssgp_msg_size] = BSSGP_IE_IMSI;
		msg[bssgp_msg_size + 1] = 0x80 | imsi_size;
		memcpy(msg + bssgp_msg_size + 2, imsi, imsi_size);
		bssgp_msg_size += 2 + imsi_size;
	}

	memcpy(msg + bssgp_msg_size, drx_ie, sizeof(drx_ie));
	bssgp_msg_size += sizeof(drx_ie);

	if (raid) {
		msg[bssgp_msg_size] = BSSGP_IE_ROUTEING_AREA;
		msg[bssgp_msg_size+1] = 0x86;
		gsm48_encode_ra((struct gsm48_ra_id *)(msg + bssgp_msg_size + 2), raid);
		bssgp_msg_size += 8;
	}

	memcpy(msg + bssgp_msg_size, qos_ie, sizeof(qos_ie));
	bssgp_msg_size += sizeof(qos_ie);

	if (ptmsi != GSM_RESERVED_TMSI) {
		const uint32_t ptmsi_be = htonl(ptmsi);
		msg[bssgp_msg_size] = BSSGP_IE_TMSI;
		msg[bssgp_msg_size+1] = 0x84;
		memcpy(msg + bssgp_msg_size + 2, &ptmsi_be, 4);
		bssgp_msg_size += 6;
	}

	send_ns_unitdata(nsi, "PAGING_PS", nsei, 0, msg, bssgp_msg_size);
}

static void send_bssgp_flow_control_bvc(struct gprs_ns2_inst *nsi,
					uint16_t nsei,
					uint16_t bvci, uint8_t tag)
{
	/* GPRS Network Service, PDU type: NS_UNITDATA,
	 * BSSGP FLOW_CONTROL_BVC */
	unsigned char msg[] = {
		0x26, 0x1e, 0x81, /* Tag */ 0xff, 0x05, 0x82, 0x01, 0xdc,
		0x03, 0x82, 0x02, 0x76, 0x01, 0x82, 0x00, 0x50,
		0x1c, 0x82, 0x02, 0x58, 0x06, 0x82, 0x00, 0x03
	};

	msg[3] = tag;

	send_ns_unitdata(nsi, "FLOW_CONTROL_BVC", nsei, bvci,
			 msg, sizeof(msg));
}

static void send_bssgp_flow_control_bvc_ack(struct gprs_ns2_inst *nsi,
					    uint16_t nsei,
					    uint16_t bvci, uint8_t tag)
{
	/* GPRS Network Service, PDU type: NS_UNITDATA,
	 * BSSGP FLOW_CONTROL_BVC_ACK */
	unsigned char msg[] = {
		0x27, 0x1e, 0x81, /* Tag */ 0xce
	};

	msg[3] = tag;

	send_ns_unitdata(nsi, "FLOW_CONTROL_BVC_ACK", nsei, bvci,
			 msg, sizeof(msg));
}

static void send_llc_ul_ui(
	struct gprs_ns2_inst *nsi, const char *text,
	uint16_t nsei, uint16_t nsbvci, uint32_t tlli,
	struct gprs_ra_id *raid, uint16_t cell_id,
	unsigned sapi, unsigned nu,
	const uint8_t *msg, size_t msg_size)
{
	unsigned char llc_msg[4096] = {
		0x00, 0xc0, 0x01
	};

	size_t llc_msg_size = 3 + msg_size + 3;
	uint8_t e_bit = 0;
	uint8_t pm_bit = 1;
	unsigned fcs;

	nu &= 0x01ff;

	OSMO_ASSERT(llc_msg_size <= sizeof(llc_msg));

	llc_msg[0] = (sapi & 0x0f);
	llc_msg[1] = 0xc0 | (nu >> 6); /* UI frame */
	llc_msg[2] = (nu << 2) | ((e_bit & 1) << 1) | (pm_bit & 1);

	memcpy(llc_msg + 3, msg, msg_size);

	fcs = gprs_llc_fcs(llc_msg, msg_size + 3);
	llc_msg[3 + msg_size + 0] = (uint8_t)(fcs >> 0);
	llc_msg[3 + msg_size + 1] = (uint8_t)(fcs >> 8);
	llc_msg[3 + msg_size + 2] = (uint8_t)(fcs >> 16);

	send_bssgp_ul_unitdata(nsi, text ? text : "LLC UI",
			       nsei, nsbvci, tlli, raid, cell_id,
			       llc_msg, llc_msg_size);
}

static void send_llc_dl_ui(
	struct gprs_ns2_inst *nsi, const char *text,
	uint16_t nsei, uint16_t nsbvci, uint32_t tlli,
	int with_racap_drx, const uint8_t *imsi, size_t imsi_size,
	unsigned sapi, unsigned nu,
	const uint8_t *msg, size_t msg_size)
{
	/* GPRS Network Service, PDU type: NS_UNITDATA */
	/* Base Station Subsystem GPRS Protocol: UL_UNITDATA */
	unsigned char llc_msg[4096] = {
		0x00, 0x00, 0x01
	};

	size_t llc_msg_size = 3 + msg_size + 3;
	uint8_t e_bit = 0;
	uint8_t pm_bit = 1;
	unsigned fcs;

	nu &= 0x01ff;

	OSMO_ASSERT(llc_msg_size <= sizeof(llc_msg));

	llc_msg[0] = 0x40 | (sapi & 0x0f);
	llc_msg[1] = 0xc0 | (nu >> 6); /* UI frame */
	llc_msg[2] = (nu << 2) | ((e_bit & 1) << 1) | (pm_bit & 1);

	memcpy(llc_msg + 3, msg, msg_size);

	fcs = gprs_llc_fcs(llc_msg, msg_size + 3);
	llc_msg[3 + msg_size + 0] = (uint8_t)(fcs >> 0);
	llc_msg[3 + msg_size + 1] = (uint8_t)(fcs >> 8);
	llc_msg[3 + msg_size + 2] = (uint8_t)(fcs >> 16);

	send_bssgp_dl_unitdata(nsi, text ? text : "LLC UI",
			       nsei, nsbvci, tlli,
			       with_racap_drx, imsi, imsi_size,
			       llc_msg, llc_msg_size);
}


/* STATUS indications */
static void send_ns_avail(struct gprs_ns2_inst *nsi,
			  uint16_t sgsn_nsei)
{
	struct osmo_gprs_ns2_prim nsp = {};
	nsp.nsei = sgsn_nsei;
	nsp.bvci = 0;
	nsp.u.status.cause = NS_AFF_CAUSE_RECOVERY;
	nsp.u.status.transfer = -1;
	nsp.u.status.first = true;
	osmo_prim_init(&nsp.oph, SAP_NS, PRIM_NS_STATUS,
			PRIM_OP_INDICATION, NULL);

	gprs_ns2_callback(&nsp.oph, &gbcfg);
}

static void setup_ns(struct gprs_ns2_inst *nsi,
		     uint16_t nsei)
{
	printf("Setup NS-VC: "
	       "NSEI 0x%04x(%d)\n\n",
	       nsei, nsei);
	send_ns_avail(nsi, nsei);
}

static void setup_bssgp(struct gprs_ns2_inst *nsi,
		     uint16_t nsei, uint16_t bvci)
{
	printf("Setup BSSGP: "
	       "BVCI 0x%04x(%d)\n\n",
	       bvci, bvci);

	send_bssgp_reset(nsi, nsei, bvci);
}

static void connect_sgsn(struct gprs_ns2_inst *nsi,
			 uint32_t sgsn_nsei)
{
	send_ns_avail(nsi, sgsn_nsei);
}

/* Function used to send a BSSGP message through NS */
static int gbprox_test_bssgp_send_cb(void *ctx, struct msgb *msg)
{
	int rc;
	struct gbproxy_config *cfg = (struct gbproxy_config *) ctx;

	uint16_t nsei = msgb_nsei(msg);
	uint16_t bvci = msgb_bvci(msg);

	if (received_messages) {
		struct msgb *msg_copy;
		msg_copy = bssgp_msgb_copy(msg, "received_messages");
		llist_add_tail(&msg_copy->list, received_messages);
	}

	if (nsei == cfg->nsip_sgsn_nsei)
		printf("Message for SGSN");
	else if (nsei == cfg->nsip_sgsn2_nsei)
		printf("Message for SGSN2");
	else
		printf("Message for BSS");
	printf(" (NSEI=%d BVCI=%d):\n%s\n\n", nsei, bvci, msgb_hexdump(msg));

	rc = msgb_length(msg);
	msgb_free(msg);

	return rc;
}

static void gprs_ns2_test_prim_status_cb(struct gbproxy_config *cfg, struct osmo_gprs_ns2_prim *nsp)
{
	enum gprs_ns2_affecting_cause cause = nsp->u.status.cause;

	switch (cause) {
		case NS_AFF_CAUSE_RECOVERY:
			LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d became available\n", nsp->nsei);
			break;
		case NS_AFF_CAUSE_FAILURE:
			LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d became unavailable\n", nsp->nsei);
			break;
		case NS_AFF_CAUSE_VC_RECOVERY:
			LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d NS-VC %s became available\n", nsp->nsei, nsp->u.status.nsvc);
			break;
		case NS_AFF_CAUSE_VC_FAILURE:
			LOGP(DPCU, LOGL_NOTICE, "NS-NSE %d NS-VC %s became unavailable\n", nsp->nsei, nsp->u.status.nsvc);
			break;
		default:
			LOGP(DPCU, LOGL_NOTICE, "Unhandled status %d (NS-NSE %d)\n", cause, nsp->nsei);
			break;
	}
}

int gprs_ns2_prim_cb(struct osmo_prim_hdr *oph, void *ctx);

/* override */
static int gprs_ns2_callback(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_gprs_ns2_prim *nsp;
	struct gbproxy_config *cfg = (struct gbproxy_config *) ctx;

	if (oph->sap != SAP_NS)
		return 0;

	nsp = container_of(oph, struct osmo_gprs_ns2_prim, oph);

	if (oph->operation != PRIM_OP_INDICATION) {
		LOGP(DPCU, LOGL_NOTICE, "NS: %s Unknown prim %d from NS\n",
		     get_value_string(osmo_prim_op_names, oph->operation),
		     oph->operation);
		return 0;
	}

	switch (oph->primitive) {
	case PRIM_NS_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		msgb_bssgph(oph->msg) = oph->msg->l3h;
		msgb_bvci(oph->msg) = nsp->bvci;
		msgb_nsei(oph->msg) = nsp->nsei;
		printf("NS2 CALLBACK, prim %d, msg length %zu, bvci 0x%04x\n%s\n\n",
			oph->primitive, msgb_bssgp_len(oph->msg), nsp->bvci,
			osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		break;
	case PRIM_NS_STATUS:
		gprs_ns2_test_prim_status_cb(cfg, nsp);
	default:
		printf("NS2 CALLBACK, prim %d, bvci 0x%04x\n\n",
			oph->primitive, nsp->bvci);

		break;
	}

	/* Hand off to gbproxy which will free the msg */
	return gprs_ns2_prim_cb(oph, ctx);
}

/* Get the next message from the receive FIFO
 *
 * \returns a pointer to the message which will be invalidated at the next call
 *          to expect_msg. Returns NULL, if there is no message left.
 */
static struct msgb *expect_msg(void)
{
	static struct msgb *msg = NULL;

	msgb_free(msg);
	msg = NULL;

	if (!received_messages)
		return NULL;

	if (llist_empty(received_messages))
		return NULL;

	msg = llist_entry(received_messages->next, struct msgb, list);
	llist_del(&msg->list);

	return msg;
}

struct expect_result {
	struct msgb *msg;
	struct gprs_gb_parse_context parse_ctx;
};

static struct expect_result *expect_bssgp_msg(
	int match_nsei, int match_bvci, int match_pdu_type)
{
	static struct expect_result result;
	static const struct expect_result empty_result = {0,};
	static struct msgb *msg;
	uint16_t nsei;
	int rc;

	memcpy(&result, &empty_result, sizeof(result));

	msg = expect_msg();
	if (!msg)
		return NULL;

	nsei = msgb_nsei(msg);

	if (match_nsei != MATCH_ANY && match_nsei != nsei) {
		fprintf(stderr, "%s: NSEI mismatch (expected %u, got %u)\n",
			__func__, match_nsei, nsei);
		return NULL;
	}

	if (match_bvci != MATCH_ANY && match_bvci != msgb_bvci(msg)) {
		fprintf(stderr, "%s: BVCI mismatch (expected %u, got %u)\n",
			__func__, match_bvci, msgb_bvci(msg));
		return NULL;
	}

	result.msg = msg;

	result.parse_ctx.to_bss = nsei != SGSN_NSEI && nsei != SGSN2_NSEI;
	result.parse_ctx.peer_nsei = nsei;

	if (!msgb_bssgph(msg)) {
		fprintf(stderr, "%s: Expected BSSGP\n", __func__);
		return NULL;
	}

	rc = gprs_gb_parse_bssgp(msgb_bssgph(msg), msgb_bssgp_len(msg),
				 &result.parse_ctx);

	if (!rc) {
		fprintf(stderr, "%s: Failed to parse message\n", __func__);
		return NULL;
	}

	if (match_pdu_type != MATCH_ANY &&
	    match_pdu_type != result.parse_ctx.pdu_type) {
		fprintf(stderr, "%s: PDU type mismatch (expected %u, got %u)\n",
			__func__, match_pdu_type, result.parse_ctx.pdu_type);
		return NULL;
	}

	return &result;
}

static struct expect_result *expect_llc_msg(
	int match_nsei, int match_bvci, int match_sapi, int match_type)
{
	static struct expect_result *result;

	result = expect_bssgp_msg(match_nsei, match_bvci, MATCH_ANY);
	if (!result)
		return NULL;

	if (!result->parse_ctx.llc) {
		fprintf(stderr, "%s: Expected LLC message\n", __func__);
		return NULL;
	}

	if (match_sapi != MATCH_ANY &&
	    match_sapi != result->parse_ctx.llc_hdr_parsed.sapi) {
		fprintf(stderr, "%s: LLC SAPI mismatch (expected %u, got %u)\n",
			__func__, match_sapi, result->parse_ctx.llc_hdr_parsed.sapi);
		return NULL;
	}

	if (match_type != MATCH_ANY &&
	    match_type != result->parse_ctx.llc_hdr_parsed.cmd) {
		fprintf(stderr,
			"%s: LLC command/type mismatch (expected %u, got %u)\n",
			__func__, match_type, result->parse_ctx.llc_hdr_parsed.cmd);
		return NULL;
	}

	return result;
}

static struct expect_result *expect_gmm_msg(int match_nsei, int match_bvci,
					    int match_type)
{
	static struct expect_result *result;

	result = expect_llc_msg(match_nsei, match_bvci, GPRS_SAPI_GMM, GPRS_LLC_UI);
	if (!result)
		return NULL;

	if (!result->parse_ctx.g48_hdr) {
		fprintf(stderr, "%s: Expected GSM 04.08 message\n", __func__);
		return NULL;
	}

	if (match_type != MATCH_ANY &&
	    match_type != result->parse_ctx.g48_hdr->msg_type) {
		fprintf(stderr,
			"%s: GSM 04.08 message type mismatch (expected %u, got %u)\n",
			__func__, match_type, result->parse_ctx.g48_hdr->msg_type);
		return NULL;
	}

	return result;
}

static void test_gbproxy()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	uint16_t bss_nsei[2] = {0x1000, 0x2000};

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);
	setup_bssgp(nsi, bss_nsei[0], 0x1002);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	printf("--- Initialise BSS 2 ---\n\n");

	setup_ns(nsi, bss_nsei[1]);
	setup_bssgp(nsi, bss_nsei[1], 0x2002);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x2002);

	printf("--- Reset BSS 1 with a new BVCI ---\n\n");

	setup_bssgp(nsi, bss_nsei[0], 0x1012);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1012);

	printf("--- Reset BSS 1 with the old BVCI ---\n\n");

	setup_bssgp(nsi, bss_nsei[0], 0x1002);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	printf("--- Reset BSS 1 with the old BVCI again ---\n\n");

	setup_bssgp(nsi, bss_nsei[0], 0x1002);
	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1012 ---\n\n");

	send_ns_unitdata(nsi, NULL, bss_nsei[0], 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 1, BVCI 0x1012 ---\n\n");

	send_ns_unitdata(nsi, NULL, SGSN_NSEI, 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	send_ns_unitdata(nsi, NULL, bss_nsei[0], 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 1, BVCI 0x1002 ---\n\n");

	send_ns_unitdata(nsi, NULL, SGSN_NSEI, 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from BSS 2 to SGSN, BVCI 0x2002 ---\n\n");

	send_ns_unitdata(nsi, NULL, bss_nsei[0], 0x2002, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 2, BVCI 0x2002 ---\n\n");

	send_ns_unitdata(nsi, NULL, SGSN_NSEI, 0x2002, (uint8_t *)"", 0);

	printf("--- Reset BSS 1 with the old BVCI on BSS2's link ---\n\n");

	setup_bssgp(nsi, bss_nsei[0], 0x1002);
	dump_peers(stdout, 0, 0, &gbcfg);

	dump_global(stdout, 0);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	send_ns_unitdata(nsi, NULL, bss_nsei[0], 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 1, BVCI 0x1002 ---\n\n");

	send_ns_unitdata(nsi, NULL, SGSN_NSEI, 0x1012, (uint8_t *)"", 0);

	printf("--- Send message from SGSN to BSS 1, BVCI 0x10ff (invalid) ---\n\n");

	send_ns_unitdata(nsi, NULL, SGSN_NSEI, 0x10ff, (uint8_t *)"", 0);

	/* Find peer */
	OSMO_ASSERT(gbproxy_peer_by_bvci(&gbcfg, 0xeeee) == NULL);
	OSMO_ASSERT(gbproxy_peer_by_bvci(&gbcfg, 0x1000) == NULL);
	OSMO_ASSERT(gbproxy_peer_by_bvci(&gbcfg, 0x1012) != NULL);
	OSMO_ASSERT(gbproxy_peer_by_nsei(&gbcfg, 0xeeee) == NULL);
	OSMO_ASSERT(gbproxy_peer_by_nsei(&gbcfg, 0x1012) == NULL);
	OSMO_ASSERT(gbproxy_peer_by_nsei(&gbcfg, 0x1000) != NULL);


	/* Cleanup */
	OSMO_ASSERT(gbproxy_cleanup_peers(&gbcfg, 0, 0) == 0);
	OSMO_ASSERT(gbproxy_cleanup_peers(&gbcfg, 0x1000, 0xeeee) == 0);
	OSMO_ASSERT(gbproxy_cleanup_peers(&gbcfg, 0, 0x1002) == 0);
	OSMO_ASSERT(gbproxy_cleanup_peers(&gbcfg, 0x1000, 0x1012) == 1);
	OSMO_ASSERT(gbproxy_cleanup_peers(&gbcfg, 0x1000, 0x1012) == 0);

	dump_peers(stdout, 0, 0, &gbcfg);

	dump_global(stdout, 0);

	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;
}

static void test_gbproxy_ident_changes()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	uint16_t bss_nsei[2] = {0x1000, 0x2000};
	uint16_t bvci[4] = {0x1002, 0x2002, 0x3002};

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);

	printf("--- Setup BVCI 1 ---\n\n");

	setup_bssgp(nsi, bss_nsei[0], bvci[0]);
	send_bssgp_reset_ack(nsi, SGSN_NSEI, bvci[0]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Setup BVCI 2 ---\n\n");

	setup_bssgp(nsi, bss_nsei[0], bvci[1]);
	send_bssgp_reset_ack(nsi, SGSN_NSEI, bvci[1]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 1 ---\n\n");

	send_ns_unitdata(nsi, NULL, bss_nsei[0], bvci[0], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, SGSN_NSEI, bvci[0], (uint8_t *)"", 0);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 2 ---\n\n");

	send_ns_unitdata(nsi, NULL, bss_nsei[0], bvci[1], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, SGSN_NSEI, bvci[1], (uint8_t *)"", 0);

	printf("--- Change NSEI ---\n\n");

	setup_ns(nsi, bss_nsei[1]);

	printf("--- Setup BVCI 1 ---\n\n");

	setup_bssgp(nsi, bss_nsei[1], bvci[0]);
	send_bssgp_reset_ack(nsi, SGSN_NSEI, bvci[0]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Setup BVCI 3 ---\n\n");

	setup_bssgp(nsi, bss_nsei[1], bvci[2]);
	send_bssgp_reset_ack(nsi, SGSN_NSEI, bvci[2]);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 1 ---\n\n");

	send_ns_unitdata(nsi, NULL, bss_nsei[1], bvci[0], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, SGSN_NSEI, bvci[0], (uint8_t *)"", 0);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 2 "
	       " (should fail) ---\n\n");

	send_ns_unitdata(nsi, NULL, bss_nsei[1], bvci[1], (uint8_t *)"", 0);
	dump_peers(stdout, 0, 0, &gbcfg);
	send_ns_unitdata(nsi, NULL, SGSN_NSEI, bvci[1], (uint8_t *)"", 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN and back, BVCI 3 ---\n\n");

	send_ns_unitdata(nsi, NULL, bss_nsei[0], bvci[2], (uint8_t *)"", 0);
	send_ns_unitdata(nsi, NULL, SGSN_NSEI, bvci[2], (uint8_t *)"", 0);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;
}

static void test_gbproxy_ra_patching()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	struct  gprs_ra_id rai_bss =
		{.mcc = 112, .mnc = 332, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_sgsn =
		{.mcc = 123, .mnc = 456, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_unknown =
		{.mcc = 1, .mnc = 99, .lac = 99, .rac = 96};
	uint16_t cell_id = 0x7530;
	const char *err_msg = NULL;
	const uint32_t ptmsi = 0xefe2b700;
	const uint32_t local_tlli = 0xefe2b700;
	const uint32_t foreign_tlli = 0xbbc54679;
	const uint32_t foreign_tlli2 = 0xbb00beef;
	const uint8_t imsi[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xf8};
	const char *patch_re = "^9898|^121314";
	struct gbproxy_link_info *link_info;
	struct gbproxy_peer *peer;
	LLIST_HEAD(rcv_list);
	struct expect_result *expect_res;

	uint16_t bss_nsei[1] = { 0x1000 };

	OSMO_ASSERT(local_tlli == gprs_tmsi2tlli(ptmsi, TLLI_LOCAL));

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;
	gbcfg.core_plmn = (struct osmo_plmn_id){ .mcc = 123, .mnc = 456 };
	gbcfg.core_apn = talloc_zero_size(tall_sgsn_ctx, 100);
	gbcfg.core_apn_size = gprs_str_to_apn(gbcfg.core_apn, 100, "foo.bar");
	gbcfg.patch_ptmsi = 0;

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	if (gbproxy_set_patch_filter(&gbcfg.matches[GBPROX_MATCH_PATCHING],
				     patch_re, &err_msg) != 0) {
		fprintf(stderr, "Failed to compile RE '%s': %s\n",
			patch_re, err_msg);
		exit(1);
	}


	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);

	received_messages = &rcv_list;

	setup_bssgp(nsi, bss_nsei[0], 0x1002);
	dump_peers(stdout, 0, 0, &gbcfg);

	peer = gbproxy_peer_by_nsei(&gbcfg, 0x1000);
	OSMO_ASSERT(peer != NULL);

	OSMO_ASSERT(expect_bssgp_msg(SGSN_NSEI, 0, BSSGP_PDUT_BVC_RESET));

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	OSMO_ASSERT(expect_bssgp_msg(0x1000, 0, BSSGP_PDUT_BVC_RESET_ACK));

	send_bssgp_suspend(nsi, bss_nsei[0], 0xccd1758b, &rai_bss);

	OSMO_ASSERT(expect_bssgp_msg(SGSN_NSEI, 0, BSSGP_PDUT_SUSPEND));

	send_bssgp_suspend_ack(nsi, SGSN_NSEI, 0xccd1758b, &rai_sgsn);

	OSMO_ASSERT(expect_bssgp_msg(0x1000, 0, BSSGP_PDUT_SUSPEND_ACK));

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(2 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);
	OSMO_ASSERT(1 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_SGSN].current);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 0,
		       dtap_attach_req, sizeof(dtap_attach_req));

	OSMO_ASSERT(4 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);
	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN_NSEI, 0x1002,
		       foreign_tlli, 0, NULL, 0,
		       GPRS_SAPI_GMM, 0,
		       dtap_identity_req, sizeof(dtap_identity_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ID_REQ));

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 3,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ID_RESP));

	OSMO_ASSERT(5 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);
	OSMO_ASSERT(1 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_SGSN].current);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, 1,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	OSMO_ASSERT(2 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_SGSN].current);

	OSMO_ASSERT(gbproxy_peer_by_rai(&gbcfg, convert_ra(&rai_bss)) != NULL);
	OSMO_ASSERT(gbproxy_peer_by_rai(&gbcfg, convert_ra(&rai_sgsn)) == NULL);
	OSMO_ASSERT(gbproxy_peer_by_rai(&gbcfg, convert_ra(&rai_unknown)) == NULL);

	OSMO_ASSERT(gbproxy_peer_by_lai(&gbcfg, convert_ra(&rai_bss)) != NULL);
	OSMO_ASSERT(gbproxy_peer_by_lai(&gbcfg, convert_ra(&rai_sgsn)) == NULL);
	OSMO_ASSERT(gbproxy_peer_by_lai(&gbcfg, convert_ra(&rai_unknown)) == NULL);

	OSMO_ASSERT(gbproxy_peer_by_lac(&gbcfg, convert_ra(&rai_bss)) != NULL);
	OSMO_ASSERT(gbproxy_peer_by_lac(&gbcfg, convert_ra(&rai_sgsn)) != NULL);
	OSMO_ASSERT(gbproxy_peer_by_lac(&gbcfg, convert_ra(&rai_unknown)) == NULL);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->tlli.current != local_tlli);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current != local_tlli);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 4,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	OSMO_ASSERT(6 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->tlli.current != local_tlli);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current != local_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	/* Replace APN (1) */
	send_llc_ul_ui(nsi, "ACT PDP CTX REQ (REPLACE APN)", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 3,
		       dtap_act_pdp_ctx_req, sizeof(dtap_act_pdp_ctx_req));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GSM_ACT_PDP_REQ));

	OSMO_ASSERT(7 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->tlli.current != local_tlli);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current != local_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, 2,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_INFO));

	OSMO_ASSERT(2 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_SGSN].current);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->tlli.current == local_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_tlli);

	/* Replace APN (2) */
	send_llc_ul_ui(nsi, "ACT PDP CTX REQ (REPLACE APN)", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 3,
		       dtap_act_pdp_ctx_req, sizeof(dtap_act_pdp_ctx_req));

	expect_res = expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GSM_ACT_PDP_REQ);
	OSMO_ASSERT(expect_res != NULL);
	OSMO_ASSERT(expect_res->parse_ctx.apn_ie_len == gbcfg.core_apn_size + 2);

	OSMO_ASSERT(8 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);

	gbcfg.core_apn[0] = 0;
	gbcfg.core_apn_size = 0;

	/* Remove APN */
	send_llc_ul_ui(nsi, "ACT PDP CTX REQ (REMOVE APN)", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 3,
		       dtap_act_pdp_ctx_req, sizeof(dtap_act_pdp_ctx_req));

	expect_res = expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GSM_ACT_PDP_REQ);
	OSMO_ASSERT(expect_res != NULL);
	OSMO_ASSERT(expect_res->parse_ctx.apn_ie_len == 0);

	OSMO_ASSERT(9 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach */
	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 6,
		       dtap_detach_req, sizeof(dtap_detach_req));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	OSMO_ASSERT(10 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);
	OSMO_ASSERT(2 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_SGSN].current);

	send_llc_dl_ui(nsi, "DETACH ACC", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, 5,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- RA update ---\n\n");

	send_llc_ul_ui(nsi, "RA UPD REQ", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, 0x7080,
		       GPRS_SAPI_GMM, 5,
		       dtap_ra_upd_req, sizeof(dtap_ra_upd_req));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_RA_UPD_REQ));

	OSMO_ASSERT(12 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);

	send_llc_dl_ui(nsi, "RA UPD ACC", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, 6,
		       dtap_ra_upd_acc, sizeof(dtap_ra_upd_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_RA_UPD_ACK));

	OSMO_ASSERT(3 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_SGSN].current);

	/* Remove APN */
	send_llc_ul_ui(nsi, "ACT PDP CTX REQ (REMOVE APN)", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 3,
		       dtap_act_pdp_ctx_req, sizeof(dtap_act_pdp_ctx_req));

	expect_res = expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GSM_ACT_PDP_REQ);
	OSMO_ASSERT(expect_res != NULL);
	OSMO_ASSERT(expect_res->parse_ctx.apn_ie_len == 0);

	OSMO_ASSERT(13 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach (power off -> no Detach Accept) */
	send_llc_ul_ui(nsi, "DETACH REQ (PWR OFF)", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 6,
		       dtap_detach_po_req, sizeof(dtap_detach_po_req));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	OSMO_ASSERT(14 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Bad cases ---\n\n");

	/* The RAI in the Attach Request message differs from the RAI in the
	 * BSSGP message, only patch the latter */

	send_llc_ul_ui(nsi, "ATTACH REQUEST (foreign RAI)", bss_nsei[0], 0x1002,
		       foreign_tlli2, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 0,
		       dtap_attach_req2, sizeof(dtap_attach_req2));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	OSMO_ASSERT(15 == peer->ctrg->ctr[GBPROX_PEER_CTR_RAID_PATCHED_BSS].current);

	printf("TLLI is already detached, shouldn't patch\n");
	send_llc_ul_ui(nsi, "ACT PDP CTX REQ", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, 3,
		       dtap_act_pdp_ctx_req, sizeof(dtap_act_pdp_ctx_req));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GSM_ACT_PDP_REQ));

	printf("Invalid RAI, shouldn't patch\n");
	send_bssgp_suspend_ack(nsi, SGSN_NSEI, 0xccd1758b, &rai_unknown);

	/* TODO: The following breaks with the current libosmocore, enable it
	 * again (and remove the plain expect_msg), when the msgb_bssgph patch
	 * is integrated */
	/* OSMO_ASSERT(expect_bssgp_msg(SGSN_NSEI, 0, BSSGP_PDUT_STATUS)); */
	OSMO_ASSERT(expect_msg());

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!expect_msg());
	received_messages = NULL;

	talloc_free(gbcfg.core_apn);
	gbcfg.core_apn = NULL;

	gbproxy_clear_patch_filter(&gbcfg.matches[GBPROX_MATCH_PATCHING]);
	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;
}

static void test_gbproxy_ptmsi_assignment()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	struct  gprs_ra_id rai_bss =
		{.mcc = 112, .mnc = 332, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_unknown =
		{.mcc = 1, .mnc = 99, .lac = 99, .rac = 96};
	uint16_t cell_id = 0x1234;

	const uint32_t ptmsi = 0xefe2b700;
	const uint32_t local_tlli = 0xefe2b700;

	const uint32_t foreign_tlli1 = 0x8000dead;
	const uint32_t foreign_tlli2 = 0x8000beef;

	const uint8_t imsi1[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xf8};
	const uint8_t imsi2[] = {0x11, 0x12, 0x99, 0x99, 0x99, 0x16, 0x17, 0xf8};

	struct gbproxy_link_info *link_info, *link_info2;
	struct gbproxy_peer *peer;
	unsigned bss_nu = 0;
	unsigned sgsn_nu = 0;

	uint16_t bss_nsei[1] = { 0x1000 };

	OSMO_ASSERT(local_tlli == gprs_tmsi2tlli(ptmsi, TLLI_LOCAL));

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;
	gbcfg.core_plmn = (struct osmo_plmn_id){};
	gbcfg.core_apn = talloc_zero_size(tall_sgsn_ctx, 100);
	gbcfg.core_apn_size = gprs_str_to_apn(gbcfg.core_apn, 100, "foo.bar");
	gbcfg.patch_ptmsi = 0;

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);
	setup_bssgp(nsi, bss_nsei[0], 0x1002);

	peer = gbproxy_peer_by_nsei(&gbcfg, 0x1000);
	OSMO_ASSERT(peer != NULL);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Establish first LLC connection ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli1, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN_NSEI, 0x1002,
		       foreign_tlli1, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_tlli1, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli1, 1, imsi1, sizeof(imsi1),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli1);
	link_info2 = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_tlli1);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == ptmsi);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_tlli1);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == ptmsi);


	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi1, sizeof(imsi1),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_imsi(peer, imsi1, ARRAY_SIZE(imsi1));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.ptmsi == ptmsi);
	OSMO_ASSERT(!gbproxy_link_info_by_imsi(peer, imsi2, ARRAY_SIZE(imsi2)));

	link_info2 = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->tlli.current == local_tlli);
	OSMO_ASSERT(link_info->tlli.ptmsi == ptmsi);

	printf("--- Establish second LLC connection with the same P-TMSI ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli2, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN_NSEI, 0x1002,
		       foreign_tlli2, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_tlli2, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity2_resp, sizeof(dtap_identity2_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli2, 1, imsi2, sizeof(imsi2),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli2);
	link_info2 = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_tlli2);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == ptmsi);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_tlli2);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == ptmsi);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi2, sizeof(imsi2),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_imsi(peer, imsi2, ARRAY_SIZE(imsi2));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.ptmsi == ptmsi);
	OSMO_ASSERT(!gbproxy_link_info_by_imsi(peer, imsi1, ARRAY_SIZE(imsi1)));

	link_info2 = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->tlli.current == local_tlli);
	OSMO_ASSERT(link_info->tlli.ptmsi == ptmsi);

	dump_global(stdout, 0);

	talloc_free(gbcfg.core_apn);
	gbcfg.core_apn = NULL;

	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;

	cleanup_test();
}

static void test_gbproxy_ptmsi_patching()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	struct  gprs_ra_id rai_bss =
		{.mcc = 112, .mnc = 332, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_sgsn =
		{.mcc = 123, .mnc = 456, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_wrong_mcc_sgsn =
		{.mcc = 999, .mnc = 456, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_unknown =
		{.mcc = 1, .mnc = 99, .lac = 99, .rac = 96};
	uint16_t cell_id = 0x1234;

	const uint32_t sgsn_ptmsi = 0xefe2b700;
	const uint32_t sgsn_ptmsi2 = 0xe0987654;
	const uint32_t sgsn_ptmsi3 = 0xe0543210;
	const uint32_t local_sgsn_tlli = 0xefe2b700;
	const uint32_t local_sgsn_tlli2 = 0xe0987654;
	const uint32_t local_sgsn_tlli3 = 0xe0543210;
	const uint32_t random_sgsn_tlli = 0x78dead00;
	const uint32_t unknown_sgsn_tlli = 0xeebadbad;

	const uint32_t bss_ptmsi = 0xc0dead01;
	const uint32_t bss_ptmsi2 = 0xc0dead02;
	const uint32_t bss_ptmsi3 = 0xc0dead03;
	const uint32_t local_bss_tlli = 0xc0dead01;
	const uint32_t local_bss_tlli2 = 0xc0dead02;
	const uint32_t local_bss_tlli3 = 0xc0dead03;
	const uint32_t foreign_bss_tlli = 0x8000dead;


	const uint8_t imsi[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xf8};
	struct gbproxy_link_info *link_info;
	struct gbproxy_peer *peer;
	unsigned bss_nu = 0;
	unsigned sgsn_nu = 0;
	int old_ctr;

	uint16_t bss_nsei[1] = { 0x1000 };

	OSMO_ASSERT(local_sgsn_tlli == gprs_tmsi2tlli(sgsn_ptmsi, TLLI_LOCAL));
	OSMO_ASSERT(local_sgsn_tlli2 == gprs_tmsi2tlli(sgsn_ptmsi2, TLLI_LOCAL));
	OSMO_ASSERT(local_sgsn_tlli3 == gprs_tmsi2tlli(sgsn_ptmsi3, TLLI_LOCAL));
	OSMO_ASSERT(local_bss_tlli == gprs_tmsi2tlli(bss_ptmsi, TLLI_LOCAL));
	OSMO_ASSERT(local_bss_tlli2 == gprs_tmsi2tlli(bss_ptmsi2, TLLI_LOCAL));
	OSMO_ASSERT(local_bss_tlli3 == gprs_tmsi2tlli(bss_ptmsi3, TLLI_LOCAL));

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;
	gbcfg.core_plmn = (struct osmo_plmn_id){ .mcc = 123, .mnc = 456 };
	gbcfg.core_apn = talloc_zero_size(tall_sgsn_ctx, 100);
	gbcfg.core_apn_size = gprs_str_to_apn(gbcfg.core_apn, 100, "foo.bar");
	gbcfg.patch_ptmsi = 1;

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);
	setup_bssgp(nsi, bss_nsei[0], 0x1002);

	peer = gbproxy_peer_by_nsei(&gbcfg, 0x1000);
	OSMO_ASSERT(peer != NULL);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, random_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == bss_ptmsi);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.ptmsi == sgsn_ptmsi);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.current == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);

	send_llc_ul_ui(nsi, "ACT PDP CTX REQ (REPLACE APN)", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_act_pdp_ctx_req, sizeof(dtap_act_pdp_ctx_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Non-DTAP */
	send_bssgp_ul_unitdata(nsi, "XID (UL)", bss_nsei[0], 0x1002,
			       local_bss_tlli, &rai_bss, cell_id,
			       llc_u_xid_ul, sizeof(llc_u_xid_ul));

	send_bssgp_dl_unitdata(nsi, "XID (DL)", SGSN_NSEI, 0x1002,
			       local_sgsn_tlli, 1, imsi, sizeof(imsi),
			       llc_u_xid_dl, sizeof(llc_u_xid_dl));

	send_bssgp_ul_unitdata(nsi, "LL11 DNS QUERY (UL)", bss_nsei[0], 0x1002,
			       local_bss_tlli, &rai_bss, cell_id,
			       llc_ui_ll11_dns_query_ul,
			       sizeof(llc_ui_ll11_dns_query_ul));

	send_bssgp_dl_unitdata(nsi, "LL11 DNS RESP (DL)", SGSN_NSEI, 0x1002,
			       local_sgsn_tlli, 1, imsi, sizeof(imsi),
			       llc_ui_ll11_dns_resp_dl,
			       sizeof(llc_ui_ll11_dns_resp_dl));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Repeated RA Update Requests */
	send_llc_ul_ui(nsi, "RA UPD REQ (P-TMSI 2)", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, 0x7080,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_ra_upd_req, sizeof(dtap_ra_upd_req));

	send_llc_dl_ui(nsi, "RA UDP ACC (P-TMSI 2)", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_ra_upd_acc2, sizeof(dtap_ra_upd_acc2));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli2, SGSN_NSEI) != NULL);
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli2);
	OSMO_ASSERT(link_info->tlli.current == local_bss_tlli);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == bss_ptmsi2);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli2);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_sgsn_tlli);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.ptmsi == sgsn_ptmsi2);

	send_llc_ul_ui(nsi, "RA UPD REQ (P-TMSI 3)", bss_nsei[0], 0x1002,
		       local_bss_tlli2, &rai_bss, 0x7080,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_ra_upd_req, sizeof(dtap_ra_upd_req));

	send_llc_dl_ui(nsi, "RA UDP ACC (P-TMSI 3)", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli2, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_ra_upd_acc3, sizeof(dtap_ra_upd_acc3));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli2, SGSN_NSEI) == NULL);
	OSMO_ASSERT(gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli3, SGSN_NSEI) != NULL);
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli3);
	OSMO_ASSERT(link_info->tlli.current == local_bss_tlli);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == bss_ptmsi3);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli3);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_sgsn_tlli);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.ptmsi == sgsn_ptmsi3);

	send_llc_ul_ui(nsi, "RA UPD COMPLETE", bss_nsei[0], 0x1002,
		       local_bss_tlli3, &rai_bss, 0x7080,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_ra_upd_complete, sizeof(dtap_ra_upd_complete));

	link_info = gbproxy_link_info_by_tlli(peer, local_bss_tlli3);

	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli3, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli3, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.current == local_bss_tlli3);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_sgsn_tlli3);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);

	/* Other messages */
	send_bssgp_llc_discarded(nsi, bss_nsei[0], 0x1002,
				 local_bss_tlli3, 1, 12);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_suspend(nsi, bss_nsei[0], local_bss_tlli3, &rai_bss);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_suspend_ack(nsi, SGSN_NSEI, local_sgsn_tlli3, &rai_sgsn);

	dump_peers(stdout, 0, 0, &gbcfg);

	old_ctr = peer->ctrg->ctr[GBPROX_PEER_CTR_PTMSI_PATCHED_SGSN].current;

	send_bssgp_paging(nsi, SGSN_NSEI, imsi, sizeof(imsi), &rai_bss, sgsn_ptmsi3);

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(old_ctr + 1 ==
		    peer->ctrg->ctr[GBPROX_PEER_CTR_PTMSI_PATCHED_SGSN].current);

	/* Bad case: Invalid BVCI */
	send_bssgp_llc_discarded(nsi, bss_nsei[0], 0xeee1,
				 local_bss_tlli3, 1, 12);
	dump_global(stdout, 0);

	/* Bad case: Invalid RAI */
	send_bssgp_suspend_ack(nsi, SGSN_NSEI, local_sgsn_tlli3, &rai_unknown);

	dump_global(stdout, 0);

	/* Bad case: Invalid MCC (LAC ok) */
	send_bssgp_suspend_ack(nsi, SGSN_NSEI, local_sgsn_tlli3,
			       &rai_wrong_mcc_sgsn);

	dump_global(stdout, 0);

	/* Bad case: Invalid TLLI from SGSN (IMSI unknown) */
	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       unknown_sgsn_tlli, 1, NULL, 0,
		       GPRS_SAPI_GMM, 2,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	/* Bad case: Invalid TLLI from SGSN (IMSI known) */
	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       unknown_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, 3,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	/* Detach */
	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       local_bss_tlli3, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "DETACH ACC", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli3, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	dump_global(stdout, 0);

	talloc_free(gbcfg.core_apn);
	gbcfg.core_apn = NULL;

	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;

	cleanup_test();
}

static void test_gbproxy_ptmsi_patching_bad_cases()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	struct  gprs_ra_id rai_bss =
		{.mcc = 112, .mnc = 332, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_unknown =
		{.mcc = 1, .mnc = 99, .lac = 99, .rac = 96};
	uint16_t cell_id = 0x1234;

	const uint32_t sgsn_ptmsi = 0xefe2b700;
	const uint32_t local_sgsn_tlli = 0xefe2b700;
	const uint32_t random_sgsn_tlli = 0x78dead00;

	const uint32_t bss_ptmsi = 0xc0dead01;
	const uint32_t local_bss_tlli = 0xc0dead01;
	const uint32_t foreign_bss_tlli = 0x8000dead;


	const uint8_t imsi[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xf8};
	struct gbproxy_link_info *link_info;
	struct gbproxy_peer *peer;
	unsigned bss_nu = 0;
	unsigned sgsn_nu = 0;
	uint16_t bss_nsei[] = { 0x1000 };

	OSMO_ASSERT(local_sgsn_tlli == gprs_tmsi2tlli(sgsn_ptmsi, TLLI_LOCAL));
	OSMO_ASSERT(local_bss_tlli == gprs_tmsi2tlli(bss_ptmsi, TLLI_LOCAL));

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;
	gbcfg.core_plmn = (struct osmo_plmn_id){ .mcc = 123, .mnc = 456 };
	gbcfg.core_apn = talloc_zero_size(tall_sgsn_ctx, 100);
	gbcfg.core_apn_size = gprs_str_to_apn(gbcfg.core_apn, 100, "foo.bar");
	gbcfg.patch_ptmsi = 1;

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);
	setup_bssgp(nsi, bss_nsei[0], 0x1002);

	peer = gbproxy_peer_by_nsei(&gbcfg, 0x1000);
	OSMO_ASSERT(peer != NULL);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, random_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == bss_ptmsi);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.ptmsi == sgsn_ptmsi);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT (duplicated)", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, random_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == bss_ptmsi);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.ptmsi == sgsn_ptmsi);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.current == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);

	/* Detach */
	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "DETACH ACC", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	dump_global(stdout, 0);

	talloc_free(gbcfg.core_apn);
	gbcfg.core_apn = NULL;

	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;

	cleanup_test();
}


static void test_gbproxy_imsi_acquisition()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	struct  gprs_ra_id rai_bss =
		{.mcc = 112, .mnc = 332, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_sgsn =
		{.mcc = 123, .mnc = 456, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_wrong_mcc_sgsn =
		{.mcc = 999, .mnc = 456, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_unknown =
		{.mcc = 1, .mnc = 99, .lac = 99, .rac = 96};
	uint16_t cell_id = 0x1234;

	const uint32_t sgsn_ptmsi = 0xefe2b700;
	const uint32_t local_sgsn_tlli = 0xefe2b700;
	const uint32_t random_sgsn_tlli = 0x78dead00;
	const uint32_t random_sgsn_tlli2 = 0x78dead02;

	const uint32_t bss_ptmsi = 0xc0dead01;
	const uint32_t local_bss_tlli = 0xc0dead01;
	const uint32_t foreign_bss_tlli = 0x8000dead;
	const uint32_t other_bss_tlli = 0x8000beef;

	const uint8_t imsi[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xf8};
	struct gbproxy_link_info *link_info;
	struct gbproxy_peer *peer;
	unsigned bss_nu = 0;
	unsigned sgsn_nu = 0;
	uint16_t bss_nsei[] = { 0x1000 };

	OSMO_ASSERT(local_sgsn_tlli == gprs_tmsi2tlli(sgsn_ptmsi, TLLI_LOCAL));

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;
	gbcfg.core_plmn = (struct osmo_plmn_id){ .mcc = 123, .mnc = 456 };
	gbcfg.core_apn = talloc_zero_size(tall_sgsn_ctx, 100);
	gbcfg.core_apn_size = gprs_str_to_apn(gbcfg.core_apn, 100, "foo.bar");
	gbcfg.patch_ptmsi = 1;
	gbcfg.acquire_imsi = 1;

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);
	setup_bssgp(nsi, bss_nsei[0], 0x1002);

	peer = gbproxy_peer_by_nsei(&gbcfg, 0x1000);
	OSMO_ASSERT(peer != NULL);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, random_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == bss_ptmsi);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.ptmsi == sgsn_ptmsi);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.current == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);

	/* Non-DTAP */
	send_bssgp_ul_unitdata(nsi, "XID (UL)", bss_nsei[0], 0x1002,
			       local_bss_tlli, &rai_bss, cell_id,
			       llc_u_xid_ul, sizeof(llc_u_xid_ul));

	send_bssgp_dl_unitdata(nsi, "XID (DL)", SGSN_NSEI, 0x1002,
			       local_sgsn_tlli, 1, imsi, sizeof(imsi),
			       llc_u_xid_dl, sizeof(llc_u_xid_dl));

	send_bssgp_ul_unitdata(nsi, "LL11 DNS QUERY (UL)", bss_nsei[0], 0x1002,
			       local_bss_tlli, &rai_bss, cell_id,
			       llc_ui_ll11_dns_query_ul,
			       sizeof(llc_ui_ll11_dns_query_ul));

	send_bssgp_dl_unitdata(nsi, "LL11 DNS RESP (DL)", SGSN_NSEI, 0x1002,
			       local_sgsn_tlli, 1, imsi, sizeof(imsi),
			       llc_ui_ll11_dns_resp_dl,
			       sizeof(llc_ui_ll11_dns_resp_dl));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Other messages */
	send_bssgp_llc_discarded(nsi, bss_nsei[0], 0x1002,
				 local_bss_tlli, 1, 12);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_llc_discarded(nsi, SGSN_NSEI, 0x1002,
				 local_sgsn_tlli, 1, 12);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_suspend(nsi, bss_nsei[0], local_bss_tlli, &rai_bss);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_suspend_ack(nsi, SGSN_NSEI, local_sgsn_tlli, &rai_sgsn);

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Bad case: Invalid BVCI */
	send_bssgp_llc_discarded(nsi, bss_nsei[0], 0xeee1,
				 local_bss_tlli, 1, 12);
	dump_global(stdout, 0);

	/* Bad case: Invalid RAI */
	send_bssgp_suspend_ack(nsi, SGSN_NSEI, local_sgsn_tlli, &rai_unknown);

	dump_global(stdout, 0);

	/* Bad case: Invalid MCC (LAC ok) */
	send_bssgp_suspend_ack(nsi, SGSN_NSEI, local_sgsn_tlli,
			       &rai_wrong_mcc_sgsn);

	dump_global(stdout, 0);

	/* Detach */
	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "DETACH ACC", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* RA Update request */

	send_llc_ul_ui(nsi, "RA UPD REQ", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_unknown, 0x7080,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_ra_upd_req, sizeof(dtap_ra_upd_req));

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "RA UDP ACC", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli2, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_ra_upd_acc, sizeof(dtap_ra_upd_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach */

	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "DETACH ACC", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Special case: Repeated Attach Requests */

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Special case: Detach from an unknown TLLI */

	send_llc_ul_ui(nsi, "DETACH REQ (unknown TLLI)", bss_nsei[0], 0x1002,
		       other_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Special case: Repeated RA Update Requests */

	send_llc_ul_ui(nsi, "RA UPD REQ", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_unknown, 0x7080,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_ra_upd_req, sizeof(dtap_ra_upd_req));

	send_llc_ul_ui(nsi, "RA UPD REQ", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_unknown, 0x7080,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_ra_upd_req, sizeof(dtap_ra_upd_req));

	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	dump_global(stdout, 0);

	talloc_free(gbcfg.core_apn);
	gbcfg.core_apn = NULL;

	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;

	cleanup_test();
}

static void test_gbproxy_secondary_sgsn()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	struct  gprs_ra_id rai_bss =
		{.mcc = 112, .mnc = 332, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_sgsn =
		{.mcc = 123, .mnc = 456, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_unknown =
		{.mcc = 1, .mnc = 99, .lac = 99, .rac = 96};
	uint16_t cell_id = 0x1234;

	const uint32_t sgsn_ptmsi = 0xefe2b700;
	const uint32_t local_sgsn_tlli = 0xefe2b700;
	const uint32_t random_sgsn_tlli = 0x78dead00;

	const uint32_t bss_ptmsi = 0xc0dead01;
	const uint32_t local_bss_tlli = 0xc0dead01;
	const uint32_t foreign_bss_tlli = 0x8000dead;

	const uint32_t sgsn_ptmsi2 = 0xe0987654;
	const uint32_t local_sgsn_tlli2 = 0xe0987654;
	const uint32_t random_sgsn_tlli2 = 0x78dead02;
	const uint32_t bss_ptmsi2 = 0xc0dead03;
	const uint32_t local_bss_tlli2 = 0xc0dead03;
	const uint32_t foreign_bss_tlli2 = 0x8000beef;

	const uint32_t random_sgsn_tlli3 = 0x78dead04;
	const uint32_t bss_ptmsi3 = 0xc0dead05;
	const uint32_t local_bss_tlli3 = 0xc0dead05;
	const uint32_t foreign_bss_tlli3 = 0x8000feed;

	const uint8_t imsi1[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xf8};
	const uint8_t imsi2[] = {0x11, 0x12, 0x99, 0x99, 0x99, 0x16, 0x17, 0xf8};
	const uint8_t imsi3[] = {0x11, 0x12, 0x99, 0x99, 0x99, 0x26, 0x27, 0xf8};
	struct gbproxy_link_info *link_info;
	struct gbproxy_link_info *other_info;
	struct gbproxy_peer *peer;
	unsigned bss_nu = 0;
	unsigned sgsn_nu = 0;

	const char *err_msg = NULL;
	const char *filter_re = "999999";
	uint16_t bss_nsei[]  = { 0x1000 };

	OSMO_ASSERT(local_sgsn_tlli == gprs_tmsi2tlli(sgsn_ptmsi, TLLI_LOCAL));
	OSMO_ASSERT(local_sgsn_tlli2 == gprs_tmsi2tlli(sgsn_ptmsi2, TLLI_LOCAL));

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;
	gbcfg.core_plmn = (struct osmo_plmn_id){ .mcc = 123, .mnc = 456 };
	gbcfg.core_apn = talloc_zero_size(tall_sgsn_ctx, 100);
	gbcfg.core_apn_size = gprs_str_to_apn(gbcfg.core_apn, 100, "foo.bar");
	gbcfg.patch_ptmsi = 1;
	gbcfg.acquire_imsi = 1;

	gbcfg.route_to_sgsn2 = 1;
	gbcfg.nsip_sgsn2_nsei = SGSN2_NSEI;

	if (gbproxy_set_patch_filter(&gbcfg.matches[GBPROX_MATCH_ROUTING],
				     filter_re, &err_msg) != 0) {
		fprintf(stderr, "gbprox_set_patch_filter: got error: %s\n",
			err_msg);
		OSMO_ASSERT(err_msg == NULL);
	}

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN 1 ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise SGSN 2 ---\n\n");

	connect_sgsn(nsi, SGSN2_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);
	setup_bssgp(nsi, bss_nsei[0], 0x0);
	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x0);
	setup_bssgp(nsi, bss_nsei[0], 0x1002);
	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);
	send_bssgp_reset_ack(nsi, SGSN2_NSEI, 0x1002);

	peer = gbproxy_peer_by_nsei(&gbcfg, 0x1000);
	OSMO_ASSERT(peer != NULL);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Flow control ---\n\n");

	send_bssgp_flow_control_bvc(nsi, bss_nsei[0], 0x1002, 1);
	send_bssgp_flow_control_bvc_ack(nsi, SGSN_NSEI, 0x1002, 1);
	send_bssgp_flow_control_bvc_ack(nsi, SGSN2_NSEI, 0x1002, 1);

	printf("--- Establish GPRS connection (SGSN 1) ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       random_sgsn_tlli, 1, imsi1, sizeof(imsi1),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN2_NSEI));
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, random_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == bss_ptmsi);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.ptmsi == sgsn_ptmsi);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN2_NSEI));
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi1, sizeof(imsi1),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN2_NSEI));
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.current == local_bss_tlli);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);

	/* Non-DTAP */
	send_bssgp_ul_unitdata(nsi, "XID (UL)", bss_nsei[0], 0x1002,
			       local_bss_tlli, &rai_bss, cell_id,
			       llc_u_xid_ul, sizeof(llc_u_xid_ul));

	send_bssgp_dl_unitdata(nsi, "XID (DL)", SGSN_NSEI, 0x1002,
			       local_sgsn_tlli, 1, imsi1, sizeof(imsi1),
			       llc_u_xid_dl, sizeof(llc_u_xid_dl));

	send_bssgp_ul_unitdata(nsi, "LL11 DNS QUERY (UL)", bss_nsei[0], 0x1002,
			       local_bss_tlli, &rai_bss, cell_id,
			       llc_ui_ll11_dns_query_ul,
			       sizeof(llc_ui_ll11_dns_query_ul));

	send_bssgp_dl_unitdata(nsi, "LL11 DNS RESP (DL)", SGSN_NSEI, 0x1002,
			       local_sgsn_tlli, 1, imsi1, sizeof(imsi1),
			       llc_ui_ll11_dns_resp_dl,
			       sizeof(llc_ui_ll11_dns_resp_dl));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Other messages */
	send_bssgp_llc_discarded(nsi, bss_nsei[0], 0x1002,
				 local_bss_tlli, 1, 12);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_llc_discarded(nsi, SGSN_NSEI, 0x1002,
				 local_sgsn_tlli, 1, 12);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_suspend(nsi, bss_nsei[0], local_bss_tlli, &rai_bss);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_suspend_ack(nsi, SGSN_NSEI, local_sgsn_tlli, &rai_sgsn);

	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Establish GPRS connection (SGSN 2) ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_bss_tlli2, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli2, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity2_resp, sizeof(dtap_identity2_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN2_NSEI, 0x1002,
		       random_sgsn_tlli2, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli2, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity2_resp, sizeof(dtap_identity2_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN2_NSEI, 0x1002,
		       random_sgsn_tlli2, 1, imsi2, sizeof(imsi2),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc2, sizeof(dtap_attach_acc2));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_sgsn_tlli(peer, random_sgsn_tlli2, SGSN_NSEI));
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, random_sgsn_tlli2, SGSN2_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli2);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli2);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == bss_ptmsi2);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli2);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli2);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.ptmsi == sgsn_ptmsi2);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_bss_tlli2, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli2, SGSN_NSEI));
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli2, SGSN2_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli2);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli2);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli2);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli2);
	OSMO_ASSERT(link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN2_NSEI, 0x1002,
		       local_sgsn_tlli2, 1, imsi2, sizeof(imsi2),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli2, SGSN_NSEI));
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli2, SGSN2_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.current == local_bss_tlli2);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_sgsn_tlli2);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);

	/* Non-DTAP */
	send_bssgp_ul_unitdata(nsi, "XID (UL)", bss_nsei[0], 0x1002,
			       local_bss_tlli2, &rai_bss, cell_id,
			       llc_u_xid_ul, sizeof(llc_u_xid_ul));

	send_bssgp_dl_unitdata(nsi, "XID (DL)", SGSN2_NSEI, 0x1002,
			       local_sgsn_tlli2, 1, imsi2, sizeof(imsi2),
			       llc_u_xid_dl, sizeof(llc_u_xid_dl));

	send_bssgp_ul_unitdata(nsi, "LL11 DNS QUERY (UL)", bss_nsei[0], 0x1002,
			       local_bss_tlli2, &rai_bss, cell_id,
			       llc_ui_ll11_dns_query_ul,
			       sizeof(llc_ui_ll11_dns_query_ul));

	send_bssgp_dl_unitdata(nsi, "LL11 DNS RESP (DL)", SGSN2_NSEI, 0x1002,
			       local_sgsn_tlli2, 1, imsi2, sizeof(imsi2),
			       llc_ui_ll11_dns_resp_dl,
			       sizeof(llc_ui_ll11_dns_resp_dl));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Other messages */
	send_bssgp_llc_discarded(nsi, bss_nsei[0], 0x1002,
				 local_bss_tlli2, 1, 12);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_llc_discarded(nsi, SGSN2_NSEI, 0x1002,
				 local_sgsn_tlli2, 1, 12);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_suspend(nsi, bss_nsei[0], local_bss_tlli2, &rai_bss);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_bssgp_suspend_ack(nsi, SGSN2_NSEI, local_sgsn_tlli2, &rai_sgsn);

	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Establish GPRS connection (SGSN 2, P-TMSI collision) ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_bss_tlli3, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli3, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity3_resp, sizeof(dtap_identity3_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN2_NSEI, 0x1002,
		       random_sgsn_tlli3, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_bss_tlli3, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity3_resp, sizeof(dtap_identity3_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT (P-TMSI 1)", SGSN2_NSEI, 0x1002,
		       random_sgsn_tlli3, 1, imsi3, sizeof(imsi3),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_sgsn_tlli(peer, random_sgsn_tlli3, SGSN_NSEI));
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, random_sgsn_tlli3, SGSN2_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli3);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli3);
	OSMO_ASSERT(!link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->tlli.ptmsi == bss_ptmsi3);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli3);
	OSMO_ASSERT(!link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.ptmsi == sgsn_ptmsi);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_bss_tlli3, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	dump_peers(stdout, 0, 0, &gbcfg);

	other_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(other_info);
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN2_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info != other_info);
	OSMO_ASSERT(link_info->tlli.assigned == local_bss_tlli3);
	OSMO_ASSERT(link_info->tlli.current == foreign_bss_tlli3);
	OSMO_ASSERT(link_info->tlli.bss_validated);
	OSMO_ASSERT(!link_info->tlli.net_validated);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.current == random_sgsn_tlli3);
	OSMO_ASSERT(link_info->sgsn_tlli.bss_validated);
	OSMO_ASSERT(!link_info->sgsn_tlli.net_validated);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN2_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi3, sizeof(imsi3),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	dump_peers(stdout, 0, 0, &gbcfg);

	other_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN_NSEI);
	OSMO_ASSERT(other_info);
	link_info = gbproxy_link_info_by_sgsn_tlli(peer, local_sgsn_tlli, SGSN2_NSEI);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info != other_info);
	OSMO_ASSERT(link_info->tlli.current == local_bss_tlli3);
	OSMO_ASSERT(link_info->tlli.assigned == 0);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_sgsn_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);


	printf("--- Shutdown GPRS connection (SGSN 1) ---\n\n");

	/* Detach */
	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       local_bss_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "DETACH ACC", SGSN_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi1, sizeof(imsi1),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Shutdown GPRS connection (SGSN 2) ---\n\n");

	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       local_bss_tlli2, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "DETACH ACC", SGSN2_NSEI, 0x1002,
		       local_sgsn_tlli2, 1, imsi2, sizeof(imsi2),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Shutdown GPRS connection (SGSN 2, P-TMSI 1) ---\n\n");

	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       local_bss_tlli3, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "DETACH ACC", SGSN2_NSEI, 0x1002,
		       local_sgsn_tlli, 1, imsi3, sizeof(imsi3),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	dump_global(stdout, 0);

	talloc_free(gbcfg.core_apn);
	gbcfg.core_apn = NULL;

	gbproxy_clear_patch_filter(&gbcfg.matches[GBPROX_MATCH_ROUTING]);
	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;

	cleanup_test();
}

static void test_gbproxy_keep_info()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	struct  gprs_ra_id rai_bss =
		{.mcc = 112, .mnc = 332, .lac = 16464, .rac = 96};
	uint16_t cell_id = 0x1234;

	const uint32_t ptmsi = 0xefe2b700;
	const uint32_t local_tlli = 0xefe2b700;
	const uint32_t foreign_tlli = 0xafe2b700;

	const uint8_t imsi[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0xf8};
	struct gbproxy_link_info *link_info, *link_info2;
	struct gbproxy_peer *peer;
	unsigned bss_nu = 0;
	unsigned sgsn_nu = 0;
	uint16_t bss_nsei[] = { 0x1000 };

	LLIST_HEAD(rcv_list);

	OSMO_ASSERT(local_tlli == gprs_tmsi2tlli(ptmsi, TLLI_LOCAL));

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;
	gbcfg.patch_ptmsi = 0;
	gbcfg.acquire_imsi = 1;
	gbcfg.core_plmn = (struct osmo_plmn_id){};
	gbcfg.core_apn = NULL;
	gbcfg.core_apn_size = 0;
	gbcfg.route_to_sgsn2 = 0;
	gbcfg.nsip_sgsn2_nsei = 0xffff;
	gbcfg.keep_link_infos = GBPROX_KEEP_ALWAYS;

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);
	setup_bssgp(nsi, bss_nsei[0], 0x1002);

	peer = gbproxy_peer_by_nsei(&gbcfg, 0x1000);
	OSMO_ASSERT(peer != NULL);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Send message from BSS 1 to SGSN, BVCI 0x1002 ---\n\n");

	received_messages = &rcv_list;

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ID_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->imsi_len == 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(link_info->imsi_acq_pending);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->imsi_len > 0);
	OSMO_ASSERT(!link_info->imsi_acq_pending);
	OSMO_ASSERT(gprs_tlli_type(link_info->sgsn_tlli.current) == TLLI_FOREIGN);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN_NSEI, 0x1002,
		       foreign_tlli, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ID_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ID_RESP));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->imsi_len > 0);
	OSMO_ASSERT(gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi)));

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_INFO));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);

	/* Detach (MO) */
	send_llc_ul_ui(nsi, "DETACH REQ", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "DETACH ACC", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, local_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);

	OSMO_ASSERT(!expect_msg());

	/* Re-Attach */
	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req3, sizeof(dtap_attach_req3));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);
	OSMO_ASSERT(gprs_tlli_type(link_info->sgsn_tlli.current) == TLLI_FOREIGN);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach (MT) */
	send_llc_dl_ui(nsi, "DETACH REQ (re-attach)", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_mt_detach_rea_req, sizeof(dtap_mt_detach_rea_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);

	send_llc_ul_ui(nsi, "DETACH ACC", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_mt_detach_acc, sizeof(dtap_mt_detach_acc));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_ACK));
	OSMO_ASSERT(!expect_msg());

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, local_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);

	/* Re-Attach */
	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req3, sizeof(dtap_attach_req3));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach (MT) */
	send_llc_dl_ui(nsi, "DETACH REQ", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_mt_detach_req, sizeof(dtap_mt_detach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);

	send_llc_ul_ui(nsi, "DETACH ACC", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_mt_detach_acc, sizeof(dtap_mt_detach_acc));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_ACK));
	OSMO_ASSERT(!expect_msg());

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, local_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);

	/* Re-Attach with IMSI */
	send_llc_ul_ui(nsi, "ATTACH REQUEST (IMSI)", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req4, sizeof(dtap_attach_req4));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);
	OSMO_ASSERT(link_info->sgsn_tlli.current == foreign_tlli);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach (MT) */
	send_llc_dl_ui(nsi, "DETACH REQ", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_mt_detach_req, sizeof(dtap_mt_detach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);

	send_llc_ul_ui(nsi, "DETACH ACC", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_mt_detach_acc, sizeof(dtap_mt_detach_acc));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_ACK));
	OSMO_ASSERT(!expect_msg());

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, local_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);

	/* Re-Attach */
	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req3, sizeof(dtap_attach_req3));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* RA update procedure (reject -> Detach) */
	send_llc_ul_ui(nsi, "RA UPD REQ", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, 0x7080,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_ra_upd_req, sizeof(dtap_ra_upd_req));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_RA_UPD_REQ));

	send_llc_dl_ui(nsi, "RA UDP REJ", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_ra_upd_rej, sizeof(dtap_ra_upd_rej));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_RA_UPD_REJ));
	OSMO_ASSERT(!expect_msg());

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, local_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);

	/* Bad case: Re-Attach with wrong (initial) P-TMSI */
	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ID_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info != link_info2);
	OSMO_ASSERT(link_info->imsi_len == 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(link_info->imsi_acq_pending);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len > 0);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach (MT) */
	send_llc_dl_ui(nsi, "DETACH REQ", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_mt_detach_req, sizeof(dtap_mt_detach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);

	send_llc_ul_ui(nsi, "DETACH ACC", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_mt_detach_acc, sizeof(dtap_mt_detach_acc));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, local_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);

	OSMO_ASSERT(!expect_msg());

	/* Bad case: Re-Attach with local TLLI */
	send_llc_ul_ui(nsi, "ATTACH REQUEST (local TLLI)", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req3, sizeof(dtap_attach_req3));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);
	OSMO_ASSERT(link_info->sgsn_tlli.current == local_tlli);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach (MT) */
	send_llc_dl_ui(nsi, "DETACH REQ (re-attach)", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_mt_detach_rea_req, sizeof(dtap_mt_detach_rea_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);

	send_llc_ul_ui(nsi, "DETACH ACC", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_mt_detach_acc, sizeof(dtap_mt_detach_acc));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_ACK));
	OSMO_ASSERT(!expect_msg());

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, local_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);

	/* Bad case: Unexpected Re-Attach with IMSI after completed attachment
	 * procedure */
	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req3, sizeof(dtap_attach_req3));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_INFO));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH REQUEST (unexpected, IMSI)",
		       bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req4, sizeof(dtap_attach_req4));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);
	OSMO_ASSERT(link_info->sgsn_tlli.current == foreign_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach (MT) */
	send_llc_dl_ui(nsi, "DETACH REQ", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_mt_detach_req, sizeof(dtap_mt_detach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);

	send_llc_ul_ui(nsi, "DETACH ACC", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_mt_detach_acc, sizeof(dtap_mt_detach_acc));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_ACK));
	OSMO_ASSERT(!expect_msg());

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, local_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);

	/* Bad case: Unexpected Re-Attach with P-TMSI after completed attachment
	 * procedure */
	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req3, sizeof(dtap_attach_req3));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "GMM INFO", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_gmm_information, sizeof(dtap_gmm_information));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_INFO));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH REQUEST (unexpected)", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req3, sizeof(dtap_attach_req3));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);
	OSMO_ASSERT(link_info->sgsn_tlli.current == foreign_tlli);
	OSMO_ASSERT(link_info->sgsn_tlli.assigned == 0);

	send_llc_dl_ui(nsi, "ATTACH ACCEPT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_acc, sizeof(dtap_attach_acc));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "ATTACH COMPLETE", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_complete, sizeof(dtap_attach_complete));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_COMPL));

	dump_peers(stdout, 0, 0, &gbcfg);

	/* Detach (MT) */
	send_llc_dl_ui(nsi, "DETACH REQ", SGSN_NSEI, 0x1002,
		       local_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_mt_detach_req, sizeof(dtap_mt_detach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, local_tlli);
	OSMO_ASSERT(link_info);

	send_llc_ul_ui(nsi, "DETACH ACC", bss_nsei[0], 0x1002,
		       local_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_mt_detach_acc, sizeof(dtap_mt_detach_acc));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_ACK));
	OSMO_ASSERT(!expect_msg());

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, local_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);


	/* Attach rejected */

	gbproxy_delete_link_infos(peer);

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ID_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->imsi_len == 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(link_info->imsi_acq_pending);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info2 = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info == link_info2);
	OSMO_ASSERT(link_info->imsi_len != 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(!link_info->imsi_acq_pending);

	send_llc_dl_ui(nsi, "ATTACH REJECT", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_attach_rej7, sizeof(dtap_attach_rej7));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ATTACH_REJ));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, foreign_tlli));

	OSMO_ASSERT(!expect_msg());

	/* Attach (incomplete) and Detach (MO) */

	gbproxy_delete_link_infos(peer);

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ID_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->imsi_len == 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(link_info->imsi_acq_pending);

	send_llc_ul_ui(nsi, "DETACH REQ (MO)", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_req, sizeof(dtap_detach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!expect_msg());

	/* Attach (incomplete) and Detach (MT) */

	gbproxy_delete_link_infos(peer);

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_ID_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->imsi_len == 0);
	OSMO_ASSERT(!link_info->is_deregistered);
	OSMO_ASSERT(link_info->imsi_acq_pending);

	send_llc_dl_ui(nsi, "DETACH REQ (MT)", SGSN_NSEI, 0x1002,
		       foreign_tlli, 1, imsi, sizeof(imsi),
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_mt_detach_req, sizeof(dtap_mt_detach_req));

	OSMO_ASSERT(expect_gmm_msg(0x1000, 0x1002, GSM48_MT_GMM_DETACH_REQ));

	dump_peers(stdout, 0, 0, &gbcfg);

	link_info = gbproxy_link_info_by_tlli(peer, foreign_tlli);
	OSMO_ASSERT(link_info);

	send_llc_ul_ui(nsi, "DETACH ACC", bss_nsei[0], 0x1002,
		       foreign_tlli, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_mt_detach_acc, sizeof(dtap_mt_detach_acc));

	/* TODO: The stored messaged should be cleaned when receiving a Detach
	 * Ack. Remove the first OSMO_ASSERT when this is fixed. */
	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_ATTACH_REQ));
	OSMO_ASSERT(expect_gmm_msg(SGSN_NSEI, 0x1002, GSM48_MT_GMM_DETACH_ACK));

	dump_peers(stdout, 0, 0, &gbcfg);

	OSMO_ASSERT(!gbproxy_link_info_by_tlli(peer, foreign_tlli));
	link_info = gbproxy_link_info_by_imsi(peer, imsi, sizeof(imsi));
	OSMO_ASSERT(link_info);
	OSMO_ASSERT(link_info->is_deregistered);

	OSMO_ASSERT(!expect_msg());
	received_messages = NULL;

	dump_global(stdout, 0);

	talloc_free(gbcfg.core_apn);
	gbcfg.core_apn = NULL;

	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;

	cleanup_test();
}

struct gbproxy_link_info *register_tlli(
	struct gbproxy_peer *peer, uint32_t tlli,
	const uint8_t *imsi, size_t imsi_len, time_t now)
{
	struct gbproxy_link_info *link_info;
	int imsi_matches = -1;
	int tlli_already_known = 0;
	struct gbproxy_config *cfg = peer->cfg;

	/* Check, whether the IMSI matches */
	if (gprs_is_mi_imsi(imsi, imsi_len)) {
		imsi_matches = gbproxy_check_imsi(
			&cfg->matches[GBPROX_MATCH_PATCHING], imsi, imsi_len);
		if (imsi_matches < 0)
			return NULL;
	}

	link_info = gbproxy_link_info_by_tlli(peer, tlli);

	if (!link_info) {
		link_info = gbproxy_link_info_by_imsi(peer, imsi, imsi_len);

		if (link_info) {
			/* TLLI has changed somehow, adjust it */
			LOGP(DGPRS, LOGL_INFO,
			     "The TLLI has changed from %08x to %08x\n",
			     link_info->tlli.current, tlli);
			link_info->tlli.current = tlli;
		}
	}

	if (!link_info) {
		link_info = gbproxy_link_info_alloc(peer);
		link_info->tlli.current = tlli;
	} else {
		gbproxy_detach_link_info(peer, link_info);
		tlli_already_known = 1;
	}

	OSMO_ASSERT(link_info != NULL);

	if (!tlli_already_known)
		LOGP(DGPRS, LOGL_INFO, "Adding TLLI %08x to list\n", tlli);

	gbproxy_attach_link_info(peer, now, link_info);
	gbproxy_update_link_info(link_info, imsi, imsi_len);

	if (imsi_matches >= 0)
		link_info->is_matching[GBPROX_MATCH_PATCHING] = imsi_matches;

	return link_info;
}

static void test_gbproxy_tlli_expire(void)
{
	struct gbproxy_config cfg = {0};
	struct gbproxy_peer *peer;
	const char *err_msg = NULL;
	const uint8_t imsi1[] = { GSM_MI_TYPE_IMSI, 0x23, 0x24, 0x25, 0xf6 };
	const uint8_t imsi2[] = { GSM_MI_TYPE_IMSI, 0x26, 0x27, 0x28, 0xf9 };
	const uint8_t imsi3[] = { GSM_MI_TYPE_IMSI | 0x10, 0x32, 0x54, 0x76, 0xf8 };
	const uint32_t tlli1 = 1234 | 0xc0000000;
	const uint32_t tlli2 = 5678 | 0xc0000000;
	const uint32_t tlli3 = 3456 | 0xc0000000;
	const char *filter_re = ".*";
	time_t now = 1407479214;

	printf("Test TLLI info expiry\n\n");

	gbproxy_init_config(&cfg);

	if (gbproxy_set_patch_filter(&cfg.matches[GBPROX_MATCH_PATCHING],
				     filter_re, &err_msg) != 0) {
		fprintf(stderr, "gbprox_set_patch_filter: got error: %s\n",
			err_msg);
		OSMO_ASSERT(err_msg == NULL);
	}

	{
		struct gbproxy_link_info *link_info;

		printf("Test TLLI replacement:\n");

		cfg.tlli_max_len = 0;
		cfg.tlli_max_age = 0;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 0);

		printf("  Add TLLI 1, IMSI 1\n");
		link_info = register_tlli(peer, tlli1,
						  imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(link_info);
		OSMO_ASSERT(link_info->tlli.current == tlli1);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		/* replace the old entry */
		printf("  Add TLLI 2, IMSI 1 (should replace TLLI 1)\n");
		link_info = register_tlli(peer, tlli2,
						  imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(link_info);
		OSMO_ASSERT(link_info->tlli.current == tlli2);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		dump_peers(stdout, 2, now, &cfg);

		/* verify that 5678 has survived */
		link_info = gbproxy_link_info_by_imsi(peer, imsi1, ARRAY_SIZE(imsi1));
		OSMO_ASSERT(link_info);
		OSMO_ASSERT(link_info->tlli.current == tlli2);
		link_info = gbproxy_link_info_by_imsi(peer, imsi2, ARRAY_SIZE(imsi2));
		OSMO_ASSERT(!link_info);

		printf("\n");

		gbproxy_peer_free(peer);
	}

	{
		struct gbproxy_link_info *link_info;

		printf("Test IMSI replacement:\n");

		cfg.tlli_max_len = 0;
		cfg.tlli_max_age = 0;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 0);

		printf("  Add TLLI 1, IMSI 1\n");
		link_info = register_tlli(peer, tlli1,
						  imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(link_info);
		OSMO_ASSERT(link_info->tlli.current == tlli1);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		/* try to replace the old entry */
		printf("  Add TLLI 1, IMSI 2 (should replace IMSI 1)\n");
		link_info = register_tlli(peer, tlli1,
						  imsi2, ARRAY_SIZE(imsi2), now);
		OSMO_ASSERT(link_info);
		OSMO_ASSERT(link_info->tlli.current == tlli1);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		dump_peers(stdout, 2, now, &cfg);

		/* verify that 5678 has survived */
		link_info = gbproxy_link_info_by_imsi(peer, imsi1, ARRAY_SIZE(imsi1));
		OSMO_ASSERT(!link_info);
		link_info = gbproxy_link_info_by_imsi(peer, imsi2, ARRAY_SIZE(imsi2));
		OSMO_ASSERT(link_info);
		OSMO_ASSERT(link_info->tlli.current == tlli1);

		printf("\n");

		gbproxy_peer_free(peer);
	}

	{
		struct gbproxy_link_info *link_info;
		int num_removed;

		printf("Test TLLI expiry, max_len == 1:\n");

		cfg.tlli_max_len = 1;
		cfg.tlli_max_age = 0;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 0);

		printf("  Add TLLI 1, IMSI 1\n");
		register_tlli(peer, tlli1, imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		/* replace the old entry */
		printf("  Add TLLI 2, IMSI 2 (should replace IMSI 1)\n");
		register_tlli(peer, tlli2, imsi2, ARRAY_SIZE(imsi2), now);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 2);

		num_removed = gbproxy_remove_stale_link_infos(peer, now + 2);
		OSMO_ASSERT(num_removed == 1);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		dump_peers(stdout, 2, now, &cfg);

		/* verify that 5678 has survived */
		link_info = gbproxy_link_info_by_imsi(peer, imsi1, ARRAY_SIZE(imsi1));
		OSMO_ASSERT(!link_info);
		link_info = gbproxy_link_info_by_imsi(peer, imsi2, ARRAY_SIZE(imsi2));
		OSMO_ASSERT(link_info);
		OSMO_ASSERT(link_info->tlli.current == tlli2);

		printf("\n");

		gbproxy_peer_free(peer);
	}

	{
		struct gbproxy_link_info *link_info;
		int num_removed;

		printf("Test TLLI expiry, max_age == 1:\n");

		cfg.tlli_max_len = 0;
		cfg.tlli_max_age = 1;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 0);

		printf("  Add TLLI 1, IMSI 1 (should expire after timeout)\n");
		register_tlli(peer, tlli1, imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		printf("  Add TLLI 2, IMSI 2 (should not expire after timeout)\n");
		register_tlli(peer, tlli2, imsi2, ARRAY_SIZE(imsi2),
				     now + 1);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 2);

		num_removed = gbproxy_remove_stale_link_infos(peer, now + 2);
		OSMO_ASSERT(num_removed == 1);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		dump_peers(stdout, 2, now + 2, &cfg);

		/* verify that 5678 has survived */
		link_info = gbproxy_link_info_by_imsi(peer, imsi1, ARRAY_SIZE(imsi1));
		OSMO_ASSERT(!link_info);
		link_info = gbproxy_link_info_by_imsi(peer, imsi2, ARRAY_SIZE(imsi2));
		OSMO_ASSERT(link_info);
		OSMO_ASSERT(link_info->tlli.current == tlli2);

		printf("\n");

		gbproxy_peer_free(peer);
	}

	{
		struct gbproxy_link_info *link_info;
		int num_removed;

		printf("Test TLLI expiry, max_len == 2, max_age == 1:\n");

		cfg.tlli_max_len = 0;
		cfg.tlli_max_age = 1;
		peer = gbproxy_peer_alloc(&cfg, 20);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 0);

		printf("  Add TLLI 1, IMSI 1 (should expire)\n");
		register_tlli(peer, tlli1, imsi1, ARRAY_SIZE(imsi1), now);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		printf("  Add TLLI 2, IMSI 2 (should expire after timeout)\n");
		register_tlli(peer, tlli2, imsi2, ARRAY_SIZE(imsi2),
				     now + 1);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 2);

		printf("  Add TLLI 3, IMSI 3 (should not expire after timeout)\n");
		register_tlli(peer, tlli3, imsi3, ARRAY_SIZE(imsi3),
				      now + 2);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 3);

		dump_peers(stdout, 2, now + 2, &cfg);

		printf("  Remove stale TLLIs\n");
		num_removed = gbproxy_remove_stale_link_infos(peer, now + 3);
		OSMO_ASSERT(num_removed == 2);
		OSMO_ASSERT(peer->patch_state.logical_link_count == 1);

		dump_peers(stdout, 2, now + 2, &cfg);

		/* verify that tlli3 has survived */
		link_info = gbproxy_link_info_by_imsi(peer, imsi1, ARRAY_SIZE(imsi1));
		OSMO_ASSERT(!link_info);
		link_info = gbproxy_link_info_by_imsi(peer, imsi2, ARRAY_SIZE(imsi2));
		OSMO_ASSERT(!link_info);
		link_info = gbproxy_link_info_by_imsi(peer, imsi3, ARRAY_SIZE(imsi3));
		OSMO_ASSERT(link_info);
		OSMO_ASSERT(link_info->tlli.current == tlli3);

		printf("\n");

		gbproxy_peer_free(peer);
	}
	gbproxy_clear_patch_filter(&cfg.matches[GBPROX_MATCH_PATCHING]);
	gbprox_reset(&cfg);
	/* gbprox_reset() frees the rate_ctr, but re-allocates it again. */
	rate_ctr_group_free(cfg.ctrg);

	cleanup_test();
}

static void test_gbproxy_imsi_matching(void)
{
	const char *err_msg = NULL;
	const uint8_t imsi1[] = { GSM_MI_TYPE_IMSI | 0x10, 0x32, 0x54, 0xf6 };
	const uint8_t imsi2[] = { GSM_MI_TYPE_IMSI | GSM_MI_ODD | 0x10, 0x32, 0x54, 0x76 };
	const uint8_t imsi3_bad[] = { GSM_MI_TYPE_IMSI | 0x10, 0xee, 0x54, 0xff };
	const uint8_t tmsi1[] = { GSM_MI_TYPE_TMSI | 0xf0, 0x11, 0x22, 0x33, 0x44 };
	const uint8_t tmsi2_bad[] = { GSM_MI_TYPE_TMSI | 0xf0, 0x11, 0x22 };
	const uint8_t imei1[] = { GSM_MI_TYPE_IMEI | 0x10, 0x32, 0x54, 0xf6 };
	const uint8_t imei2[] = { GSM_MI_TYPE_IMEI | GSM_MI_ODD | 0x10, 0x32, 0x54, 0x76 };
	const char *filter_re1 = ".*";
	const char *filter_re2 = "^1234";
	const char *filter_re3 = "^4321";
	const char *filter_re4_bad = "^12[";
	struct gbproxy_match match = {0,};

	printf("=== Test IMSI/TMSI matching ===\n\n");

	OSMO_ASSERT(match.enable == 0);

	OSMO_ASSERT(gbproxy_set_patch_filter(&match, filter_re1, &err_msg) == 0);
	OSMO_ASSERT(match.enable == 1);

	OSMO_ASSERT(gbproxy_set_patch_filter(&match, filter_re2, &err_msg) == 0);
	OSMO_ASSERT(match.enable == 1);

	err_msg = NULL;
	OSMO_ASSERT(gbproxy_set_patch_filter(&match, filter_re4_bad, &err_msg) == -1);
	OSMO_ASSERT(err_msg != NULL);
	OSMO_ASSERT(match.enable == 0);

	OSMO_ASSERT(gbproxy_set_patch_filter(&match, filter_re2, &err_msg) == 0);
	OSMO_ASSERT(match.enable == 1);

	OSMO_ASSERT(gbproxy_set_patch_filter(&match, NULL, &err_msg) == 0);
	OSMO_ASSERT(match.enable == 0);

	OSMO_ASSERT(gbproxy_set_patch_filter(&match, filter_re2, &err_msg) == 0);
	OSMO_ASSERT(match.enable == 1);

	gbproxy_clear_patch_filter(&match);
	OSMO_ASSERT(match.enable == 0);

	OSMO_ASSERT(gbproxy_set_patch_filter(&match, filter_re2, &err_msg) == 0);
	OSMO_ASSERT(match.enable == 1);

	OSMO_ASSERT(gbproxy_check_imsi(&match, imsi1, ARRAY_SIZE(imsi1)) == 1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, imsi2, ARRAY_SIZE(imsi2)) == 1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, imsi3_bad, ARRAY_SIZE(imsi3_bad)) == -1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, tmsi1, ARRAY_SIZE(tmsi1)) == -1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, tmsi2_bad, ARRAY_SIZE(tmsi2_bad)) == -1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, imei1, ARRAY_SIZE(imei1)) == -1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, imei2, ARRAY_SIZE(imei2)) == -1);

	OSMO_ASSERT(gbproxy_set_patch_filter(&match, filter_re3, &err_msg) == 0);
	OSMO_ASSERT(match.enable == 1);

	OSMO_ASSERT(gbproxy_check_imsi(&match, imsi1, ARRAY_SIZE(imsi1)) == 0);
	OSMO_ASSERT(gbproxy_check_imsi(&match, imsi2, ARRAY_SIZE(imsi2)) == 0);
	OSMO_ASSERT(gbproxy_check_imsi(&match, imsi3_bad, ARRAY_SIZE(imsi3_bad)) == -1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, tmsi1, ARRAY_SIZE(tmsi1)) == -1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, tmsi2_bad, ARRAY_SIZE(tmsi2_bad)) == -1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, imei1, ARRAY_SIZE(imei1)) == -1);
	OSMO_ASSERT(gbproxy_check_imsi(&match, imei2, ARRAY_SIZE(imei2)) == -1);

	/* TODO: Check correct length but wrong type with is_mi_tmsi */

	gbproxy_clear_patch_filter(&match);
	OSMO_ASSERT(match.enable == 0);

	cleanup_test();
}

static void test_gbproxy_stored_messages()
{
	struct gprs_ns2_inst *nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_callback, &gbcfg);
	struct  gprs_ra_id rai_bss =
		{.mcc = 112, .mnc = 332, .lac = 16464, .rac = 96};
	struct  gprs_ra_id rai_unknown =
		{.mcc = 1, .mnc = 99, .lac = 99, .rac = 96};
	uint16_t cell_id = 0x1234;

	const uint32_t ptmsi = 0xefe2b700;
	const uint32_t local_tlli = 0xefe2b700;

	const uint32_t foreign_tlli1 = 0x8000dead;

	struct gbproxy_peer *peer;
	unsigned bss_nu = 0;
	unsigned sgsn_nu = 0;
	uint16_t bss_nsei[] = { 0x1000 };

	OSMO_ASSERT(local_tlli == gprs_tmsi2tlli(ptmsi, TLLI_LOCAL));

	gbcfg.nsi = nsi;
	gbcfg.nsip_sgsn_nsei = SGSN_NSEI;
	gbcfg.core_plmn = (struct osmo_plmn_id){};
	gbcfg.core_apn = talloc_zero_size(tall_sgsn_ctx, 100);
	gbcfg.core_apn_size = gprs_str_to_apn(gbcfg.core_apn, 100, "foo.bar");
	gbcfg.patch_ptmsi = 0;
	gbcfg.acquire_imsi = 1;
	gbcfg.keep_link_infos = 0;

	bssgp_set_bssgp_callback(gbprox_test_bssgp_send_cb, &gbcfg);

	printf("=== %s ===\n", __func__);
	printf("--- Initialise SGSN ---\n\n");

	connect_sgsn(nsi, SGSN_NSEI);

	printf("--- Initialise BSS 1 ---\n\n");

	setup_ns(nsi, bss_nsei[0]);
	setup_bssgp(nsi, bss_nsei[0], 0x1002);

	peer = gbproxy_peer_by_nsei(&gbcfg, 0x1000);
	OSMO_ASSERT(peer != NULL);

	send_bssgp_reset_ack(nsi, SGSN_NSEI, 0x1002);

	dump_global(stdout, 0);
	dump_peers(stdout, 0, 0, &gbcfg);

	printf("--- Establish first LLC connection ---\n\n");

	send_llc_ul_ui(nsi, "ATTACH REQUEST", bss_nsei[0], 0x1002,
		       foreign_tlli1, &rai_unknown, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_attach_req, sizeof(dtap_attach_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_dl_ui(nsi, "IDENT REQUEST", SGSN_NSEI, 0x1002,
		       foreign_tlli1, 0, NULL, 0,
		       GPRS_SAPI_GMM, sgsn_nu++,
		       dtap_identity_req, sizeof(dtap_identity_req));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "DETACH ACCEPT", bss_nsei[0], 0x1002,
		       foreign_tlli1, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_detach_acc, sizeof(dtap_detach_acc));

	dump_peers(stdout, 0, 0, &gbcfg);

	send_llc_ul_ui(nsi, "IDENT RESPONSE", bss_nsei[0], 0x1002,
		       foreign_tlli1, &rai_bss, cell_id,
		       GPRS_SAPI_GMM, bss_nu++,
		       dtap_identity_resp, sizeof(dtap_identity_resp));

	dump_peers(stdout, 0, 0, &gbcfg);

	dump_global(stdout, 0);

	talloc_free(gbcfg.core_apn);
	gbcfg.core_apn = NULL;

	gbprox_reset(&gbcfg);
	gprs_ns2_free(nsi);
	nsi = NULL;

	cleanup_test();
}

/* See OS#3178 "gbproxy: failed to parse invalid BSSGP-UNITDATA message" */
static void test_gbproxy_parse_bssgp_unitdata()
{
	const char *hex = "0000239401e155cfea000004088872f4801018009c4000800e000601c0416c4338";
	struct msgb *msg = msgb_alloc(1034, "bssgp_unitdata");
	struct gprs_gb_parse_context parse_ctx;
	int rc;

	memset(&parse_ctx, 0, sizeof(parse_ctx));

	OSMO_ASSERT(msg);
	msgb_bssgph(msg) = msg->head;
	msgb_put(msg, osmo_hexparse(hex, msg->head, msgb_tailroom(msg)));

	parse_ctx.to_bss = 0;
	parse_ctx.peer_nsei = msgb_nsei(msg);

	rc = gprs_gb_parse_bssgp(msg->data, msg->len, &parse_ctx);
	if (!rc)
		fprintf(stderr, "%s: Test passed; Failed to parse invalid message %s\n", __func__, msgb_hexdump(msg));
	else
		fprintf(stderr, "%s: Test failed; invalid message was accepted by parser: %s\n", __func__, msgb_hexdump(msg));

	OSMO_ASSERT(!rc);

	/* Manually decoded message according to:
	   ETSI TS 148 018 V10.6.0 (2012 07) 96
	   3GPP TS 48.018 version 10.6.0 Release 10
	   Table 10.2.2: UL-UNITDATA PDU content

	00	- PDU type UL-UNITDATA (ok)

		11.3.35 Temporary logical link Identity (TLLI)
	00	- TLLI[0]
	23	- TLLI[1]
	94	- TLLI[2]
	01	- TLLI[3]
		  TLLI == "00239401"

	e1	- QOS[0] (bit rate MSB)
	55	- QOS[1] (bit rate LSB)
		  bit rate = "57685" (57685*100000 bit/s per PBRG)
	cf	- QOS[2] PBRG = 11 (bit rate is expressed in 100000 bit/s increments),
			C/R 0 (contains LLC ACK/SACK),
			T 0 (contains signalling),
			A 1 (radio if uses MAC/UNITDATA,
			Precedence 111 (reserved value)

	ea	- CELL_ID[0] (TLV IEI: wrong, should be 0x08)
	00	- CELL_ID[1] (length 1)
	00	- CELL_ID[2] (length 2)
		lenth == 0
	04	-- CELL_ID[3]
	08	-- CELL_ID[4]
	88	-- CELL_ID[5]
	72	-- CELL_ID[6]
	f4	-- CELL_ID[7]
	80	-- CELL_ID[8]
	10	-- CELL_DI[9]

	18	-- QOSP[0] OoS Profile IEI
		not allowed in BSSGP Userdata
	00	-- QOSP[1]
	9c	-- QOSP[2]
	40	-- QOSP[3]
	00	-- QOSP[4]

	80	-- IEI for "E-UTRAN Inter RAT Handover Info"
		not allowed in BSSGP Userdata
	0e	-- length (14 bytes -- only 8 bytes remain)
	00 06 01 c0 41 6c 43 38 */

	msgb_free(msg);

	cleanup_test();
}

static struct log_info_cat gprs_categories[] = {
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DNS] = {
		.name = "DNS",
		.description = "GPRS Network Service (NS)",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DBSSGP] = {
		.name = "DBSSGP",
		.description = "GPRS BSS Gateway Protocol (BSSGP)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

int main(int argc, char **argv)
{
	talloc_enable_leak_report();
	tall_sgsn_ctx = talloc_named_const(NULL, 0, "gbproxy_test");
	void *log_ctx = talloc_named_const(tall_sgsn_ctx, 0, "log");

	msgb_talloc_ctx_init(tall_sgsn_ctx, 0);

	osmo_init_logging2(log_ctx, &info);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_log_level(osmo_stderr_target, LOGL_DEBUG);
	log_set_all_filter(osmo_stderr_target, 1);

	rate_ctr_init(tall_sgsn_ctx);

	setlinebuf(stdout);

	printf("===== GbProxy test START\n");
	gbproxy_init_config(&gbcfg);
	test_gbproxy();
	test_gbproxy_ident_changes();
	test_gbproxy_ra_patching();
	test_gbproxy_imsi_matching();
	test_gbproxy_ptmsi_assignment();
	test_gbproxy_ptmsi_patching();
	test_gbproxy_ptmsi_patching_bad_cases();
	test_gbproxy_imsi_acquisition();
	test_gbproxy_secondary_sgsn();
	test_gbproxy_keep_info();
	test_gbproxy_tlli_expire();
	test_gbproxy_stored_messages();
	test_gbproxy_parse_bssgp_unitdata();
	gbprox_reset(&gbcfg);
	/* gbprox_reset() frees the rate_ctr, but re-allocates it again. */
	rate_ctr_group_free(gbcfg.ctrg);
	printf("===== GbProxy test END\n\n");

	talloc_free(log_ctx);
	/* expecting root and msgb ctx, empty */
	OSMO_ASSERT(talloc_total_blocks(tall_sgsn_ctx) == 2);
	talloc_free(tall_sgsn_ctx);

	return 0;
}
