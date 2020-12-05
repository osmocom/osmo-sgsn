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
	struct gbproxy_nse *nse;
	struct gprs_ra_id raid;
	unsigned int i, _nse;
	const struct rate_ctr_group_desc *desc;
	int rc;

	rc = fprintf(stream, "%*sPeers:\n", indent, "");
	if (rc < 0)
		return rc;


	hash_for_each(cfg->bss_nses, _nse, nse, list) {
		struct gbproxy_bvc *peer;
		int _peer;
		hash_for_each(nse->bvcs, _peer, peer, list) {
			gsm48_parse_ra(&raid, peer->ra);

			rc = fprintf(stream, "%*s  NSEI %u, BVCI %u, %sblocked, RAI %s\n",
				     indent, "",
				     nse->nsei, peer->bvci,
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
	send_bssgp_reset(nsi, nsei, 0);
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
	OSMO_ASSERT(gbproxy_bvc_by_bvci(&gbcfg, 0xeeee) == NULL);
	OSMO_ASSERT(gbproxy_bvc_by_bvci(&gbcfg, 0x1000) == NULL);
	OSMO_ASSERT(gbproxy_bvc_by_bvci(&gbcfg, 0x1012) != NULL);
	OSMO_ASSERT(gbproxy_bvc_by_nsei(&gbcfg, 0xeeee) == NULL);
	OSMO_ASSERT(gbproxy_bvc_by_nsei(&gbcfg, 0x1012) == NULL);
	OSMO_ASSERT(gbproxy_bvc_by_nsei(&gbcfg, 0x1000) != NULL);


	/* Cleanup */
	OSMO_ASSERT(gbproxy_cleanup_bvcs(&gbcfg, 0, 0) == 0);
	OSMO_ASSERT(gbproxy_cleanup_bvcs(&gbcfg, 0x1000, 0xeeee) == 0);
	OSMO_ASSERT(gbproxy_cleanup_bvcs(&gbcfg, 0, 0x1002) == 0);
	OSMO_ASSERT(gbproxy_cleanup_bvcs(&gbcfg, 0x1000, 0x1012) == 1);
	OSMO_ASSERT(gbproxy_cleanup_bvcs(&gbcfg, 0x1000, 0x1012) == 0);

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
