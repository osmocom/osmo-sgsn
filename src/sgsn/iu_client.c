/* Common parts of IuCS and IuPS interfaces implementation */

/* (C) 2016-2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <asn1c/asn1helpers.h>

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/sgsn/iu_client.h>

#include <osmocom/core/logging.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sccp/sccp_types.h>
#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>

/* Parsed global RNC id. See also struct RANAP_GlobalRNC_ID, and note that the
 * PLMN identity is a BCD representation of the MCC and MNC.
 * See iu_grnc_id_parse(). */
struct iu_grnc_id {
	struct osmo_plmn_id plmn;
	uint16_t rnc_id;
};

struct iu_lac_rac_entry {
	struct llist_head entry;

	struct osmo_routing_area_id rai;
};

/* Entry to cache conn_id <-> sccp_addr mapping in case we receive an empty CR */
struct iu_new_ctx_entry {
	struct llist_head list;

	uint32_t conn_id;
	struct osmo_sccp_addr sccp_addr;
};

/* A remote RNC (Radio Network Controller, like BSC but for UMTS) that has
 * called us and is currently reachable at the given osmo_sccp_addr. So, when we
 * know a LAC for a subscriber, we can page it at the RNC matching that LAC or
 * RAC. An HNB-GW typically presents itself as if it were a single RNC, even
 * though it may have several RNCs in hNodeBs connected to it. Those will then
 * share the same RNC id, which they actually receive and adopt from the HNB-GW
 * in the HNBAP HNB REGISTER ACCEPT message. */
struct ranap_iu_rnc {
	struct llist_head entry;

	struct osmo_rnc_id rnc_id;
	struct osmo_sccp_addr sccp_addr;

	/* A list of struct iu_lac_rac_entry */
	struct llist_head lac_rac_list;
};

void *talloc_iu_ctx;

ranap_iu_recv_cb_t global_iu_recv_cb = NULL;
ranap_iu_event_cb_t global_iu_event_cb = NULL;
int iu_log_subsystem = 0;

#define LOGPIU(level, fmt, args...) \
	LOGP(iu_log_subsystem, level, fmt, ## args)

#define LOGPIUC(level, fmt, args...) \
	LOGPC(iu_log_subsystem, level, fmt, ## args)

static LLIST_HEAD(ue_conn_sccp_addr_list);
static LLIST_HEAD(ue_conn_ctx_list);
static LLIST_HEAD(rnc_list);

static struct osmo_sccp_instance *g_sccp;
static struct osmo_sccp_user *g_scu;
static struct osmo_sccp_addr g_local_sccp_addr;

/* This rac will be used internally. RAC with 0xff will be rejected */
#define OSMO_RESERVED_RAC 0xff

const struct value_string ranap_iu_event_type_names[] = {
	OSMO_VALUE_STRING(RANAP_IU_EVENT_RAB_ASSIGN),
	OSMO_VALUE_STRING(RANAP_IU_EVENT_SECURITY_MODE_COMPLETE),
	OSMO_VALUE_STRING(RANAP_IU_EVENT_IU_RELEASE),
	OSMO_VALUE_STRING(RANAP_IU_EVENT_LINK_INVALIDATED),
	OSMO_VALUE_STRING(RANAP_IU_EVENT_NEW_AREA),
	{ 0, NULL }
};

static int global_iu_event(struct ranap_ue_conn_ctx *ue_ctx,
			   enum ranap_iu_event_type type,
			   void *data)
{
	if (!global_iu_event_cb)
		return 0;

	if (ue_ctx && !ue_ctx->notification)
		return 0;

	LOGPIU(LOGL_DEBUG, "Submit Iu event to upper layer: %s\n", ranap_iu_event_type_str(type));

	return global_iu_event_cb(ue_ctx, type, data);
}

static void global_iu_event_new_area(const struct osmo_rnc_id *rnc_id, const struct osmo_routing_area_id *rai)
{
	struct ranap_iu_event_new_area new_area = (struct ranap_iu_event_new_area) {
	    .rnc_id = rnc_id,
	    .cell_type = RANAP_IU_NEW_RAC
	};

	if (rai->rac == OSMO_RESERVED_RAC) {
		new_area.cell_type = RANAP_IU_NEW_LAC;
		new_area.u.lai = &rai->lac;
	} else {
		new_area.cell_type = RANAP_IU_NEW_RAC;
		new_area.u.rai = rai;
	}

	global_iu_event(NULL, RANAP_IU_EVENT_NEW_AREA, &new_area);
}


static void ue_conn_ctx_release_timeout_cb(void *ctx_)
{
	struct ranap_ue_conn_ctx *ctx = (struct ranap_ue_conn_ctx *)ctx_;
	global_iu_event(ctx, RANAP_IU_EVENT_IU_RELEASE, NULL);
}

static struct ranap_ue_conn_ctx *ue_conn_ctx_alloc(struct ranap_iu_rnc *rnc, uint32_t conn_id)
{
	struct ranap_ue_conn_ctx *ctx = talloc_zero(talloc_iu_ctx, struct ranap_ue_conn_ctx);

	ctx->rnc = rnc;
	ctx->conn_id = conn_id;
	ctx->notification = true;
	ctx->free_on_release = false;
	osmo_timer_setup(&ctx->release_timeout,
			 ue_conn_ctx_release_timeout_cb,
			 ctx);
	llist_add(&ctx->list, &ue_conn_ctx_list);

	return ctx;
}

static struct ranap_ue_conn_ctx *ue_conn_ctx_find(uint32_t conn_id)
{
	struct ranap_ue_conn_ctx *ctx;

	llist_for_each_entry(ctx, &ue_conn_ctx_list, list) {
		if (ctx->conn_id == conn_id)
			return ctx;
	}
	return NULL;
}

void ranap_iu_free_ue(struct ranap_ue_conn_ctx *ue_ctx)
{
	if (!ue_ctx)
		return;

	osmo_timer_del(&ue_ctx->release_timeout);
	osmo_sccp_tx_disconn(g_scu, ue_ctx->conn_id, NULL, 0);
	llist_del(&ue_ctx->list);
	talloc_free(ue_ctx);
}

static void ue_conn_sccp_addr_add(uint32_t conn_id, const struct osmo_sccp_addr *calling_addr)
{
	struct iu_new_ctx_entry *entry = talloc_zero(talloc_iu_ctx, struct iu_new_ctx_entry);

	entry->conn_id = conn_id;
	entry->sccp_addr = *calling_addr;

	llist_add(&entry->list, &ue_conn_sccp_addr_list);
}

static const struct osmo_sccp_addr *ue_conn_sccp_addr_find(uint32_t conn_id)
{
	struct iu_new_ctx_entry *entry;
	llist_for_each_entry(entry, &ue_conn_sccp_addr_list, list) {
		if (entry->conn_id == conn_id)
			return &entry->sccp_addr;
	}
	return NULL;
}

static void ue_conn_sccp_addr_del(uint32_t conn_id)
{
	struct iu_new_ctx_entry *entry;
	llist_for_each_entry(entry, &ue_conn_sccp_addr_list, list) {
		if (entry->conn_id == conn_id) {
			llist_del(&entry->list);
			talloc_free(entry);
			return;
		}
	}
}

static struct ranap_iu_rnc *iu_rnc_alloc(const struct osmo_rnc_id *rnc_id, struct osmo_sccp_addr *addr)
{
	struct ranap_iu_rnc *rnc = talloc_zero(talloc_iu_ctx, struct ranap_iu_rnc);
	OSMO_ASSERT(rnc);

	INIT_LLIST_HEAD(&rnc->lac_rac_list);

	rnc->rnc_id = *rnc_id;
	rnc->sccp_addr = *addr;
	llist_add(&rnc->entry, &rnc_list);

	LOGPIU(LOGL_NOTICE, "New RNC %s at %s\n", osmo_rnc_id_name(&rnc->rnc_id), osmo_sccp_addr_dump(addr));

	return rnc;
}

/* Find a match for the given LAC (and RAC). For CS, pass rac as 0.
 * If rnc and lre pointers are not NULL, *rnc / *lre are set to NULL if no match is found, or to the
 * match if a match is found.  Return true if a match is found. */
static bool iu_rnc_lac_rac_find(struct ranap_iu_rnc **rnc, struct iu_lac_rac_entry **lre,
				const struct osmo_routing_area_id *ra_id)
{
	struct ranap_iu_rnc *r;
	struct iu_lac_rac_entry *e;

	if (rnc)
		*rnc = NULL;
	if (lre)
		*lre = NULL;

	llist_for_each_entry(r, &rnc_list, entry) {
		llist_for_each_entry(e, &r->lac_rac_list, entry) {
			if (!osmo_rai_cmp(&e->rai, ra_id)) {
				if (rnc)
					*rnc = r;
				if (lre)
					*lre = e;
				return true;
			}
		}
	}
	return false;
}

/* legacy, do a first match with ignoring PLMN */
static bool iu_rnc_lac_rac_find_legacy(struct ranap_iu_rnc **rnc, struct iu_lac_rac_entry **lre,
				       uint16_t lac, uint8_t rac)
{
	struct ranap_iu_rnc *r;
	struct iu_lac_rac_entry *e;

	if (rnc)
		*rnc = NULL;
	if (lre)
		*lre = NULL;

	llist_for_each_entry(r, &rnc_list, entry) {
		llist_for_each_entry(e, &r->lac_rac_list, entry) {
			if (e->rai.lac.lac == lac && e->rai.rac == rac) {
				if (rnc)
					*rnc = r;
				if (lre)
					*lre = e;
				return true;
			}
		}
	}
	return false;
}

static struct ranap_iu_rnc *iu_rnc_id_find(struct osmo_rnc_id *rnc_id)
{
	struct ranap_iu_rnc *rnc;
	llist_for_each_entry(rnc, &rnc_list, entry) {
		if (!osmo_rnc_id_cmp(&rnc->rnc_id, rnc_id))
			return rnc;
	}
	return NULL;
}

static bool same_sccp_addr(struct osmo_sccp_addr *a, struct osmo_sccp_addr *b)
{
	char buf[256];
	osmo_strlcpy(buf, osmo_sccp_addr_dump(a), sizeof(buf));
	return !strcmp(buf, osmo_sccp_addr_dump(b));
}

static struct ranap_iu_rnc *iu_rnc_register(struct osmo_rnc_id *rnc_id,
					    const struct osmo_routing_area_id *rai,
					    struct osmo_sccp_addr *addr)
{
	struct ranap_iu_rnc *rnc;
	struct ranap_iu_rnc *old_rnc;
	struct iu_lac_rac_entry *lre;

	/* Make sure we know this rnc_id and that this SCCP address is in our records */
	rnc = iu_rnc_id_find(rnc_id);

	if (rnc) {
		if (!same_sccp_addr(&rnc->sccp_addr, addr)) {
			LOGPIU(LOGL_NOTICE, "RNC %s changed its SCCP addr to %s (LAC/RAC %s)\n",
			       osmo_rnc_id_name(rnc_id), osmo_sccp_addr_dump(addr), osmo_rai_name2(rai));
			rnc->sccp_addr = *addr;
		}
	} else
		rnc = iu_rnc_alloc(rnc_id, addr);

	/* Detect whether the LAC,RAC is already recorded in another RNC */
	iu_rnc_lac_rac_find(&old_rnc, &lre, rai);

	if (old_rnc && old_rnc != rnc) {
		/* LAC, RAC already exists in a different RNC */
		LOGPIU(LOGL_NOTICE, "LAC/RAC %s moved from RNC %s %s",
		       osmo_rai_name2(rai),
		       osmo_rnc_id_name(&old_rnc->rnc_id), osmo_sccp_addr_dump(&old_rnc->sccp_addr));
		LOGPIUC(LOGL_NOTICE, " to RNC %s %s\n",
			osmo_rnc_id_name(&rnc->rnc_id), osmo_sccp_addr_dump(&rnc->sccp_addr));

		llist_del(&lre->entry);
		llist_add(&lre->entry, &rnc->lac_rac_list);
		global_iu_event_new_area(rnc_id, rai);
	} else if (!old_rnc) {
		/* LAC, RAC not recorded yet */
		LOGPIU(LOGL_NOTICE, "RNC %s: new LAC/RAC %s\n", osmo_rnc_id_name(rnc_id), osmo_rai_name2(rai));
		lre = talloc_zero(rnc, struct iu_lac_rac_entry);
		lre->rai = *rai;
		llist_add(&lre->entry, &rnc->lac_rac_list);
		global_iu_event_new_area(rnc_id, rai);
	}
	/* else, LAC,RAC already recorded with the current RNC. */

	return rnc;
}

/***********************************************************************
 * RANAP handling
 ***********************************************************************/

int ranap_iu_rab_act(struct ranap_ue_conn_ctx *ue_ctx, struct msgb *msg)
{
	struct osmo_scu_prim *prim;

	/* wrap RANAP message in SCCP N-DATA.req */
	prim = (struct osmo_scu_prim *) msgb_push(msg, sizeof(*prim));
	prim->u.data.conn_id = ue_ctx->conn_id;
	osmo_prim_init(&prim->oph,
		       SCCP_SAP_USER,
		       OSMO_SCU_PRIM_N_DATA,
		       PRIM_OP_REQUEST,
		       msg);
	return osmo_sccp_user_sap_down(g_scu, &prim->oph);
}

int ranap_iu_rab_deact(struct ranap_ue_conn_ctx *ue_ctx, uint8_t rab_id)
{
	/* FIXME */
	return -1;
}

int ranap_iu_tx_sec_mode_cmd(struct ranap_ue_conn_ctx *uectx, struct osmo_auth_vector *vec,
			     int send_ck, int new_key)
{
	struct osmo_scu_prim *prim;
	struct msgb *msg;

	/* create RANAP message */
	msg = ranap_new_msg_sec_mod_cmd(vec->ik, send_ck ? vec->ck : NULL,
			new_key ? RANAP_KeyStatus_new : RANAP_KeyStatus_old);
	msg->l2h = msg->data;
	/* wrap RANAP message in SCCP N-DATA.req */
	prim = (struct osmo_scu_prim *) msgb_push(msg, sizeof(*prim));
	prim->u.data.conn_id = uectx->conn_id;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DATA,
			PRIM_OP_REQUEST, msg);
	return osmo_sccp_user_sap_down(g_scu, &prim->oph);
}

int ranap_iu_tx_common_id(struct ranap_ue_conn_ctx *uectx, const char *imsi)
{
	struct msgb *msg;
	struct osmo_scu_prim *prim;

	LOGPIU(LOGL_INFO, "Transmitting RANAP CommonID (SCCP conn_id %u)\n",
	       uectx->conn_id);

	msg = ranap_new_msg_common_id(imsi);
	msg->l2h = msg->data;
	prim = (struct osmo_scu_prim *) msgb_push(msg, sizeof(*prim));
	prim->u.data.conn_id = uectx->conn_id;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DATA,
			PRIM_OP_REQUEST, msg);
	return osmo_sccp_user_sap_down(g_scu, &prim->oph);
}

static int iu_grnc_id_parse(struct osmo_rnc_id *dst, struct RANAP_GlobalRNC_ID *src)
{
	/* The size is coming from arbitrary sender, check it gracefully */
	if (src->pLMNidentity.size != 3) {
		LOGPIU(LOGL_ERROR, "Invalid PLMN Identity size:"
		       " should be 3, is %d\n", src->pLMNidentity.size);
		return -1;
	}
	osmo_plmn_from_bcd(&src->pLMNidentity.buf[0], &dst->plmn);
	dst->rnc_id = (uint16_t)src->rNC_ID;
	return 0;
}

#if 0
/* not used at present */
static int iu_grnc_id_compose(struct iu_grnc_id *src, struct RANAP_GlobalRNC_ID *dst)
{
	/* The caller must ensure proper size */
	OSMO_ASSERT(dst->pLMNidentity.size == 3);
	gsm48_mcc_mnc_to_bcd(&dst->pLMNidentity.buf[0],
			     src->mcc, src->mnc);
	dst->rNC_ID = src->rnc_id;
	return 0;
}
#endif

struct new_ue_conn_ctx {
	struct osmo_sccp_addr sccp_addr;
	uint32_t conn_id;
};

static int ranap_handle_co_initial_ue(void *ctx, RANAP_InitialUE_MessageIEs_t *ies)
{
	struct new_ue_conn_ctx *new_ctx = ctx;
	struct gprs_ra_id ra_id = {};
	struct osmo_routing_area_id ra_id2 = {};
	struct osmo_rnc_id rnc_id = {};
	uint16_t sai;
	struct ranap_ue_conn_ctx *ue;
	struct msgb *msg = msgb_alloc(256, "RANAP->NAS");
	struct ranap_iu_rnc *rnc;

	if (ranap_parse_lai(&ra_id, &ies->lai) != 0) {
		LOGPIU(LOGL_ERROR, "Failed to parse RANAP LAI IE\n");
		return -1;
	}

	if (ies->presenceMask & INITIALUE_MESSAGEIES_RANAP_RAC_PRESENT) {
		ra_id.rac = asn1str_to_u8(&ies->rac);
		if (ra_id.rac == OSMO_RESERVED_RAC) {
			LOGPIU(LOGL_ERROR,
			       "Rejecting RNC with invalid/internally used RAC 0x%02x\n", ra_id.rac);
			return -1;
		}
	} else {
		ra_id.rac = OSMO_RESERVED_RAC;
	}

	if (iu_grnc_id_parse(&rnc_id, &ies->globalRNC_ID) != 0) {
		LOGPIU(LOGL_ERROR,
		       "Failed to parse RANAP Global-RNC-ID IE\n");
		return -1;
	}

	sai = asn1str_to_u16(&ies->sai.sAC);
	msgb_gmmh(msg) = msgb_put(msg, ies->nas_pdu.size);
	memcpy(msgb_gmmh(msg), ies->nas_pdu.buf, ies->nas_pdu.size);

	gprs_rai_to_osmo(&ra_id2, &ra_id);

	/* Make sure we know the RNC Id and LAC+RAC coming in on this connection. */
	rnc = iu_rnc_register(&rnc_id, &ra_id2, &new_ctx->sccp_addr);

	ue = ue_conn_ctx_alloc(rnc, new_ctx->conn_id);
	OSMO_ASSERT(ue);
	ue->ra_id = ra_id;

	/* Feed into the MM layer */
	msg->dst = ue;
	global_iu_recv_cb(msg, &ra_id, &sai);

	msgb_free(msg);

	return 0;
}

static int ranap_handle_co_dt(void *ctx, RANAP_DirectTransferIEs_t *ies)
{
	struct gprs_ra_id _ra_id, *ra_id = NULL;
	uint16_t _sai, *sai = NULL;
	struct msgb *msg = msgb_alloc(256, "RANAP->NAS");

	if (ies->presenceMask & DIRECTTRANSFERIES_RANAP_LAI_PRESENT) {
		if (ranap_parse_lai(&_ra_id, &ies->lai) != 0) {
			LOGPIU(LOGL_ERROR, "Failed to parse RANAP LAI IE\n");
			return -1;
		}
		ra_id = &_ra_id;
		if (ies->presenceMask & DIRECTTRANSFERIES_RANAP_RAC_PRESENT)
			_ra_id.rac = asn1str_to_u8(&ies->rac);

		if (ies->presenceMask & DIRECTTRANSFERIES_RANAP_SAI_PRESENT) {
			_sai = asn1str_to_u16(&ies->sai.sAC);
			sai = &_sai;
		}
	}

	msgb_gmmh(msg) = msgb_put(msg, ies->nas_pdu.size);
	memcpy(msgb_gmmh(msg), ies->nas_pdu.buf, ies->nas_pdu.size);

	/* Feed into the MM/CC/SMS-CP layer */
	msg->dst = ctx;
	global_iu_recv_cb(msg, ra_id, sai);

	msgb_free(msg);

	return 0;
}

static int ranap_handle_co_err_ind(void *ctx, RANAP_ErrorIndicationIEs_t *ies)
{
	if (ies->presenceMask & ERRORINDICATIONIES_RANAP_CAUSE_PRESENT)
		LOGPIU(LOGL_ERROR, "Rx Error Indication (%s)\n",
		       ranap_cause_str(&ies->cause));
	else
		LOGPIU(LOGL_ERROR, "Rx Error Indication\n");

	return 0;
}

int ranap_iu_tx(struct msgb *msg_nas, uint8_t sapi)
{
	struct ranap_ue_conn_ctx *uectx = msg_nas->dst;
	struct msgb *msg;
	struct osmo_scu_prim *prim;

	if (!uectx) {
		LOGPIU(LOGL_ERROR, "Discarding to-be-transmitted L3 Message as RANAP DT with unset dst SCCP conn_id!\n");
		return -ENOTCONN;
	}

	LOGPIU(LOGL_INFO, "Transmitting L3 Message as RANAP DT (SCCP conn_id %u)\n",
	       uectx->conn_id);

	msg = ranap_new_msg_dt(sapi, msg_nas->data, msgb_length(msg_nas));
	msgb_free(msg_nas);
	msg->l2h = msg->data;
	prim = (struct osmo_scu_prim *) msgb_push(msg, sizeof(*prim));
	prim->u.data.conn_id = uectx->conn_id;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DATA,
			PRIM_OP_REQUEST, msg);
	return osmo_sccp_user_sap_down(g_scu, &prim->oph);
}

/* Send Iu Release for the given UE connection.
 * If cause is NULL, Normal Release cause is sent, otherwise
 * the provided cause. */
int ranap_iu_tx_release(struct ranap_ue_conn_ctx *ctx, const struct RANAP_Cause *cause)
{
	struct msgb *msg;
	struct osmo_scu_prim *prim;
	static const struct RANAP_Cause default_cause = {
		.present = RANAP_Cause_PR_nAS,
		.choice.radioNetwork = RANAP_CauseNAS_normal_release,
	};

	if (!cause)
		cause = &default_cause;

	msg = ranap_new_msg_iu_rel_cmd(cause);
	msg->l2h = msg->data;
	prim = (struct osmo_scu_prim *) msgb_push(msg, sizeof(*prim));
	prim->u.data.conn_id = ctx->conn_id;
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_DATA,
			PRIM_OP_REQUEST, msg);
	return osmo_sccp_user_sap_down(g_scu, &prim->oph);
}

void ranap_iu_tx_release_free(struct ranap_ue_conn_ctx *ctx,
			     const struct RANAP_Cause *cause,
			     int timeout)
{
	ctx->notification = false;
	ctx->free_on_release = true;
	int ret = ranap_iu_tx_release(ctx, cause);
	/* On Tx failure, trigger timeout immediately, as the response will never arrive */
	if (ret)
		timeout = 0;

	osmo_timer_schedule(&ctx->release_timeout, timeout, 0);
}

static int ranap_handle_co_iu_rel_req(struct ranap_ue_conn_ctx *ctx, RANAP_Iu_ReleaseRequestIEs_t *ies)
{
	LOGPIU(LOGL_INFO, "Received Iu Release Request, Sending Release Command\n");
	ranap_iu_tx_release(ctx, &ies->cause);
	return 0;
}

static int ranap_handle_co_rab_ass_resp(struct ranap_ue_conn_ctx *ctx, RANAP_RAB_AssignmentResponseIEs_t *ies)
{
	int rc = -1;

	LOGPIU(LOGL_INFO,
	       "Rx RAB Assignment Response for UE conn_id %u\n", ctx->conn_id);
	if (ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_SETUPORMODIFIEDLIST_PRESENT) {
		/* TODO: Iterate over list of SetupOrModifiedList IEs and handle each one */
		RANAP_IE_t *ranap_ie = ies->raB_SetupOrModifiedList.raB_SetupOrModifiedList_ies.list.array[0];
		RANAP_RAB_SetupOrModifiedItemIEs_t setup_ies;

		rc = ranap_decode_rab_setupormodifieditemies_fromlist(&setup_ies, &ranap_ie->value);
		if (rc) {
			LOGPIU(LOGL_ERROR, "Error in ranap_decode_rab_setupormodifieditemies()\n");
			return rc;
		}

		rc = global_iu_event(ctx, RANAP_IU_EVENT_RAB_ASSIGN, &setup_ies);

		ranap_free_rab_setupormodifieditemies(&setup_ies);
	}
	/* FIXME: handle RAB Ass failure? */

	return rc;
}

static void cn_ranap_handle_co_initial(void *ctx, ranap_message *message)
{
	int rc;

	LOGPIU(LOGL_NOTICE, "handle_co_initial(dir=%u, proc=%u)\n", message->direction, message->procedureCode);

	if (message->direction != RANAP_RANAP_PDU_PR_initiatingMessage
	    || message->procedureCode != RANAP_ProcedureCode_id_InitialUE_Message) {
		LOGPIU(LOGL_ERROR, "Expected direction 'InitiatingMessage',"
		       " procedureCode 'InitialUE_Message', instead got %u and %u\n",
		       message->direction, message->procedureCode);
		rc = -1;
	} else
		rc = ranap_handle_co_initial_ue(ctx, &message->msg.initialUE_MessageIEs);

	if (rc) {
		LOGPIU(LOGL_ERROR, "Error in %s (%d)\n", __func__, rc);
		/* TODO handling of the error? */
	}
}

/* Entry point for connection-oriented RANAP message */
static void cn_ranap_handle_co(void *ctx, ranap_message *message)
{
	int rc;

	LOGPIU(LOGL_NOTICE, "handle_co(dir=%u, proc=%u)\n", message->direction, message->procedureCode);

	switch (message->direction) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		switch (message->procedureCode) {
		case RANAP_ProcedureCode_id_InitialUE_Message:
			LOGPIU(LOGL_ERROR, "Got InitialUE_Message but this is not a new conn\n");
			rc = -1;
			break;
		case RANAP_ProcedureCode_id_DirectTransfer:
			rc = ranap_handle_co_dt(ctx, &message->msg.directTransferIEs);
			break;
		case RANAP_ProcedureCode_id_ErrorIndication:
			rc = ranap_handle_co_err_ind(ctx, &message->msg.errorIndicationIEs);
			break;
		case RANAP_ProcedureCode_id_Iu_ReleaseRequest:
			/* Iu Release Request */
			rc = ranap_handle_co_iu_rel_req(ctx, &message->msg.iu_ReleaseRequestIEs);
			break;
		default:
			LOGPIU(LOGL_ERROR, "Received Initiating Message: unknown Procedure Code %d\n",
			       message->procedureCode);
			rc = -1;
			break;
		}
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		switch (message->procedureCode) {
		case RANAP_ProcedureCode_id_SecurityModeControl:
			/* Security Mode Complete */
			rc = global_iu_event(ctx, RANAP_IU_EVENT_SECURITY_MODE_COMPLETE, NULL);
			break;
		case RANAP_ProcedureCode_id_Iu_Release:
			/* Iu Release Complete */
			rc = global_iu_event(ctx, RANAP_IU_EVENT_IU_RELEASE, NULL);
			if (rc) {
				LOGPIU(LOGL_ERROR, "Iu Release event: Iu Event callback returned %d\n",
				       rc);
			}
			break;
		default:
			LOGPIU(LOGL_ERROR, "Received Successful Outcome: unknown Procedure Code %d\n",
			       message->procedureCode);
			rc = -1;
			break;
		}
		break;
	case RANAP_RANAP_PDU_PR_outcome:
		switch (message->procedureCode) {
		case RANAP_ProcedureCode_id_RAB_Assignment:
			/* RAB Assignment Response */
			rc = ranap_handle_co_rab_ass_resp(ctx, &message->msg.raB_AssignmentResponseIEs);
			break;
		default:
			LOGPIU(LOGL_ERROR, "Received Outcome: unknown Procedure Code %d\n",
			       message->procedureCode);
			rc = -1;
			break;
		}
		break;
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
	default:
		LOGPIU(LOGL_ERROR, "Received Unsuccessful Outcome: Procedure Code %d\n",
		       message->procedureCode);
		rc = -1;
		break;
	}

	if (rc) {
		LOGPIU(LOGL_ERROR, "Error in %s (%d)\n", __func__, rc);
		/* TODO handling of the error? */
	}
}

static int ranap_handle_cl_reset_req(void *ctx, RANAP_ResetIEs_t *ies)
{
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) ctx;
	struct osmo_scu_unitdata_param *ud_prim = &prim->u.unitdata;
	RANAP_GlobalRNC_ID_t *grnc_id = NULL;
	struct msgb *resp;

	OSMO_ASSERT(prim->oph.primitive == OSMO_SCU_PRIM_N_UNITDATA);

	/* FIXME: verify ies.cN_DomainIndicator */

	if (ies->presenceMask & RESETIES_RANAP_GLOBALRNC_ID_PRESENT)
		grnc_id = &ies->globalRNC_ID;

	/* send reset response */
	resp = ranap_new_msg_reset_ack(ies->cN_DomainIndicator, grnc_id);
	if (!resp)
		return -ENOMEM;
	resp->l2h = resp->data;
	return osmo_sccp_tx_unitdata_msg(g_scu, &g_local_sccp_addr, &ud_prim->calling_addr, resp);
}

static int ranap_handle_cl_err_ind(void *ctx, RANAP_ErrorIndicationIEs_t *ies)
{
	if (ies->presenceMask & ERRORINDICATIONIES_RANAP_CAUSE_PRESENT)
		LOGPIU(LOGL_ERROR, "Rx Error Indication (%s)\n",
		       ranap_cause_str(&ies->cause));
	else
		LOGPIU(LOGL_ERROR, "Rx Error Indication\n");

	return 0;
}

/* Entry point for connection-less RANAP message */
static void cn_ranap_handle_cl(void *ctx, ranap_message *message)
{
	int rc;

	switch (message->direction) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		switch (message->procedureCode) {
		case RANAP_ProcedureCode_id_Reset:
			/* received reset.req, send reset.resp */
			rc = ranap_handle_cl_reset_req(ctx, &message->msg.resetIEs);
			break;
		case RANAP_ProcedureCode_id_ErrorIndication:
			rc = ranap_handle_cl_err_ind(ctx, &message->msg.errorIndicationIEs);
			break;
		default:
			rc = -1;
			break;
		}
		break;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
	case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
	case RANAP_RANAP_PDU_PR_outcome:
	default:
		rc = -1;
		break;
	}

	if (rc) {
		LOGPIU(LOGL_ERROR, "Error in %s (%d)\n", __func__, rc);
		/* TODO handling of the error? */
	}
}

/***********************************************************************
 * Paging
 ***********************************************************************/

/* Send a paging command down a given SCCP User. tmsi and paging_cause are
 * optional and may be passed NULL and 0, respectively, to disable their use.
 * See enum RANAP_PagingCause.
 *
 * If TMSI is given, the IMSI is not sent over the air interface. Nevertheless,
 * the IMSI is still required for resolution in the HNB-GW and/or(?) RNC. */
static int iu_tx_paging_cmd(struct osmo_sccp_addr *called_addr,
			    const char *imsi, const uint32_t *tmsi,
			    bool is_ps, uint32_t paging_cause)
{
	struct msgb *msg;
	msg = ranap_new_msg_paging_cmd(imsi, tmsi, is_ps ? 1 : 0, paging_cause);
	msg->l2h = msg->data;
	return osmo_sccp_tx_unitdata_msg(g_scu, &g_local_sccp_addr, called_addr, msg);
}

static int iu_page(const char *imsi, const uint32_t *tmsi_or_ptmsi,
		   uint16_t lac, uint8_t rac, bool is_ps)
{
	struct ranap_iu_rnc *rnc;
	const char *log_msg;
	int log_level;
	int paged = 0;

	iu_rnc_lac_rac_find_legacy(&rnc, NULL, lac, rac);
	if (rnc) {
		if (iu_tx_paging_cmd(&rnc->sccp_addr, imsi, tmsi_or_ptmsi, is_ps, 0) == 0) {
			log_msg = "Paging";
			log_level = LOGL_DEBUG;
			paged = 1;
		} else {
			log_msg = "Paging failed";
			log_level = LOGL_ERROR;
		}
	} else {
		log_msg = "Found no RNC to Page";
		log_level = LOGL_ERROR;
	}

	if (is_ps)
		LOGPIU(log_level, "IuPS: %s on LAC %d RAC %d", log_msg, lac, rac);
	else
		LOGPIU(log_level, "IuCS: %s on LAC %d", log_msg, lac);
	if (rnc)
		LOGPIUC(log_level, " at SCCP-addr %s", osmo_sccp_addr_dump(&rnc->sccp_addr));
	if (tmsi_or_ptmsi)
		LOGPIUC(log_level, ", for %s %08x\n", is_ps ? "PTMSI" : "TMSI", *tmsi_or_ptmsi);
	else
		LOGPIUC(log_level, ", for IMSI %s\n", imsi);

	return paged;
}

/*! Old paging() doesn't use PLMN and transmit paging command only to the first RNC  */
int ranap_iu_page_cs(const char *imsi, const uint32_t *tmsi, uint16_t lac)
{
	return iu_page(imsi, tmsi, lac, 0, false);
}

/*! Old paging() doesn't use PLMN and transmit paging command only to the first RNC  */
int ranap_iu_page_ps(const char *imsi, const uint32_t *ptmsi, uint16_t lac, uint8_t rac)
{
	return iu_page(imsi, ptmsi, lac, rac, true);
}

/*! Transmit a single page request towards all RNCs serving the specific LAI (no page retransmission).
 *
 * \param imsi the imsi as human readable string
 * \param tmsi NULL or pointer to the tmsi
 * \param lai full Location Area Identifier
 * \return amount of paged RNCs. 0 when no RNC found.
 */
int ranap_iu_page_cs2(const char *imsi, const uint32_t *tmsi, const struct osmo_location_area_id *lai)
{
	struct ranap_iu_rnc *rnc;
	struct iu_lac_rac_entry *entry;
	char log_msg[32] = {};
	int paged = 0;
	int rc = 0;

	/* find all RNCs which are serving this LA */
	llist_for_each_entry(rnc, &rnc_list, entry) {
		llist_for_each_entry(entry, &rnc->lac_rac_list, entry) {
			if (osmo_lai_cmp(&entry->rai.lac, lai))
				continue;

			rc = iu_tx_paging_cmd(&rnc->sccp_addr, imsi, tmsi, false, 0);
			if (rc > 0) {
				LOGPIU(LOGL_ERROR, "IuCS: Failed to tx Paging RNC %s for LAC %s for IMSI %s / TMSI %08x",
				       osmo_rnc_id_name(&rnc->rnc_id),
				       osmo_lai_name(lai), imsi, tmsi ? *tmsi : GSM_RESERVED_TMSI);
			}
			paged++;
			break;
		}
	}

	if (tmsi)
		snprintf(log_msg, sizeof(log_msg), "for TMSI %08x\n", *tmsi);
	else
		snprintf(log_msg, sizeof(log_msg) - 1, "for IMSI %s\n", imsi);

	if (paged)
		LOGPIU(LOGL_DEBUG, "IuPS: Paged %d RNCs on LAI %s for %s", paged, osmo_lai_name(lai), log_msg);
	else
		LOGPIU(LOGL_INFO, "IuPS: Found no RNC to Page on LAI %s for %s", osmo_lai_name(lai), log_msg);


	return paged;
}

/*! Transmit a single page request towards all RNCs serving the specific RAI (no page retransmission).
 *
 * \param imsi the imsi as human readable string
 * \param ptmsi NULL or pointer to the tmsi
 * \param rai full Location Area Identifier
 * \return amount of paged RNCs. 0 when no RNC found.
 */
int ranap_iu_page_ps2(const char *imsi, const uint32_t *ptmsi, const struct osmo_routing_area_id *rai)
{
	struct ranap_iu_rnc *rnc;
	struct iu_lac_rac_entry *entry;
	char log_msg[32] = {};
	int paged = 0;
	int rc = 0;

	/* find all RNCs which are serving this RAC */
	llist_for_each_entry(rnc, &rnc_list, entry) {
		llist_for_each_entry(entry, &rnc->lac_rac_list, entry) {
			if (osmo_rai_cmp(&entry->rai, rai))
				continue;

			rc = iu_tx_paging_cmd(&rnc->sccp_addr, imsi, ptmsi, true, 0);
			if (rc > 0) {
				LOGPIU(LOGL_ERROR, "IuPS: Failed to tx Paging RNC %s for RAC %s for IMSI %s / P-TMSI %08x",
				       osmo_rnc_id_name(&rnc->rnc_id),
				       osmo_rai_name2(rai), imsi, ptmsi ? *ptmsi : GSM_RESERVED_TMSI);
			}
			paged++;
			break;
		}
	}

	if (ptmsi)
		snprintf(log_msg, sizeof(log_msg) - 1, "for PTMSI %08x\n", *ptmsi);
	else
		snprintf(log_msg, sizeof(log_msg) - 1, "for IMSI %s\n", imsi);

	if (paged)
		LOGPIU(LOGL_DEBUG, "IuPS: Paged %d RNCs on RAI %s for %s", paged, osmo_rai_name2(rai), log_msg);
	else
		LOGPIU(LOGL_INFO, "IuPS: Found no RNC to Page on RAI %s for %s", osmo_rai_name2(rai), log_msg);

	return paged;
}

/***********************************************************************
 *
 ***********************************************************************/

int tx_unitdata(struct osmo_sccp_user *scu);
int tx_conn_req(struct osmo_sccp_user *scu, uint32_t conn_id);

struct osmo_prim_hdr *make_conn_req(uint32_t conn_id);
struct osmo_prim_hdr *make_dt1_req(uint32_t conn_id, const uint8_t *data, unsigned int len);

static struct osmo_prim_hdr *make_conn_resp(struct osmo_scu_connect_param *param)
{
	struct msgb *msg = msgb_alloc(1024, "conn_resp");
	struct osmo_scu_prim *prim;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_CONNECT,
			PRIM_OP_RESPONSE, msg);
	memcpy(&prim->u.connect, param, sizeof(prim->u.connect));
	return &prim->oph;
}

static void ue_ctx_link_invalidated_free(struct ranap_ue_conn_ctx *ue)
{
	uint32_t conn_id = ue->conn_id;
	global_iu_event(ue, RANAP_IU_EVENT_LINK_INVALIDATED, NULL);

	/* A RANAP_IU_EVENT_LINK_INVALIDATED, can lead to a free */
	ue = ue_conn_ctx_find(conn_id);
	if (!ue)
		return;
	if (ue->free_on_release)
		ranap_iu_free_ue(ue);
}

static void handle_notice_ind(struct osmo_ss7_instance *cs7, const struct osmo_scu_notice_param *ni)
{
	struct ranap_iu_rnc *rnc;

	LOGPIU(LOGL_DEBUG, "(calling_addr=%s) N-NOTICE.ind cause=%u='%s' importance=%u\n",
	       osmo_sccp_addr_dump(&ni->calling_addr),
	       ni->cause, osmo_sccp_return_cause_name(ni->cause),
	       ni->importance);

	switch (ni->cause) {
	case SCCP_RETURN_CAUSE_SUBSYSTEM_CONGESTION:
	case SCCP_RETURN_CAUSE_NETWORK_CONGESTION:
		/* Transient failures (hopefully), keep going. */
		return;
	default:
		break;
	}

	/* Messages are not arriving to RNC. Signal to user that all related ue_ctx are invalid. */
	llist_for_each_entry(rnc, &rnc_list, entry) {
		struct ranap_ue_conn_ctx *ue_ctx, *ue_ctx_tmp;
		if (osmo_sccp_addr_ri_cmp(&rnc->sccp_addr, &ni->calling_addr))
			continue;
		LOGPIU(LOGL_NOTICE,
		       "RNC %s now unreachable: N-NOTICE.ind cause=%u='%s' importance=%u\n",
		       osmo_rnc_id_name(&rnc->rnc_id),
		       ni->cause, osmo_sccp_return_cause_name(ni->cause),
		       ni->importance);
		llist_for_each_entry_safe(ue_ctx, ue_ctx_tmp, &ue_conn_ctx_list, list) {
			if (ue_ctx->rnc != rnc)
				continue;
			ue_ctx_link_invalidated_free(ue_ctx);
		}
		/* TODO: ideally we'd have some event to submit to upper
		 * layer to inform about peer availability change... */
	}
}

static void handle_pcstate_ind(struct osmo_ss7_instance *cs7, const struct osmo_scu_pcstate_param *pcst)
{
	struct osmo_sccp_addr rem_addr;
	struct ranap_iu_rnc *rnc;
	bool connected;
	bool disconnected;

	LOGPIU(LOGL_DEBUG, "N-PCSTATE ind: affected_pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
	       pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
	       osmo_sccp_sp_status_name(pcst->sp_status),
	       osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));

	osmo_sccp_make_addr_pc_ssn(&rem_addr, pcst->affected_pc, OSMO_SCCP_SSN_RANAP);

	/* See if this marks the point code to have become available, or to have been lost.
	 *
	 * I want to detect two events:
	 * - connection event (both indicators say PC is reachable).
	 * - disconnection event (at least one indicator says the PC is not reachable).
	 *
	 * There are two separate incoming indicators with various possible values -- the incoming events can be:
	 *
	 * - neither connection nor disconnection indicated -- just indicating congestion
	 *   connected == false, disconnected == false --> do nothing.
	 * - both incoming values indicate that we are connected
	 *   --> trigger connected
	 * - both indicate we are disconnected
	 *   --> trigger disconnected
	 * - one value indicates 'connected', the other indicates 'disconnected'
	 *   --> trigger disconnected
	 *
	 * Congestion could imply that we're connected, but it does not indicate
	 * that a PC's reachability changed, so no need to trigger on that.
	 */
	connected = false;
	disconnected = false;

	switch (pcst->sp_status) {
	case OSMO_SCCP_SP_S_ACCESSIBLE:
		connected = true;
		break;
	case OSMO_SCCP_SP_S_INACCESSIBLE:
		disconnected = true;
		break;
	default:
	case OSMO_SCCP_SP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	switch (pcst->remote_sccp_status) {
	case OSMO_SCCP_REM_SCCP_S_AVAILABLE:
		if (!disconnected)
			connected = true;
		break;
	case OSMO_SCCP_REM_SCCP_S_UNAVAILABLE_UNKNOWN:
	case OSMO_SCCP_REM_SCCP_S_UNEQUIPPED:
	case OSMO_SCCP_REM_SCCP_S_INACCESSIBLE:
		disconnected = true;
		connected = false;
		break;
	default:
	case OSMO_SCCP_REM_SCCP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	if (disconnected) {
		/* A previously usable RNC has disconnected. Signal to user that all related ue_ctx are invalid. */
		llist_for_each_entry(rnc, &rnc_list, entry) {
			struct ranap_ue_conn_ctx *ue_ctx, *ue_ctx_tmp;
			if (osmo_sccp_addr_cmp(&rnc->sccp_addr, &rem_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
				continue;
			LOGPIU(LOGL_NOTICE,
			       "RNC %s now unreachable: N-PCSTATE ind: pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
			       osmo_rnc_id_name(&rnc->rnc_id),
			       pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
			       osmo_sccp_sp_status_name(pcst->sp_status),
			       osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
			llist_for_each_entry_safe(ue_ctx, ue_ctx_tmp, &ue_conn_ctx_list, list) {
				if (ue_ctx->rnc != rnc)
					continue;
				ue_ctx_link_invalidated_free(ue_ctx);
			}
			/* TODO: ideally we'd have some event to submit to upper
			 * layer to inform about peer availability change... */
		}
	} else if (connected) {
		llist_for_each_entry(rnc, &rnc_list, entry) {
			if (osmo_sccp_addr_cmp(&rnc->sccp_addr, &rem_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
				continue;
			LOGPIU(LOGL_NOTICE,
			       "RNC %s now available: N-PCSTATE ind: pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
			       osmo_rnc_id_name(&rnc->rnc_id),
			       pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
			       osmo_sccp_sp_status_name(pcst->sp_status),
			       osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
			/* TODO: ideally we'd have some event to submit to upper
			 * layer to inform about peer availability change... */
		}
	}
}

static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu = _scu;
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct osmo_sccp_instance *sccp = osmo_sccp_get_sccp(scu);
	struct osmo_prim_hdr *resp = NULL;
	int rc = -1;
	struct ranap_ue_conn_ctx *ue;
	struct new_ue_conn_ctx new_ctx = {};
	uint32_t conn_id;

	LOGPIU(LOGL_DEBUG, "sccp_sap_up(%s)\n", osmo_scu_prim_name(oph));

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		/* confirmation of outbound connection */
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* indication of new inbound connection request*/
		conn_id = prim->u.connect.conn_id;
		LOGPIU(LOGL_DEBUG, "N-CONNECT.ind(X->%u)\n", conn_id);

		new_ctx.sccp_addr = prim->u.connect.calling_addr;
		new_ctx.conn_id = conn_id;

		/* first ensure the local SCCP socket is ACTIVE */
		resp = make_conn_resp(&prim->u.connect);
		osmo_sccp_user_sap_down(scu, resp);
		/* then handle the RANAP payload */
		if (/*  prim->u.connect.called_addr.ssn != OSMO_SCCP_SSN_RANAP || */
		    !msgb_l2(oph->msg) || msgb_l2len(oph->msg) == 0) {
			LOGPIU(LOGL_DEBUG,
			     "Received N-CONNECT.ind without data\n");
			ue_conn_sccp_addr_add(conn_id, &prim->u.connect.calling_addr);
		} else {
			rc = ranap_cn_rx_co(cn_ranap_handle_co_initial, &new_ctx, msgb_l2(oph->msg), msgb_l2len(oph->msg));
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		/* indication of disconnect */
		conn_id = prim->u.disconnect.conn_id;
		LOGPIU(LOGL_DEBUG, "N-DISCONNECT.ind(%u)\n", conn_id);

		ue_conn_sccp_addr_del(conn_id);
		ue = ue_conn_ctx_find(conn_id);
		if (!ue)
			break;

		rc = 0;
		if (msgb_l2len(oph->msg) > 0)
			rc = ranap_cn_rx_co(cn_ranap_handle_co, ue, msgb_l2(oph->msg), msgb_l2len(oph->msg));

		/* A Iu Release event might be used to free the UE in cn_ranap_handle_co. */
		ue = ue_conn_ctx_find(conn_id);
		if (!ue)
			break;
		ue_ctx_link_invalidated_free(ue);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* connection-oriented data received */
		conn_id = prim->u.data.conn_id;
		LOGPIU(LOGL_DEBUG, "N-DATA.ind(%u, %s)\n", conn_id,
		       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));

		/* resolve UE context */
		ue = ue_conn_ctx_find(conn_id);
		if (!ue) {
			/* Could be an InitialUE-Message after an empty CR, recreate new_ctx */
			const struct osmo_sccp_addr *sccp_addr = ue_conn_sccp_addr_find(conn_id);
			if (!sccp_addr) {
				LOGPIU(LOGL_NOTICE,
				       "N-DATA.ind for unknown conn_id (%u)\n", conn_id);
				break;
			}
			new_ctx.conn_id = conn_id;
			new_ctx.sccp_addr = *sccp_addr;
			ue_conn_sccp_addr_del(conn_id);
			rc = ranap_cn_rx_co(cn_ranap_handle_co_initial, &new_ctx, msgb_l2(oph->msg), msgb_l2len(oph->msg));
			break;
		}

		rc = ranap_cn_rx_co(cn_ranap_handle_co, ue, msgb_l2(oph->msg), msgb_l2len(oph->msg));
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* connection-less data received */
		LOGPIU(LOGL_DEBUG, "N-UNITDATA.ind(%s)\n",
		       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		rc = ranap_cn_rx_cl(cn_ranap_handle_cl, prim, msgb_l2(oph->msg), msgb_l2len(oph->msg));
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_NOTICE, PRIM_OP_INDICATION):
		LOGPIU(LOGL_DEBUG, "N-NOTICE.ind(%s)\n",
		       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		handle_notice_ind(osmo_sccp_get_ss7(sccp), &prim->u.notice);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_PCSTATE, PRIM_OP_INDICATION):
		handle_pcstate_ind(osmo_sccp_get_ss7(sccp), &prim->u.pcstate);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_STATE, PRIM_OP_INDICATION):
		LOGPIU(LOGL_DEBUG, "SCCP-User-SAP: Ignoring %s.%s\n",
		       osmo_scu_prim_type_name(oph->primitive),
		       get_value_string(osmo_prim_op_names, oph->operation));
		break;
	default:
		break;
	}

	msgb_free(oph->msg);
	return rc;
}

int ranap_iu_init(void *ctx, int log_subsystem, const char *sccp_user_name, struct osmo_sccp_instance *sccp,
		  ranap_iu_recv_cb_t iu_recv_cb, ranap_iu_event_cb_t iu_event_cb)
{
	iu_log_subsystem = log_subsystem;
	talloc_iu_ctx = talloc_named_const(ctx, 1, "iu");
	talloc_asn1_ctx = talloc_named_const(talloc_iu_ctx, 1, "asn1");

	global_iu_recv_cb = iu_recv_cb;
	global_iu_event_cb = iu_event_cb;
	g_sccp = sccp;
	osmo_sccp_local_addr_by_instance(&g_local_sccp_addr, sccp, OSMO_SCCP_SSN_RANAP);
	g_scu = osmo_sccp_user_bind(g_sccp, sccp_user_name, sccp_sap_up, OSMO_SCCP_SSN_RANAP);

	return 0;
}
