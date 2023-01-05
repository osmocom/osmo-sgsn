/* GPRS SGSN functionality */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsup.h>

#include <osmocom/sgsn/gprs_subscriber.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_sgsn.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_sm.h>
#include <osmocom/sgsn/gprs_utils.h>
#include <osmocom/sgsn/signal.h>
#include <osmocom/sgsn/gprs_gmm_attach.h>
#include <osmocom/sgsn/gprs_mm_state_gb_fsm.h>
#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>
#include <osmocom/sgsn/gprs_gmm_fsm.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_sndcp.h>
#include <osmocom/sgsn/gtp_ggsn.h>
#include <osmocom/sgsn/gtp.h>

#include <pdp.h>

#include <time.h>

#include "../../bscconfig.h"

#define GPRS_LLME_CHECK_TICK 30

extern struct sgsn_instance *sgsn;
extern void *tall_sgsn_ctx;
extern struct osmo_tdef sgsn_T_defs[];

LLIST_HEAD(sgsn_mm_ctxts);
LLIST_HEAD(sgsn_pdp_ctxts);

const struct value_string sgsn_ran_type_names[] = {
	{ MM_CTX_T_GERAN_Gb, "GPRS/EDGE via Gb" },
	{ MM_CTX_T_UTRAN_Iu, "UMTS via Iu" },
#if 0
	{ MM_CTX_T_GERAN_Iu, "GPRS/EDGE via Iu" },
#endif
	{ 0, NULL }
};

static const struct rate_ctr_desc mmctx_ctr_description[] = {
	{ "sign:packets:in",	"Signalling Messages ( In)" },
	{ "sign:packets:out",	"Signalling Messages (Out)" },
	{ "udata:packets:in",	"User Data  Messages ( In)" },
	{ "udata:packets:out",	"User Data  Messages (Out)" },
	{ "udata:bytes:in",	"User Data  Bytes    ( In)" },
	{ "udata:bytes:out",	"User Data  Bytes    (Out)" },
	{ "pdp_ctx_act",	"PDP Context Activations  " },
	{ "suspend",		"SUSPEND Count            " },
	{ "paging:ps",		"Paging Packet Switched   " },
	{ "paging:cs",		"Paging Circuit Switched  " },
	{ "ra_update",		"Routing Area Update      " },
};

static const struct rate_ctr_group_desc mmctx_ctrg_desc = {
	.group_name_prefix = "sgsn:mmctx",
	.group_description = "SGSN MM Context Statistics",
	.num_ctr = ARRAY_SIZE(mmctx_ctr_description),
	.ctr_desc = mmctx_ctr_description,
	.class_id = OSMO_STATS_CLASS_SUBSCRIBER,
};

static const struct rate_ctr_desc pdpctx_ctr_description[] = {
	{ "udata:packets:in",	"User Data  Messages ( In)" },
	{ "udata:packets:out",	"User Data  Messages (Out)" },
	{ "udata:bytes:in",	"User Data  Bytes    ( In)" },
	{ "udata:bytes:out",	"User Data  Bytes    (Out)" },
};

static const struct rate_ctr_group_desc pdpctx_ctrg_desc = {
	.group_name_prefix = "sgsn:pdpctx",
	.group_description = "SGSN PDP Context Statistics",
	.num_ctr = ARRAY_SIZE(pdpctx_ctr_description),
	.ctr_desc = pdpctx_ctr_description,
	.class_id = OSMO_STATS_CLASS_SUBSCRIBER,
};

static const struct rate_ctr_desc sgsn_ctr_description[] = {
	{ "llc:dl_bytes", "Count sent LLC bytes before giving it to the bssgp layer" },
	{ "llc:ul_bytes", "Count successful received LLC bytes (encrypt & fcs correct)" },
	{ "llc:dl_packets", "Count successful sent LLC packets before giving it to the bssgp layer" },
	{ "llc:ul_packets", "Count successful received LLC packets (encrypt & fcs correct)" },
	{ "gprs:attach_requested", "Received attach requests" },
	{ "gprs:attach_accepted", "Sent attach accepts" },
	{ "gprs:attach_rejected", "Sent attach rejects" },
	{ "gprs:detach_requested", "Received detach requests" },
	{ "gprs:detach_acked", "Sent detach acks" },
	{ "gprs:routing_area_requested", "Received routing area requests" },
	{ "gprs:routing_area_requested", "Sent routing area acks" },
	{ "gprs:routing_area_requested", "Sent routing area rejects" },
	{ "pdp:activate_requested", "Received activate requests" },
	{ "pdp:activate_rejected", "Sent activate rejects" },
	{ "pdp:activate_accepted", "Sent activate accepts" },
	{ "pdp:request_activated", "unused" },
	{ "pdp:request_activate_rejected", "unused" },
	{ "pdp:modify_requested", "unused" },
	{ "pdp:modify_accepted", "unused" },
	{ "pdp:dl_deactivate_requested", "Sent deactivate requests" },
	{ "pdp:dl_deactivate_accepted", "Sent deactivate accepted" },
	{ "pdp:ul_deactivate_requested", "Received deactivate requests" },
	{ "pdp:ul_deactivate_accepted", "Received deactivate accepts" },
};

static const struct rate_ctr_group_desc sgsn_ctrg_desc = {
	"sgsn",
	"SGSN Overall Statistics",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(sgsn_ctr_description),
	sgsn_ctr_description,
};

/* look-up an SGSN MM context based on Iu UE context (struct ue_conn_ctx)*/
struct sgsn_mm_ctx *sgsn_mm_ctx_by_ue_ctx(const void *uectx)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if (ctx->ran_type == MM_CTX_T_UTRAN_Iu
		    && uectx == ctx->iu.ue_ctx)
			return ctx;
	}

	return NULL;
}

/* look-up a SGSN MM context based on TLLI + RAI */
struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli(uint32_t tlli,
					const struct gprs_ra_id *raid)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if ((tlli == ctx->gb.tlli || tlli == ctx->gb.tlli_new) &&
		    gprs_ra_id_equals(raid, &ctx->ra))
			return ctx;
	}

	return NULL;
}

struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli_and_ptmsi(uint32_t tlli,
					const struct gprs_ra_id *raid)
{
	struct sgsn_mm_ctx *ctx;
	int tlli_type;

	/* TODO: Also check the P_TMSI signature to be safe. That signature
	 * should be different (at least with a sufficiently high probability)
	 * after SGSN restarts and for multiple SGSN instances.
	 */

	tlli_type = gprs_tlli_type(tlli);
	if (tlli_type != TLLI_FOREIGN && tlli_type != TLLI_LOCAL)
		return NULL;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if ((gprs_tmsi2tlli(ctx->p_tmsi, tlli_type) == tlli ||
		     gprs_tmsi2tlli(ctx->p_tmsi_old, tlli_type) == tlli) &&
		    gprs_ra_id_equals(raid, &ctx->ra))
			return ctx;
	}

	return NULL;
}

struct sgsn_mm_ctx *sgsn_mm_ctx_by_ptmsi(uint32_t p_tmsi)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if (p_tmsi == ctx->p_tmsi ||
		    (ctx->p_tmsi_old && ctx->p_tmsi_old == p_tmsi))
			return ctx;
	}
	return NULL;
}

struct sgsn_mm_ctx *sgsn_mm_ctx_by_imsi(const char *imsi)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if (!strcmp(imsi, ctx->imsi))
			return ctx;
	}
	return NULL;

}

/* Allocate a new SGSN MM context, generic part */
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc(uint32_t rate_ctr_id)
{
	struct sgsn_mm_ctx *ctx;

	ctx = talloc_zero(tall_sgsn_ctx, struct sgsn_mm_ctx);
	if (!ctx)
		return NULL;

	ctx->auth_triplet.key_seq = GSM_KEY_SEQ_INVAL;
	ctx->ctrg = rate_ctr_group_alloc(ctx, &mmctx_ctrg_desc, rate_ctr_id);
	if (!ctx->ctrg) {
		LOGMMCTXP(LOGL_ERROR, ctx, "Cannot allocate counter group\n");
		talloc_free(ctx);
		return NULL;
	}

	ctx->gmm_fsm = osmo_fsm_inst_alloc(&gmm_fsm, ctx, ctx, LOGL_DEBUG, "gmm_fsm");
	if (!ctx->gmm_fsm)
		goto out;
	ctx->gmm_att_req.fsm = osmo_fsm_inst_alloc(&gmm_attach_req_fsm, ctx, ctx, LOGL_DEBUG, "gb_gmm_req");
	if (!ctx->gmm_att_req.fsm)
		goto out;
	ctx->gb.mm_state_fsm = osmo_fsm_inst_alloc(&mm_state_gb_fsm, ctx, ctx, LOGL_DEBUG, NULL);
	if (!ctx->gb.mm_state_fsm)
		goto out;
#ifdef BUILD_IU
	ctx->iu.mm_state_fsm = osmo_fsm_inst_alloc(&mm_state_iu_fsm, ctx, ctx, LOGL_DEBUG, NULL);
	if (!ctx->iu.mm_state_fsm)
		goto out;
#endif

	INIT_LLIST_HEAD(&ctx->pdp_list);

	llist_add(&ctx->list, &sgsn_mm_ctxts);

	return ctx;

out:
	if (ctx->iu.mm_state_fsm)
		osmo_fsm_inst_free(ctx->iu.mm_state_fsm);
	if (ctx->gb.mm_state_fsm)
		osmo_fsm_inst_free(ctx->gb.mm_state_fsm);
	if (ctx->gmm_att_req.fsm)
		osmo_fsm_inst_free(ctx->gmm_att_req.fsm);
	if (ctx->gmm_fsm)
		osmo_fsm_inst_free(ctx->gmm_fsm);

	rate_ctr_group_free(ctx->ctrg);
	talloc_free(ctx);

	return NULL;
}
/* Allocate a new SGSN MM context for GERAN_Gb */
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc_gb(uint32_t tlli,
					 const struct gprs_ra_id *raid)
{
	struct sgsn_mm_ctx *ctx;

	ctx = sgsn_mm_ctx_alloc(tlli);
	if (!ctx)
		return NULL;

	memcpy(&ctx->ra, raid, sizeof(ctx->ra));
	ctx->ran_type = MM_CTX_T_GERAN_Gb;
	ctx->gb.tlli = tlli;
	osmo_fsm_inst_update_id_f(ctx->gb.mm_state_fsm, "%" PRIu32, tlli);

	return ctx;
}

/* Allocate a new SGSN MM context for UTRAN_Iu */
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc_iu(void *uectx)
{
#if BUILD_IU
	struct sgsn_mm_ctx *ctx;
	struct ranap_ue_conn_ctx *ue_ctx = uectx;

	ctx = sgsn_mm_ctx_alloc(ue_ctx->conn_id);
	if (!ctx)
		return NULL;

	/* Need to get RAID from IU conn */
	ctx->ra = ue_ctx->ra_id;
	ctx->ran_type = MM_CTX_T_UTRAN_Iu;
	ctx->iu.ue_ctx = ue_ctx;
	ctx->iu.ue_ctx->rab_assign_addr_enc = sgsn->cfg.iu.rab_assign_addr_enc;
	ctx->iu.new_key = 1;
	osmo_fsm_inst_update_id_f(ctx->iu.mm_state_fsm, "%" PRIu32, ue_ctx->conn_id);


	return ctx;
#else
	return NULL;
#endif
}


/* this is a hard _free_ function, it doesn't clean up the PDP contexts
 * in libgtp! */
static void sgsn_mm_ctx_free(struct sgsn_mm_ctx *mm)
{
	struct sgsn_pdp_ctx *pdp, *pdp2;

	/* Unlink from global list of MM contexts */
	llist_del(&mm->list);

	/* Free all PDP contexts */
	llist_for_each_entry_safe(pdp, pdp2, &mm->pdp_list, list)
		sgsn_pdp_ctx_free(pdp);

	rate_ctr_group_free(mm->ctrg);

	talloc_free(mm);
}

void sgsn_mm_ctx_cleanup_free(struct sgsn_mm_ctx *mm)
{
	struct gprs_llc_llme *llme = NULL;
	struct sgsn_pdp_ctx *pdp, *pdp2;
	struct sgsn_signal_data sig_data;

	if (mm->ran_type == MM_CTX_T_GERAN_Gb)
		llme = mm->gb.llme;
	else
		OSMO_ASSERT(mm->gb.llme == NULL);

	/* Forget about ongoing look-ups */
	if (mm->ggsn_lookup) {
		LOGMMCTXP(LOGL_NOTICE, mm,
			"Cleaning mmctx with on-going query.\n");
		mm->ggsn_lookup->mmctx = NULL;
		mm->ggsn_lookup = NULL;
	}

	/* delete all existing PDP contexts for this MS */
	llist_for_each_entry_safe(pdp, pdp2, &mm->pdp_list, list) {
		LOGMMCTXP(LOGL_NOTICE, mm,
			  "Dropping PDP context for NSAPI=%u\n", pdp->nsapi);
		sgsn_pdp_ctx_terminate(pdp);
	}

	if (osmo_timer_pending(&mm->timer)) {
		LOGMMCTXP(LOGL_INFO, mm, "Cancelling MM timer %u\n", mm->T);
		osmo_timer_del(&mm->timer);
	}

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.mm = mm;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_MM_FREE, &sig_data);


	/* Detach from subscriber which is possibly freed then */
	if (mm->subscr) {
		struct gprs_subscr *subscr = gprs_subscr_get(mm->subscr);
		gprs_subscr_cleanup(subscr);
		gprs_subscr_put(subscr);
	}

	if (mm->gmm_att_req.fsm)
		gmm_att_req_free(mm);
	if (mm->gb.mm_state_fsm)
		osmo_fsm_inst_free(mm->gb.mm_state_fsm);
	if (mm->iu.mm_state_fsm)
		osmo_fsm_inst_free(mm->iu.mm_state_fsm);
	if (mm->gmm_fsm)
		osmo_fsm_inst_free(mm->gmm_fsm);

	sgsn_mm_ctx_free(mm);
	mm = NULL;

	if (llme) {
		/* TLLI unassignment, must be called after sgsn_mm_ctx_free */
		if (gprs_llgmm_unassign(llme) < 0)
			LOGMMCTXP(LOGL_ERROR, mm, "gprs_llgmm_unassign failed, llme not freed!\n");
	}
}


/* look up PDP context by MM context and NSAPI */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_nsapi(const struct sgsn_mm_ctx *mm,
					   uint8_t nsapi)
{
	struct sgsn_pdp_ctx *pdp;

	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		if (pdp->nsapi == nsapi)
			return pdp;
	}
	return NULL;
}

/* look up PDP context by MM context and transaction ID */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_tid(const struct sgsn_mm_ctx *mm,
					 uint8_t tid)
{
	struct sgsn_pdp_ctx *pdp;

	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		if (pdp->ti == tid)
			return pdp;
	}
	return NULL;
}

/* you don't want to use this directly, call sgsn_create_pdp_ctx() */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_alloc(struct sgsn_mm_ctx *mm,
					struct sgsn_ggsn_ctx *ggsn,
					uint8_t nsapi)
{
	struct sgsn_pdp_ctx *pdp;

	pdp = sgsn_pdp_ctx_by_nsapi(mm, nsapi);
	if (pdp)
		return NULL;

	pdp = talloc_zero(tall_sgsn_ctx, struct sgsn_pdp_ctx);
	if (!pdp)
		return NULL;

	pdp->mm = mm;
	pdp->ggsn = ggsn;
	pdp->nsapi = nsapi;
	pdp->ctrg = rate_ctr_group_alloc(pdp, &pdpctx_ctrg_desc, nsapi);
	if (!pdp->ctrg) {
		LOGPDPCTXP(LOGL_ERROR, pdp, "Error allocation counter group\n");
		talloc_free(pdp);
		return NULL;
	}
	llist_add(&pdp->list, &mm->pdp_list);
	sgsn_ggsn_ctx_add_pdp(pdp->ggsn, pdp);
	llist_add(&pdp->g_list, &sgsn_pdp_ctxts);

	return pdp;
}

/*
 * This function will not trigger any GSM DEACT PDP ACK messages, so you
 * probably want to call sgsn_delete_pdp_ctx() instead if the connection
 * isn't detached already.
 */
void sgsn_pdp_ctx_terminate(struct sgsn_pdp_ctx *pdp)
{
	struct sgsn_signal_data sig_data;

	OSMO_ASSERT(pdp->mm != NULL);

	/* There might still be pending callbacks in libgtp. So the parts of
	 * this object relevant to GTP need to remain intact in this case. */

	LOGPDPCTXP(LOGL_INFO, pdp, "Forcing release of PDP context\n");

	if (pdp->mm->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Force the deactivation of the SNDCP layer */
		if (pdp->mm->gb.llme)
			sndcp_sm_deactivate_ind(&pdp->mm->gb.llme->lle[pdp->sapi], pdp->nsapi);
	}

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.pdp = pdp;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_PDP_TERMINATE, &sig_data);

	/* Detach from MM context */
	pdp_ctx_detach_mm_ctx(pdp);
	if (pdp->ggsn)
		sgsn_delete_pdp_ctx(pdp);
}

/*
 * Don't call this function directly unless you know what you are doing.
 * In normal conditions use sgsn_delete_pdp_ctx and in unspecified or
 * implementation dependent abnormal ones sgsn_pdp_ctx_terminate.
 */
void sgsn_pdp_ctx_free(struct sgsn_pdp_ctx *pdp)
{
	struct sgsn_signal_data sig_data;

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.pdp = pdp;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_PDP_FREE, &sig_data);

	if (osmo_timer_pending(&pdp->timer)) {
		LOGPDPCTXP(LOGL_ERROR, pdp, "Freeing PDP ctx with timer %u pending\n", pdp->T);
		osmo_timer_del(&pdp->timer);
	}

	rate_ctr_group_free(pdp->ctrg);
	if (pdp->mm)
		llist_del(&pdp->list);
	if (pdp->ggsn)
		sgsn_ggsn_ctx_remove_pdp(pdp->ggsn, pdp);
	llist_del(&pdp->g_list);

	/* _if_ we still have a library handle, at least set it to NULL
	 * to avoid any dereferences of the now-deleted PDP context from
	 * sgsn_libgtp:cb_data_ind() */
	if (pdp->lib) {
		struct pdp_t *lib = pdp->lib;
		LOGPDPCTXP(LOGL_NOTICE, pdp, "freeing PDP context that still "
		     "has a libgtp handle attached to it, this shouldn't "
		     "happen!\n");
		osmo_generate_backtrace();
		lib->priv = NULL;
	}

	talloc_free(pdp);
}

uint32_t sgsn_alloc_ptmsi(void)
{
	struct sgsn_mm_ctx *mm;
	uint32_t ptmsi = 0xdeadbeef;
	int max_retries = 100, rc = 0;

restart:
	rc = osmo_get_rand_id((uint8_t *) &ptmsi, sizeof(ptmsi));
	if (rc < 0)
		goto failed;

	/* Enforce that the 2 MSB are set without loosing the distance between
	 * identical values. Since rand() has no duplicate values within a
	 * period (because the size of the state is the same like the size of
	 * the random value), this leads to a distance of period/4 when the
	 * distribution of the 2 MSB is uniform. This approach fails with a
	 * probability of (3/4)^max_retries, only 1% of the approaches will
	 * need more than 16 numbers (even distribution assumed).
	 *
	 * Alternatively, a freeze list could be used if another PRNG is used
	 * or when this approach proves to be not sufficient.
	 */
	if (ptmsi >= GSM23003_TMSI_SGSN_MASK) {
		if (!max_retries--)
			goto failed;
		goto restart;
	}
	ptmsi |= GSM23003_TMSI_SGSN_MASK;

	if (ptmsi == GSM_RESERVED_TMSI) {
		if (!max_retries--)
			goto failed;
		goto restart;
	}

	llist_for_each_entry(mm, &sgsn_mm_ctxts, list) {
		if (mm->p_tmsi == ptmsi) {
			if (!max_retries--)
				goto failed;
			goto restart;
		}
	}

	return ptmsi;

failed:
	LOGP(DGPRS, LOGL_ERROR, "Failed to allocate a P-TMSI: %d (%s)\n", rc, strerror(-rc));
	return GSM_RESERVED_TMSI;
}

void sgsn_update_subscriber_data(struct sgsn_mm_ctx *mmctx)
{
	OSMO_ASSERT(mmctx != NULL);
	LOGMMCTXP(LOGL_INFO, mmctx, "Subscriber data update\n");

	sgsn_auth_update(mmctx);
}

static void insert_extra(struct tlv_parsed *tp,
			struct sgsn_subscriber_data *data,
			struct sgsn_subscriber_pdp_data *pdp)
{
	tp->lv[OSMO_IE_GSM_SUB_QOS].len = pdp->qos_subscribed_len;
	tp->lv[OSMO_IE_GSM_SUB_QOS].val = pdp->qos_subscribed;

	/* Prefer PDP charging characteristics of per subscriber one */
	if (pdp->has_pdp_charg) {
		tp->lv[OSMO_IE_GSM_CHARG_CHAR].len = sizeof(pdp->pdp_charg);
		tp->lv[OSMO_IE_GSM_CHARG_CHAR].val = &pdp->pdp_charg[0];
	} else if (data->has_pdp_charg) {
		tp->lv[OSMO_IE_GSM_CHARG_CHAR].len = sizeof(data->pdp_charg);
		tp->lv[OSMO_IE_GSM_CHARG_CHAR].val = &data->pdp_charg[0];
	}
}

/**
 * The tlv_parsed tp parameter will be modified to insert a
 * OSMO_IE_GSM_SUB_QOS in case the data is available in the
 * PDP context handling.
 */
struct sgsn_ggsn_ctx *sgsn_mm_ctx_find_ggsn_ctx(struct sgsn_mm_ctx *mmctx,
						struct tlv_parsed *tp,
						enum gsm48_gsm_cause *gsm_cause,
						char *out_apn_str)
{
	char req_apn_str[GSM_APN_LENGTH] = {0};
	const struct apn_ctx *apn_ctx = NULL;
	const char *selected_apn_str = NULL;
	struct sgsn_subscriber_pdp_data *pdp;
	struct sgsn_ggsn_ctx *ggsn = NULL;
	int allow_any_apn = 0;

	out_apn_str[0] = '\0';

	if (TLVP_PRESENT(tp, GSM48_IE_GSM_APN)) {
		if (TLVP_LEN(tp, GSM48_IE_GSM_APN) >= GSM_APN_LENGTH - 1) {
			LOGMMCTXP(LOGL_ERROR, mmctx, "APN IE too long\n");
			*gsm_cause = GSM_CAUSE_INV_MAND_INFO;
			return NULL;
		}

		osmo_apn_to_str(req_apn_str,
				TLVP_VAL(tp, GSM48_IE_GSM_APN),
				TLVP_LEN(tp, GSM48_IE_GSM_APN));

		if (strcmp(req_apn_str, "*") == 0)
			req_apn_str[0] = 0;
	}

	if (mmctx->subscr == NULL)
		allow_any_apn = 1;

	if (strlen(req_apn_str) == 0 && !allow_any_apn) {
		/* No specific APN requested, check for an APN that is both
		 * granted and configured */

		llist_for_each_entry(pdp, &mmctx->subscr->sgsn_data->pdp_list, list) {
			if (strcmp(pdp->apn_str, "*") == 0)
			{
				allow_any_apn = 1;
				selected_apn_str = "";
				insert_extra(tp, mmctx->subscr->sgsn_data, pdp);
				continue;
			}
			if (!llist_empty(&sgsn->apn_list)) {
				apn_ctx = sgsn_apn_ctx_match(req_apn_str, mmctx->imsi);
				/* Not configured */
				if (apn_ctx == NULL)
					continue;
			}
			insert_extra(tp, mmctx->subscr->sgsn_data, pdp);
			selected_apn_str = pdp->apn_str;
			break;
		}
	} else if (!allow_any_apn) {
		/* Check whether the given APN is granted */
		llist_for_each_entry(pdp, &mmctx->subscr->sgsn_data->pdp_list, list) {
			if (strcmp(pdp->apn_str, "*") == 0) {
				insert_extra(tp, mmctx->subscr->sgsn_data, pdp);
				selected_apn_str = req_apn_str;
				allow_any_apn = 1;
				continue;
			}
			if (strcasecmp(pdp->apn_str, req_apn_str) == 0) {
				insert_extra(tp, mmctx->subscr->sgsn_data, pdp);
				selected_apn_str = req_apn_str;
				break;
			}
		}
	} else if (strlen(req_apn_str) != 0) {
		/* Any APN is allowed */
		selected_apn_str = req_apn_str;
	} else {
		/* Prefer the GGSN associated with the wildcard APN */
		selected_apn_str = "";
	}

	if (!allow_any_apn && selected_apn_str == NULL) {
		/* Access not granted */
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			  "The requested APN '%s' is not allowed\n",
			  req_apn_str);
		*gsm_cause = GSM_CAUSE_REQ_SERV_OPT_NOTSUB;
		return NULL;
	}

	/* copy the selected apn_str */
	if (selected_apn_str)
		strcpy(out_apn_str, selected_apn_str);
	else
		out_apn_str[0] = '\0';

	if (apn_ctx == NULL && selected_apn_str)
		apn_ctx = sgsn_apn_ctx_match(selected_apn_str, mmctx->imsi);

	if (apn_ctx != NULL) {
		ggsn = apn_ctx->ggsn;
	} else if (llist_empty(&sgsn->apn_list)) {
		/* No configuration -> use GGSN 0 */
		ggsn = sgsn_ggsn_ctx_by_id(0);
	} else if (allow_any_apn &&
		   (selected_apn_str == NULL || strlen(selected_apn_str) == 0)) {
		/* No APN given and no default configuration -> Use GGSN 0 */
		ggsn = sgsn_ggsn_ctx_by_id(0);
	} else {
		/* No matching configuration found */
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			  "The selected APN '%s' has not been configured\n",
			  selected_apn_str);
		*gsm_cause = GSM_CAUSE_MISSING_APN;
		return NULL;
	}

	if (!ggsn) {
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			"No static GGSN configured. Selected APN '%s'\n",
			selected_apn_str);
		*gsm_cause = GSM_CAUSE_MISSING_APN;
		return NULL;
	}

	LOGMMCTXP(LOGL_INFO, mmctx,
		  "Found GGSN %d for APN '%s' (requested '%s')\n",
		  ggsn->id, selected_apn_str ? selected_apn_str : "---",
		  req_apn_str);

	return ggsn;
}

static void sgsn_llme_cleanup_free(struct gprs_llc_llme *llme)
{
	struct sgsn_mm_ctx *mmctx = NULL;

	llist_for_each_entry(mmctx, &sgsn_mm_ctxts, list) {
		if (llme == mmctx->gb.llme) {
			gsm0408_gprs_access_cancelled(mmctx, SGSN_ERROR_CAUSE_NONE);
			return;
		}
	}

	/* No MM context found */
	LOGP(DGPRS, LOGL_INFO, "Deleting orphaned LLME, TLLI 0x%08x\n",
	     llme->tlli);
	gprs_llgmm_unassign(llme);
}

static void sgsn_llme_check_cb(void *data_)
{
	struct gprs_llc_llme *llme, *llme_tmp;
	struct timespec now_tp;
	time_t now, age;
	time_t max_age = gprs_max_time_to_idle();

	int rc;

	rc = osmo_clock_gettime(CLOCK_MONOTONIC, &now_tp);
	OSMO_ASSERT(rc >= 0);
	now = now_tp.tv_sec;

	LOGP(DGPRS, LOGL_DEBUG,
	     "Checking for inactive LLMEs, time = %u\n", (unsigned)now);

	llist_for_each_entry_safe(llme, llme_tmp, &gprs_llc_llmes, list) {
		if (llme->age_timestamp == GPRS_LLME_RESET_AGE)
			llme->age_timestamp = now;

		age = now - llme->age_timestamp;

		if (age > max_age || age < 0) {
			LOGP(DGPRS, LOGL_INFO,
			     "Inactivity timeout for TLLI 0x%08x, age %d\n",
			     llme->tlli, (int)age);
			sgsn_llme_cleanup_free(llme);
		}
	}

	osmo_timer_schedule(&sgsn->llme_timer, GPRS_LLME_CHECK_TICK, 0);
}

static int sgsn_instance_talloc_destructor(struct sgsn_instance *sgi)
{
	sgsn_cdr_release(sgi);
	osmo_timer_del(&sgi->llme_timer);
	rate_ctr_group_free(sgi->rate_ctrs);
	return 0;
}

struct sgsn_instance *sgsn_instance_alloc(void *talloc_ctx)
{
	struct sgsn_instance *inst;
	inst = talloc_zero(talloc_ctx, struct sgsn_instance);

	talloc_set_destructor(inst, sgsn_instance_talloc_destructor);

	inst->cfg.gtp_statedir = talloc_strdup(inst, "./");
	inst->cfg.auth_policy = SGSN_AUTH_POLICY_CLOSED;
	inst->cfg.require_authentication = true; /* only applies if auth_policy is REMOTE */
	inst->cfg.gsup_server_port = OSMO_GSUP_PORT;

	inst->cfg.T_defs = sgsn_T_defs;
	osmo_tdefs_reset(inst->cfg.T_defs);
	inst->cfg.T_defs_gtp = gtp_T_defs;
	osmo_tdefs_reset(inst->cfg.T_defs_gtp);

	inst->rate_ctrs = rate_ctr_group_alloc(inst, &sgsn_ctrg_desc, 0);
	OSMO_ASSERT(inst->rate_ctrs);

	INIT_LLIST_HEAD(&inst->apn_list);
	INIT_LLIST_HEAD(&inst->ggsn_list);
	INIT_LLIST_HEAD(&inst->mme_list);

	osmo_timer_setup(&inst->llme_timer, sgsn_llme_check_cb, NULL);
	osmo_timer_schedule(&inst->llme_timer, GPRS_LLME_CHECK_TICK, 0);
	/* These are mostly setting up stuff not related to VTY cfg, so they can be set up here: */
	sgsn_auth_init(inst);
	sgsn_cdr_init(inst);
	return inst;
}

/* To be called after VTY config parsing: */
int sgsn_inst_init(struct sgsn_instance *sgsn)
{
	int rc;

	/* start control interface after reading config for
	 * ctrl_vty_get_bind_addr() */
	sgsn->ctrlh = ctrl_interface_setup(NULL, OSMO_CTRL_PORT_SGSN, NULL);
	if (!sgsn->ctrlh) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to create CTRL interface.\n");
		return -EIO;
	}

	rc = sgsn_ctrl_cmds_install();
	if (rc != 0) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to install CTRL commands.\n");
		return -EFAULT;
	}

	rc = gprs_subscr_init(sgsn);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot set up SGSN\n");
		return rc;
	}
	return 0;
}
