/* PDP context functionality */

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

#include <osmocom/sgsn/pdpctx.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/signal.h>
#include <osmocom/sgsn/gtp_ggsn.h>
#include <osmocom/sgsn/gprs_sndcp.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_sm.h>
#include <osmocom/sgsn/gtp.h>

static const struct rate_ctr_desc pdpctx_ctr_description[] = {
	{ "udata:packets:in",	"User Data Messages ( In)" },
	{ "udata:packets:out",	"User Data Messages (Out)" },
	{ "udata:bytes:in",	"User Data Bytes    ( In)" },
	{ "udata:bytes:out",	"User Data Bytes    (Out)" },
};

static const struct rate_ctr_group_desc pdpctx_ctrg_desc = {
	.group_name_prefix = "sgsn:pdpctx",
	.group_description = "SGSN PDP Context Statistics",
	.num_ctr = ARRAY_SIZE(pdpctx_ctr_description),
	.ctr_desc = pdpctx_ctr_description,
	.class_id = OSMO_STATS_CLASS_SUBSCRIBER,
};

/* you don't want to use this directly, call sgsn_create_pdp_ctx() */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_alloc(struct sgsn_mm_ctx *mm,
					struct sgsn_ggsn_ctx *ggsn,
					uint8_t nsapi)
{
	struct sgsn_pdp_ctx *pdp;

	pdp = sgsn_pdp_ctx_by_nsapi(mm, nsapi);
	if (pdp)
		return NULL;

	pdp = talloc_zero(sgsn, struct sgsn_pdp_ctx);
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
	llist_add(&pdp->g_list, &sgsn->pdp_list);

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
			sgsn_sndcp_snsm_deactivate_ind(pdp->mm->gb.llme->tlli, pdp->nsapi);
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
