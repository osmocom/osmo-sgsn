/* GGSN context (peer) */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
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

#include <osmocom/sgsn/gtp_ggsn.h>
#include <osmocom/sgsn/gtp.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_gmm_fsm.h>
#include <osmocom/sgsn/gprs_sm.h>

void sgsn_ggsn_ctx_check_echo_timer(struct sgsn_ggsn_ctx *ggc)
{
	bool pending = osmo_timer_pending(&ggc->echo_timer);

	/* Only enable if allowed by policy and at least 1 pdp ctx exists against ggsn */
	if (!llist_empty(&ggc->pdp_list) && ggc->echo_interval) {
		if (!pending)
			osmo_timer_schedule(&ggc->echo_timer, ggc->echo_interval, 0);
	} else {
		if (pending)
			osmo_timer_del(&ggc->echo_timer);
	}
}

/* GGSN contexts */
static void echo_timer_cb(void *data)
{
	struct sgsn_ggsn_ctx *ggc = (struct sgsn_ggsn_ctx *) data;
	sgsn_ggsn_echo_req(ggc);
	osmo_timer_schedule(&ggc->echo_timer, ggc->echo_interval, 0);
}

struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_alloc(struct sgsn_instance *sgsn, uint32_t id)
{
	struct sgsn_ggsn_ctx *ggc;

	ggc = talloc_zero(sgsn, struct sgsn_ggsn_ctx);
	if (!ggc)
		return NULL;

	ggc->id = id;
	ggc->gtp_version = 1;
	ggc->remote_restart_ctr = -1;
	/* if we are called from config file parse, this gsn doesn't exist yet */
	ggc->gsn = sgsn->gsn;
	INIT_LLIST_HEAD(&ggc->pdp_list);
	osmo_timer_setup(&ggc->echo_timer, echo_timer_cb, ggc);
	llist_add(&ggc->list, &sgsn->ggsn_list);

	return ggc;
}

void sgsn_ggsn_ctx_free(struct sgsn_ggsn_ctx *ggc)
{
	OSMO_ASSERT(llist_empty(&ggc->pdp_list));
	llist_del(&ggc->list);
	talloc_free(ggc);
}

struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_by_id(struct sgsn_instance *sgsn, uint32_t id)
{
	struct sgsn_ggsn_ctx *ggc;

	llist_for_each_entry(ggc, &sgsn->ggsn_list, list) {
		if (id == ggc->id)
			return ggc;
	}
	return NULL;
}

struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_by_addr(struct sgsn_instance *sgsn, struct in_addr *addr)
{
	struct sgsn_ggsn_ctx *ggc;

	llist_for_each_entry(ggc, &sgsn->ggsn_list, list) {
		if (!memcmp(addr, &ggc->remote_addr, sizeof(*addr)))
			return ggc;
	}
	return NULL;
}


struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_find_alloc(struct sgsn_instance *sgsn, uint32_t id)
{
	struct sgsn_ggsn_ctx *ggc;

	ggc = sgsn_ggsn_ctx_by_id(sgsn, id);
	if (!ggc)
		ggc = sgsn_ggsn_ctx_alloc(sgsn, id);
	return ggc;
}

void sgsn_ggsn_ctx_drop_pdp(struct sgsn_pdp_ctx *pctx)
{
	/* the MM context can be deleted while the GGSN is not reachable or
	 * if has been crashed. */
	if (pctx->mm && pctx->mm->gmm_fsm->state == ST_GMM_REGISTERED_NORMAL) {
		gsm48_tx_gsm_deact_pdp_req(pctx, GSM_CAUSE_NET_FAIL, true);
		sgsn_ggsn_ctx_remove_pdp(pctx->ggsn, pctx);
	} else  {
		/* FIXME: GPRS paging in case MS is SUSPENDED */
		LOGPDPCTXP(LOGL_NOTICE, pctx, "Hard-dropping PDP ctx due to GGSN "
			"recovery\n");
		/* FIXME: how to tell this to libgtp? */
		sgsn_pdp_ctx_free(pctx);
	}
}

/* High-level function to be called in case a GGSN has disappeared or
 * otherwise lost state (recovery procedure). It will detach all related pdp ctx
 * from a ggsn and communicate deact to MS. Optionally (!NULL), one pdp ctx can
 * be kept alive to allow handling later message which contained the Recovery IE. */
int sgsn_ggsn_ctx_drop_all_pdp_except(struct sgsn_ggsn_ctx *ggsn, struct sgsn_pdp_ctx *except)
{
	int num = 0;

	struct sgsn_pdp_ctx *pdp, *pdp2;
	llist_for_each_entry_safe(pdp, pdp2, &ggsn->pdp_list, ggsn_list) {
		if (pdp == except)
			continue;
		sgsn_ggsn_ctx_drop_pdp(pdp);
		num++;
	}

	return num;
}

int sgsn_ggsn_ctx_drop_all_pdp(struct sgsn_ggsn_ctx *ggsn)
{
	return sgsn_ggsn_ctx_drop_all_pdp_except(ggsn, NULL);
}

void sgsn_ggsn_ctx_add_pdp(struct sgsn_ggsn_ctx *ggc, struct sgsn_pdp_ctx *pdp)
{
	llist_add(&pdp->ggsn_list, &ggc->pdp_list);
	sgsn_ggsn_ctx_check_echo_timer(ggc);
}

void sgsn_ggsn_ctx_remove_pdp(struct sgsn_ggsn_ctx *ggc, struct sgsn_pdp_ctx *pdp)
{
	llist_del(&pdp->ggsn_list);
	sgsn_ggsn_ctx_check_echo_timer(ggc);
	if (pdp->destroy_ggsn)
		sgsn_ggsn_ctx_free(pdp->ggsn);
	pdp->ggsn = NULL;
	/* Drop references to libgtp since the conn is down */
	if (pdp->lib)
		pdp_freepdp(pdp->lib);
	pdp->lib = NULL;
}
