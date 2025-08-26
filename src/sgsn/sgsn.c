/* SGSN instance */

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

#include "config.h"

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

#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/crypt/utran_cipher.h>

#include <osmocom/gtp/pdp.h>

#include <osmocom/sgsn/gprs_subscriber.h>
#include <osmocom/sgsn/debug.h>
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
#include <osmocom/sgsn/pdpctx.h>
#include <osmocom/sgsn/gprs_routing_area.h>
#if BUILD_IU
#include <osmocom/sgsn/sccp.h>
#endif /* #if BUILD_IU */

#include <time.h>

#define GPRS_LLME_CHECK_TICK 30

extern struct osmo_tdef sgsn_T_defs[];

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

static void sgsn_llme_cleanup_free(struct gprs_llc_llme *llme)
{
	struct sgsn_mm_ctx *mmctx = NULL;

	llist_for_each_entry(mmctx, &sgsn->mm_list, list) {
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
#if BUILD_IU
	sgsn_sccp_release(sgi);
#endif /* #if BUILD_IU */
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
	inst->cfg.gea_encryption_mask = (1 << GPRS_ALGO_GEA0); /* no encryption */
	inst->cfg.uea_encryption_mask = (1 << OSMO_UTRAN_UEA2) | (1 << OSMO_UTRAN_UEA1);
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
	INIT_LLIST_HEAD(&inst->mm_list);
	INIT_LLIST_HEAD(&inst->pdp_list);
#if BUILD_IU
	INIT_LLIST_HEAD(&inst->rnc_list);
#endif /* #if BUILD_IU */

	osmo_timer_setup(&inst->llme_timer, sgsn_llme_check_cb, NULL);
	osmo_timer_schedule(&inst->llme_timer, GPRS_LLME_CHECK_TICK, 0);
	/* These are mostly setting up stuff not related to VTY cfg, so they can be set up here: */
	sgsn_auth_init(inst);
	sgsn_cdr_init(inst);
	sgsn_ra_init(inst);
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

#if BUILD_IU
	rc = sgsn_sccp_init(sgsn);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot set up SGSN SCCP layer\n");
		return rc;
	}
#endif /* #if BUILD_IU */
	return 0;
}
