/* GMM mobility management states on the network side, 3GPP TS 24.008 § 4.1.3.3 */
/*
 * (C) 2019 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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
 */
#include <osmocom/core/tdef.h>

#include <osmocom/sgsn/gprs_gmm_fsm.h>
#include <osmocom/sgsn/gprs_mm_state_gb_fsm.h>
#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>

#define X(s) (1 << (s))

static const struct osmo_tdef_state_timeout gmm_fsm_timeouts[32] = {
	[ST_GMM_DEREGISTERED] = { },
	[ST_GMM_COMMON_PROC_INIT] = { },
	[ST_GMM_REGISTERED_NORMAL] = { },
	[ST_GMM_REGISTERED_SUSPENDED] = { },
	[ST_GMM_DEREGISTERED_INIT] = { },
};

#define gmm_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, gmm_fsm_timeouts, sgsn->cfg.T_defs, -1)

static void st_gmm_deregistered(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_GMM_COMMON_PROC_INIT_REQ:
		gmm_fsm_state_chg(fi, ST_GMM_COMMON_PROC_INIT);
		break;
	case E_GMM_ATTACH_SUCCESS:
		gmm_fsm_state_chg(fi, ST_GMM_REGISTERED_NORMAL);
		break;
	}
}

static void st_gmm_common_proc_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_GMM_COMMON_PROC_INIT_REQ:
		/* MS may retransmit GPRS Attach Request if for some reason
		 * CommonProcedure didn't go forward correctly */
		break;
	/* TODO: events not used
	case E_GMM_LOWER_LAYER_FAILED:
	case E_GMM_COMMON_PROC_FAILED:
		gmm_fsm_state_chg(fi, ST_GMM_DEREGISTERED);
		break;
	*/
	case E_GMM_COMMON_PROC_SUCCESS:
	case E_GMM_ATTACH_SUCCESS:
		gmm_fsm_state_chg(fi, ST_GMM_REGISTERED_NORMAL);
		break;
	}
}

static void st_gmm_registered_normal(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_GMM_COMMON_PROC_INIT_REQ:
		gmm_fsm_state_chg(fi, ST_GMM_COMMON_PROC_INIT);
		break;
	case E_GMM_COMMON_PROC_SUCCESS:
		/* If we were moved from ST_GMM_COMMON_PROC_INIT here by
		 *  E_GMM_ATTACH_SUCCESS instead of E_GMM_COMMON_PROC_SUCCESS then we'll receive the latter here:
		 *  we should simply ignore it */
		break;
	/* case E_GMM_NET_INIT_DETACH_REQ:
		gmm_fsm_state_chg(fi, ST_GMM_DEREGISTERED_INIT);
		break; */
	/* case E_GMM_MS_INIT_DETACH_REQ:
		gmm_fsm_state_chg(fi, ST_GMM_DEREGISTERED);
		break; */
	case E_GMM_SUSPEND:
		gmm_fsm_state_chg(fi, ST_GMM_REGISTERED_SUSPENDED);
		break;
	}
}

static void st_gmm_registered_suspended(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_GMM_RESUME:		/* explicit BSSGP RESUME from BSS */
		gmm_fsm_state_chg(fi, ST_GMM_REGISTERED_NORMAL);
		break;
	case E_GMM_COMMON_PROC_INIT_REQ: /* implicit resume from MS */
		gmm_fsm_state_chg(fi, ST_GMM_COMMON_PROC_INIT);
		break;
	}
}

static void st_gmm_deregistered_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	/* TODO: events not used in osmo-sgsn code
	case E_GMM_DETACH_ACCEPTED:
	case E_GMM_LOWER_LAYER_FAILED:
		gmm_fsm_state_chg(fi, ST_GMM_DEREGISTERED);
		break;
	*/
	}
}

static struct osmo_fsm_state gmm_fsm_states[] = {
	[ST_GMM_DEREGISTERED] = {
		.in_event_mask =
			X(E_GMM_COMMON_PROC_INIT_REQ) |
			X(E_GMM_ATTACH_SUCCESS),
		.out_state_mask = X(ST_GMM_COMMON_PROC_INIT),
		.name = "Deregistered",
		.action = st_gmm_deregistered,
	},
	[ST_GMM_COMMON_PROC_INIT] = {
		.in_event_mask =
			/* X(E_GMM_LOWER_LAYER_FAILED) | */
			/* X(E_GMM_COMMON_PROC_FAILED) | */
			X(E_GMM_COMMON_PROC_SUCCESS) |
			X(E_GMM_ATTACH_SUCCESS) |
			X(E_GMM_COMMON_PROC_INIT_REQ),
		.out_state_mask =
			X(ST_GMM_DEREGISTERED) |
			X(ST_GMM_REGISTERED_NORMAL),
		.name = "CommonProcedureInitiated",
		.action = st_gmm_common_proc_init,
	},
	[ST_GMM_REGISTERED_NORMAL] = {
		.in_event_mask =
			X(E_GMM_COMMON_PROC_INIT_REQ) |
			X(E_GMM_COMMON_PROC_SUCCESS) |
			/* X(E_GMM_NET_INIT_DETACH_REQ) | */
			/* X(E_GMM_MS_INIT_DETACH_REQ) | */
			X(E_GMM_SUSPEND),
		.out_state_mask =
			X(ST_GMM_DEREGISTERED) |
			X(ST_GMM_COMMON_PROC_INIT) |
			X(ST_GMM_DEREGISTERED_INIT) |
			X(ST_GMM_REGISTERED_SUSPENDED),
		.name = "Registered.NORMAL",
		.action = st_gmm_registered_normal,
	},
	[ST_GMM_REGISTERED_SUSPENDED] = {
		.in_event_mask = X(E_GMM_RESUME) |
				 X(E_GMM_COMMON_PROC_INIT_REQ),
		.out_state_mask =
			X(ST_GMM_DEREGISTERED) |
			X(ST_GMM_REGISTERED_NORMAL) |
			X(ST_GMM_COMMON_PROC_INIT),
		.name = "Registered.SUSPENDED",
		.action = st_gmm_registered_suspended,
	},
	[ST_GMM_DEREGISTERED_INIT] = {
		.in_event_mask = 0
			/* X(E_GMM_DETACH_ACCEPTED) | */
			/* X(E_GMM_LOWER_LAYER_FAILED) */,
		.out_state_mask = X(ST_GMM_DEREGISTERED),
		.name = "DeregisteredInitiated",
		.action = st_gmm_deregistered_init,
	},
};

const struct value_string gmm_fsm_event_names[] = {
	OSMO_VALUE_STRING(E_GMM_COMMON_PROC_INIT_REQ),
	/* OSMO_VALUE_STRING(E_GMM_COMMON_PROC_FAILED), */
	/*  OSMO_VALUE_STRING(E_GMM_LOWER_LAYER_FAILED),  */
	OSMO_VALUE_STRING(E_GMM_COMMON_PROC_SUCCESS),
	OSMO_VALUE_STRING(E_GMM_ATTACH_SUCCESS),
	/*  OSMO_VALUE_STRING(E_GMM_NET_INIT_DETACH_REQ), */
	/*  OSMO_VALUE_STRING(E_GMM_MS_INIT_DETACH_REQ), */
	/* OSMO_VALUE_STRING(E_GMM_DETACH_ACCEPTED), */
	OSMO_VALUE_STRING(E_GMM_SUSPEND),
	OSMO_VALUE_STRING(E_GMM_CLEANUP),
	OSMO_VALUE_STRING(E_GMM_RAT_CHANGE),
	{ 0, NULL }
};

void gmm_fsm_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data) {
	struct sgsn_mm_ctx *mmctx = fi->priv;
	struct gmm_rat_change_data *rat_chg = (struct gmm_rat_change_data *)data;

	switch (event) {
	case E_GMM_RAT_CHANGE:

		switch (fi->state) {
		case ST_GMM_COMMON_PROC_INIT:
			gmm_fsm_state_chg(fi, ST_GMM_DEREGISTERED);
		default:
			if (mmctx->ran_type == MM_CTX_T_GERAN_Gb)
				osmo_fsm_inst_dispatch(mmctx->gb.mm_state_fsm, E_MM_GPRS_DETACH, NULL);
			else if (mmctx->ran_type == MM_CTX_T_UTRAN_Iu) {
				osmo_fsm_inst_dispatch(mmctx->iu.mm_state_fsm, E_PMM_PS_DETACH, NULL);
				mmctx->gb.llme = rat_chg->llme;
			}

			mmctx->ran_type = rat_chg->new_ran_type;
			break;
		}

	case E_GMM_CLEANUP:
		switch (fi->state) {
		case ST_GMM_DEREGISTERED:
			break;
		default:
			gmm_fsm_state_chg(fi, ST_GMM_DEREGISTERED);
			break;
		}
	}
}

int gmm_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	return 0;
}

struct osmo_fsm gmm_fsm = {
	.name = "GMM",
	.states = gmm_fsm_states,
	.num_states = ARRAY_SIZE(gmm_fsm_states),
	.event_names = gmm_fsm_event_names,
	.allstate_event_mask = X(E_GMM_CLEANUP) | X(E_GMM_RAT_CHANGE),
	.allstate_action = gmm_fsm_allstate_action,
	.log_subsys = DMM,
	.timer_cb = gmm_fsm_timer_cb,
};

static __attribute__((constructor)) void gmm_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&gmm_fsm) == 0);
}
