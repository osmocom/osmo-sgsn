/* A remote RNC (Radio Network Controller) FSM */

/* (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include "config.h"

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <osmocom/sigtran/sccp_helpers.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_ranap.h>
#include <osmocom/sgsn/iu_rnc_fsm.h>
#include <osmocom/sgsn/iu_rnc.h>
#include <osmocom/sgsn/sgsn.h>

#define S(x)	(1 << (x))

struct osmo_fsm iu_rnc_fsm;


static const struct osmo_tdef_state_timeout iu_rnc_fsm_timeouts[32] = {
	[IU_RNC_ST_WAIT_RX_RESET_ACK] = { .T = -1002 },
	[IU_RNC_ST_DISCARDING] = { .T = -1002 },
};

#define iu_rnc_state_chg(iu_rnc, next_st) \
	osmo_tdef_fsm_inst_state_chg((iu_rnc)->fi, next_st, iu_rnc_fsm_timeouts, sgsn_T_defs, 5)

static const struct value_string iu_rnc_fsm_event_names[] = {
	OSMO_VALUE_STRING(IU_RNC_EV_MSG_UP_CO_INITIAL),
	OSMO_VALUE_STRING(IU_RNC_EV_MSG_UP_CO),
	OSMO_VALUE_STRING(IU_RNC_EV_RX_RESET),
	OSMO_VALUE_STRING(IU_RNC_EV_RX_RESET_ACK),
	OSMO_VALUE_STRING(IU_RNC_EV_AVAILABLE),
	OSMO_VALUE_STRING(IU_RNC_EV_UNAVAILABLE),
	{}
};

/* Drop all SCCP connections for this iu_rnc, respond with RESET ACKNOWLEDGE and move to READY state. */
static void iu_rnc_rx_reset(struct ranap_iu_rnc *rnc)
{
	struct msgb *reset_ack;
	struct iu_grnc_id grnc_id;
	sgsn_ranap_iu_grnc_id_compose(&grnc_id, &rnc->rnc_id);

	iu_rnc_discard_all_ue_ctx(rnc);

	reset_ack = ranap_new_msg_reset_ack(RANAP_CN_DomainIndicator_ps_domain, &grnc_id.grnc_id);
	if (!reset_ack) {
		LOG_RNC(rnc, LOGL_ERROR, "Failed to compose RESET ACKNOWLEDGE message\n");
		iu_rnc_state_chg(rnc, IU_RNC_ST_WAIT_RX_RESET);
		return;
	}
	if (sgsn_ranap_iu_tx_cl(rnc->scu_iups, &rnc->sccp_addr, reset_ack) < 0) {
		LOG_RNC(rnc, LOGL_ERROR, "Failed to send RESET ACKNOWLEDGE message\n");
		iu_rnc_state_chg(rnc, IU_RNC_ST_WAIT_RX_RESET);
		return;
	}

	LOG_RNC(rnc, LOGL_INFO, "Sent RESET ACKNOWLEDGE\n");
	iu_rnc_state_chg(rnc, IU_RNC_ST_READY);
}

static void iu_rnc_reset(struct ranap_iu_rnc *rnc)
{
	struct msgb *reset;
	const RANAP_Cause_t cause = {
		.present = RANAP_Cause_PR_protocol,
		.choice = {
			.protocol = RANAP_CauseProtocol_message_not_compatible_with_receiver_state,
		},
	};

	iu_rnc_state_chg(rnc, IU_RNC_ST_WAIT_RX_RESET_ACK);
	iu_rnc_discard_all_ue_ctx(rnc);

	reset = ranap_new_msg_reset(RANAP_CN_DomainIndicator_ps_domain, &cause);
	if (!reset) {
		LOG_RNC(rnc, LOGL_ERROR, "Failed to compose RESET message\n");
		iu_rnc_state_chg(rnc, IU_RNC_ST_WAIT_RX_RESET);
		return;
	}

	if (sgsn_ranap_iu_tx_cl(rnc->scu_iups, &rnc->sccp_addr, reset) < 0) {
		LOG_RNC(rnc, LOGL_ERROR, "Failed to send RESET message\n");
		iu_rnc_state_chg(rnc, IU_RNC_ST_WAIT_RX_RESET);
		return;
	}
}

static void iu_rnc_st_wait_rx_reset(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ranap_iu_rnc *rnc = fi->priv;
	switch (event) {

	case IU_RNC_EV_MSG_UP_CO:
	case IU_RNC_EV_MSG_UP_CO_INITIAL:
		OSMO_ASSERT(data);

#define LEGACY_BEHAVIOR
#ifdef LEGACY_BEHAVIOR
		LOG_RNC(rnc, LOGL_ERROR, "Receiving CO message on RAN peer that has not done a proper RESET yet."
			" Accepting RAN peer implicitly (legacy compat)\n");
		iu_rnc_state_chg(rnc, IU_RNC_ST_READY);
		osmo_fsm_inst_dispatch(rnc->fi, event, data);
		return;
#else
		LOG_RNC(rnc, LOGL_ERROR, "Receiving CO message on RAN peer that has not done a proper RESET yet."
			     " Disconnecting on incoming message, sending RESET to RAN peer.\n");
		/* No valid RESET procedure has happened here yet. Usually, we're expecting the RAN peer (BSC,
		 * RNC) to first send a RESET message before sending Connection Oriented messages. So if we're
		 * getting a CO message, likely we've just restarted or something. Send a RESET to the peer. */

		/* Make sure the MS / UE properly disconnects. */
		clear_and_disconnect(rnc, ctx->conn_id);

		iu_rnc_reset(rnc);
		return;
#endif

	case IU_RNC_EV_RX_RESET:
		iu_rnc_rx_reset(rnc);
		return;

	case IU_RNC_EV_AVAILABLE:
		/* Send a RESET to the peer. */
		iu_rnc_reset(rnc);
		return;

	case IU_RNC_EV_UNAVAILABLE:
		/* Do nothing, wait for peer to come up again. */
		return;

	default:
		LOG_RNC(rnc, LOGL_ERROR, "Unhandled event: %s\n", osmo_fsm_event_name(&iu_rnc_fsm, event));
		return;
	}
}

static void iu_rnc_st_wait_rx_reset_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ranap_iu_rnc *rnc = fi->priv;
	struct iu_rnc_ev_msg_up_co_initial_ctx *ev_msg_up_co_initial_ctx;
	struct iu_rnc_ev_msg_up_co_ctx *ev_msg_up_co_ctx;

	switch (event) {

	case IU_RNC_EV_RX_RESET_ACK:
		iu_rnc_state_chg(rnc, IU_RNC_ST_READY);
		return;


	case IU_RNC_EV_MSG_UP_CO_INITIAL:
		ev_msg_up_co_initial_ctx = data;
		OSMO_ASSERT(ev_msg_up_co_initial_ctx);
		LOG_RNC(rnc, LOGL_ERROR, "Receiving CO Initial message on RAN peer that has not done a proper RESET yet."
			     " Disconnecting on incoming message, sending RESET to RAN peer.\n");
		osmo_sccp_tx_disconn(ev_msg_up_co_initial_ctx->rnc->scu_iups->scu,
				     ev_msg_up_co_initial_ctx->conn_id, NULL, 0);
		/* No valid RESET procedure has happened here yet. */
		iu_rnc_reset(rnc);
		return;
		return;
	case IU_RNC_EV_MSG_UP_CO:
		ev_msg_up_co_ctx = data;
		OSMO_ASSERT(ev_msg_up_co_ctx);
		LOG_RNC(rnc, LOGL_ERROR, "Receiving CO message on RAN peer that has not done a proper RESET yet."
			     " Disconnecting on incoming message, sending RESET to RAN peer.\n");
		ue_conn_ctx_link_invalidated_free(ev_msg_up_co_ctx->ue_ctx);
		/* No valid RESET procedure has happened here yet. */
		iu_rnc_reset(rnc);
		return;

	case IU_RNC_EV_RX_RESET:
		iu_rnc_rx_reset(rnc);
		return;

	case IU_RNC_EV_AVAILABLE:
		/* Send a RESET to the peer. */
		iu_rnc_reset(rnc);
		return;

	case IU_RNC_EV_UNAVAILABLE:
		iu_rnc_state_chg(rnc, IU_RNC_ST_WAIT_RX_RESET);
		return;

	default:
		LOG_RNC(rnc, LOGL_ERROR, "Unhandled event: %s\n", osmo_fsm_event_name(&iu_rnc_fsm, event));
		return;
	}
}

static void iu_rnc_st_ready_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	if (prev_state != IU_RNC_ST_READY)
		sgsn_stat_inc(SGSN_STAT_IU_PEERS_ACTIVE, 1);
}

static void iu_rnc_st_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ranap_iu_rnc *rnc = fi->priv;
	struct iu_rnc_ev_msg_up_co_initial_ctx *ev_msg_up_co_initial_ctx;
	struct iu_rnc_ev_msg_up_co_ctx *ev_msg_up_co_ctx;

	switch (event) {

	case IU_RNC_EV_MSG_UP_CO_INITIAL:
		ev_msg_up_co_initial_ctx = data;
		OSMO_ASSERT(ev_msg_up_co_initial_ctx);
		OSMO_ASSERT(ev_msg_up_co_initial_ctx->rnc);

		sgsn_ranap_iu_handle_co_initial(ev_msg_up_co_initial_ctx->rnc,
						      ev_msg_up_co_initial_ctx->conn_id,
						      &ev_msg_up_co_initial_ctx->message);
		return;

	case IU_RNC_EV_MSG_UP_CO:
		ev_msg_up_co_ctx = data;
		OSMO_ASSERT(ev_msg_up_co_ctx);
		OSMO_ASSERT(ev_msg_up_co_ctx->ue_ctx);

		sgsn_ranap_iu_handle_co(ev_msg_up_co_ctx->ue_ctx, &ev_msg_up_co_ctx->message);
		return;

	case IU_RNC_EV_RX_RESET:
		iu_rnc_rx_reset(rnc);
		return;

	case IU_RNC_EV_AVAILABLE:
		/* Do nothing, we were already up. */
		return;

	case IU_RNC_EV_UNAVAILABLE:
		iu_rnc_discard_all_ue_ctx(rnc);
		iu_rnc_state_chg(rnc, IU_RNC_ST_WAIT_RX_RESET);
		return;

	default:
		LOG_RNC(rnc, LOGL_ERROR, "Unhandled event: %s\n", osmo_fsm_event_name(&iu_rnc_fsm, event));
		return;
	}
}

static void iu_rnc_st_ready_onleave(struct osmo_fsm_inst *fi, uint32_t next_state)
{
	if (next_state != IU_RNC_ST_READY)
		sgsn_stat_dec(SGSN_STAT_IU_PEERS_ACTIVE, 1);
}

static int iu_rnc_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct ranap_iu_rnc *rnc = fi->priv;
	iu_rnc_state_chg(rnc, IU_RNC_ST_WAIT_RX_RESET);
	return 0;
}

static void iu_rnc_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct ranap_iu_rnc *rnc = fi->priv;

	iu_rnc_discard_all_ue_ctx(rnc);

	if (rnc->fi->state == IU_RNC_ST_READY)
		sgsn_stat_dec(SGSN_STAT_IU_PEERS_ACTIVE, 1);
	sgsn_stat_dec(SGSN_STAT_IU_PEERS_TOTAL, 1);
}

static const struct osmo_fsm_state iu_rnc_fsm_states[] = {
	[IU_RNC_ST_WAIT_RX_RESET] = {
		.name = "WAIT_RX_RESET",
		.action = iu_rnc_st_wait_rx_reset,
		.in_event_mask = 0
			| S(IU_RNC_EV_RX_RESET)
			| S(IU_RNC_EV_MSG_UP_CO_INITIAL)
			| S(IU_RNC_EV_MSG_UP_CO)
			| S(IU_RNC_EV_AVAILABLE)
			| S(IU_RNC_EV_UNAVAILABLE)
			,
		.out_state_mask = 0
			| S(IU_RNC_ST_WAIT_RX_RESET)
			| S(IU_RNC_ST_WAIT_RX_RESET_ACK)
			| S(IU_RNC_ST_READY)
			| S(IU_RNC_ST_DISCARDING)
			,
	},
	[IU_RNC_ST_WAIT_RX_RESET_ACK] = {
		.name = "WAIT_RX_RESET_ACK",
		.action = iu_rnc_st_wait_rx_reset_ack,
		.in_event_mask = 0
			| S(IU_RNC_EV_RX_RESET)
			| S(IU_RNC_EV_RX_RESET_ACK)
			| S(IU_RNC_EV_MSG_UP_CO_INITIAL)
			| S(IU_RNC_EV_MSG_UP_CO)
			| S(IU_RNC_EV_AVAILABLE)
			| S(IU_RNC_EV_UNAVAILABLE)
			,
		.out_state_mask = 0
			| S(IU_RNC_ST_WAIT_RX_RESET)
			| S(IU_RNC_ST_WAIT_RX_RESET_ACK)
			| S(IU_RNC_ST_READY)
			| S(IU_RNC_ST_DISCARDING)
			,
	},
	[IU_RNC_ST_READY] = {
		.name = "READY",
		.action = iu_rnc_st_ready,
		.onenter = iu_rnc_st_ready_onenter,
		.onleave = iu_rnc_st_ready_onleave,
		.in_event_mask = 0
			| S(IU_RNC_EV_RX_RESET)
			| S(IU_RNC_EV_MSG_UP_CO_INITIAL)
			| S(IU_RNC_EV_MSG_UP_CO)
			| S(IU_RNC_EV_AVAILABLE)
			| S(IU_RNC_EV_UNAVAILABLE)
			,
		.out_state_mask = 0
			| S(IU_RNC_ST_WAIT_RX_RESET)
			| S(IU_RNC_ST_WAIT_RX_RESET_ACK)
			| S(IU_RNC_ST_READY)
			| S(IU_RNC_ST_DISCARDING)
			,
	},
	[IU_RNC_ST_DISCARDING] = {
		.name = "DISCARDING",
	},
};

struct osmo_fsm iu_rnc_fsm = {
	.name = "iu_rnc",
	.states = iu_rnc_fsm_states,
	.num_states = ARRAY_SIZE(iu_rnc_fsm_states),
	.log_subsys = DRANAP,
	.event_names = iu_rnc_fsm_event_names,
	.timer_cb = iu_rnc_fsm_timer_cb,
	.cleanup = iu_rnc_fsm_cleanup,
};

static __attribute__((constructor)) void iu_rnc_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&iu_rnc_fsm) == 0);
}
