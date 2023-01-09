/* TS 23.060 § 6.1.1 Mobility Management States (A/Gb mode) */
/*
 * (C) 2019 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
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

#include <osmocom/sgsn/gprs_mm_state_gb_fsm.h>
#include <osmocom/sgsn/gprs_llc.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/mmctx.h>

#define X(s) (1 << (s))

static const struct osmo_tdef_state_timeout mm_state_gb_fsm_timeouts[32] = {
	[ST_MM_IDLE] = { },
	[ST_MM_READY] = { .T=3314 },
	[ST_MM_STANDBY] = { },
};

#define mm_state_gb_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, mm_state_gb_fsm_timeouts, sgsn->cfg.T_defs, -1)

static void st_mm_idle_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state) {
	struct sgsn_mm_ctx *ctx = fi->priv;

	/* FIXME: remove this timer when RAU has it's own fsm */
	if (ctx->T == 3350 && osmo_timer_pending(&ctx->timer))
		osmo_timer_del(&ctx->timer);

	if (ctx->gb.llme) {
		gprs_llgmm_unassign(ctx->gb.llme);
		ctx->gb.llme = NULL;
	}
}

static void st_mm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_MM_GPRS_ATTACH:
		mm_state_gb_fsm_state_chg(fi, ST_MM_READY);
		break;
	case E_MM_PDU_RECEPTION:
		break;
	}
}

static void st_mm_ready(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	unsigned long t_secs;

	switch(event) {
	case E_MM_READY_TIMER_EXPIRY:
		mm_state_gb_fsm_state_chg(fi, ST_MM_STANDBY);
		break;
	case E_MM_GPRS_DETACH:
		mm_state_gb_fsm_state_chg(fi, ST_MM_IDLE);
		break;
	case E_MM_PDU_RECEPTION:
		/* RE-arm the READY timer upon receival of Gb PDUs */
		t_secs = osmo_tdef_get(sgsn->cfg.T_defs, 3314, OSMO_TDEF_S, -1);
		osmo_timer_schedule(&fi->timer, t_secs, 0);
		break;
	case E_MM_RA_UPDATE:
		break;
	}
}

static void st_mm_standby(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_MM_PDU_RECEPTION:
		mm_state_gb_fsm_state_chg(fi, ST_MM_READY);
		break;
	case E_MM_GPRS_DETACH:
		mm_state_gb_fsm_state_chg(fi, ST_MM_IDLE);
		break;
	}
}

static struct osmo_fsm_state mm_state_gb_fsm_states[] = {
	[ST_MM_IDLE] = {
		.in_event_mask = X(E_MM_GPRS_ATTACH) | X(E_MM_PDU_RECEPTION),
		.out_state_mask = X(ST_MM_READY),
		.onenter = st_mm_idle_on_enter,
		.name = "Idle",
		.action = st_mm_idle,
	},
	[ST_MM_READY] = {
		.in_event_mask = X(E_MM_READY_TIMER_EXPIRY) | X(E_MM_RA_UPDATE) | X(E_MM_GPRS_DETACH) | X(E_MM_PDU_RECEPTION),
		.out_state_mask = X(ST_MM_IDLE) | X(ST_MM_STANDBY),
		.name = "Ready",
		.action = st_mm_ready,
	},
	[ST_MM_STANDBY] = {
		.in_event_mask = X(E_MM_PDU_RECEPTION) | X(E_MM_GPRS_DETACH),
		.out_state_mask = X(ST_MM_IDLE) | X(ST_MM_READY),
		.name = "Standby",
		.action = st_mm_standby,
	},
};

const struct value_string mm_state_gb_fsm_event_names[] = {
	OSMO_VALUE_STRING(E_MM_GPRS_ATTACH),
	OSMO_VALUE_STRING(E_MM_PDU_RECEPTION),
	OSMO_VALUE_STRING(E_MM_GPRS_DETACH),
	OSMO_VALUE_STRING(E_MM_READY_TIMER_EXPIRY),
	OSMO_VALUE_STRING(E_MM_RA_UPDATE),
	{ 0, NULL }
};

int mm_state_gb_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch(fi->state) {
	case ST_MM_READY:
		/* timer for mm state. state=READY: T3314 (aka TS 23.060 "READY timer") */
		osmo_fsm_inst_dispatch(fi, E_MM_READY_TIMER_EXPIRY, NULL);
		break;
	}

	return 0;
}

struct osmo_fsm mm_state_gb_fsm = {
	.name = "MM_STATE_Gb",
	.states = mm_state_gb_fsm_states,
	.num_states = ARRAY_SIZE(mm_state_gb_fsm_states),
	.event_names = mm_state_gb_fsm_event_names,
	.log_subsys = DMM,
	.timer_cb = mm_state_gb_fsm_timer_cb,
};

static __attribute__((constructor)) void mm_state_gb_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&mm_state_gb_fsm) == 0);
}
