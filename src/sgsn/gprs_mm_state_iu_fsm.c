/* TS 23.060 § 6.1.2 Mobility Management States (Iu mode) */
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
#include <arpa/inet.h>

#include <osmocom/core/tdef.h>

#include <osmocom/sgsn/gprs_mm_state_iu_fsm.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_ranap.h>

#define X(s) (1 << (s))

static const struct osmo_tdef_state_timeout mm_state_iu_fsm_timeouts[32] = {
	[ST_PMM_DETACHED] = { },
	[ST_PMM_CONNECTED] = { },
	[ST_PMM_IDLE] = { },
};

#define mm_state_iu_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, mm_state_iu_fsm_timeouts, sgsn->cfg.T_defs, -1)

static void mmctx_change_gtpu_endpoints_to_sgsn(struct sgsn_mm_ctx *mm_ctx)
{
	char buf[INET_ADDRSTRLEN];
	struct sgsn_pdp_ctx *pdp;
	llist_for_each_entry(pdp, &mm_ctx->pdp_list, list) {
		LOGMMCTXP(LOGL_INFO, mm_ctx, "Changing GTP-U endpoints %s -> %s\n",
			  sgsn_gtp_ntoa(&pdp->lib->gsnlu),
			  inet_ntop(AF_INET, &sgsn->cfg.gtp_listenaddr.sin_addr, buf, sizeof(buf)));
		sgsn_pdp_upd_gtp_u(pdp,
				   &sgsn->cfg.gtp_listenaddr.sin_addr,
				   sizeof(sgsn->cfg.gtp_listenaddr.sin_addr));
	}
}

static void st_pmm_detached(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_PMM_PS_ATTACH:
		mm_state_iu_fsm_state_chg(fi, ST_PMM_CONNECTED);
		break;
	case E_PMM_IMPLICIT_DETACH:
		break;
	}
}

static void st_pmm_connected(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sgsn_mm_ctx *ctx = fi->priv;

	switch(event) {
	case E_PMM_PS_CONN_RELEASE:
		sgsn_ranap_iu_free(ctx);
		mm_state_iu_fsm_state_chg(fi, ST_PMM_IDLE);
		break;
	case E_PMM_IMPLICIT_DETACH:
		sgsn_ranap_iu_release_free(ctx, NULL);
		mm_state_iu_fsm_state_chg(fi, ST_PMM_DETACHED);
		break;
	case E_PMM_RA_UPDATE:
		break;
	}
}

static void st_pmm_idle_on_enter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct sgsn_mm_ctx *ctx = fi->priv;

	mmctx_change_gtpu_endpoints_to_sgsn(ctx);
}

static void st_pmm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch(event) {
	case E_PMM_PS_ATTACH:
	case E_PMM_PS_CONN_ESTABLISH:
		mm_state_iu_fsm_state_chg(fi, ST_PMM_CONNECTED);
		break;
	case E_PMM_IMPLICIT_DETACH:
		mm_state_iu_fsm_state_chg(fi, ST_PMM_DETACHED);
		break;
	}
}

static struct osmo_fsm_state mm_state_iu_fsm_states[] = {
	[ST_PMM_DETACHED] = {
		.in_event_mask = X(E_PMM_PS_ATTACH) | X(E_PMM_IMPLICIT_DETACH),
		.out_state_mask = X(ST_PMM_CONNECTED),
		.name = "Detached",
		.action = st_pmm_detached,
	},
	[ST_PMM_CONNECTED] = {
		.in_event_mask =
			X(E_PMM_PS_CONN_RELEASE) |
			X(E_PMM_RA_UPDATE) |
			X(E_PMM_IMPLICIT_DETACH),
		.out_state_mask = X(ST_PMM_DETACHED) | X(ST_PMM_IDLE),
		.name = "Connected",
		.action = st_pmm_connected,
	},
	[ST_PMM_IDLE] = {
		.in_event_mask =
			X(E_PMM_IMPLICIT_DETACH) |
			X(E_PMM_PS_CONN_ESTABLISH) |
			X(E_PMM_PS_ATTACH),
		.out_state_mask = X(ST_PMM_DETACHED) | X(ST_PMM_CONNECTED),
		.name = "Idle",
		.onenter = st_pmm_idle_on_enter,
		.action = st_pmm_idle,
	},
};

const struct value_string mm_state_iu_fsm_event_names[] = {
	OSMO_VALUE_STRING(E_PMM_PS_ATTACH),
	OSMO_VALUE_STRING(E_PMM_PS_CONN_RELEASE),
	OSMO_VALUE_STRING(E_PMM_PS_CONN_ESTABLISH),
	OSMO_VALUE_STRING(E_PMM_IMPLICIT_DETACH),
	OSMO_VALUE_STRING(E_PMM_RA_UPDATE),
	{ 0, NULL }
};

struct osmo_fsm mm_state_iu_fsm = {
	.name = "MM_STATE_Iu",
	.states = mm_state_iu_fsm_states,
	.num_states = ARRAY_SIZE(mm_state_iu_fsm_states),
	.event_names = mm_state_iu_fsm_event_names,
	.log_subsys = DMM,
};

static __attribute__((constructor)) void mm_state_iu_fsm_init(void)
{
	OSMO_ASSERT(osmo_fsm_register(&mm_state_iu_fsm) == 0);
}
