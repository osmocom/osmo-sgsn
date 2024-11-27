/* Routing Area Update FSM for MMCtx to synchrozie for foreign RAU to local RAU transistions */

/* (C) 2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Alexander Couzens <lynxis@fe80.eu>
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

#include <osmocom/core/utils.h>

struct sgsn_mm_ctx;

enum gmm_rau_state {
	GMM_RAU_S_INIT,
	GMM_RAU_S_WAIT_VLR_ANSWER,
	GMM_RAU_S_WAIT_GGSN_UPDATE,
	GMM_RAU_S_WAIT_UE_RAU_COMPLETE,
};

enum gmm_rau_events {
	GMM_RAU_E_UE_RAU_REQUEST,
	GMM_RAU_E_UE_RAU_COMPLETE,
	GMM_RAU_E_VLR_RAU_ACCEPT,
	GMM_RAU_E_VLR_RAU_REJECT,
	GMM_RAU_E_GGSN_UPD_RESP,
};

extern const struct value_string gmm_rau_event_names[];

void gmm_rau_fsm_req(struct sgsn_mm_ctx *mmctx);
