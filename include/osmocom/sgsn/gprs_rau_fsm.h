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
	GMM_RAU_S_WAIT_UE_RAU_COMPLETE,
};

enum gmm_rau_events {
	GMM_RAU_E_UE_RAU_REQUEST,
	GMM_RAU_E_UE_RAU_COMPLETE,
	GMM_RAU_E_VLR_RAU_ACCEPT, /* Request to transmit Att/RAU Accept */
	GMM_RAU_E_VLR_RAU_REJECT, /* Request to transmit Att/RAU Reject */
	GMM_RAU_E_VLR_TERM_SUCCESS, /* VLR Lu FSM terminates. Inform GMM about Att/RAU Success (including Att/RAU complete) */
	GMM_RAU_E_VLR_TERM_FAIL, /* VLR Lu FSM terminates. Inform GMM about Att/RAU fail */
};

/* To be used as data when terminating the fsm */
extern char *fsm_term_rau_att_req; /*! while RAU, receive a Attach Req */
extern char *fsm_term_att_req_chg; /*! Second Attach Req with changed context */
extern char *fsm_term_att_rej; /*! By SGSN decision, tx Reject */
extern char *fsm_term_rau_req_chg; /*! Second Rau Req with changed context */
extern char *fsm_term_rau_rej; /*! By SGSN decision, tx Reject */

extern const struct value_string gmm_rau_event_names[];

void gmm_rau_fsm_req(struct sgsn_mm_ctx *mmctx);
