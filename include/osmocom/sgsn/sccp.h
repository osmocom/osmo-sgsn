/* SCCP Handling */
/* (C) 2025 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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
#pragma once

#include <stdint.h>

#include <osmocom/sigtran/sccp_sap.h>

struct sgsn_instance;
struct ranap_ue_conn_ctx;

struct sgsn_sccp_user_iups {
	struct sgsn_instance *sgsn; /* backpointer */
	struct osmo_sccp_instance *sccp; /* backpointer */
	struct osmo_sccp_user *scu; /* IuPS */
	struct osmo_sccp_addr local_sccp_addr;
	struct llist_head ue_conn_ctx_list; /* list of "struct ranap_ue_conn_ctx" */
	struct llist_head ue_conn_sccp_addr_list; /* list of "struct iu_new_ctx_entry" */
};

struct sgsn_sccp_user_iups *sgsn_scu_iups_inst_alloc(struct sgsn_instance *sgsn, struct osmo_sccp_instance *sccp);
void sgsn_scu_iups_free(struct sgsn_sccp_user_iups *scu_iups);

int sgsn_scu_iups_tx_data_req(struct sgsn_sccp_user_iups *scu_iups, uint32_t conn_id, struct msgb *ranap_msg);

struct ranap_ue_conn_ctx *sgsn_scu_iups_ue_conn_ctx_find(struct sgsn_sccp_user_iups *scu_iups, uint32_t conn_id);

int sgsn_sccp_init(struct sgsn_instance *sgsn);
void sgsn_sccp_release(struct sgsn_instance *sgsn);

