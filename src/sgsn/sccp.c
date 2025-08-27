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

#include "config.h"

#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sccp/sccp_types.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/iu_client.h>
#include <osmocom/sgsn/iu_rnc.h>
#include <osmocom/sgsn/gprs_ranap.h>
#include <osmocom/sgsn/sccp.h>
#include <osmocom/sgsn/sgsn.h>

/* Entry to cache conn_id <-> sccp_addr mapping in case we receive an empty CR */
struct iu_new_ctx_entry {
	struct llist_head list;

	uint32_t conn_id;
	struct osmo_sccp_addr sccp_addr;
};

static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu);

struct sgsn_sccp_user_iups *sgsn_scu_iups_inst_alloc(struct sgsn_instance *sgsn, struct osmo_sccp_instance *sccp)
{
	struct sgsn_sccp_user_iups *scu_iups;

	scu_iups = talloc_zero(sgsn, struct sgsn_sccp_user_iups);
	OSMO_ASSERT(scu_iups);

	scu_iups->sgsn = sgsn;
	scu_iups->sccp = sccp;

	INIT_LLIST_HEAD(&scu_iups->ue_conn_ctx_list);
	INIT_LLIST_HEAD(&scu_iups->ue_conn_sccp_addr_list);

	osmo_sccp_local_addr_by_instance(&scu_iups->local_sccp_addr, scu_iups->sccp, OSMO_SCCP_SSN_RANAP);
	scu_iups->scu = osmo_sccp_user_bind(scu_iups->sccp, "OsmoSGSN-IuPS", sccp_sap_up, OSMO_SCCP_SSN_RANAP);
	osmo_sccp_user_set_priv(scu_iups->scu, scu_iups);

	return scu_iups;
}

void sgsn_scu_iups_free(struct sgsn_sccp_user_iups *scu_iups)
{
	if (!scu_iups)
		return;

	if (scu_iups->scu)
		osmo_sccp_user_unbind(scu_iups->scu);
	talloc_free(scu_iups);
}

/* wrap RANAP message in SCCP N-DATA.req
 * ranap_msg becomes owned by the callee. */
int sgsn_scu_iups_tx_data_req(struct sgsn_sccp_user_iups *scu_iups, uint32_t conn_id, struct msgb *ranap_msg)
{
	struct osmo_scu_prim *prim;
	int rc;

	if (!scu_iups) {
		LOGP(DSUA, LOGL_ERROR, "Failed to send SCCP N-DATA.req(%u): no SCCP User\n", conn_id);
		return -1;
	}

	ranap_msg->l2h = ranap_msg->data;
	prim = (struct osmo_scu_prim *)msgb_push(ranap_msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER, OSMO_SCU_PRIM_N_DATA, PRIM_OP_REQUEST, ranap_msg);
	prim->u.data.conn_id = conn_id;

	rc = osmo_sccp_user_sap_down(scu_iups->scu, &prim->oph);
	if (rc)
		LOGP(DSUA, LOGL_ERROR, "Failed to send SCCP N-DATA.req(%u)\n", conn_id);
	return rc;
}

static struct ranap_ue_conn_ctx *ue_conn_ctx_find(struct sgsn_sccp_user_iups *scu_iups, uint32_t conn_id)
{
	struct ranap_ue_conn_ctx *ctx;

	llist_for_each_entry(ctx, &scu_iups->ue_conn_ctx_list, list) {
		if (ctx->conn_id == conn_id)
			return ctx;
	}
	return NULL;
}

static void ue_conn_sccp_addr_add(struct sgsn_sccp_user_iups *scu_iups, uint32_t conn_id, const struct osmo_sccp_addr *calling_addr)
{
	struct iu_new_ctx_entry *entry = talloc_zero(scu_iups, struct iu_new_ctx_entry);

	entry->conn_id = conn_id;
	entry->sccp_addr = *calling_addr;

	llist_add(&entry->list, &scu_iups->ue_conn_sccp_addr_list);
}

static const struct osmo_sccp_addr *ue_conn_sccp_addr_find(struct sgsn_sccp_user_iups *scu_iups, uint32_t conn_id)
{
	struct iu_new_ctx_entry *entry;
	llist_for_each_entry(entry, &scu_iups->ue_conn_sccp_addr_list, list) {
		if (entry->conn_id == conn_id)
			return &entry->sccp_addr;
	}
	return NULL;
}

static void ue_conn_sccp_addr_del(struct sgsn_sccp_user_iups *scu_iups, uint32_t conn_id)
{
	struct iu_new_ctx_entry *entry;
	llist_for_each_entry(entry, &scu_iups->ue_conn_sccp_addr_list, list) {
		if (entry->conn_id == conn_id) {
			llist_del(&entry->list);
			talloc_free(entry);
			return;
		}
	}
}

static void ue_ctx_link_invalidated_free(struct ranap_ue_conn_ctx *ue)
{
	uint32_t conn_id = ue->conn_id;
	struct sgsn_sccp_user_iups *scu_iups = ue->scu_iups;

	global_iu_event(ue, RANAP_IU_EVENT_LINK_INVALIDATED, NULL);

	/* A RANAP_IU_EVENT_LINK_INVALIDATED, can lead to a free */
	ue = ue_conn_ctx_find(scu_iups, conn_id);
	if (!ue)
		return;
	if (ue->free_on_release)
		ranap_iu_free_ue(ue);
}

static void handle_notice_ind(struct sgsn_sccp_user_iups *scu_iups, const struct osmo_scu_notice_param *ni)
{
	struct ranap_iu_rnc *rnc;

	LOGP(DSUA, LOGL_DEBUG, "(calling_addr=%s) N-NOTICE.ind cause=%u='%s' importance=%u\n",
	     osmo_sccp_addr_dump(&ni->calling_addr),
	     ni->cause, osmo_sccp_return_cause_name(ni->cause),
	     ni->importance);

	switch (ni->cause) {
	case SCCP_RETURN_CAUSE_SUBSYSTEM_CONGESTION:
	case SCCP_RETURN_CAUSE_NETWORK_CONGESTION:
		/* Transient failures (hopefully), keep going. */
		return;
	default:
		break;
	}

	/* Messages are not arriving to RNC. Signal to user that all related ue_ctx are invalid. */
	llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
		struct ranap_ue_conn_ctx *ue_ctx, *ue_ctx_tmp;
		if (osmo_sccp_addr_ri_cmp(&rnc->sccp_addr, &ni->calling_addr))
			continue;
		LOGP(DSUA, LOGL_NOTICE,
		     "RNC %s now unreachable: N-NOTICE.ind cause=%u='%s' importance=%u\n",
		     osmo_rnc_id_name(&rnc->rnc_id),
		     ni->cause, osmo_sccp_return_cause_name(ni->cause),
		     ni->importance);
		llist_for_each_entry_safe(ue_ctx, ue_ctx_tmp, &scu_iups->ue_conn_ctx_list, list) {
			if (ue_ctx->rnc != rnc)
				continue;
			ue_ctx_link_invalidated_free(ue_ctx);
		}
		/* TODO: ideally we'd have some event to submit to upper
		 * layer to inform about peer availability change... */
	}
}

static void handle_pcstate_ind(struct sgsn_sccp_user_iups *scu_iups, const struct osmo_scu_pcstate_param *pcst)
{
	struct osmo_ss7_instance *cs7 = osmo_sccp_get_ss7(scu_iups->sccp);
	struct osmo_sccp_addr rem_addr;
	struct ranap_iu_rnc *rnc;
	bool connected;
	bool disconnected;

	LOGP(DSUA, LOGL_DEBUG, "N-PCSTATE ind: affected_pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
	     pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
	     osmo_sccp_sp_status_name(pcst->sp_status),
	     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));

	osmo_sccp_make_addr_pc_ssn(&rem_addr, pcst->affected_pc, OSMO_SCCP_SSN_RANAP);

	/* See if this marks the point code to have become available, or to have been lost.
	 *
	 * I want to detect two events:
	 * - connection event (both indicators say PC is reachable).
	 * - disconnection event (at least one indicator says the PC is not reachable).
	 *
	 * There are two separate incoming indicators with various possible values -- the incoming events can be:
	 *
	 * - neither connection nor disconnection indicated -- just indicating congestion
	 *   connected == false, disconnected == false --> do nothing.
	 * - both incoming values indicate that we are connected
	 *   --> trigger connected
	 * - both indicate we are disconnected
	 *   --> trigger disconnected
	 * - one value indicates 'connected', the other indicates 'disconnected'
	 *   --> trigger disconnected
	 *
	 * Congestion could imply that we're connected, but it does not indicate
	 * that a PC's reachability changed, so no need to trigger on that.
	 */
	connected = false;
	disconnected = false;

	switch (pcst->sp_status) {
	case OSMO_SCCP_SP_S_ACCESSIBLE:
		connected = true;
		break;
	case OSMO_SCCP_SP_S_INACCESSIBLE:
		disconnected = true;
		break;
	default:
	case OSMO_SCCP_SP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	switch (pcst->remote_sccp_status) {
	case OSMO_SCCP_REM_SCCP_S_AVAILABLE:
		if (!disconnected)
			connected = true;
		break;
	case OSMO_SCCP_REM_SCCP_S_UNAVAILABLE_UNKNOWN:
	case OSMO_SCCP_REM_SCCP_S_UNEQUIPPED:
	case OSMO_SCCP_REM_SCCP_S_INACCESSIBLE:
		disconnected = true;
		connected = false;
		break;
	default:
	case OSMO_SCCP_REM_SCCP_S_CONGESTED:
		/* Neither connecting nor disconnecting */
		break;
	}

	if (disconnected) {
		/* A previously usable RNC has disconnected. Signal to user that all related ue_ctx are invalid. */
		llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
			struct ranap_ue_conn_ctx *ue_ctx, *ue_ctx_tmp;
			if (osmo_sccp_addr_cmp(&rnc->sccp_addr, &rem_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
				continue;
			LOGP(DSUA, LOGL_NOTICE,
			     "RNC %s now unreachable: N-PCSTATE ind: pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
			     osmo_rnc_id_name(&rnc->rnc_id),
			     pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
			     osmo_sccp_sp_status_name(pcst->sp_status),
			     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
			llist_for_each_entry_safe(ue_ctx, ue_ctx_tmp, &scu_iups->ue_conn_ctx_list, list) {
				if (ue_ctx->rnc != rnc)
					continue;
				ue_ctx_link_invalidated_free(ue_ctx);
			}
			/* TODO: ideally we'd have some event to submit to upper
			 * layer to inform about peer availability change... */
		}
	} else if (connected) {
		llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
			if (osmo_sccp_addr_cmp(&rnc->sccp_addr, &rem_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
				continue;
			LOGP(DSUA, LOGL_NOTICE,
			     "RNC %s now available: N-PCSTATE ind: pc=%u=%s sp_status=%s remote_sccp_status=%s\n",
			     osmo_rnc_id_name(&rnc->rnc_id),
			     pcst->affected_pc, osmo_ss7_pointcode_print(cs7, pcst->affected_pc),
			     osmo_sccp_sp_status_name(pcst->sp_status),
			     osmo_sccp_rem_sccp_status_name(pcst->remote_sccp_status));
			/* TODO: ideally we'd have some event to submit to upper
			 * layer to inform about peer availability change... */
		}
	}
}

static struct osmo_prim_hdr *make_conn_resp(struct osmo_scu_connect_param *param)
{
	struct msgb *msg = msgb_alloc(1024, "conn_resp");
	struct osmo_scu_prim *prim;

	prim = (struct osmo_scu_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			OSMO_SCU_PRIM_N_CONNECT,
			PRIM_OP_RESPONSE, msg);
	memcpy(&prim->u.connect, param, sizeof(prim->u.connect));
	return &prim->oph;
}

static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu = _scu;
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct sgsn_sccp_user_iups *scu_iups = osmo_sccp_user_get_priv(scu);
	struct osmo_prim_hdr *resp = NULL;
	int rc = -1;
	struct ranap_ue_conn_ctx *ue;
	uint32_t conn_id;

	LOGP(DSUA, LOGL_DEBUG, "sccp_sap_up(%s)\n", osmo_scu_prim_name(oph));

	switch (OSMO_PRIM_HDR(oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		/* confirmation of outbound connection */
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* indication of new inbound connection request*/
		conn_id = prim->u.connect.conn_id;
		LOGP(DSUA, LOGL_DEBUG, "N-CONNECT.ind(X->%u)\n", conn_id);

		/* first ensure the local SCCP socket is ACTIVE */
		resp = make_conn_resp(&prim->u.connect);
		osmo_sccp_user_sap_down(scu, resp);
		/* then handle the RANAP payload */
		if (/*  prim->u.connect.called_addr.ssn != OSMO_SCCP_SSN_RANAP || */
		    !msgb_l2(oph->msg) || msgb_l2len(oph->msg) == 0) {
			LOGP(DSUA, LOGL_DEBUG,
			     "Received N-CONNECT.ind without data\n");
			ue_conn_sccp_addr_add(scu_iups, conn_id, &prim->u.connect.calling_addr);
		} else {
			rc = sgsn_ranap_iu_rx_co_initial_msg(scu_iups, &prim->u.connect.calling_addr,
							     conn_id,
							     msgb_l2(oph->msg), msgb_l2len(oph->msg));
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		/* indication of disconnect */
		conn_id = prim->u.disconnect.conn_id;
		LOGP(DSUA, LOGL_DEBUG, "N-DISCONNECT.ind(%u)\n", conn_id);

		ue_conn_sccp_addr_del(scu_iups, conn_id);
		ue = ue_conn_ctx_find(scu_iups, conn_id);
		if (!ue)
			break;

		rc = 0;
		if (msgb_l2len(oph->msg) > 0)
			rc = sgsn_ranap_iu_rx_co_msg(ue, msgb_l2(oph->msg), msgb_l2len(oph->msg));

		/* A Iu Release event might be used to free the UE in cn_ranap_handle_co(). */
		ue = ue_conn_ctx_find(scu_iups, conn_id);
		if (!ue)
			break;
		ue_ctx_link_invalidated_free(ue);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* connection-oriented data received */
		conn_id = prim->u.data.conn_id;
		LOGP(DSUA, LOGL_DEBUG, "N-DATA.ind(%u, %s)\n", conn_id,
		     osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));

		/* resolve UE context */
		ue = ue_conn_ctx_find(scu_iups, conn_id);
		if (!ue) {
			/* Could be an InitialUE-Message after an empty CR, recreate new_ctx */
			const struct osmo_sccp_addr *sccp_addr = ue_conn_sccp_addr_find(scu_iups, conn_id);
			if (!sccp_addr) {
				LOGP(DSUA, LOGL_NOTICE,
				     "N-DATA.ind for unknown conn_id (%u)\n", conn_id);
				break;
			}
			/* Hold copy of address before deleting it: */
			struct osmo_sccp_addr rem_sccp_addr = *sccp_addr;
			ue_conn_sccp_addr_del(scu_iups, conn_id);
			rc = sgsn_ranap_iu_rx_co_initial_msg(scu_iups, &rem_sccp_addr, conn_id,
							     msgb_l2(oph->msg), msgb_l2len(oph->msg));
			break;
		}
		rc = sgsn_ranap_iu_rx_co_msg(ue, msgb_l2(oph->msg), msgb_l2len(oph->msg));
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* connection-less data received */
		LOGP(DSUA, LOGL_DEBUG, "N-UNITDATA.ind(%s)\n",
		     osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		rc = sgsn_ranap_iu_rx_cl_msg(scu_iups, &prim->u.unitdata, msgb_l2(oph->msg), msgb_l2len(oph->msg));
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_NOTICE, PRIM_OP_INDICATION):
		LOGP(DSUA, LOGL_DEBUG, "N-NOTICE.ind(%s)\n",
		     osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		handle_notice_ind(scu_iups, &prim->u.notice);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_PCSTATE, PRIM_OP_INDICATION):
		handle_pcstate_ind(scu_iups, &prim->u.pcstate);
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_STATE, PRIM_OP_INDICATION):
		LOGP(DSUA, LOGL_DEBUG, "SCCP-User-SAP: Ignoring %s.%s\n",
		     osmo_scu_prim_type_name(oph->primitive),
		     get_value_string(osmo_prim_op_names, oph->operation));
		break;
	default:
		break;
	}

	msgb_free(oph->msg);
	return rc;
}

int sgsn_sccp_init(struct sgsn_instance *sgi)
{
	/* Note that these are mostly defaults and can be overridden from the VTY */
	sgi->sccp.sccp = osmo_sccp_simple_client_on_ss7_id(tall_sgsn_ctx,
							   sgi->cfg.iu.cs7_instance,
							   "OsmoSGSN",
							   (23 << 3) + 4,
							   OSMO_SS7_ASP_PROT_M3UA,
							   0, "localhost",
							   0, "localhost");
	if (!sgi->sccp.sccp) {
		LOGP(DGPRS, LOGL_ERROR, "Setting up SCCP instance on cs7 instance %d failed!\n",
		     sgi->cfg.iu.cs7_instance);
		return -EINVAL;
	}
	osmo_sccp_set_priv(sgi->sccp.sccp, sgsn);

	sgi->sccp.scu_iups = sgsn_scu_iups_inst_alloc(sgsn, sgi->sccp.sccp);
	OSMO_ASSERT(sgi->sccp.scu_iups);

	return 0;
}

void sgsn_sccp_release(struct sgsn_instance *sgi)
{
	sgsn_scu_iups_free(sgi->sccp.scu_iups);
	sgi->sccp.scu_iups = NULL;
	if (sgi->sccp.sccp) {
		osmo_sccp_instance_destroy(sgi->sccp.sccp);
		sgi->sccp.sccp = NULL;
	}
}
