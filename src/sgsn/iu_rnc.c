/* A remote RNC (Radio Network Controller), connected over IuPS */

/* (C) 2016-2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/core/logging.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sccp/sccp_types.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_ranap.h>
#include <osmocom/sgsn/iu_client.h>
#include <osmocom/sgsn/iu_rnc.h>
#include <osmocom/sgsn/iu_rnc_fsm.h>
#include <osmocom/sgsn/sccp.h>
#include <osmocom/sgsn/sgsn.h>

static struct ranap_iu_rnc *iu_rnc_alloc(const struct osmo_rnc_id *rnc_id,
					 struct sgsn_sccp_user_iups *scu_iups,
					 const struct osmo_sccp_addr *rnc_sccp_addr)
{
	struct ranap_iu_rnc *rnc;
	char *addr_str, *pos;

	rnc = talloc_zero(sgsn, struct ranap_iu_rnc);
	OSMO_ASSERT(rnc);

	INIT_LLIST_HEAD(&rnc->lac_rac_list);

	rnc->rnc_id = *rnc_id;
	rnc->scu_iups = scu_iups;
	rnc->sccp_addr = *rnc_sccp_addr;

	rnc->fi = osmo_fsm_inst_alloc(&iu_rnc_fsm, rnc, rnc, LOGL_INFO, NULL);
	OSMO_ASSERT(rnc->fi);

	/* Unfortunately, osmo_sccp_inst_addr_name() returns "RI=SSN_PC,PC=0.24.1,SSN=BSSAP" but neither commas nor
	 * full-stops are allowed as FSM inst id. Make it "RI-SSN_PC:PC-0-24-1:SSN-BSSAP". */
	addr_str = osmo_sccp_addr_dump(rnc_sccp_addr);
	for (pos = addr_str; *pos; pos++) {
		if (*pos == ',')
			*pos = ':';
		else if (*pos == '.' || *pos == '=')
			*pos = '-';
	}
	osmo_fsm_inst_update_id_f(rnc->fi, "RNC_ID-%s:%s",
				  osmo_rnc_id_name(rnc_id), addr_str);

	llist_add(&rnc->entry, &sgsn->rnc_list);
	sgsn_stat_inc(SGSN_STAT_IU_PEERS_TOTAL, 1);

	LOGP(DRANAP, LOGL_NOTICE, "New RNC %s at %s\n",
	     osmo_rnc_id_name(&rnc->rnc_id), osmo_sccp_addr_dump(rnc_sccp_addr));

	return rnc;
}

static struct ranap_iu_rnc *iu_rnc_find_by_id(const struct osmo_rnc_id *rnc_id)
{
	struct ranap_iu_rnc *rnc;
	llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
		if (!osmo_rnc_id_cmp(&rnc->rnc_id, rnc_id))
			return rnc;
	}
	return NULL;
}

struct ranap_iu_rnc *iu_rnc_find_by_addr(const struct osmo_sccp_addr *rnc_sccp_addr)
{
	struct ranap_iu_rnc *rnc;
	llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
		if (osmo_sccp_addr_ri_cmp(rnc_sccp_addr, &rnc->sccp_addr))
			continue;
		return rnc;
	}
	return NULL;
}

struct ranap_iu_rnc *iu_rnc_find_or_create(const struct osmo_rnc_id *rnc_id,
					   struct sgsn_sccp_user_iups *scu_iups,
					   const struct osmo_sccp_addr *addr)
{
	struct ranap_iu_rnc *rnc;

	/* Make sure we know this rnc_id and that this SCCP address is in our records */
	rnc = iu_rnc_find_by_id(rnc_id);
	if (rnc) {
		if (!osmo_sccp_addr_ri_cmp(&rnc->sccp_addr, addr)) {
			LOGP(DRANAP, LOGL_NOTICE, "RNC %s changed its SCCP addr to %s\n",
			     osmo_rnc_id_name(&rnc->rnc_id), osmo_sccp_addr_dump(addr));
			rnc->sccp_addr = *addr;
		}
	} else {
		rnc = iu_rnc_alloc(rnc_id, scu_iups, addr);
	}
	return rnc;
}

/* Find a match for the given LAC (and RAC). For CS, pass rac as 0.
 * If rnc and lre pointers are not NULL, *rnc / *lre are set to NULL if no match is found, or to the
 * match if a match is found.  Return true if a match is found. */
static bool iu_rnc_lac_rac_find(struct ranap_iu_rnc **rnc, struct iu_lac_rac_entry **lre,
				const struct osmo_routing_area_id *ra_id)
{
	struct ranap_iu_rnc *r;
	struct iu_lac_rac_entry *e;

	if (rnc)
		*rnc = NULL;
	if (lre)
		*lre = NULL;

	llist_for_each_entry(r, &sgsn->rnc_list, entry) {
		llist_for_each_entry(e, &r->lac_rac_list, entry) {
			if (!osmo_rai_cmp(&e->rai, ra_id)) {
				if (rnc)
					*rnc = r;
				if (lre)
					*lre = e;
				return true;
			}
		}
	}
	return false;
}

static void global_iu_event_new_area(const struct osmo_rnc_id *rnc_id, const struct osmo_routing_area_id *rai)
{
	struct ranap_iu_event_new_area new_area = (struct ranap_iu_event_new_area) {
	    .rnc_id = rnc_id,
	    .cell_type = RANAP_IU_NEW_RAC
	};

	if (rai->rac == OSMO_RESERVED_RAC) {
		new_area.cell_type = RANAP_IU_NEW_LAC;
		new_area.u.lai = &rai->lac;
	} else {
		new_area.cell_type = RANAP_IU_NEW_RAC;
		new_area.u.rai = rai;
	}

	global_iu_event(NULL, RANAP_IU_EVENT_NEW_AREA, &new_area);
}


void iu_rnc_update_rai_seen(struct ranap_iu_rnc *rnc, const struct osmo_routing_area_id *rai)
{
	struct ranap_iu_rnc *old_rnc;
	struct iu_lac_rac_entry *lre;

	/* Detect whether the LAC,RAC is already recorded in another RNC */
	iu_rnc_lac_rac_find(&old_rnc, &lre, rai);

	if (old_rnc && old_rnc != rnc) {
		/* LAC, RAC already exists in a different RNC */
		LOGP(DRANAP, LOGL_NOTICE, "LAC/RAC %s moved from RNC %s %s",
		     osmo_rai_name2(rai),
		     osmo_rnc_id_name(&old_rnc->rnc_id), osmo_sccp_addr_dump(&old_rnc->sccp_addr));
		LOGPC(DRANAP, LOGL_NOTICE, " to RNC %s %s\n",
		      osmo_rnc_id_name(&rnc->rnc_id), osmo_sccp_addr_dump(&rnc->sccp_addr));

		llist_del(&lre->entry);
		llist_add(&lre->entry, &rnc->lac_rac_list);
		global_iu_event_new_area(&rnc->rnc_id, rai);
	} else if (!old_rnc) {
		/* LAC, RAC not recorded yet */
		LOGP(DRANAP, LOGL_NOTICE, "RNC %s: new LAC/RAC %s\n",
		     osmo_rnc_id_name(&rnc->rnc_id), osmo_rai_name2(rai));
		lre = talloc_zero(rnc, struct iu_lac_rac_entry);
		lre->rai = *rai;
		llist_add(&lre->entry, &rnc->lac_rac_list);
		global_iu_event_new_area(&rnc->rnc_id, rai);
	}
	/* else, LAC,RAC already recorded with the current RNC. */
}

void iu_rnc_discard_all_ue_ctx(struct ranap_iu_rnc *rnc)
{
	struct ranap_ue_conn_ctx *ue_ctx, *ue_ctx_tmp;

	llist_for_each_entry_safe(ue_ctx, ue_ctx_tmp, &sgsn->sccp.scu_iups->ue_conn_ctx_list, list) {
		if (ue_ctx->rnc != rnc)
			continue;
		ue_conn_ctx_link_invalidated_free(ue_ctx);
	}
}

/* Send a paging command down a given SCCP User. tmsi_or_ptmsi and paging_cause are
 * optional and may be passed NULL and 0, respectively, to disable their use.
 * See enum RANAP_PagingCause.
 *
 * If tmsi_or_ptmsi is given, the imsi is not sent over the air interface.
 * Nevertheless, the IMSI is still required for resolution in the HNB-GW
 * and/or(?) RNC.
 *
 * returns negative if paging couldn't be sent (eg. because RNC is currently
 * unreachable in lower layers).
 **/
int iu_rnc_tx_paging_cmd(struct ranap_iu_rnc *rnc,
			 const char *imsi,
			 const uint32_t *tmsi_or_ptmsi,
			 bool is_ps,
			 uint32_t paging_cause)
{
	struct msgb *ranap_msg;
	int rc;

	/* rnc is not ready for paging (link not ready). */
	if (rnc->fi->state != IU_RNC_ST_READY)
		return -ENOLINK;

	LOG_RNC(rnc, LOGL_DEBUG, "Paging %s for %s=%08x IMSI=%s\n",
		is_ps ? "PS" : "CS",
		is_ps ? "P-TMSI" : "TMSI",
		tmsi_or_ptmsi ? *tmsi_or_ptmsi : GSM_RESERVED_TMSI,
		imsi);

	ranap_msg = ranap_new_msg_paging_cmd(imsi, tmsi_or_ptmsi, is_ps ? 1 : 0, paging_cause);
	if (!ranap_msg)
		return -EINVAL;

	rc = osmo_fsm_inst_dispatch(rnc->fi, IU_RNC_EV_MSG_DOWN_CL, ranap_msg);
	if (rc != 0)
		msgb_free(ranap_msg);
	return rc;
}
