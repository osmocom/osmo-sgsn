/* Common parts of IuCS and IuPS interfaces implementation */

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
#include <osmocom/sgsn/sccp.h>
#include <osmocom/sgsn/sgsn.h>

const struct value_string iu_client_event_type_names[] = {
	OSMO_VALUE_STRING(RANAP_IU_EVENT_RAB_ASSIGN),
	OSMO_VALUE_STRING(RANAP_IU_EVENT_SECURITY_MODE_COMPLETE),
	OSMO_VALUE_STRING(RANAP_IU_EVENT_IU_RELEASE),
	OSMO_VALUE_STRING(RANAP_IU_EVENT_LINK_INVALIDATED),
	OSMO_VALUE_STRING(RANAP_IU_EVENT_NEW_AREA),
	{ 0, NULL }
};

int global_iu_event(struct ranap_ue_conn_ctx *ue_ctx,
		    enum ranap_iu_event_type type,
		    void *data)
{

	if (ue_ctx && !ue_ctx->notification)
		return 0;

	LOGP(DRANAP, LOGL_DEBUG, "Submit Iu event to upper layer: %s\n", iu_client_event_type_str(type));

	return sgsn_ranap_iu_event(ue_ctx, type, data);
}


static void ue_conn_ctx_release_timeout_cb(void *ctx_)
{
	struct ranap_ue_conn_ctx *ctx = (struct ranap_ue_conn_ctx *)ctx_;
	global_iu_event(ctx, RANAP_IU_EVENT_IU_RELEASE, NULL);
}

struct ranap_ue_conn_ctx *ue_conn_ctx_alloc(struct ranap_iu_rnc *rnc, uint32_t conn_id)
{
	struct ranap_ue_conn_ctx *ctx = talloc_zero(sgsn, struct ranap_ue_conn_ctx);

	ctx->rnc = rnc;
	ctx->conn_id = conn_id;
	ctx->notification = true;
	ctx->free_on_release = false;
	osmo_timer_setup(&ctx->release_timeout,
			 ue_conn_ctx_release_timeout_cb,
			 ctx);
	llist_add(&ctx->list, &rnc->scu_iups->ue_conn_ctx_list);

	return ctx;
}

void sgsn_ranap_iu_free_ue(struct ranap_ue_conn_ctx *ue_ctx)
{
	if (!ue_ctx)
		return;

	osmo_timer_del(&ue_ctx->release_timeout);
	osmo_sccp_tx_disconn(ue_ctx->rnc->scu_iups->scu, ue_ctx->conn_id, NULL, 0);
	llist_del(&ue_ctx->list);
	talloc_free(ue_ctx);
}

void ue_conn_ctx_link_invalidated_free(struct ranap_ue_conn_ctx *ue)
{
	uint32_t conn_id = ue->conn_id;
	struct sgsn_sccp_user_iups *scu_iups = ue->rnc->scu_iups;

	global_iu_event(ue, RANAP_IU_EVENT_LINK_INVALIDATED, NULL);

	/* A RANAP_IU_EVENT_LINK_INVALIDATED, can lead to a free */
	ue = sgsn_scu_iups_ue_conn_ctx_find(scu_iups, conn_id);
	if (!ue)
		return;
	if (ue->free_on_release)
		sgsn_ranap_iu_free_ue(ue);
}


/***********************************************************************
 * Paging
 ***********************************************************************/

/* legacy, do a first match with ignoring PLMN */
static struct ranap_iu_rnc *iu_rnc_lac_rac_find_legacy(uint16_t lac, uint8_t rac)
{
	struct ranap_iu_rnc *rnc;
	struct iu_lac_rac_entry *e;

	llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
		llist_for_each_entry(e, &rnc->lac_rac_list, entry) {
			if (e->rai.lac.lac == lac && e->rai.rac == rac)
				return rnc;
		}
	}
	return NULL;
}

/*! Old paging() doesn't use PLMN and transmit paging command only to the first RNC  */
int ranap_iu_page_cs(const char *imsi, const uint32_t *tmsi, uint16_t lac)
{
	struct ranap_iu_rnc *rnc;
	char log_msg[32] = {};
	int rc;

	if (tmsi)
		snprintf(log_msg, sizeof(log_msg), "TMSI %08x\n", *tmsi);
	else
		snprintf(log_msg, sizeof(log_msg), "IMSI %s\n", imsi);

	rnc = iu_rnc_lac_rac_find_legacy(lac, 0);
	if (!rnc) {
		LOGP(DRANAP, LOGL_INFO, "Found no RNC to Page CS on LAC %u for %s",
		     lac, log_msg);
		return 0;
	}

	rc = iu_rnc_tx_paging_cmd(rnc, imsi, tmsi, false, 0);
	if (rc != 0) {
		LOG_RNC(rnc, LOGL_ERROR, "Failed to tx Paging CS for LAC %u for %s",
			lac, log_msg);
		return 0;
	}
	return 1;
}

/*! Old paging() doesn't use PLMN and transmit paging command only to the first RNC  */
int ranap_iu_page_ps(const char *imsi, const uint32_t *ptmsi, uint16_t lac, uint8_t rac)
{
	struct ranap_iu_rnc *rnc;
	char log_msg[32] = {};
	int rc;

	if (ptmsi)
		snprintf(log_msg, sizeof(log_msg), "P-TMSI %08x\n", *ptmsi);
	else
		snprintf(log_msg, sizeof(log_msg), "IMSI %s\n", imsi);

	rnc = iu_rnc_lac_rac_find_legacy(lac, rac);
	if (!rnc) {
		LOGP(DRANAP, LOGL_INFO, "Found no RNC to Page PS on LAC %u RAC %u for %s",
		     lac, rac, log_msg);
		return 0;
	}

	rc = iu_rnc_tx_paging_cmd(rnc, imsi, ptmsi, true, 0);
	if (rc != 0) {
		LOG_RNC(rnc, LOGL_ERROR, "Failed to tx Paging PS for LAC %u RAC %u for %s",
			lac, rac, log_msg);
		return 0;
	}
	return 1;
}

/*! Transmit a single page request towards all RNCs serving the specific LAI (no page retransmission).
 *
 * \param imsi the imsi as human readable string
 * \param tmsi NULL or pointer to the tmsi
 * \param lai full Location Area Identifier
 * \return amount of paged RNCs. 0 when no RNC found.
 */
int ranap_iu_page_cs2(const char *imsi, const uint32_t *tmsi, const struct osmo_location_area_id *lai)
{
	struct ranap_iu_rnc *rnc;
	struct iu_lac_rac_entry *entry;
	char log_msg[32] = {};
	unsigned int paged = 0;
	int rc;

	if (tmsi)
		snprintf(log_msg, sizeof(log_msg), "TMSI %08x\n", *tmsi);
	else
		snprintf(log_msg, sizeof(log_msg), "IMSI %s\n", imsi);

	/* find all RNCs which are serving this LA */
	llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
		llist_for_each_entry(entry, &rnc->lac_rac_list, entry) {
			if (osmo_lai_cmp(&entry->rai.lac, lai))
				continue;

			rc = iu_rnc_tx_paging_cmd(rnc, imsi, tmsi, false, 0);
			if (rc != 0) {
				LOG_RNC(rnc, LOGL_ERROR, "Failed to tx Paging CS for LAI %s for %s",
					osmo_lai_name(lai), log_msg);
			} else {
				paged++;
			}
			break;
		}
	}

	if (paged)
		LOGP(DRANAP, LOGL_DEBUG, "Paged CS %u RNCs on LAI %s for %s",
		     paged, osmo_lai_name(lai), log_msg);
	else
		LOGP(DRANAP, LOGL_INFO, "Found no RNC to Page CS on LAI %s for %s",
		     osmo_lai_name(lai), log_msg);

	return paged;
}

/*! Transmit a single page request towards all RNCs serving the specific RAI (no page retransmission).
 *
 * \param imsi the imsi as human readable string
 * \param ptmsi NULL or pointer to the ptmsi
 * \param rai full Location Area Identifier
 * \return amount of paged RNCs. 0 when no RNC found.
 */
int ranap_iu_page_ps2(const char *imsi, const uint32_t *ptmsi, const struct osmo_routing_area_id *rai)
{
	struct ranap_iu_rnc *rnc;
	struct iu_lac_rac_entry *entry;
	char log_msg[32] = {};
	unsigned int paged = 0;
	int rc;

	if (ptmsi)
		snprintf(log_msg, sizeof(log_msg), "P-TMSI %08x\n", *ptmsi);
	else
		snprintf(log_msg, sizeof(log_msg), "IMSI %s\n", imsi);

	/* find all RNCs which are serving this RAC */
	llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
		llist_for_each_entry(entry, &rnc->lac_rac_list, entry) {
			if (osmo_rai_cmp(&entry->rai, rai))
				continue;

			rc = iu_rnc_tx_paging_cmd(rnc, imsi, ptmsi, true, 0);
			if (rc != 0) {
				LOG_RNC(rnc, LOGL_ERROR, "Failed to tx Paging PS for RAI %s for %s",
					osmo_rai_name2(rai), log_msg);
			} else {
				paged++;
			}
			break;
		}
	}

	if (paged)
		LOGP(DRANAP, LOGL_DEBUG, "Paged PS %u RNCs on RAI %s for %s",
		     paged, osmo_rai_name2(rai), log_msg);
	else
		LOGP(DRANAP, LOGL_INFO, "Found no RNC to Page PS on RAI %s for %s",
		     osmo_rai_name2(rai), log_msg);

	return paged;
}

/***********************************************************************
 *
 ***********************************************************************/

int ranap_iu_init(void *ctx)
{
	talloc_asn1_ctx = talloc_named_const(ctx, 1, "asn1");
	return 0;
}
