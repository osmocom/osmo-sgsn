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

#define LOGPIU(level, fmt, args...) \
	LOGP(DRANAP, level, fmt, ## args)

#define LOGPIUC(level, fmt, args...) \
	LOGPC(DRANAP, level, fmt, ## args)

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

	LOGPIU(LOGL_DEBUG, "Submit Iu event to upper layer: %s\n", iu_client_event_type_str(type));

	return sgsn_ranap_iu_event(ue_ctx, type, data);
}


static void ue_conn_ctx_release_timeout_cb(void *ctx_)
{
	struct ranap_ue_conn_ctx *ctx = (struct ranap_ue_conn_ctx *)ctx_;
	global_iu_event(ctx, RANAP_IU_EVENT_IU_RELEASE, NULL);
}

struct ranap_ue_conn_ctx *ue_conn_ctx_alloc(struct ranap_iu_rnc *rnc, struct sgsn_sccp_user_iups *scu_iups, uint32_t conn_id)
{
	struct ranap_ue_conn_ctx *ctx = talloc_zero(sgsn, struct ranap_ue_conn_ctx);

	ctx->rnc = rnc;
	ctx->scu_iups = scu_iups;
	ctx->conn_id = conn_id;
	ctx->notification = true;
	ctx->free_on_release = false;
	osmo_timer_setup(&ctx->release_timeout,
			 ue_conn_ctx_release_timeout_cb,
			 ctx);
	llist_add(&ctx->list, &scu_iups->ue_conn_ctx_list);

	return ctx;
}

void sgsn_ranap_iu_free_ue(struct ranap_ue_conn_ctx *ue_ctx)
{
	if (!ue_ctx)
		return;

	osmo_timer_del(&ue_ctx->release_timeout);
	osmo_sccp_tx_disconn(ue_ctx->scu_iups->scu, ue_ctx->conn_id, NULL, 0);
	llist_del(&ue_ctx->list);
	talloc_free(ue_ctx);
}

/***********************************************************************
 * Paging
 ***********************************************************************/

/* legacy, do a first match with ignoring PLMN */
static bool iu_rnc_lac_rac_find_legacy(struct ranap_iu_rnc **rnc, struct iu_lac_rac_entry **lre,
				       uint16_t lac, uint8_t rac)
{
	struct ranap_iu_rnc *r;
	struct iu_lac_rac_entry *e;

	if (rnc)
		*rnc = NULL;
	if (lre)
		*lre = NULL;

	llist_for_each_entry(r, &sgsn->rnc_list, entry) {
		llist_for_each_entry(e, &r->lac_rac_list, entry) {
			if (e->rai.lac.lac == lac && e->rai.rac == rac) {
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

static int iu_page(const char *imsi, const uint32_t *tmsi_or_ptmsi,
		   uint16_t lac, uint8_t rac, bool is_ps)
{
	struct ranap_iu_rnc *rnc;
	const char *log_msg;
	int log_level;
	int paged = 0;

	iu_rnc_lac_rac_find_legacy(&rnc, NULL, lac, rac);
	if (rnc) {
		if (sgsn_ranap_iu_tx_paging_cmd(&rnc->sccp_addr, imsi, tmsi_or_ptmsi, is_ps, 0) == 0) {
			log_msg = "Paging";
			log_level = LOGL_DEBUG;
			paged = 1;
		} else {
			log_msg = "Paging failed";
			log_level = LOGL_ERROR;
		}
	} else {
		log_msg = "Found no RNC to Page";
		log_level = LOGL_ERROR;
	}

	if (is_ps)
		LOGPIU(log_level, "IuPS: %s on LAC %d RAC %d", log_msg, lac, rac);
	else
		LOGPIU(log_level, "IuCS: %s on LAC %d", log_msg, lac);
	if (rnc)
		LOGPIUC(log_level, " at SCCP-addr %s", osmo_sccp_addr_dump(&rnc->sccp_addr));
	if (tmsi_or_ptmsi)
		LOGPIUC(log_level, ", for %s %08x\n", is_ps ? "PTMSI" : "TMSI", *tmsi_or_ptmsi);
	else
		LOGPIUC(log_level, ", for IMSI %s\n", imsi);

	return paged;
}

/*! Old paging() doesn't use PLMN and transmit paging command only to the first RNC  */
int ranap_iu_page_cs(const char *imsi, const uint32_t *tmsi, uint16_t lac)
{
	return iu_page(imsi, tmsi, lac, 0, false);
}

/*! Old paging() doesn't use PLMN and transmit paging command only to the first RNC  */
int ranap_iu_page_ps(const char *imsi, const uint32_t *ptmsi, uint16_t lac, uint8_t rac)
{
	return iu_page(imsi, ptmsi, lac, rac, true);
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
	int paged = 0;
	int rc = 0;

	/* find all RNCs which are serving this LA */
	llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
		llist_for_each_entry(entry, &rnc->lac_rac_list, entry) {
			if (osmo_lai_cmp(&entry->rai.lac, lai))
				continue;

			rc = sgsn_ranap_iu_tx_paging_cmd(&rnc->sccp_addr, imsi, tmsi, false, 0);
			if (rc > 0) {
				LOGPIU(LOGL_ERROR, "IuCS: Failed to tx Paging RNC %s for LAC %s for IMSI %s / TMSI %08x",
				       osmo_rnc_id_name(&rnc->rnc_id),
				       osmo_lai_name(lai), imsi, tmsi ? *tmsi : GSM_RESERVED_TMSI);
			}
			paged++;
			break;
		}
	}

	if (tmsi)
		snprintf(log_msg, sizeof(log_msg), "for TMSI %08x\n", *tmsi);
	else
		snprintf(log_msg, sizeof(log_msg) - 1, "for IMSI %s\n", imsi);

	if (paged)
		LOGPIU(LOGL_DEBUG, "IuPS: Paged %d RNCs on LAI %s for %s", paged, osmo_lai_name(lai), log_msg);
	else
		LOGPIU(LOGL_INFO, "IuPS: Found no RNC to Page on LAI %s for %s", osmo_lai_name(lai), log_msg);


	return paged;
}

/*! Transmit a single page request towards all RNCs serving the specific RAI (no page retransmission).
 *
 * \param imsi the imsi as human readable string
 * \param ptmsi NULL or pointer to the tmsi
 * \param rai full Location Area Identifier
 * \return amount of paged RNCs. 0 when no RNC found.
 */
int ranap_iu_page_ps2(const char *imsi, const uint32_t *ptmsi, const struct osmo_routing_area_id *rai)
{
	struct ranap_iu_rnc *rnc;
	struct iu_lac_rac_entry *entry;
	char log_msg[32] = {};
	int paged = 0;
	int rc = 0;

	/* find all RNCs which are serving this RAC */
	llist_for_each_entry(rnc, &sgsn->rnc_list, entry) {
		llist_for_each_entry(entry, &rnc->lac_rac_list, entry) {
			if (osmo_rai_cmp(&entry->rai, rai))
				continue;

			rc = sgsn_ranap_iu_tx_paging_cmd(&rnc->sccp_addr, imsi, ptmsi, true, 0);
			if (rc > 0) {
				LOGPIU(LOGL_ERROR, "IuPS: Failed to tx Paging RNC %s for RAC %s for IMSI %s / P-TMSI %08x",
				       osmo_rnc_id_name(&rnc->rnc_id),
				       osmo_rai_name2(rai), imsi, ptmsi ? *ptmsi : GSM_RESERVED_TMSI);
			}
			paged++;
			break;
		}
	}

	if (ptmsi)
		snprintf(log_msg, sizeof(log_msg) - 1, "for PTMSI %08x\n", *ptmsi);
	else
		snprintf(log_msg, sizeof(log_msg) - 1, "for IMSI %s\n", imsi);

	if (paged)
		LOGPIU(LOGL_DEBUG, "IuPS: Paged %d RNCs on RAI %s for %s", paged, osmo_rai_name2(rai), log_msg);
	else
		LOGPIU(LOGL_INFO, "IuPS: Found no RNC to Page on RAI %s for %s", osmo_rai_name2(rai), log_msg);

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
