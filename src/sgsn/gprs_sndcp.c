/* GPRS SNDCP User/SN/SNSM interfaces as per 3GPP TS 04.65 */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * (C) 2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 *
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

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/endian.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/sndcp/sndcp_prim.h>
#include <osmocom/gprs/sndcp/sndcp.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gprs_ns.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gtp.h>
#include <osmocom/sgsn/gprs_sndcp.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/pdpctx.h>

/* Send SN-XID.rsp to lower layer (SNDCP): */
static int sgsn_sndcp_sn_xid_rsp(struct sgsn_pdp_ctx *pdp)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	int rc;

	sndcp_prim = osmo_gprs_sndcp_prim_alloc_sn_xid_rsp(pdp->mm->gb.llme->tlli, pdp->sapi, pdp->nsapi);
	OSMO_ASSERT(sndcp_prim);
	rc = osmo_gprs_sndcp_prim_upper_down(sndcp_prim);
	return rc;
}

/* Received SN-XID.ind from SNDCP layer: */
static int sgsn_sndcp_handle_sn_xid_ind(struct osmo_gprs_sndcp_prim *sndcp_prim)
{
	struct sgsn_mm_ctx *mmctx;
	struct sgsn_pdp_ctx *pdp;

	/* look-up the MM context for this message */
	mmctx = sgsn_mm_ctx_by_tlli(sndcp_prim->sn.tlli);
	if (!mmctx) {
		LOGP(DSNDCP, LOGL_ERROR, "Cannot find MM CTX for TLLI %08x\n", sndcp_prim->sn.tlli);
		return -EIO;
	}
	/* look-up the PDP context for this message */
	pdp = sgsn_pdp_ctx_by_nsapi(mmctx, sndcp_prim->sn.xid_ind.nsapi);
	if (!pdp) {
		LOGMMCTXP(LOGL_ERROR, mmctx, "Cannot find PDP CTX for TLLI=%08x, NSAPI=%u\n",
			  sndcp_prim->sn.tlli, sndcp_prim->sn.xid_ind.nsapi);
		return -EIO;
	}
	return sgsn_sndcp_sn_xid_rsp(pdp);
}

static int sgsn_sndcp_prim_up_cb(struct osmo_gprs_sndcp_prim *sndcp_prim, void *user_data)
{
	const char *npdu_name = osmo_gprs_sndcp_prim_name(sndcp_prim);
	int rc = 0;

	if (sndcp_prim->oph.sap != OSMO_GPRS_SNDCP_SAP_SN) {
		printf("%s(): Unexpected Rx %s\n", __func__, npdu_name);
		OSMO_ASSERT(0);
	}

	switch (OSMO_PRIM_HDR(&sndcp_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SN_UNITDATA, PRIM_OP_INDICATION):
		LOGP(DSNDCP, LOGL_DEBUG, "%s(): Rx %s TLLI=0x%08x SAPI=%s NSAPI=%u NPDU=[%s]\n",
		     __func__, npdu_name,
		     sndcp_prim->sn.tlli, osmo_gprs_llc_sapi_name(sndcp_prim->sn.sapi),
		     sndcp_prim->sn.data_req.nsapi,
		     osmo_hexdump(sndcp_prim->sn.data_ind.npdu, sndcp_prim->sn.data_ind.npdu_len));

		sgsn_gtp_data_req(sndcp_prim->sn.tlli, sndcp_prim->sn.data_req.nsapi,
				  sndcp_prim->sn.data_ind.npdu, sndcp_prim->sn.data_ind.npdu_len);
		break;
	case OSMO_PRIM(OSMO_GPRS_SNDCP_SN_XID, PRIM_OP_INDICATION):
		printf("%s(): Rx %s TODO IMPLEMENT see libosm-gprs gprs_sndcp_snme_handle_llc_ll_xid_ind()!\n", __func__, npdu_name);
		rc = sgsn_sndcp_handle_sn_xid_ind(sndcp_prim);
		break;
	default:
		printf("%s(): Rx %s\n", __func__, npdu_name);
		break;
	};
	return rc;
}

static int sgsn_sndcp_prim_down_cb(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_llc_prim_name(llc_prim);

	if (llc_prim->oph.sap != OSMO_GPRS_LLC_SAP_LL) {
		printf("%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}

	switch (OSMO_PRIM_HDR(&llc_prim->oph)) {
	case OSMO_PRIM(OSMO_GPRS_LLC_LL_UNITDATA, PRIM_OP_REQUEST):
		printf("%s(): Rx %s TLLI=0x%08x SAPI=%s L3=[%s]\n",
		       __func__, pdu_name,
		       llc_prim->ll.tlli, osmo_gprs_llc_sapi_name(llc_prim->ll.sapi),
		       osmo_hexdump(llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len));
		break;
	default:
		printf("%s(): Rx %s\n", __func__, pdu_name);
		break;
	};
	return 0;
}

static int sgsn_sndcp_prim_snsm_cb(struct osmo_gprs_sndcp_prim *sndcp_prim, void *user_data)
{
	const char *npdu_name = osmo_gprs_sndcp_prim_name(sndcp_prim);

	if (sndcp_prim->oph.sap != OSMO_GPRS_SNDCP_SAP_SNSM) {
		printf("%s(): Unexpected Rx %s\n", __func__, npdu_name);
		OSMO_ASSERT(0);
	}

	printf("%s(): Rx %s\n", __func__, npdu_name);
	return 0;
}


int sgsn_sndcp_init(void)
{
	int rc;
	rc = osmo_gprs_sndcp_init(OSMO_GPRS_SNDCP_LOCATION_NET);
	if (rc != 0)
		return rc;

	osmo_gprs_sndcp_set_log_cat(OSMO_GPRS_SNDCP_LOGC_SNDCP, DSNDCP);
	osmo_gprs_sndcp_set_log_cat(OSMO_GPRS_SNDCP_LOGC_SLHC, DSNDCP);

	osmo_gprs_sndcp_prim_set_up_cb(sgsn_sndcp_prim_up_cb, NULL);
	osmo_gprs_sndcp_prim_set_down_cb(sgsn_sndcp_prim_down_cb, NULL);
	osmo_gprs_sndcp_prim_set_snsm_cb(sgsn_sndcp_prim_snsm_cb, NULL);
	return rc;
}

int sgsn_sndcp_sn_xid_req(uint32_t tlli, uint8_t nsapi, uint8_t sapi)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	int rc;

	sndcp_prim = osmo_gprs_sndcp_prim_alloc_sn_xid_req(tlli, sapi, nsapi);
	OSMO_ASSERT(sndcp_prim);
	sndcp_prim->sn.xid_req.pcomp_rfc1144.active = sgsn->cfg.pcomp_rfc1144.active;
	sndcp_prim->sn.xid_req.pcomp_rfc1144.s01 = sgsn->cfg.pcomp_rfc1144.s01;
	sndcp_prim->sn.xid_req.dcomp_v42bis.active = sgsn->cfg.dcomp_v42bis.active;
	sndcp_prim->sn.xid_req.dcomp_v42bis.p0 = sgsn->cfg.dcomp_v42bis.p0;
	sndcp_prim->sn.xid_req.dcomp_v42bis.p1 = sgsn->cfg.dcomp_v42bis.p1;
	sndcp_prim->sn.xid_req.dcomp_v42bis.p2 = sgsn->cfg.dcomp_v42bis.p2;
	rc = osmo_gprs_sndcp_prim_upper_down(sndcp_prim);
	return rc;
}

int sgsn_sndcp_sn_unitdata_req(uint32_t tlli, uint8_t nsapi, uint8_t sapi,
			       uint8_t *npdu, unsigned int npdu_len)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	int rc;

	sndcp_prim = osmo_gprs_sndcp_prim_alloc_sn_unitdata_req(tlli, sapi, nsapi, npdu, npdu_len);
	OSMO_ASSERT(sndcp_prim);
	rc = osmo_gprs_sndcp_prim_upper_down(sndcp_prim);
	return rc;
}

/* Submit SNSM-ACTIVATE.indication to SNDCP */
int sgsn_sndcp_snsm_activate_ind(uint32_t tlli, uint8_t nsapi, uint8_t sapi)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	int rc;

	sndcp_prim = osmo_gprs_sndcp_prim_alloc_snsm_activate_ind(tlli, nsapi, sapi);
	OSMO_ASSERT(sndcp_prim);
	/* TODO: fill following fields:
	 * uint8_t qos_params[3];
	 * uint8_t radio_prio;
	 */
	rc = osmo_gprs_sndcp_prim_dispatch_snsm(sndcp_prim);
	return rc;
}

/* Submit SNSM-DEACTIVATE.indication to SNDCP */
int sgsn_sndcp_snsm_deactivate_ind(uint32_t tlli, uint8_t nsapi)
{
	struct osmo_gprs_sndcp_prim *sndcp_prim;
	int rc;

	sndcp_prim = osmo_gprs_sndcp_prim_alloc_snsm_deactivate_ind(tlli, nsapi);
	OSMO_ASSERT(sndcp_prim);
	rc = osmo_gprs_sndcp_prim_dispatch_snsm(sndcp_prim);
	return rc;
}
