/* GPRS BSSGP protocol implementation as per 3GPP TS 08.18 */

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

#include <osmocom/core/prim.h>

#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns2.h>

#include <osmocom/gsm/gsm48.h>

#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_routing_area.h>
#include <osmocom/sgsn/sgsn_rim.h>
#include <osmocom/sgsn/mmctx.h>

#include <osmocom/sgsn/debug.h>

static int bssgp_nm_bvc_reset_ind(struct osmo_bssgp_prim *bp)
{
	struct osmo_cell_global_id_ps cgi_ps = {};

	if (!bp->tp)
		return -EINVAL;

	if (!TLVP_PRES_LEN(bp->tp, BSSGP_IE_CELL_ID, 8))
		return -EINVAL;

	bssgp_parse_cell_id2(&cgi_ps.rai, &cgi_ps.cell_identity, TLVP_VAL(bp->tp, BSSGP_IE_CELL_ID), 8);
	return sgsn_ra_bvc_reset_ind(bp->nsei, bp->bvci, &cgi_ps);
}

/* call-back function for the BSSGP protocol */
int sgsn_bssgp_rx_prim(struct osmo_prim_hdr *oph)
{
	struct osmo_bssgp_prim *bp;
	struct osmo_routing_area_id rai = {};
	bp = container_of(oph, struct osmo_bssgp_prim, oph);

	switch (oph->sap) {
	case SAP_BSSGP_LL:
		switch (oph->primitive) {
		case PRIM_BSSGP_UL_UD:
			return gprs_llc_rcvmsg(oph->msg, bp->tp);
		}
		break;
	case SAP_BSSGP_GMM:
		gprs_rai_to_osmo(&rai, bp->ra_id);
		switch (oph->primitive) {
		case PRIM_BSSGP_GMM_SUSPEND:
			return gprs_gmm_rx_suspend(&rai, bp->tlli);
		case PRIM_BSSGP_GMM_RESUME:
			return gprs_gmm_rx_resume(&rai, bp->tlli,
						  bp->u.resume.suspend_ref);
		}
		break;
	case SAP_BSSGP_NM:
		switch (oph->primitive) {
		case PRIM_NM_BVC_RESET:
			if (oph->operation == PRIM_OP_INDICATION)
				bssgp_nm_bvc_reset_ind(bp);
			break;
		case PRIM_NM_BVC_BLOCK:
		case PRIM_NM_BVC_UNBLOCK:
		case PRIM_NM_STATUS:
		case PRIM_NM_LLC_DISCARDED:
			break;
		}

		break;
	case SAP_BSSGP_RIM:
		return sgsn_rim_rx_from_gb(bp, oph->msg);
	}
	return 0;
}

int sgsn_bssgp_page_ps_bvci(struct sgsn_mm_ctx *mmctx, uint16_t nsei, uint16_t bvci)
{
	struct bssgp_paging_info pinfo;

	/* initiate PS PAGING procedure */
	memset(&pinfo, 0, sizeof(pinfo));
	pinfo.mode = BSSGP_PAGING_PS;
	pinfo.scope = BSSGP_PAGING_BVCI;
	pinfo.bvci = bvci;
	pinfo.imsi = mmctx->imsi;
	pinfo.ptmsi = &mmctx->p_tmsi;
	pinfo.drx_params = mmctx->drx_parms;
	pinfo.qos[0] = 0; // FIXME
	return bssgp_tx_paging(nsei, 0, &pinfo);
}

/* called by the bssgp layer to send NS PDUs */
int sgsn_bssgp_dispatch_ns_unitdata_req_cb(void *ctx, struct msgb *msg)
{
	struct gprs_ns2_inst *nsi = (struct gprs_ns2_inst *) ctx;
	struct osmo_gprs_ns2_prim nsp = {};
	nsp.nsei = msgb_nsei(msg);
	nsp.bvci = msgb_bvci(msg);
	osmo_prim_init(&nsp.oph, SAP_NS, GPRS_NS2_PRIM_UNIT_DATA, PRIM_OP_REQUEST, msg);
	return gprs_ns2_recv_prim(nsi, &nsp.oph);
}
