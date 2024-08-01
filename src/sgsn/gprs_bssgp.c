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
#include <osmocom/core/rate_ctr.h>

#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns2.h>

#include <osmocom/gprs/llc/llc_prim.h>

#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/sgsn_rim.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/mmctx.h>

/* receive an incoming LLC PDU (BSSGP-UL-UNITDATA-IND, 7.2.4.2) */
static int sgsn_bssgp_rx_ul_unitdata(struct osmo_bssgp_prim *bp)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;
	struct gprs_ra_id ra_id;
	uint8_t *llc_pdu =(uint8_t *)TLVP_VAL(bp->tp, BSSGP_IE_LLC_PDU);
	size_t llc_pdu_len = TLVP_LEN(bp->tp, BSSGP_IE_LLC_PDU);

	switch (gprs_tlli_type(bp->tlli)) {
	case TLLI_LOCAL:
	case TLLI_FOREIGN:
	case TLLI_RANDOM:
	case TLLI_AUXILIARY:
		break;
	default:
		LOGP(DLLC, LOGL_ERROR,
			"Discarding frame with strange TLLI type\n");
		return -EINVAL;
	}

	/* TODO: Update LLE's (BVCI, NSEI) tuple */
	//lle->llme->bvci = msgb_bvci(msg);
	//lle->llme->nsei = msgb_nsei(msg);

	OSMO_ASSERT(TLVP_PRES_LEN(bp->tp, BSSGP_IE_CELL_ID, 8));
	bssgp_parse_cell_id(&ra_id, TLVP_VAL(bp->tp, BSSGP_IE_CELL_ID));

	llc_prim = osmo_gprs_llc_prim_alloc_bssgp_ul_unitdata_ind(bp->tlli, llc_pdu, llc_pdu_len);
	OSMO_ASSERT(llc_prim);
	llc_prim->bssgp.ul_unitdata_ind.cell_id.ci =
			bssgp_parse_cell_id(&llc_prim->bssgp.ul_unitdata_ind.cell_id.rai,
					    TLVP_VAL(bp->tp, BSSGP_IE_CELL_ID));
	rc = osmo_gprs_llc_prim_lower_up(llc_prim);

	return rc;
}

/* call-back function for the BSSGP protocol */
int sgsn_bssgp_rx_prim(struct osmo_prim_hdr *oph)
{
	struct osmo_bssgp_prim *bp;
	bp = container_of(oph, struct osmo_bssgp_prim, oph);

	switch (oph->sap) {
	case SAP_BSSGP_LL:
		switch (oph->primitive) {
		case PRIM_BSSGP_UL_UD:
			return sgsn_bssgp_rx_ul_unitdata(bp);
		}
		break;
	case SAP_BSSGP_GMM:
		switch (oph->primitive) {
		case PRIM_BSSGP_GMM_SUSPEND:
			return gprs_gmm_rx_suspend(bp->ra_id, bp->tlli);
		case PRIM_BSSGP_GMM_RESUME:
			return gprs_gmm_rx_resume(bp->ra_id, bp->tlli,
						  bp->u.resume.suspend_ref);
		}
		break;
	case SAP_BSSGP_NM:
		break;
	case SAP_BSSGP_RIM:
		return sgsn_rim_rx_from_gb(bp, oph->msg);
	}
	return 0;
}

int sgsn_bssgp_page_ps_ra(struct sgsn_mm_ctx *mmctx)
{
	struct bssgp_paging_info pinfo;
	int rc;

	/* FIXME: page whole routing area, not only the last known cell */

	/* initiate PS PAGING procedure */
	memset(&pinfo, 0, sizeof(pinfo));
	pinfo.mode = BSSGP_PAGING_PS;
	pinfo.scope = BSSGP_PAGING_BVCI;
	pinfo.bvci = mmctx->gb.bvci;
	pinfo.imsi = mmctx->imsi;
	pinfo.ptmsi = &mmctx->p_tmsi;
	pinfo.drx_params = mmctx->drx_parms;
	pinfo.qos[0] = 0; // FIXME
	rc = bssgp_tx_paging(mmctx->gb.nsei, 0, &pinfo);
	rate_ctr_inc(rate_ctr_group_get_ctr(mmctx->ctrg, GMM_CTR_PAGING_PS));

	return rc;
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
