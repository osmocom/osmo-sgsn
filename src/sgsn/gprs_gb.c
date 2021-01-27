/* Messages on the Gb interface (A/Gb mode) */

/* (C) 2009-2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/rate_ctr.h>

#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/gprs_bssgp_bss.h>
#include <osmocom/sgsn/gprs_llc.h>

#include "bscconfig.h"

#include <osmocom/sgsn/gprs_mm_state_gb_fsm.h>
#include <osmocom/sgsn/gprs_sgsn.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_sm.h>
#include <osmocom/sgsn/debug.h>

/* Has to be called whenever any PDU (signaling, data, ...) has been received */
void gprs_gb_recv_pdu(struct sgsn_mm_ctx *mmctx) {
	if (mmctx->gb.llme)
		osmo_fsm_inst_dispatch(mmctx->gb.mm_state_fsm, E_MM_PDU_RECEPTION, NULL);
}

/* Main entry point for incoming 04.08 GPRS messages from Gb */
int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	struct sgsn_mm_ctx *mmctx;
	struct gprs_ra_id ra_id;
	int rc = -EINVAL;

	bssgp_parse_cell_id(&ra_id, msgb_bcid(msg));
	mmctx = sgsn_mm_ctx_by_tlli(msgb_tlli(msg), &ra_id);
	if (mmctx) {
		msgid2mmctx(mmctx, msg);
		rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PKTS_SIG_IN]);
		mmctx->gb.llme = llme;
		gprs_gb_recv_pdu(mmctx);
	}

	/* MMCTX can be NULL */

	switch (pdisc) {
	case GSM48_PDISC_MM_GPRS:
		rc = gsm0408_rcv_gmm(mmctx, msg, llme, drop_cipherable);
		break;
	case GSM48_PDISC_SM_GPRS:
		rc = gsm0408_rcv_gsm(mmctx, msg, llme);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			"Unknown GSM 04.08 discriminator 0x%02x: %s\n",
			pdisc, osmo_hexdump((uint8_t *)gh, msgb_l3len(msg)));
		/* FIXME: return status message */
		break;
	}

	/* MMCTX can be invalid */

	return rc;
}


int gprs_gb_page_ps_ra(struct sgsn_mm_ctx *mmctx)
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
	rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PAGING_PS]);

	return rc;
}

/* called by the bssgp layer to send NS PDUs */
int gprs_gb_send_cb(void *ctx, struct msgb *msg)
{
	struct gprs_ns2_inst *nsi = (struct gprs_ns2_inst *) ctx;
	struct osmo_gprs_ns2_prim nsp = {};
	nsp.nsei = msgb_nsei(msg);
	nsp.bvci = msgb_bvci(msg);
	osmo_prim_init(&nsp.oph, SAP_NS, GPRS_NS2_PRIM_UNIT_DATA, PRIM_OP_REQUEST, msg);
	return gprs_ns2_recv_prim(nsi, &nsp.oph);
}

void gprs_ns_prim_status_cb(struct osmo_gprs_ns2_prim *nsp)
{
	switch (nsp->u.status.cause) {
	case GPRS_NS2_AFF_CAUSE_SNS_CONFIGURED:
		LOGP(DGPRS, LOGL_NOTICE, "NS-E %d SNS configured.\n", nsp->nsei);
		break;
	case GPRS_NS2_AFF_CAUSE_RECOVERY:
		LOGP(DGPRS, LOGL_NOTICE, "NS-E %d became available\n", nsp->nsei);
		/* workaround for broken BSS which doesn't respond correct to BSSGP status message.
		 * Sent a BSSGP Reset when a persistent NSVC comes up for the first time. */
		if (nsp->u.status.first && nsp->u.status.persistent) {
			struct bssgp_bvc_ctx bctx = {
				.nsei = nsp->nsei,
			};
			bssgp_tx_bvc_reset2(&bctx, BVCI_SIGNALLING, BSSGP_CAUSE_EQUIP_FAIL, false);
		}
		break;
	case GPRS_NS2_AFF_CAUSE_FAILURE:
		LOGP(DGPRS, LOGL_NOTICE, "NS-E %d became unavailable\n", nsp->nsei);
		break;
	default:
		LOGP(DGPRS, LOGL_NOTICE, "NS: %s Unknown prim %d from NS\n",
		     get_value_string(osmo_prim_op_names, nsp->oph.operation), nsp->oph.primitive);
		break;
	}
}

/* call-back function for the NS protocol */
int gprs_ns_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_gprs_ns2_prim *nsp;
	int rc = 0;

	if (oph->sap != SAP_NS)
		return 0;

	nsp = container_of(oph, struct osmo_gprs_ns2_prim, oph);

	if (oph->operation != PRIM_OP_INDICATION) {
		LOGP(DGPRS, LOGL_NOTICE, "NS: %s Unknown prim %d from NS\n",
		     get_value_string(osmo_prim_op_names, oph->operation),
		     oph->operation);
		return 0;
	}

	switch (oph->primitive) {
	case GPRS_NS2_PRIM_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		/* add required msg fields for Gb layer */
		msgb_bssgph(oph->msg) = oph->msg->l3h;
		msgb_bvci(oph->msg) = nsp->bvci;
		msgb_nsei(oph->msg) = nsp->nsei;
		rc = bssgp_rcvmsg(oph->msg);
		break;
	case GPRS_NS2_PRIM_STATUS:
		gprs_ns_prim_status_cb(nsp);
		break;
	default:
		LOGP(DGPRS, LOGL_NOTICE, "NS: %s Unknown prim %d from NS\n",
		     get_value_string(osmo_prim_op_names, oph->operation), oph->primitive);
		break;
	}

	if (oph->msg)
		msgb_free(oph->msg);

	return rc;
}
