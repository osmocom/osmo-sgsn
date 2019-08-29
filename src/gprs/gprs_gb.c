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

#include "bscconfig.h"

#include <osmocom/sgsn/gprs_sgsn.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/debug.h>

/* Update the MM context state */
static void gsm0408_gprs_notify_pdu_gb(struct sgsn_mm_ctx *mmctx)
{
	switch (mmctx->gb.mm_state) {
	case MM_STANDBY:
		mmctx_set_mm_state(mmctx, MM_READY);
		break;
	case MM_READY: /* RE-arm the timer upon receival of Gb PDUs */
		mmctx_state_timer_start(mmctx, 3314);
		break;
	default:
		break;
	}
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
	}

	/* MMCTX can be NULL */

	if (mmctx)
		gsm0408_gprs_notify_pdu_gb(mmctx);

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
