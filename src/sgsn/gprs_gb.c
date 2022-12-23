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

#include <osmocom/sgsn/gprs_sgsn.h>
#include <osmocom/sgsn/debug.h>

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
