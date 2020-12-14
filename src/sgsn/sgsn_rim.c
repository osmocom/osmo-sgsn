
#include <stdio.h>

#include <errno.h>
#include <stdint.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/vty/logging.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_bssgp_rim.h>
#include <osmocom/sgsn/sgsn_rim.h>
#include <osmocom/sgsn/debug.h>

/* Find an NSEI for the destination cell, this function works only for GERAN! */
static int find_dest_nsei_geran(struct bssgp_rim_routing_info *dest_rim_ri, uint16_t nsei)
{
	struct bssgp_bvc_ctx *bvc_ctx;

	OSMO_ASSERT(dest_rim_ri->discr == BSSGP_RIM_ROUTING_INFO_GERAN);

	bvc_ctx = btsctx_by_raid_cid(&dest_rim_ri->geran.raid, dest_rim_ri->geran.cid);
	if (!bvc_ctx) {
		LOGP(DRIM, LOGL_ERROR, "BSSGP RIM (NSEI=%u) cannot find NSEI for destination cell\n", nsei);
		return -EINVAL;
	}

	return bvc_ctx->nsei;
}

int sgsn_rim_rx(struct osmo_bssgp_prim *bp, struct msgb *msg)
{
	struct bssgp_ran_information_pdu *pdu = &bp->u.rim_pdu;
	int d_nsei;
	uint16_t nsei = msgb_nsei(msg);

	/* At the moment we only support GERAN, so we block all other network
	 * types here. */
	if (pdu->routing_info_dest.discr != BSSGP_RIM_ROUTING_INFO_GERAN) {
		LOGP(DRIM, LOGL_ERROR,
		     "BSSGP RIM (NSEI=%u) only GERAN supported, destination cell is not a GERAN cell -- rejected.\n",
		     nsei);
		/* At the moment we can only handle GERAN addresses, any other
		 * type of address will be consideres as an invalid address.
		 * see also: 3GPP TS 48.018, section 8c.3.1.3 */
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_RIM_AI, NULL, msg);
	}
	if (pdu->routing_info_src.discr != BSSGP_RIM_ROUTING_INFO_GERAN) {
		LOGP(DRIM, LOGL_ERROR,
		     "BSSGP RIM (NSEI=%u) only GERAN supported, source cell is not a GERAN cell -- rejected.\n", nsei);
		/* See comment above */
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_RIM_AI, NULL, msg);
	}

	d_nsei = find_dest_nsei_geran(&pdu->routing_info_dest, nsei);
	if (d_nsei < 0) {
		LOGP(DRIM, LOGL_NOTICE, "BSSGP RIM (NSEI=%u) Cell %s unknown to this sgsn\n",
		     nsei, bssgp_rim_ri_name(&pdu->routing_info_dest));
		/* In case of an invalid destination address we respond with
		 * a BSSGP STATUS PDU, see also: 3GPP TS 48.018, section 8c.3.1.3 */
		return bssgp_tx_status(BSSGP_CAUSE_UNKN_RIM_AI, NULL, msg);
	}

	/* Forward PDU as it is to the correct interface */
	return bssgp_tx_rim(pdu, (uint16_t) d_nsei);
}
