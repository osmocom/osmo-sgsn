
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
#include <osmocom/sgsn/gtp_mme.h>
#include <osmocom/sgsn/gtp.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>

static int sgsn_bssgp_fwd_rim_to_geran(const struct bssgp_ran_information_pdu *pdu)
{
	struct bssgp_bvc_ctx *bvc_ctx;
	OSMO_ASSERT(pdu->routing_info_dest.discr == BSSGP_RIM_ROUTING_INFO_GERAN);

	/* Resolve RIM ROUTING ADDRESS to a BVC context */
	bvc_ctx = btsctx_by_raid_cid(&pdu->routing_info_dest.geran.raid, pdu->routing_info_dest.geran.cid);
	if (!bvc_ctx) {
		LOGP(DRIM, LOGL_ERROR, "Unable to find NSEI for destination cell %s\n",
		       bssgp_rim_ri_name(&pdu->routing_info_dest));
		return -EINVAL;
	}

	/* Forward PDU to the NSEI of the resolved BVC context */
	return bssgp_tx_rim(pdu, bvc_ctx->nsei);
}

static int sgsn_bssgp_fwd_rim_to_geran_encoded(struct msgb *msg, struct bssgp_rim_routing_info *rim_routing_address)
{
	struct bssgp_bvc_ctx *bvc_ctx;
	OSMO_ASSERT(rim_routing_address->discr == BSSGP_RIM_ROUTING_INFO_GERAN);

	/* Resolve RIM ROUTING ADDRESS to a BVC context */
	bvc_ctx = btsctx_by_raid_cid(&rim_routing_address->geran.raid, rim_routing_address->geran.cid);
	if (!bvc_ctx) {
		LOGP(DRIM, LOGL_ERROR, "Unable to find NSEI for destination cell %s\n",
		       bssgp_rim_ri_name(rim_routing_address));
		return -EINVAL;
	}

	/* Forward PDU to the NSEI of the resolved BVC context */
	return bssgp_tx_rim_encoded(msg, bvc_ctx->nsei);
}

static int sgsn_bssgp_fwd_rim_to_eutran(const struct bssgp_ran_information_pdu *pdu)
{
	struct sgsn_mme_ctx *mme;
	OSMO_ASSERT(pdu->routing_info_dest.discr == BSSGP_RIM_ROUTING_INFO_EUTRAN);

	mme = sgsn_mme_ctx_by_route(sgsn, &pdu->routing_info_dest.eutran.tai);
	if (!mme) { /* See if we have a default route configured */
		mme = sgsn_mme_ctx_by_default_route(sgsn);
		if (!mme) {
			LOGP(DRIM, LOGL_ERROR, "Unable to find MME for destination cell %s\n",
			       bssgp_rim_ri_name(&pdu->routing_info_dest));
			return -EINVAL;
		}
	}

	return sgsn_mme_ran_info_req(mme, pdu);
}

/* Receive a RIM PDU from BSSGP (GERAN) */
int sgsn_rim_rx_from_gb(struct osmo_bssgp_prim *bp, struct msgb *msg)
{
	uint16_t nsei = msgb_nsei(msg);
	struct bssgp_ran_information_pdu *pdu = &bp->u.rim_pdu;

	if (pdu->routing_info_src.discr != BSSGP_RIM_ROUTING_INFO_GERAN) {
		LOGP(DRIM, LOGL_ERROR,
		     "Rx BSSGP RIM (NSEI=%u): Expected src %s, got %s\n", nsei,
		     bssgp_rim_routing_info_discr_str(BSSGP_RIM_ROUTING_INFO_GERAN),
		     bssgp_rim_routing_info_discr_str(pdu->routing_info_src.discr));
		goto err;
	}

	switch (pdu->routing_info_dest.discr) {
	case BSSGP_RIM_ROUTING_INFO_GERAN:
		return sgsn_bssgp_fwd_rim_to_geran(pdu);
	case BSSGP_RIM_ROUTING_INFO_EUTRAN:
		return sgsn_bssgp_fwd_rim_to_eutran(pdu);
	default:
		/* At the moment we can only handle GERAN/EUTRAN addresses, any
		 * other type of address will be considered as an invalid
		 * address. see also: 3GPP TS 48.018, section 8c.3.1.3
		 */
		LOGP(DRIM, LOGL_ERROR,
		     "Rx BSSGP RIM (NSEI=%u): Unsupported dst %s\n", nsei,
		     bssgp_rim_routing_info_discr_str(pdu->routing_info_dest.discr));
	}

	LOGP(DRIM, LOGL_INFO, "Rx BSSGP RIM (NSEI=%u): for dest cell %s\n", nsei,
	     bssgp_rim_ri_name(&pdu->routing_info_dest));

err:
	/* In case of an invalid destination address we respond with
	 * a BSSGP STATUS PDU, see also: 3GPP TS 48.018, section 8c.3.1.3 */
	bssgp_tx_status(BSSGP_CAUSE_UNKN_RIM_AI, NULL, msg);
	return -1;
}

/* Receive a RIM PDU from GTPv1C (EUTRAN) */
int sgsn_rim_rx_from_gtp(struct msgb *msg, struct bssgp_rim_routing_info *rim_routing_address)
{
	/* TODO: In this code path, we currently only support RIM message forwarding to GERAN (BSSGP). However, it
	 * technically also be possible to route a message back to GTP (BSSGP_RIM_ROUTING_INFO_EUTRAN) or to
	 * IuPS (BSSGP_RIM_ROUTING_INFO_UTRAN) */
	if (rim_routing_address->discr != BSSGP_RIM_ROUTING_INFO_GERAN) {
		LOGP(DRIM, LOGL_ERROR, "Rx GTP RAN Information Relay: Expected dst %s, got %s\n",
		     bssgp_rim_routing_info_discr_str(BSSGP_RIM_ROUTING_INFO_GERAN),
		     bssgp_rim_routing_info_discr_str(rim_routing_address->discr));
		return -EINVAL;
	}

	LOGP(DRIM, LOGL_INFO, "Rx GTP RAN Information Relay for dest cell %s\n",
	     bssgp_rim_ri_name(rim_routing_address));

	return sgsn_bssgp_fwd_rim_to_geran_encoded(msg, rim_routing_address);
}
