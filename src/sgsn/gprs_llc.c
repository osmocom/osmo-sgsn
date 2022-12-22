/* GPRS LLC protocol implementation as per 3GPP TS 04.64 */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
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
#include <inttypes.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/crypt/kdf.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gprs/llc/llc_prim.h>
#include <osmocom/gprs/llc/llc.h>
#include <osmocom/gprs/sndcp/sndcp_prim.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_sndcp.h>

LLIST_HEAD(sgsn_llmes);

static int sgsn_llc_handle_ll_gmm(struct osmo_gprs_llc_prim *llc_prim)
{
	struct msgb *msg;

	switch (llc_prim->oph.primitive) {
	case OSMO_GPRS_LLC_LL_UNITDATA:
		break;
	case OSMO_GPRS_LLC_LL_RESET:
	case OSMO_GPRS_LLC_LL_ESTABLISH:
	case OSMO_GPRS_LLC_LL_XID:
	case OSMO_GPRS_LLC_LL_DATA:
	case OSMO_GPRS_LLC_LL_STATUS:
	default:
		LOGP(DLLC, LOGL_NOTICE, "%s(): Unexpected Rx LL prim %u\n",
			__func__, llc_prim->oph.primitive);
		return -EINVAL;
	}

	msg = msgb_alloc(4096, "gsm0408_rx");
	msgb_tlli(msg) = llc_prim->ll.tlli;
	msgb_gmmh(msg) = msgb_put(msg, llc_prim->ll.l3_pdu_len);
	if (llc_prim->ll.l3_pdu_len > 0) {
		memcpy(msgb_gmmh(msg), llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len);
	}
	gsm0408_rcv_gb(msg);
	//TODO: free msg?
	return 0;
}

static int sgsn_llc_handle_ll_sndcp(struct osmo_gprs_llc_prim *llc_prim)
{
	int rc;
	switch (llc_prim->oph.primitive) {
	case OSMO_GPRS_LLC_LL_RESET:
	case OSMO_GPRS_LLC_LL_ESTABLISH:
	case OSMO_GPRS_LLC_LL_XID:
	case OSMO_GPRS_LLC_LL_DATA:
	case OSMO_GPRS_LLC_LL_UNITDATA:
	case OSMO_GPRS_LLC_LL_STATUS:
		/* Forward it to upper layers, pass owneserip over to SNDCP: */
		osmo_gprs_sndcp_prim_lower_up(llc_prim);
		rc = 1; /* Tell LLC that we take ownership of the prim. */
		break;
	default:
		LOGP(DLLC, LOGL_NOTICE, "%s(): Unexpected Rx LL prim %u\n",
			__func__, llc_prim->oph.primitive);
		rc = -EINVAL;
	}
	return rc;
}

int sgsn_llc_prim_up_cb(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_llc_prim_name(llc_prim);
	int rc = 0;

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_LLGM:
		LOGP(DLLC, LOGL_DEBUG, "%s(): Rx %s TLLI=0x%08x\n",
		     __func__, pdu_name, llc_prim->llgmm.tlli);
		break;
	case OSMO_GPRS_LLC_SAP_LL:
		LOGP(DLLC, LOGL_DEBUG, "%s(): Rx %s TLLI=0x%08x SAPI=%s l3=[%s]\n",
		     __func__, pdu_name, llc_prim->ll.tlli,
		     osmo_gprs_llc_sapi_name(llc_prim->ll.sapi),
		     osmo_hexdump(llc_prim->ll.l3_pdu, llc_prim->ll.l3_pdu_len));

		switch (llc_prim->ll.sapi) {
		case OSMO_GPRS_LLC_SAPI_GMM:
			rc = sgsn_llc_handle_ll_gmm(llc_prim);
			break;
		case OSMO_GPRS_LLC_SAPI_SNDCP3:
		case OSMO_GPRS_LLC_SAPI_SNDCP5:
		case OSMO_GPRS_LLC_SAPI_SNDCP9:
		case OSMO_GPRS_LLC_SAPI_SNDCP11:
			rc = sgsn_llc_handle_ll_sndcp(llc_prim);
			break;
		case OSMO_GPRS_LLC_SAPI_TOM2:
		case OSMO_GPRS_LLC_SAPI_SMS:
		case OSMO_GPRS_LLC_SAPI_TOM8:
			LOGP(DLLC, LOGL_NOTICE, "%s(): Unimplemented Rx llc_sapi %s\n", __func__, pdu_name);
			rc = -EINVAL;
			break;
		default:
			LOGP(DLLC, LOGL_NOTICE, "%s(): Unexpected Rx llc_sapi %s\n", __func__, pdu_name);
			rc = -EINVAL;
			break;
		}
		break;
	default:
		LOGP(DLLC, LOGL_NOTICE, "%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return rc;
}

/* Entry function from upper level (LLC), asking us to transmit a BSSGP PDU
 * to a remote MS (identified by TLLI) at a BTS identified by its BVCI and NSEI */
static int _bssgp_tx_dl_ud(struct osmo_gprs_llc_prim *llc_prim)
{
	struct msgb *msg;
	struct sgsn_mm_ctx *mmctx;
	struct bssgp_dl_ud_par dup;
	const uint8_t qos_profile_default[3] = { 0x00, 0x00, 0x20 };
	int rc;

	memset(&dup, 0, sizeof(dup));
	/* before we have received some identity from the MS, we might
	 * not yet have a MMC context (e.g. XID negotiation of primarly
	 * LLC connection from GMM sapi). */
	mmctx = sgsn_mm_ctx_by_tlli(llc_prim->bssgp.tlli);
	if (mmctx) {
		/* In rare cases the LLME is NULL in those cases don't
		 * use the mm radio capabilities */
		dup.imsi = mmctx->imsi;
		if (mmctx->gb.llme) {
			dup.drx_parms = mmctx->drx_parms;
			dup.ms_ra_cap.len = mmctx->ms_radio_access_capa.len;
			dup.ms_ra_cap.v = mmctx->ms_radio_access_capa.buf;

			/* make sure we only send it to the right llme */
			if (!(llc_prim->ll.tlli == mmctx->gb.llme->tlli
			      || llc_prim->ll.tlli == mmctx->gb.llme->old_tlli)) {
				LOGP(DLLC, LOGL_ERROR,
				     "_bssgp_tx_dl_ud(): Attempt to send Downlink Unitdata to wrong LLME:"
				     " msgb_tlli=0x%x mmctx->gb.llme->tlli=0x%x ->old_tlli=0x%x\n",
				     llc_prim->ll.tlli, mmctx->gb.llme->tlli, mmctx->gb.llme->old_tlli);
				return -EINVAL;
			}
		}
	}
	memcpy(&dup.qos_profile, qos_profile_default,
		sizeof(qos_profile_default));

	msg = msgb_alloc_headroom(4096, 128, "llc2bssgp");
	msgb_tlli(msg) = llc_prim->ll.tlli;
	msgb_bvci(msg) = mmctx ? mmctx->gb.bvci : 0;
	msgb_nsei(msg) = mmctx ? mmctx->gb.nsei : 0;
	msgb_gmmh(msg) = msgb_put(msg, llc_prim->bssgp.ll_pdu_len);
	if (llc_prim->bssgp.ll_pdu_len > 0) {
		memcpy(msgb_put(msg, llc_prim->bssgp.ll_pdu_len), llc_prim->bssgp.ll_pdu, llc_prim->bssgp.ll_pdu_len);
	}

	rc = bssgp_tx_dl_ud(msg, 1000, &dup);
	//TODO: free msg?
	return rc;
}

int sgsn_llc_prim_down_cb(struct osmo_gprs_llc_prim *llc_prim, void *user_data)
{
	const char *pdu_name = osmo_gprs_llc_prim_name(llc_prim);
	int rc = 0;

	switch (llc_prim->oph.sap) {
	case OSMO_GPRS_LLC_SAP_GRR:
		LOGP(DLLC, LOGL_DEBUG, "%s(): Rx %s l3=[%s]\n",  __func__, pdu_name,
		     osmo_hexdump(llc_prim->grr.ll_pdu, llc_prim->grr.ll_pdu_len));
		OSMO_ASSERT(0);
		break;
	case OSMO_GPRS_LLC_SAP_BSSGP:
		LOGP(DLLC, LOGL_DEBUG, "%s(): Rx %s TLLI=0x%08x l3=[%s]\n", __func__, pdu_name,
		     llc_prim->bssgp.tlli, osmo_hexdump(llc_prim->bssgp.ll_pdu, llc_prim->bssgp.ll_pdu_len));
		switch (llc_prim->oph.primitive) {
		case OSMO_GPRS_LLC_BSSGP_DL_UNITDATA:
			rc = _bssgp_tx_dl_ud(llc_prim);
			break;
		case OSMO_GPRS_LLC_BSSGP_UL_UNITDATA:
			OSMO_ASSERT(0);
			break;
		}
		break;
	default:
		LOGP(DLLC, LOGL_DEBUG, "%s(): Unexpected Rx %s\n", __func__, pdu_name);
		OSMO_ASSERT(0);
	}
	return rc;
}

/* Propagate crypto parameters MM -> LLME */
void gprs_llme_copy_key(const struct sgsn_mm_ctx *mm, struct sgsn_llme *llme)
{
	if (!mm)
		return;
	if (mm->ciph_algo != GPRS_ALGO_GEA0) {
		llme->algo = mm->ciph_algo;
		if (llme->cksn != mm->auth_triplet.key_seq &&
		    mm->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL) {

			/* gea4 needs kc128 */
			if (mm->ciph_algo == GPRS_ALGO_GEA4)
				osmo_kdf_kc128(mm->auth_triplet.vec.ck, mm->auth_triplet.vec.ik, llme->kc);
			else
				memcpy(llme->kc, mm->auth_triplet.vec.kc, gprs_cipher_key_length(mm->ciph_algo));

			llme->cksn = mm->auth_triplet.key_seq;
		}
	} else
		llme->cksn = GSM_KEY_SEQ_INVAL;
}

int sgsn_llgmm_assign_req(uint32_t old_tlli, uint32_t new_tlli)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;

	llc_prim = osmo_gprs_llc_prim_alloc_llgm_assign_req(old_tlli);
	OSMO_ASSERT(llc_prim);
	llc_prim->llgmm.assign_req.tlli_new = new_tlli;
	rc = osmo_gprs_llc_prim_upper_down(llc_prim);
	return rc;
}

int sgsn_llgmm_assign_req_mmctx(struct sgsn_mm_ctx *mmctx, uint32_t old_tlli, uint32_t new_tlli)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;

	llc_prim = osmo_gprs_llc_prim_alloc_llgm_assign_req(old_tlli);
	OSMO_ASSERT(llc_prim);
	llc_prim->llgmm.assign_req.tlli_new = new_tlli;
	llc_prim->llgmm.assign_req.gea = mmctx->ciph_algo;
	if (mmctx->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL) {
		/* gea4 needs kc128 */
		if (mmctx->ciph_algo == GPRS_ALGO_GEA4)
			osmo_kdf_kc128(mmctx->auth_triplet.vec.ck, mmctx->auth_triplet.vec.ik, llc_prim->llgmm.assign_req.kc);
		else
			memcpy(llc_prim->llgmm.assign_req.kc, mmctx->auth_triplet.vec.kc, gprs_cipher_key_length(mmctx->ciph_algo));
	}
	rc = osmo_gprs_llc_prim_upper_down(llc_prim);
	return rc;
}

/* TLLI unassignment */
int sgsn_llgmm_unassign_req(unsigned int tlli)
{
	return sgsn_llgmm_assign_req(tlli, TLLI_UNASSIGNED);
}
int sgsn_llgmm_unassign_req_mmctx(struct sgsn_mm_ctx *mmctx)
{
	return sgsn_llgmm_assign_req_mmctx(mmctx, mmctx->gb.tlli, TLLI_UNASSIGNED);
}

int sgsn_llgmm_reset_req(unsigned int tlli)
{
	struct osmo_gprs_llc_prim *llc_prim;
	int rc;

	llc_prim = osmo_gprs_llc_prim_alloc_llgm_reset_req(tlli);
	OSMO_ASSERT(llc_prim);

	rc = osmo_gprs_llc_prim_upper_down(llc_prim);
	return rc;
}

/* FIXME: look again at why this exists */
int sgsn_llgmm_reset_req_oldmsg(struct msgb* oldmsg, uint8_t sapi, unsigned int tlli)
{
	return sgsn_llgmm_reset_req(tlli);
}

int sgsn_llc_init(const char *cipher_plugin_path)
{
	int rc;
	rc = osmo_gprs_llc_init(OSMO_GPRS_LLC_LOCATION_SGSN, cipher_plugin_path);
	if (rc != 0)
		return rc;

	osmo_gprs_llc_set_log_cat(OSMO_GPRS_LLC_LOGC_LLC, DLLC);

	osmo_gprs_llc_prim_set_up_cb(sgsn_llc_prim_up_cb, NULL);
	osmo_gprs_llc_prim_set_down_cb(sgsn_llc_prim_down_cb, NULL);
	return rc;
}
