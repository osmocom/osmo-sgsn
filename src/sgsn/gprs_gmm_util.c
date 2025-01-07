/*! \file gprs_bssgp_util.c
 * GPRS GMM protocol implementation as per 3GPP TS 24.008 */
/*
 * (C) 2009-2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2024 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Alexander Couzens <lynxis@fe80.eu>
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
 */

#include <osmocom/core/msgb.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/sgsn/gprs_gmm_util.h>

const struct tlv_definition gsm48_gmm_ie_tlvdef = {
	.def = {
		[GSM48_IE_GMM_CIPH_CKSN]	= { TLV_TYPE_SINGLE_TV, 1 },
		[GSM48_IE_GMM_PTMSI_TYPE]	= { TLV_TYPE_SINGLE_TV, 1 },
		[GSM48_IE_GMM_TMSI_BASED_NRI_C]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_TIMER_READY]	= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GMM_ALLOC_PTMSI]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PTMSI_SIG]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_GMM_ADD_IDENTITY]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_RAI2]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_AUTH_RAND]	= { TLV_TYPE_FIXED, 16 },
		[GSM48_IE_GMM_AUTH_SRES]	= { TLV_TYPE_FIXED, 4 },
		[GSM48_IE_GMM_IMEISV]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_CAUSE]		= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GMM_RX_NPDU_NUM_LIST]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_DRX_PARAM]	= { TLV_TYPE_FIXED, 2 },
		[GSM48_IE_GMM_AUTN]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_AUTH_RES_EXT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_TIMER_T3302]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_AUTH_FAIL_PAR]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_MS_NET_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_UE_NET_CAP]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PDP_CTX_STATUS]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PS_LCS_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_GMM_MBMS_CTX_ST]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_TIMER_T3346]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_UE_NET_CAP]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_VD_PREF_UE_USAGE] = { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_NET_FEAT_SUPPORT] = { TLV_TYPE_SINGLE_TV, 1 },
	},
};

/*! Parse 24.008 9.4.14 RAU Request
 * \param[in] msg l3 pointers must point to gmm.
 * \param[out] rau_req parsed RA update request
 * \returns 0 on success or GMM cause
 */
int gprs_gmm_parse_ra_upd_req(struct msgb *msg, struct gprs_gmm_ra_upd_req *rau_req)
{
	uint8_t *cur, len;
	size_t mandatory_fields_len;
	struct gsm48_hdr *gh;
	int ret;

	OSMO_ASSERT(msg);
	OSMO_ASSERT(rau_req);

	memset(rau_req, 0, sizeof(struct gprs_gmm_ra_upd_req));

	/* all mandatory fields + variable length MS Radio Cap (min value) would be 15 bytes.
	 * But even short radio capabilities we should handle with 14 bytes */
	if (msgb_l3len(msg) < 14)
		return GMM_CAUSE_PROTO_ERR_UNSPEC;

	gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	cur = gh->data;

	rau_req->skip_ind = gh->proto_discr >> 4;

	/* V: Update Type 10.5.5.18 */
	rau_req->update_type = *cur & 0x07;
	rau_req->follow_up_req = !!(*cur & 0x08);
	/* V: GPRS Ciphering Key Sequence 10.5.1.2 */
	rau_req->cksq = *cur >> 4;
	cur++;

	/* V: Old routing area identification 10.5.5.15 */
	osmo_routing_area_id_decode(&rau_req->old_rai, cur, 6);
	cur += 6;

	/* LV: MS radio cap 10.5.5.12a */
	len = *cur++;
	if (msgb_l3len(msg) < (len + (cur - msgb_gmmh(msg))))
		return GMM_CAUSE_PROTO_ERR_UNSPEC;

	rau_req->ms_radio_cap = cur;
	rau_req->ms_radio_cap_len = len;
	cur += len;

	mandatory_fields_len = (cur - msgb_gmmh(msg));
	if (msgb_l3len(msg) == mandatory_fields_len)
		return 0;

	ret = tlv_parse(&rau_req->tlv, &gsm48_gmm_ie_tlvdef,
		  cur, msgb_l3len(msg) - mandatory_fields_len, 0, 0);

	if (ret < 0)
		return GMM_CAUSE_COND_IE_ERR;

	return 0;
}
