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

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/tlv.h>

const struct tlv_definition gsm48_gmm_ie_tlvdef = {
	.def = {
		[GSM48_IE_GMM_CIPH_CKSN]	= { TLV_TYPE_SINGLE_TV, 1 },
		[GSM48_IE_GMM_TIMER_READY]	= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GMM_ALLOC_PTMSI]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PTMSI_SIG]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_GMM_AUTH_RAND]	= { TLV_TYPE_FIXED, 16 },
		[GSM48_IE_GMM_AUTH_SRES]	= { TLV_TYPE_FIXED, 4 },
		[GSM48_IE_GMM_AUTH_RES_EXT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_AUTH_FAIL_PAR]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_IMEISV]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_RX_NPDU_NUM_LIST] = { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_DRX_PARAM]	= { TLV_TYPE_FIXED, 2 },
		[GSM48_IE_GMM_MS_NET_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PDP_CTX_STATUS]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PS_LCS_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_GMM_MBMS_CTX_ST]	= { TLV_TYPE_TLV, 0 },
	},
};

