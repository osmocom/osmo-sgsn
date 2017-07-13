/* Generic signalling/notification infrastructure */
/* (C) 2009-2010, 2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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

#ifndef OPENBSC_SIGNAL_H
#define OPENBSC_SIGNAL_H

#include <stdlib.h>
#include <errno.h>

#include <osmocom/core/signal.h>

/* GPRS SGSN signals SS_SGSN */
enum signal_sgsn {
	S_SGSN_ATTACH,
	S_SGSN_DETACH,
	S_SGSN_UPDATE,
	S_SGSN_PDP_ACT,
	S_SGSN_PDP_DEACT,
	S_SGSN_PDP_TERMINATE,
	S_SGSN_PDP_FREE,
	S_SGSN_MM_FREE,
};

struct sgsn_mm_ctx;
struct sgsn_signal_data {
	struct sgsn_mm_ctx *mm;
	struct sgsn_pdp_ctx *pdp;	/* non-NULL for PDP_ACT, PDP_DEACT, PDP_FREE */
};

#endif
