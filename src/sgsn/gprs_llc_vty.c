/* VTY interface for our GPRS LLC implementation */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

#include <arpa/inet.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/signal.h>
#include <osmocom/sgsn/gprs_llc.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>

static void vty_dump_lle(struct vty *vty, struct sgsn_lle *lle)
{
	vty_out(vty, " SAPI %2u VUsend=%u, VUrecv=%u", lle->sapi,
		lle->vu_send, lle->vu_recv);
	vty_out(vty, " Vsent=%u Vack=%u Vrecv=%u, RetransCtr=%u%s",
		lle->v_sent, lle->v_ack, lle->v_recv,
		lle->retrans_ctr, VTY_NEWLINE);
}

static uint8_t valid_sapis[] = { 1, 2, 3, 5, 7, 8, 9, 11 };

static void vty_dump_llme(struct vty *vty, struct sgsn_llme *llme)
{
	unsigned int i;
	struct timespec now_tp = {0};
	osmo_clock_gettime(CLOCK_MONOTONIC, &now_tp);

	vty_out(vty, "TLLI %08x (Old TLLI %08x) BVCI=%u NSEI=%u %s: "
		"IOV-UI=0x%06x CKSN=%d Age=%d%s", llme->tlli,
		llme->old_tlli, llme->bvci, llme->nsei,
		get_value_string(gprs_cipher_names, llme->algo), llme->iov_ui,
		llme->cksn, llme->age_timestamp == GPRS_LLME_RESET_AGE ? 0 :
		(int)(now_tp.tv_sec - (time_t)llme->age_timestamp), VTY_NEWLINE);

	for (i = 0; i < ARRAY_SIZE(valid_sapis); i++) {
		struct sgsn_lle *lle;
		uint8_t sapi = valid_sapis[i];

		if (sapi >= ARRAY_SIZE(llme->lle))
			continue;

		lle = &llme->lle[sapi];
		vty_dump_lle(vty, lle);
	}
}


DEFUN(show_llc, show_llc_cmd,
	"show llc",
	SHOW_STR "Display information about the LLC protocol")
{
	struct sgsn_llme *llme;

	vty_out(vty, "State of LLC Entities%s", VTY_NEWLINE);
	llist_for_each_entry(llme, &sgsn_llmes, list) {
		vty_dump_llme(vty, llme);
	}
	return CMD_SUCCESS;
}

int sgsn_llc_vty_init(void)
{
	install_element_ve(&show_llc_cmd);

	return 0;
}
