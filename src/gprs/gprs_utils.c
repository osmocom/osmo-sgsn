/* GPRS utility functions */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2014 by On-Waves
 * (C) 2013 by Holger Hans Peter Freyther
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
#include <osmocom/sgsn/gprs_utils.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gprs/gprs_ns2.h>

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48.h>

#include <string.h>

int gprs_str_to_apn(uint8_t *apn_enc, size_t max_len, const char *str)
{
	uint8_t *last_len_field;
	int len;

	/* Can we even write the length field to the output? */
	if (max_len == 0)
		return -1;

	/* Remember where we need to put the length once we know it */
	last_len_field = apn_enc;
	len = 1;
	apn_enc += 1;

	while (str[0]) {
		if (len >= max_len)
			return -1;

		if (str[0] == '.') {
			*last_len_field = (apn_enc - last_len_field) - 1;
			last_len_field = apn_enc;
		} else {
			*apn_enc = str[0];
		}
		apn_enc += 1;
		str += 1;
		len += 1;
	}

	*last_len_field = (apn_enc - last_len_field) - 1;

	return len;
}

/* This functions returns a tmr value such that
 *   - f is monotonic
 *   - f(s) <= s
 *   - f(s) == s if a tmr exists with s = gprs_tmr_to_secs(tmr)
 *   - the best possible resolution is used
 * where
 *   f(s) = gprs_tmr_to_secs(gprs_secs_to_tmr_floor(s))
 */
uint8_t gprs_secs_to_tmr_floor(int secs)
{
	if (secs < 0)
		return GPRS_TMR_DEACTIVATED;
	if (secs < 2 * 32)
		return GPRS_TMR_2SECONDS | (secs / 2);
	if (secs < 60 * 2)
		/* Ensure monotonicity */
		return GPRS_TMR_2SECONDS | GPRS_TMR_FACT_MASK;
	if (secs < 60 * 32)
		return GPRS_TMR_MINUTE | (secs / 60);
	if (secs < 360 * 6)
		/* Ensure monotonicity */
		return GPRS_TMR_MINUTE | GPRS_TMR_FACT_MASK;
	if (secs < 360 * 32)
		return GPRS_TMR_6MINUTE | (secs / 360);

	return GPRS_TMR_6MINUTE | GPRS_TMR_FACT_MASK;
}

/* GSM 04.08, 10.5.1.4 */
int gprs_is_mi_tmsi(const uint8_t *value, size_t value_len)
{
	if (value_len != GSM48_TMSI_LEN)
		return 0;

	if (!value || (value[0] & GSM_MI_TYPE_MASK) != GSM_MI_TYPE_TMSI)
		return 0;

	return 1;
}

/* GSM 04.08, 10.5.1.4 */
int gprs_is_mi_imsi(const uint8_t *value, size_t value_len)
{
	if (value_len == 0)
		return 0;

	if (!value || (value[0] & GSM_MI_TYPE_MASK) != GSM_MI_TYPE_IMSI)
		return 0;

	return 1;
}

int gprs_parse_mi_tmsi(const uint8_t *value, size_t value_len, uint32_t *tmsi)
{
	uint32_t tmsi_be;

	if (!gprs_is_mi_tmsi(value, value_len))
		return 0;

	memcpy(&tmsi_be, value + 1, sizeof(tmsi_be));

	*tmsi = ntohl(tmsi_be);
	return 1;
}

void gprs_parse_tmsi(const uint8_t *value, uint32_t *tmsi)
{
	uint32_t tmsi_be;

	memcpy(&tmsi_be, value, sizeof(tmsi_be));

	*tmsi = ntohl(tmsi_be);
}

int gprs_ra_id_equals(const struct gprs_ra_id *id1,
		      const struct gprs_ra_id *id2)
{
	return (id1->mcc == id2->mcc
		&& !osmo_mnc_cmp(id1->mnc, id1->mnc_3_digits,
				 id2->mnc, id2->mnc_3_digits)
		&& id1->lac == id2->lac && id1->rac == id2->rac);
}
