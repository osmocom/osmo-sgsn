/* APN contexts */

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

#include <string.h>
#include <talloc.h>

#include <osmocom/sgsn/apn.h>

extern void *tall_sgsn_ctx;

LLIST_HEAD(sgsn_apn_ctxts);

static struct apn_ctx *sgsn_apn_ctx_alloc(const char *ap_name, const char *imsi_prefix)
{
	struct apn_ctx *actx;

	actx = talloc_zero(tall_sgsn_ctx, struct apn_ctx);
	if (!actx)
		return NULL;
	actx->name = talloc_strdup(actx, ap_name);
	actx->imsi_prefix = talloc_strdup(actx, imsi_prefix);

	llist_add_tail(&actx->list, &sgsn_apn_ctxts);

	return actx;
}

void sgsn_apn_ctx_free(struct apn_ctx *actx)
{
	llist_del(&actx->list);
	talloc_free(actx);
}

struct apn_ctx *sgsn_apn_ctx_match(const char *name, const char *imsi)
{
	struct apn_ctx *actx;
	struct apn_ctx *found_actx = NULL;
	size_t imsi_prio = 0;
	size_t name_prio = 0;
	size_t name_req_len = strlen(name);

	llist_for_each_entry(actx, &sgsn_apn_ctxts, list) {
		size_t name_ref_len, imsi_ref_len;
		const char *name_ref_start, *name_match_start;

		imsi_ref_len = strlen(actx->imsi_prefix);
		if (strncmp(actx->imsi_prefix, imsi, imsi_ref_len) != 0)
			continue;

		if (imsi_ref_len < imsi_prio)
			continue;

		/* IMSI matches */

		name_ref_start = &actx->name[0];
		if (name_ref_start[0] == '*') {
			/* Suffix match */
			name_ref_start += 1;
			name_ref_len = strlen(name_ref_start);
			if (name_ref_len > name_req_len)
				continue;
		} else {
			name_ref_len = strlen(name_ref_start);
			if (name_ref_len != name_req_len)
				continue;
		}

		name_match_start = name + (name_req_len - name_ref_len);
		if (strcasecmp(name_match_start, name_ref_start) != 0)
			continue;

		/* IMSI and name match */

		if (imsi_ref_len == imsi_prio && name_ref_len < name_prio)
			/* Lower priority, skip */
			continue;

		imsi_prio = imsi_ref_len;
		name_prio = name_ref_len;
		found_actx = actx;
	}
	return found_actx;
}

struct apn_ctx *sgsn_apn_ctx_by_name(const char *name, const char *imsi_prefix)
{
	struct apn_ctx *actx;

	llist_for_each_entry(actx, &sgsn_apn_ctxts, list) {
		if (strcasecmp(name, actx->name) == 0 &&
		    strcasecmp(imsi_prefix, actx->imsi_prefix) == 0)
			return actx;
	}
	return NULL;
}

struct apn_ctx *sgsn_apn_ctx_find_alloc(const char *name, const char *imsi_prefix)
{
	struct apn_ctx *actx;

	actx = sgsn_apn_ctx_by_name(name, imsi_prefix);
	if (!actx)
		actx = sgsn_apn_ctx_alloc(name, imsi_prefix);

	return actx;
}
