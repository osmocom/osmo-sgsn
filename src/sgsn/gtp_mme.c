/* TS 29.060 § 7.5.14 RAN Information Management Messages */
/*
 * (C) 2021 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: AGPL-3.0+
 *
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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

#include <talloc.h>

#include <osmocom/sgsn/gtp_mme.h>
#include <osmocom/sgsn/sgsn.h>

static bool _eutran_tai_equal(const struct osmo_eutran_tai *t1, const struct osmo_eutran_tai *t2)
{
	return  t1->mcc == t2->mcc &&
		t1->mnc == t2->mnc &&
		t1->mnc_3_digits == t2->mnc_3_digits &&
		t1->tac == t2->tac;
}

struct sgsn_mme_ctx *sgsn_mme_ctx_alloc(struct sgsn_instance *sgsn, const char *name)
{
	struct sgsn_mme_ctx *mme;
	mme = talloc_zero(sgsn, struct sgsn_mme_ctx);
	if (!mme)
		return NULL;

	/* if we are called from config file parse, this gsn doesn't exist yet */
	mme->sgsn = sgsn;

	mme->name = talloc_strdup(mme, name);

	INIT_LLIST_HEAD(&mme->routes);
	llist_add_tail(&mme->list, &sgsn->mme_list);

	return mme;
}

void sgsn_mme_ctx_free(struct sgsn_mme_ctx *mme)
{
	struct mme_rim_route *rt, *rt2;
	llist_del(&mme->list);

	llist_for_each_entry_safe(rt, rt2, &mme->routes, list) {
		llist_del(&rt->list);
		talloc_free(rt);
	}

	talloc_free(mme);
}

struct sgsn_mme_ctx *sgsn_mme_ctx_find_alloc(struct sgsn_instance *sgsn, const char *name)
{
	struct sgsn_mme_ctx *mme;

	mme = sgsn_mme_ctx_by_name(sgsn, name);
	if (!mme)
		mme = sgsn_mme_ctx_alloc(sgsn, name);
	return mme;
}

void sgsn_mme_ctx_route_add(struct sgsn_mme_ctx *mme, const struct osmo_eutran_tai *tai)
{
	struct mme_rim_route *rt = talloc_zero(mme, struct mme_rim_route);
	rt->tai = *tai;
	llist_add_tail(&rt->list, &mme->routes);
}

void sgsn_mme_ctx_route_del(struct sgsn_mme_ctx *mme, const struct osmo_eutran_tai *tai)
{
	struct mme_rim_route *rt;

	llist_for_each_entry(rt, &mme->routes, list) {
		if (_eutran_tai_equal(tai, &rt->tai)) {
			llist_del(&rt->list);
			talloc_free(rt);
			return;
		}
	}
}

struct sgsn_mme_ctx *sgsn_mme_ctx_by_name(const struct sgsn_instance *sgsn, const char *name)
{
	struct sgsn_mme_ctx *mme;

	llist_for_each_entry(mme, &sgsn->mme_list, list) {
		if (!strcmp(name, mme->name))
			return mme;
	}
	return NULL;
}

struct sgsn_mme_ctx *sgsn_mme_ctx_by_addr(const struct sgsn_instance *sgsn, const struct in_addr *addr)
{
	struct sgsn_mme_ctx *mme;

	llist_for_each_entry(mme, &sgsn->mme_list, list) {
		if (!memcmp(addr, &mme->remote_addr, sizeof(*addr)))
			return mme;
	}
	return NULL;
}

struct sgsn_mme_ctx *sgsn_mme_ctx_by_route(const struct sgsn_instance *sgsn, const struct osmo_eutran_tai *tai)
{
	struct sgsn_mme_ctx *mme;
	llist_for_each_entry(mme, &sgsn->mme_list, list) {
		struct mme_rim_route *rt;
		llist_for_each_entry(rt, &mme->routes, list) {
			if (_eutran_tai_equal(tai, &rt->tai)) {
				return mme;
			}
		}
	}
	return NULL;
}

struct sgsn_mme_ctx *sgsn_mme_ctx_by_default_route(const struct sgsn_instance *sgsn)
{
	struct sgsn_mme_ctx *mme;

	llist_for_each_entry(mme, &sgsn->mme_list, list) {
		if (mme->default_route)
			return mme;
	}
	return NULL;
}
