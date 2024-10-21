/* MS authorization and subscriber data handling */

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

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/core/utils.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/mmctx.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_subscriber.h>
#include <osmocom/sgsn/debug.h>

const struct value_string auth_state_names[] = {
	{ SGSN_AUTH_ACCEPTED,	"accepted"},
	{ SGSN_AUTH_REJECTED,	"rejected"},
	{ SGSN_AUTH_UNKNOWN,	"unknown"},
	{ SGSN_AUTH_AUTHENTICATE, "authenticate" },
	{ SGSN_AUTH_UMTS_RESYNC, "UMTS-resync" },
	{ 0, NULL }
};

const struct value_string *sgsn_auth_state_names = auth_state_names;

void sgsn_auth_init(struct sgsn_instance *sgsn)
{
	INIT_LLIST_HEAD(&sgsn->cfg.imsi_acl);
}

struct imsi_acl_entry *sgsn_acl_lookup(const char *imsi, const struct sgsn_config *cfg)
{
	struct imsi_acl_entry *acl;
	llist_for_each_entry(acl, &cfg->imsi_acl, list) {
		if (!strcmp(imsi, acl->imsi))
			return acl;
	}
	return NULL;
}

int sgsn_acl_add(const char *imsi, struct sgsn_config *cfg)
{
	struct imsi_acl_entry *acl;

	if (sgsn_acl_lookup(imsi, cfg))
		return -EEXIST;

	acl = talloc_zero(NULL, struct imsi_acl_entry);
	if (!acl)
		return -ENOMEM;
	osmo_strlcpy(acl->imsi, imsi, sizeof(acl->imsi));

	llist_add(&acl->list, &cfg->imsi_acl);

	return 0;
}

int sgsn_acl_del(const char *imsi, struct sgsn_config *cfg)
{
	struct imsi_acl_entry *acl;

	acl = sgsn_acl_lookup(imsi, cfg);
	if (!acl)
		return -ENODEV;

	llist_del(&acl->list);
	talloc_free(acl);

	return 0;
}

