/*
 * (C) 2013 by Holger Hans Peter Freyther
 * (C) 2013 by sysmocom s.f.m.c. GmbH
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

#include <openbsc/control_cmd.h>
#include <openbsc/ipaccess.h>
#include <openbsc/gsm_data.h>

#define CTRL_CMD_VTY_STRING(cmdname, cmdstr, dtype, element) \
	CTRL_HELPER_GET_STRING(cmdname, dtype, element) \
	CTRL_HELPER_SET_STRING(cmdname, dtype, element) \
static struct ctrl_cmd_element cmd_##cmdname = { \
	.name = cmdstr, \
	.param = NULL, \
	.get = get_##cmdname, \
	.set = set_##cmdname, \
	.verify = verify_vty_description_string, \
}

/**
 * Check that there are no newlines or comments or other things
 * that could make the VTY configuration unparsable.
 */
static int verify_vty_description_string(struct ctrl_cmd *cmd,
			const char *value, void *data)
{
	int i;
	const size_t len = strlen(value);

	for (i = 0; i < len; ++i) {
		switch(value[i]) {
		case '#':
		case '\n':
		case '\r':
			cmd->reply = "String includes illegal character";
			return -1;
		default:
			break;
		}
	}

	return 0;
}

CTRL_CMD_DEFINE_RANGE(net_mnc, "mnc", struct gsm_network, network_code, 0, 999);
CTRL_CMD_DEFINE_RANGE(net_mcc, "mcc", struct gsm_network, country_code, 1, 999);
CTRL_CMD_VTY_STRING(net_short_name, "short-name", struct gsm_network, name_short);
CTRL_CMD_VTY_STRING(net_long_name, "long-name", struct gsm_network, name_long);

static int verify_net_apply_config(struct ctrl_cmd *cmd, const char *v, void *d)
{
	return 0;
}

static int get_net_apply_config(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Write only attribute";
	return CTRL_CMD_ERROR;
}

static int set_net_apply_config(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (!is_ipaccess_bts(bts))
			continue;

		ipaccess_drop_oml(bts);
	}

	cmd->reply = "Tried to drop the BTS";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(net_apply_config, "apply-configuration");

static int verify_net_mcc_mnc_apply(struct ctrl_cmd *cmd, const char *value, void *d)
{
	char *tmp, *saveptr, *mcc, *mnc;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	mcc = strtok_r(tmp, ",", &saveptr);
	mnc = strtok_r(NULL, ",", &saveptr);
	talloc_free(tmp);

	if (!mcc || !mnc)
		return 1;
	return 0;
}

static int get_net_mcc_mnc_apply(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Write only attribute";
	return CTRL_CMD_ERROR;
}

static int set_net_mcc_mnc_apply(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	char *tmp, *saveptr, *mcc_str, *mnc_str;
	int mcc, mnc;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;


	mcc_str = strtok_r(tmp, ",", &saveptr);
	mnc_str = strtok_r(NULL, ",", &saveptr);

	mcc = atoi(mcc_str);
	mnc = atoi(mnc_str);

	talloc_free(tmp);

	if (net->network_code == mnc && net->country_code == mcc) {
		cmd->reply = "Nothing changed";
		return CTRL_CMD_REPLY;
	}

	net->network_code = mnc;
	net->country_code = mcc;

	return set_net_apply_config(cmd, data);

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}
CTRL_CMD_DEFINE(net_mcc_mnc_apply, "mcc-mnc-apply");

int bsc_base_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mnc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_short_name);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_long_name);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_apply_config);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc_mnc_apply);

	return rc;
}
