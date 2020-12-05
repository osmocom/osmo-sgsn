/* Control Interface Implementation for the Gb-proxy */
/*
 * (C) 2018 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Daniel Willmann
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

#include <osmocom/core/talloc.h>


#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gprs/gprs_ns.h>

#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/sgsn/gb_proxy.h>
#include <osmocom/sgsn/debug.h>

extern vector ctrl_node_vec;

struct nsvc_cb_data {
	struct ctrl_cmd *cmd;
	uint16_t nsei;
	bool is_sgsn;
};

static int ctrl_nsvc_state_cb(struct gprs_ns2_vc *nsvc, void *ctx) {
	struct nsvc_cb_data *data = (struct nsvc_cb_data *)ctx;
	struct ctrl_cmd *cmd = (struct ctrl_cmd *)data->cmd;

	cmd->reply = talloc_asprintf_append(cmd->reply, "%u,%s,%s,%s\n",
			data->nsei, gprs_ns2_ll_str(nsvc), gprs_ns2_nsvc_state_name(nsvc),
			data->is_sgsn ? "SGSN" : "BSS" );

	return 0;
}

static int get_nsvc_state(struct ctrl_cmd *cmd, void *data)
{
	struct gbproxy_config *cfg = data;
	struct gprs_ns2_inst *nsi = cfg->nsi;
	struct gprs_ns2_nse *nse;
	struct gbproxy_nse *nse_peer;
	int i;

	cmd->reply = talloc_strdup(cmd, "");

	/* NS-VCs for SGSN */
	nse = gprs_ns2_nse_by_nsei(nsi, cfg->nsip_sgsn_nsei);
	if (nse)
		gprs_ns2_nse_foreach_nsvc(nse, &ctrl_nsvc_state_cb, cmd);
	/* NS-VCs for SGSN2 */
	nse = gprs_ns2_nse_by_nsei(nsi, cfg->nsip_sgsn2_nsei);
	if (nse)
		gprs_ns2_nse_foreach_nsvc(nse, &ctrl_nsvc_state_cb, cmd);

	/* NS-VCs for BSS peers */
	hash_for_each(cfg->bss_nses, i, nse_peer, list) {
		nse = gprs_ns2_nse_by_nsei(nsi, nse_peer->nsei);
		if (nse)
			gprs_ns2_nse_foreach_nsvc(nse, &ctrl_nsvc_state_cb, cmd);
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(nsvc_state, "nsvc-state");

static int get_gbproxy_state(struct ctrl_cmd *cmd, void *data)
{
	struct gbproxy_config *cfg = data;
	struct gbproxy_nse *nse_peer;
	int i, j;

	cmd->reply = talloc_strdup(cmd, "");

	hash_for_each(cfg->bss_nses, i, nse_peer, list) {
		struct gbproxy_bvc *bvc;
		hash_for_each(nse_peer->bvcs, j, bvc, list) {
			struct gprs_ra_id raid;
			gsm48_parse_ra(&raid, bvc->ra);

			cmd->reply = talloc_asprintf_append(cmd->reply, "%u,%u,%u,%u,%u,%u,%s\n",
					nse_peer->nsei, bvc->bvci,
					raid.mcc, raid.mnc,
					raid.lac, raid.rac,
					bvc->blocked ? "BLOCKED" : "UNBLOCKED");
		}
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(gbproxy_state, "gbproxy-state");

static int get_num_peers(struct ctrl_cmd *cmd, void *data)
{
	struct gbproxy_config *cfg = data;
	struct gbproxy_nse *nse_peer;
	struct gbproxy_bvc *bvc;
	uint32_t count = 0;
	int i, j;

	hash_for_each(cfg->bss_nses, i, nse_peer, list) {
		hash_for_each(nse_peer->bvcs, j, bvc, list)
			count++;
	}

	cmd->reply = talloc_strdup(cmd, "");
	cmd->reply = talloc_asprintf_append(cmd->reply, "%u", count);

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(num_peers, "number-of-peers");

int gb_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_nsvc_state);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_gbproxy_state);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_num_peers);

	return rc;
}
