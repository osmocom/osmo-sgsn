/*
 * (C) 2010 by Harald Welte <laforge@gnumonks.org>
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/bssgp_bvc_fsm.h>
#include <osmocom/gsm/apn.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gb_proxy.h>
#include <osmocom/sgsn/gprs_utils.h>
#include <osmocom/sgsn/vty.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>


static struct gbproxy_config *g_cfg = NULL;

/*
 * vty code for gbproxy below
 */
static struct cmd_node gbproxy_node = {
	GBPROXY_NODE,
	"%s(config-gbproxy)# ",
	1,
};

static void gbprox_vty_print_bvc(struct vty *vty, struct gbproxy_bvc *bvc)
{

	if (bvc->bvci == 0) {
		vty_out(vty, "NSEI %5u, SIG-BVCI %5u [%s]%s", bvc->nse->nsei, bvc->bvci,
			osmo_fsm_inst_state_name(bvc->fi), VTY_NEWLINE);
	} else {
		struct gprs_ra_id raid;
		gsm48_parse_ra(&raid, bvc->ra);
		vty_out(vty, "NSEI %5u, PTP-BVCI %5u, RAI %s [%s]%s", bvc->nse->nsei, bvc->bvci,
			osmo_rai_name(&raid), osmo_fsm_inst_state_name(bvc->fi), VTY_NEWLINE);
	}
}

static void gbproxy_vty_print_nse(struct vty *vty, struct gbproxy_nse *nse, bool show_stats)
{
	struct gbproxy_bvc *bvc;
	int j;

	hash_for_each(nse->bvcs, j, bvc, list) {
		gbprox_vty_print_bvc(vty, bvc);

		if (show_stats)
			vty_out_rate_ctr_group(vty, "  ", bvc->ctrg);
	}
}

static int config_write_gbproxy(struct vty *vty)
{
	struct gbproxy_nse *nse;
	int i;

	vty_out(vty, "gbproxy%s", VTY_NEWLINE);

	if (g_cfg->pool.bvc_fc_ratio != 100)
		vty_out(vty, " pool bvc-flow-control-ratio %u%s", g_cfg->pool.bvc_fc_ratio, VTY_NEWLINE);

	hash_for_each(g_cfg->sgsn_nses, i, nse, list) {
		vty_out(vty, " sgsn nsei %u%s", nse->nsei, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy,
      cfg_gbproxy_cmd,
      "gbproxy",
      "Configure the Gb proxy")
{
	vty->node = GBPROXY_NODE;
	return CMD_SUCCESS;
}

extern const struct bssgp_bvc_fsm_ops sgsn_sig_bvc_fsm_ops;
#include <osmocom/gprs/protocol/gsm_08_18.h>

DEFUN(cfg_nsip_sgsn_nsei,
      cfg_nsip_sgsn_nsei_cmd,
      "sgsn nsei <0-65534>",
      "SGSN information\n"
      "NSEI to be used in the connection with the SGSN\n"
      "The NSEI\n")
{
	uint32_t features = 0; // FIXME: make configurable
	unsigned int nsei = atoi(argv[0]);
	struct gbproxy_nse *nse;
	struct gbproxy_bvc *bvc;

	nse = gbproxy_nse_by_nsei_or_new(g_cfg, nsei, true);
	if (!nse)
		goto free_nothing;

	if (!gbproxy_bvc_by_bvci(nse, 0)) {
		uint8_t cause = BSSGP_CAUSE_OML_INTERV;
		bvc = gbproxy_bvc_alloc(nse, 0);
		if (!bvc)
			goto free_nse;
		bvc->fi = bssgp_bvc_fsm_alloc_sig_bss(bvc, nse->cfg->nsi, nsei, features);
		if (!bvc->fi)
			goto free_bvc;
		bssgp_bvc_fsm_set_ops(bvc->fi, &sgsn_sig_bvc_fsm_ops, bvc);
		osmo_fsm_inst_dispatch(bvc->fi, BSSGP_BVCFSM_E_REQ_RESET, &cause);
	}

	return CMD_SUCCESS;

free_bvc:
	gbproxy_bvc_free(bvc);
free_nse:
	gbproxy_nse_free(nse);
free_nothing:
	vty_out(vty, "%% Unable to create NSE for NSEI=%05u%s", nsei, VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(cfg_pool_bvc_fc_ratio,
      cfg_pool_bvc_fc_ratio_cmd,
      "pool bvc-flow-control-ratio <1-100>",
      "SGSN Pool related configuration\n"
      "Ratio of BSS-advertised bucket size + leak rate advertised to each SGSN\n"
      "Ratio of BSS-advertised bucket size + leak rate advertised to each SGSN (Percent)\n")
{
	g_cfg->pool.bvc_fc_ratio = atoi(argv[0]);
	return CMD_SUCCESS;
}

static void log_set_bvc_filter(struct log_target *target,
				const uint16_t *bvci)
{
	if (bvci) {
		uintptr_t bvci_filter = *bvci | BVC_LOG_CTX_FLAG;
		target->filter_map |= (1 << LOG_FLT_GB_BVC);
		target->filter_data[LOG_FLT_GB_BVC] = (void *)bvci_filter;
	} else if (target->filter_data[LOG_FLT_GB_BVC]) {
		target->filter_map = ~(1 << LOG_FLT_GB_BVC);
		target->filter_data[LOG_FLT_GB_BVC] = NULL;
	}
}

DEFUN(logging_fltr_bvc,
      logging_fltr_bvc_cmd,
      "logging filter bvc bvci <0-65535>",
	LOGGING_STR FILTER_STR
	"Filter based on BSSGP VC\n"
	"Identify BVC by BVCI\n"
	"Numeric identifier\n")
{
	struct log_target *tgt;
	uint16_t id = atoi(argv[0]);

	log_tgt_mutex_lock();
	tgt = osmo_log_vty2tgt(vty);
	if (!tgt) {
		log_tgt_mutex_unlock();
		return CMD_WARNING;
	}

	log_set_bvc_filter(tgt, &id);
	log_tgt_mutex_unlock();
	return CMD_SUCCESS;
}

DEFUN(show_gbproxy_bvc, show_gbproxy_bvc_cmd, "show gbproxy bvc (bss|sgsn) [stats]",
       SHOW_STR "Display information about the Gb proxy\n"
       "Show BSSGP Virtual Connections\n"
       "Display BSS-side BVCs\n"
       "Display SGSN-side BVCs\n"
       "Show statistics\n")
{
	struct gbproxy_nse *nse;
	bool show_stats = argc >= 2;
	int i;

	if (show_stats)
		vty_out_rate_ctr_group(vty, "", g_cfg->ctrg);

	if (!strcmp(argv[0], "bss")) {
		hash_for_each(g_cfg->bss_nses, i, nse, list)
			gbproxy_vty_print_nse(vty, nse, show_stats);
	} else {
		hash_for_each(g_cfg->sgsn_nses, i, nse, list)
			gbproxy_vty_print_nse(vty, nse, show_stats);
	}
	return CMD_SUCCESS;
}

DEFUN(show_gbproxy_links, show_gbproxy_links_cmd, "show gbproxy links",
       SHOW_STR "Display information about the Gb proxy\n" "Show logical links\n")
{
	struct gbproxy_nse *nse;
	int i, j;

	hash_for_each(g_cfg->bss_nses, i, nse, list) {
		struct gbproxy_bvc *bvc;
		hash_for_each(nse->bvcs, j, bvc, list) {
			gbprox_vty_print_bvc(vty, bvc);
		}
	}
	return CMD_SUCCESS;
}

DEFUN(delete_gb_bvci, delete_gb_bvci_cmd,
	"delete-gbproxy-peer <0-65534> bvci <2-65534>",
	"Delete a GBProxy bvc by NSEI and optionally BVCI\n"
	"NSEI number\n"
	"Only delete bvc with a matching BVCI\n"
	"BVCI number\n")
{
	const uint16_t nsei = atoi(argv[0]);
	const uint16_t bvci = atoi(argv[1]);
	struct gbproxy_nse *nse = gbproxy_nse_by_nsei(g_cfg, nsei, NSE_F_BSS);
	int counter;

	if (!nse) {
		vty_out(vty, "NSE not found%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	counter = gbproxy_cleanup_bvcs(nse, bvci);

	if (counter == 0) {
		vty_out(vty, "BVC not found%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(delete_gb_nsei, delete_gb_nsei_cmd,
	"delete-gbproxy-peer <0-65534> (only-bvc|only-nsvc|all) [dry-run]",
	"Delete a GBProxy bvc by NSEI and optionally BVCI\n"
	"NSEI number\n"
	"Only delete BSSGP connections (BVC)\n"
	"Only delete dynamic NS connections (NS-VC)\n"
	"Delete BVC and dynamic NS connections\n"
	"Show what would be deleted instead of actually deleting\n"
	)
{
	const uint16_t nsei = atoi(argv[0]);
	const char *mode = argv[1];
	int dry_run = argc > 2;
	int delete_bvc = 0;
	int delete_nsvc = 0;
	int counter;

	if (strcmp(mode, "only-bvc") == 0)
		delete_bvc = 1;
	else if (strcmp(mode, "only-nsvc") == 0)
		delete_nsvc = 1;
	else
		delete_bvc = delete_nsvc = 1;

	if (delete_bvc) {
		if (!dry_run) {
			struct gbproxy_nse *nse = gbproxy_nse_by_nsei(g_cfg, nsei, NSE_F_BSS);
			counter = gbproxy_cleanup_bvcs(nse, 0);
			gbproxy_nse_free(nse);
		} else {
			struct gbproxy_nse *nse;
			struct gbproxy_bvc *bvc;
			int i, j;
			counter = 0;
			hash_for_each(g_cfg->bss_nses, i, nse, list) {
				if (nse->nsei != nsei)
					continue;
				hash_for_each(nse->bvcs, j, bvc, list) {
					vty_out(vty, "BVC: ");
					gbprox_vty_print_bvc(vty, bvc);
					counter += 1;
				}
			}
		}
		vty_out(vty, "%sDeleted %d BVC%s",
			dry_run ? "Not " : "", counter, VTY_NEWLINE);
	}

	if (delete_nsvc) {
		struct gprs_ns2_inst *nsi = g_cfg->nsi;
		struct gprs_ns2_nse *nse;

		nse = gprs_ns2_nse_by_nsei(nsi, nsei);
		if (!nse) {
			vty_out(vty, "NSEI not found%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		/* TODO: We should NOT delete a persistent NSEI/NSVC as soon as we can check for these */
		if (!dry_run)
			gprs_ns2_free_nse(nse);

		vty_out(vty, "%sDeleted NS-VCs for NSEI %d%s",
			dry_run ? "Not " : "", nsei, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

int gbproxy_vty_init(void)
{
	install_element_ve(&show_gbproxy_bvc_cmd);
	install_element_ve(&show_gbproxy_links_cmd);
	install_element_ve(&logging_fltr_bvc_cmd);

	install_element(ENABLE_NODE, &delete_gb_bvci_cmd);
	install_element(ENABLE_NODE, &delete_gb_nsei_cmd);

	install_element(CONFIG_NODE, &cfg_gbproxy_cmd);
	install_node(&gbproxy_node, config_write_gbproxy);
	install_element(GBPROXY_NODE, &cfg_nsip_sgsn_nsei_cmd);
	install_element(GBPROXY_NODE, &cfg_pool_bvc_fc_ratio_cmd);

	return 0;
}

int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg)
{
	int rc;

	g_cfg = cfg;
	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	return 0;
}
