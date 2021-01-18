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

#include <osmocom/core/hashtable.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>

#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/bssgp_bvc_fsm.h>

#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/gsm23236.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/gb_proxy.h>
#include <osmocom/sgsn/gprs_utils.h>
#include <osmocom/sgsn/vty.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>

#define GBPROXY_STR "Display information about the Gb proxy\n"
#define NRI_STR "Mapping of Network Resource Indicators to this SGSN, for SGSN pooling\n"
#define NULL_NRI_STR "Define NULL-NRI values that cause re-assignment of an MS to a different SGSN, for SGSN pooling.\n"
#define NRI_FIRST_LAST_STR "First value of the NRI value range, should not surpass the configured 'nri bitlen'.\n" \
	"Last value of the NRI value range, should not surpass the configured 'nri bitlen' and be larger than the" \
	" first value; if omitted, apply only the first value.\n"
#define NRI_ARGS_TO_STR_FMT "%s%s%s"
#define NRI_ARGS_TO_STR_ARGS(ARGC, ARGV) ARGV[0], (ARGC>1)? ".." : "", (ARGC>1)? ARGV[1] : ""
#define NRI_WARN(SGSN, FORMAT, args...) do { \
		vty_out(vty, "%% Warning: NSE(%05d/SGSN): " FORMAT "%s", (SGSN)->nse->nsei, ##args, VTY_NEWLINE); \
		LOGP(DLBSSGP, LOGL_ERROR, "NSE(%05d/SGSN): " FORMAT "\n", (SGSN)->nse->nsei, ##args); \
	} while (0)

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

static void gbproxy_vty_print_cell(struct vty *vty, struct gbproxy_cell *cell, bool show_stats)
{
	struct gprs_ra_id raid;
	gsm48_parse_ra(&raid, cell->ra);
	unsigned int num_sgsn_bvc = 0;
	unsigned int i;

	vty_out(vty, "BVCI %5u RAI %s: ", cell->bvci, osmo_rai_name(&raid));
	if (cell->bss_bvc)
		vty_out(vty, "BSS NSEI %5u, SGSN NSEI ", cell->bss_bvc->nse->nsei);
	else
		vty_out(vty, "BSS NSEI <none>, SGSN NSEI ");

	for (i = 0; i < ARRAY_SIZE(cell->sgsn_bvc); i++) {
		struct gbproxy_bvc *sgsn_bvc = cell->sgsn_bvc[i];
		if (sgsn_bvc) {
			vty_out(vty, "%5u ", sgsn_bvc->nse->nsei);
			num_sgsn_bvc++;
		}
	}
	if (num_sgsn_bvc)
		vty_out(vty, "%s", VTY_NEWLINE);
	else
		vty_out(vty, "<none>%s", VTY_NEWLINE);
}

static int config_write_gbproxy(struct vty *vty)
{
	struct osmo_nri_range *r;

	vty_out(vty, "gbproxy%s", VTY_NEWLINE);

	if (g_cfg->pool.bvc_fc_ratio != 100)
		vty_out(vty, " pool bvc-flow-control-ratio %u%s", g_cfg->pool.bvc_fc_ratio, VTY_NEWLINE);

	if (g_cfg->pool.nri_bitlen != OSMO_NRI_BITLEN_DEFAULT)
		vty_out(vty, " nri bitlen %u%s", g_cfg->pool.nri_bitlen, VTY_NEWLINE);

	llist_for_each_entry(r, &g_cfg->pool.null_nri_ranges->entries, entry) {
		vty_out(vty, " nri null add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
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

/* VTY code for SGSN (pool) configuration */
extern const struct bssgp_bvc_fsm_ops sgsn_sig_bvc_fsm_ops;
#include <osmocom/gprs/protocol/gsm_08_18.h>

static struct cmd_node sgsn_node = {
	SGSN_NODE,
	"%s(config-sgsn)# ",
	1,
};

static void sgsn_write_nri(struct vty *vty, struct gbproxy_sgsn *sgsn, bool verbose)
{
	struct osmo_nri_range *r;

	if (verbose) {
		vty_out(vty, "sgsn nsei %d%s", sgsn->nse->nsei, VTY_NEWLINE);
		if (llist_empty(&sgsn->pool.nri_ranges->entries)) {
			vty_out(vty, " %% no NRI mappings%s", VTY_NEWLINE);
			return;
		}
	}

	llist_for_each_entry(r, &sgsn->pool.nri_ranges->entries, entry) {
		if (osmo_nri_range_validate(r, 255))
			vty_out(vty, " %% INVALID RANGE:");
		vty_out(vty, " nri add %d", r->first);
		if (r->first != r->last)
			vty_out(vty, " %d", r->last);
		vty_out(vty, "%s", VTY_NEWLINE);
	}
}

static void write_sgsn(struct vty *vty, struct gbproxy_sgsn *sgsn)
{
	vty_out(vty, "sgsn nsei %u%s", sgsn->nse->nsei, VTY_NEWLINE);
	vty_out(vty, " name %s%s", sgsn->name, VTY_NEWLINE);
	vty_out(vty, " %sallow-attach%s", sgsn->pool.allow_attach ? "" : "no ", VTY_NEWLINE);
	sgsn_write_nri(vty, sgsn, false);
}

static int config_write_sgsn(struct vty *vty)
{
	struct gbproxy_sgsn *sgsn;

	llist_for_each_entry(sgsn, &g_cfg->sgsns, list)
		write_sgsn(vty, sgsn);

	return CMD_SUCCESS;
}

DEFUN(cfg_sgsn_nsei,
      cfg_sgsn_nsei_cmd,
      "sgsn nsei <0-65534>",
      "Configure the SGSN\n"
      "NSEI to be used in the connection with the SGSN\n"
      "The NSEI\n")
{
	uint32_t features = 0; // FIXME: make configurable
	unsigned int nsei = atoi(argv[0]);
	unsigned int num_sgsn = llist_count(&g_cfg->sgsns);
	struct gbproxy_sgsn *sgsn;
	struct gbproxy_nse *nse;
	struct gbproxy_bvc *bvc;

	if (num_sgsn >= GBPROXY_MAX_NR_SGSN) {
		vty_out(vty, "%% Too many SGSN NSE defined (%d), increase GBPROXY_MAX_NR_SGSN%s",
			num_sgsn, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* This will have created the gbproxy_nse as well */
	sgsn = gbproxy_sgsn_by_nsei_or_new(g_cfg, nsei);
	if (!sgsn)
		goto free_nothing;
	nse = sgsn->nse;
	if (num_sgsn > 1 && g_cfg->pool.nri_bitlen == 0)
		vty_out(vty, "%% Multiple SGSNs defined, but no pooling enabled%s", VTY_NEWLINE);


	if (!gbproxy_bvc_by_bvci(nse, 0)) {
		uint8_t cause = BSSGP_CAUSE_OML_INTERV;
		bvc = gbproxy_bvc_alloc(nse, 0);
		if (!bvc)
			goto free_sgsn;
		bvc->fi = bssgp_bvc_fsm_alloc_sig_bss(bvc, nse->cfg->nsi, nsei, features);
		if (!bvc->fi)
			goto free_bvc;
		bssgp_bvc_fsm_set_ops(bvc->fi, &sgsn_sig_bvc_fsm_ops, bvc);
		osmo_fsm_inst_dispatch(bvc->fi, BSSGP_BVCFSM_E_REQ_RESET, &cause);
	}

	vty->node = SGSN_NODE;
	vty->index = sgsn;
	return CMD_SUCCESS;

free_bvc:
	gbproxy_bvc_free(bvc);
free_sgsn:
	gbproxy_sgsn_free(sgsn);
free_nothing:
	vty_out(vty, "%% Unable to create NSE for NSEI=%05u%s", nsei, VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN(cfg_sgsn_name,
      cfg_sgsn_name_cmd,
      "name NAME",
      "Configure the SGSN\n"
      "Name the SGSN\n"
      "The name\n")
{
	struct gbproxy_sgsn *sgsn = vty->index;
	const char *name = argv[0];


	osmo_talloc_replace_string(sgsn, &sgsn->name, name);
	if (!sgsn->name) {
		vty_out(vty, "%% Unable to set name for SGSN with nsei %05u%s", sgsn->nse->nsei, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_sgsn_nri_add, cfg_sgsn_nri_add_cmd,
	   "nri add <0-32767> [<0-32767>]",
	   NRI_STR "Add NRI value or range to the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct gbproxy_sgsn *sgsn = vty->index;
	struct gbproxy_sgsn *other_sgsn;
	bool before;
	int rc;
	const char *message;
	struct osmo_nri_range add_range;

	rc = osmo_nri_ranges_vty_add(&message, &add_range, sgsn->pool.nri_ranges, argc, argv, g_cfg->pool.nri_bitlen);
	if (message) {
		NRI_WARN(sgsn, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;

	/* Issue a warning about NRI range overlaps (but still allow them).
	 * Overlapping ranges will map to whichever SGSN comes fist in the gbproxy_config->sgsns llist,
	 * which should be the first one defined in the config */
	before = true;

	llist_for_each_entry(other_sgsn, &g_cfg->sgsns, list) {
		if (other_sgsn == sgsn) {
			before = false;
			continue;
		}
		if (osmo_nri_range_overlaps_ranges(&add_range, other_sgsn->pool.nri_ranges)) {
			uint16_t nsei = sgsn->nse->nsei;
			uint16_t other_nsei = other_sgsn->nse->nsei;
			NRI_WARN(sgsn, "NRI range [%d..%d] overlaps between NSE %05d and NSE %05d."
				 " For overlaps, NSE %05d has higher priority than NSE %05d",
				 add_range.first, add_range.last, nsei, other_nsei,
				 before ? other_nsei : nsei, before ? nsei : other_nsei);
		}
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_sgsn_nri_del, cfg_sgsn_nri_del_cmd,
	   "nri del <0-32767> [<0-32767>]",
	   NRI_STR "Remove NRI value or range from the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct gbproxy_sgsn *sgsn = vty->index;
	int rc;
	const char *message;

	rc = osmo_nri_ranges_vty_del(&message, NULL, sgsn->pool.nri_ranges, argc, argv);
	if (message) {
		NRI_WARN(sgsn, "%s: " NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_sgsn_allow_attach, cfg_sgsn_allow_attach_cmd,
	   "allow-attach",
	   "Allow this SGSN to attach new subscribers (default).\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gbproxy_sgsn *sgsn = vty->index;
	sgsn->pool.allow_attach = true;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_sgsn_no_allow_attach, cfg_sgsn_no_allow_attach_cmd,
	   "no allow-attach",
	   NO_STR
	   "Do not assign new subscribers to this MSC."
	   " Useful if an MSC in an MSC pool is configured to off-load subscribers."
	   " The MSC will still be operational for already IMSI-Attached subscribers,"
	   " but the NAS node selection function will skip this MSC for new subscribers\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct gbproxy_sgsn *sgsn = vty->index;
	sgsn->pool.allow_attach = false;
	return CMD_SUCCESS;
}

DEFUN(sgsn_show_nri_all, show_nri_all_cmd,
      "show nri all",
      SHOW_STR NRI_STR "Show all SGSNs\n")
{
	struct gbproxy_sgsn *sgsn;

	llist_for_each_entry(sgsn, &g_cfg->sgsns, list)
		sgsn_write_nri(vty, sgsn, true);

	return CMD_SUCCESS;
}

DEFUN(show_nri_nsei, show_nri_nsei_cmd,
      "show nri nsei <0-65535>",
      SHOW_STR NRI_STR "Identify SGSN by NSEI\n"
      "NSEI of the SGSN\n")
{
	struct gbproxy_sgsn *sgsn;
	int nsei = atoi(argv[0]);

	sgsn = gbproxy_sgsn_by_nsei(g_cfg, nsei);
	if (!sgsn) {
		vty_out(vty, "%% No SGSN with found for NSEI %05d%s", nsei, VTY_NEWLINE);
		return CMD_SUCCESS;
	}
	sgsn_write_nri(vty, sgsn, true);

	return CMD_SUCCESS;
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
DEFUN_ATTR(cfg_gbproxy_nri_bitlen,
	   cfg_gbproxy_nri_bitlen_cmd,
	   "nri bitlen <0-15>",
	   NRI_STR
	   "Set number of bits that an NRI has, to extract from TMSI identities (always starting just after the TMSI's most significant octet).\n"
	   "bit count (0 disables) pooling)\n",
	   CMD_ATTR_IMMEDIATE)
{
	g_cfg->pool.nri_bitlen = atoi(argv[0]);

	if (llist_count(&g_cfg->sgsns) > 1 && g_cfg->pool.nri_bitlen == 0)
		vty_out(vty, "%% Pooling disabled, but multiple SGSNs defined%s", VTY_NEWLINE);

	/* TODO: Verify all nri ranges and warn on mismatch */

	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_gbproxy_nri_null_add,
	   cfg_gbproxy_nri_null_add_cmd,
	   "nri null add <0-32767> [<0-32767>]",
	   NRI_STR NULL_NRI_STR "Add NULL-NRI value (or range)\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *message;

	rc = osmo_nri_ranges_vty_add(&message, NULL, g_cfg->pool.null_nri_ranges, argc, argv,
				     g_cfg->pool.nri_bitlen);
	if (message) {
		vty_out(vty, "%% nri null add: %s: " NRI_ARGS_TO_STR_FMT "%s", message, NRI_ARGS_TO_STR_ARGS(argc, argv),
			VTY_NEWLINE);
		vty_out(vty, "%s: \n" NRI_ARGS_TO_STR_FMT, message, NRI_ARGS_TO_STR_ARGS(argc, argv));
	}
	if (rc < 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cfg_gbproxy_nri_null_del,
	   cfg_gbproxy_nri_null_del_cmd,
	   "nri null del <0-32767> [<0-32767>]",
	   NRI_STR NULL_NRI_STR "Remove NRI value or range from the NRI mapping for this MSC\n"
	   NRI_FIRST_LAST_STR,
	   CMD_ATTR_IMMEDIATE)
{
	int rc;
	const char *message;
	rc = osmo_nri_ranges_vty_del(&message, NULL, g_cfg->pool.null_nri_ranges, argc, argv);
	if (message) {
		vty_out(vty, "%% %s: " NRI_ARGS_TO_STR_FMT "%s", message, NRI_ARGS_TO_STR_ARGS(argc, argv),
			VTY_NEWLINE);
	}
	if (rc < 0)
		return CMD_WARNING;
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
       SHOW_STR GBPROXY_STR
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

DEFUN(show_gbproxy_cell, show_gbproxy_cell_cmd, "show gbproxy cell [stats]",
       SHOW_STR GBPROXY_STR
       "Show GPRS Cell Information\n"
       "Show statistics\n")
{
	struct gbproxy_cell *cell;
	bool show_stats = argc >= 1;
	int i;

	hash_for_each(g_cfg->cells, i, cell, list)
		gbproxy_vty_print_cell(vty, cell, show_stats);

	return CMD_SUCCESS;
}

DEFUN(show_gbproxy_links, show_gbproxy_links_cmd, "show gbproxy links",
       SHOW_STR GBPROXY_STR "Show logical links\n")
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

DEFUN(show_gbproxy_tlli_cache, show_gbproxy_tlli_cache_cmd,
      "show gbproxy tlli-cache",
      SHOW_STR GBPROXY_STR "Show TLLI cache entries\n")
{
	struct gbproxy_tlli_cache_entry *entry;
	struct timespec now;
	time_t expiry;
	int i, count = 0;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);
	expiry = now.tv_sec - g_cfg->tlli_cache.timeout;

	vty_out(vty, "TLLI cache timeout %us%s", g_cfg->tlli_cache.timeout, VTY_NEWLINE);
	hash_for_each(g_cfg->tlli_cache.entries, i, entry, list) {
		time_t valid = entry->tstamp - expiry;
		struct gbproxy_nse *nse = entry->nse;

		vty_out(vty, " TLLI %08x -> NSE(%05u/%s) valid %lds%s", entry->tlli, nse->nsei,
			nse->sgsn_facing ? "SGSN" : "BSS", valid, VTY_NEWLINE);
		count++;
	}
	vty_out(vty, "TLLI cache contains %u entries%s", count, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_gbproxy_imsi_cache, show_gbproxy_imsi_cache_cmd,
      "show gbproxy imsi-cache",
      SHOW_STR GBPROXY_STR "Show IMSI cache entries\n")
{
	struct gbproxy_imsi_cache_entry *entry;
	struct timespec now;
	time_t expiry;
	int i, count = 0;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);
	expiry = now.tv_sec - g_cfg->imsi_cache.timeout;

	vty_out(vty, "IMSI cache timeout %us%s", g_cfg->imsi_cache.timeout, VTY_NEWLINE);
	hash_for_each(g_cfg->imsi_cache.entries, i, entry, list) {
		time_t valid = entry->tstamp - expiry;
		struct gbproxy_nse *nse = entry->nse;
		vty_out(vty, " IMSI %s -> NSE(%05u/%s): valid %lds%s", entry->imsi, nse->nsei,
			nse->sgsn_facing ? "SGSN" : "BSS", valid, VTY_NEWLINE);
		count++;
	}
	vty_out(vty, "IMSI cache contains %u entries%s", count, VTY_NEWLINE);
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

/* Only for ttcn3 testing */
DEFUN_HIDDEN(sgsn_pool_nsf_fixed, sgsn_pool_nsf_fixed_cmd,
	     "sgsn-pool nsf fixed NAME",
	     "SGSN pooling: load balancing across multiple SGSNs.\n"
	     "Customize the Network Selection Function.\n"
	     "Set a fixed SGSN to use (for testing).\n"
	     "The name of the SGSN to use.\n")
{
	const char *name = argv[0];
	struct gbproxy_sgsn *sgsn = gbproxy_sgsn_by_name(g_cfg, name);

	if (!sgsn) {
		vty_out(vty, "%% Could not find SGSN with name %s%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_cfg->pool.nsf_override = sgsn;
	return CMD_SUCCESS;
}

DEFUN_HIDDEN(sgsn_pool_nsf_normal, sgsn_pool_nsf_normal_cmd,
	     "sgsn-pool nsf normal",
	     "SGSN pooling: load balancing across multiple SGSNs.\n"
	     "Customize the Network Selection Function.\n"
	     "Reset the NSF back to regular operation (for testing).\n")
{
	g_cfg->pool.nsf_override = NULL;
	return CMD_SUCCESS;
}

int gbproxy_vty_init(void)
{
	install_element_ve(&show_gbproxy_bvc_cmd);
	install_element_ve(&show_gbproxy_cell_cmd);
	install_element_ve(&show_gbproxy_links_cmd);
	install_element_ve(&show_gbproxy_tlli_cache_cmd);
	install_element_ve(&show_gbproxy_imsi_cache_cmd);
	install_element_ve(&show_nri_all_cmd);
	install_element_ve(&show_nri_nsei_cmd);
	install_element_ve(&logging_fltr_bvc_cmd);

	install_element(ENABLE_NODE, &delete_gb_bvci_cmd);
	install_element(ENABLE_NODE, &delete_gb_nsei_cmd);
	install_element(ENABLE_NODE, &sgsn_pool_nsf_fixed_cmd);
	install_element(ENABLE_NODE, &sgsn_pool_nsf_normal_cmd);

	install_element(CONFIG_NODE, &cfg_gbproxy_cmd);
	install_node(&gbproxy_node, config_write_gbproxy);
	install_element(GBPROXY_NODE, &cfg_pool_bvc_fc_ratio_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_nri_bitlen_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_nri_null_add_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_nri_null_del_cmd);

	install_element(CONFIG_NODE, &cfg_sgsn_nsei_cmd);
	install_node(&sgsn_node, config_write_sgsn);
	install_element(SGSN_NODE, &cfg_sgsn_name_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_allow_attach_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_no_allow_attach_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_nri_add_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_nri_del_cmd);


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
