/* GPRS SGSN Implementation */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
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

#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/stats.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/misc.h>

#include <osmocom/ctrl/control_vty.h>

#include <osmocom/sgsn/signal.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/vty.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/sgsn/gprs_llc.h>
#include <osmocom/sgsn/gprs_gmm.h>

#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>

#include <gtp.h>

#include "../../bscconfig.h"

#if BUILD_IU
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/ranap/iu_client.h>
#endif

#define _GNU_SOURCE
#include <getopt.h>

void *tall_sgsn_ctx;
struct ctrl_handle *g_ctrlh;

struct gprs_ns_inst *sgsn_nsi;
static int daemonize = 0;
const char *openbsc_copyright =
	"Copyright (C) 2010 Harald Welte and On-Waves\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

#define CONFIG_FILE_DEFAULT "osmo-sgsn.cfg"
#define CONFIG_FILE_LEGACY "osmo_sgsn.cfg"


struct sgsn_instance *sgsn;

/* call-back function for the NS protocol */
static int sgsn_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc,
		      struct msgb *msg, uint16_t bvci)
{
	int rc = 0;

	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		rc = bssgp_rcvmsg(msg);
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "SGSN: Unknown event %u from NS\n", event);
		if (msg)
			msgb_free(msg);
		rc = -EIO;
		break;
	}
	return rc;
}

/* call-back function for the BSSGP protocol */
int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_bssgp_prim *bp;
	bp = container_of(oph, struct osmo_bssgp_prim, oph);

	switch (oph->sap) {
	case SAP_BSSGP_LL:
		switch (oph->primitive) {
		case PRIM_BSSGP_UL_UD:
			return gprs_llc_rcvmsg(oph->msg, bp->tp);
		}
		break;
	case SAP_BSSGP_GMM:
		switch (oph->primitive) {
		case PRIM_BSSGP_GMM_SUSPEND:
			return gprs_gmm_rx_suspend(bp->ra_id, bp->tlli);
		case PRIM_BSSGP_GMM_RESUME:
			return gprs_gmm_rx_resume(bp->ra_id, bp->tlli,
						  bp->u.resume.suspend_ref);
		}
		break;
	case SAP_BSSGP_NM:
		break;
	}
	return 0;
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
	case SIGTERM:
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(1);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_sgsn_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

/* NSI that BSSGP uses when transmitting on NS */
extern struct gprs_ns_inst *bssgp_nsi;

int sgsn_vty_is_config_node(struct vty *vty, int node)
{
	/* So far the SGSN has no nested nodes that need parent node
	 * declaration, except for the ss7 vty nodes. */
	switch (node) {
	case SGSN_NODE:
		return 1;
	default:
#if BUILD_IU
		return osmo_ss7_is_config_node(vty, node);
#else
		return 0;
#endif
	}
}

int sgsn_vty_go_parent(struct vty *vty)
{
	/* So far the SGSN has no nested nodes that need parent node
	 * declaration, except for the ss7 vty nodes. */
#if BUILD_IU
	return osmo_ss7_vty_go_parent(vty);
#else
	vty->node = CONFIG_NODE;
	vty->index = NULL;
	return 0;
#endif
}

static struct vty_app_info vty_info = {
	.name 		= "OsmoSGSN",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= sgsn_vty_go_parent,
	.is_config_node	= sgsn_vty_is_config_node,
};

static void print_help(void)
{
	printf("Some useful help...\n");
	printf("  -h --help\tthis text\n");
	printf("  -V --version\tPrint the version\n");
	printf("  -D --daemonize\tFork the process into a background daemon\n");
	printf("  -d option --debug\tenable Debugging\n");
	printf("  -s --disable-color\n");
	printf("  -c --config-file\tThe config file to use [%s]\n", CONFIG_FILE_DEFAULT);
	printf("  -e --log-level number\tSet a global log level\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{ "version", 0, 0, 'V' },
			{"log-level", 1, 0, 'e'},
			{NULL, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:Dc:sTVe:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			//print_usage();
			print_help();
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			daemonize = 1;
			break;
		case 'c':
			osmo_talloc_replace_string(sgsn, &sgsn->config_file, optarg);
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		default:
			/* ignore */
			break;
		}
	}
}

/* default categories */
static struct log_info_cat gprs_categories[] = {
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DPAG]	= {
		.name = "DPAG",
		.description = "Paging Subsystem",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMEAS] = {
		.name = "DMEAS",
		.description = "Radio Measurement Processing",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DNS] = {
		.name = "DNS",
		.description = "GPRS Network Service (NS)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DBSSGP] = {
		.name = "DBSSGP",
		.description = "GPRS BSS Gateway Protocol (BSSGP)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DLLC] = {
		.name = "DLLC",
		.description = "GPRS Logical Link Control Protocol (LLC)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSNDCP] = {
		.name = "DSNDCP",
		.description = "GPRS Sub-Network Dependent Control Protocol (SNDCP)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DRANAP] = {
		.name = "DRANAP",
		.description = "RAN Application Part (RANAP)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSUA] = {
		.name = "DSUA",
		.description = "SCCP User Adaptation (SUA)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSLHC] = {
		.name = "DSLHC",
		.description = "RFC1144 TCP/IP Header compression (SLHC)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DV42BIS] = {
		.name = "DV42BIS",
		.description = "V.42bis data compression (SNDCP)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	}
};

static const struct log_info gprs_log_info = {
	.filter_fn = gprs_log_filter_fn,
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

#if BUILD_IU
int sgsn_ranap_iu_event(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type, void *data);
#endif

static bool file_exists(const char *path)
{
	struct stat sb;
	return stat(path, &sb) ? false : true;
}

int main(int argc, char **argv)
{
	int rc;
#if BUILD_IU
	struct osmo_sccp_instance *sccp;
#endif

	srand(time(NULL));
	tall_sgsn_ctx = talloc_named_const(NULL, 0, "osmo_sgsn");
	sgsn = sgsn_instance_alloc(tall_sgsn_ctx);
	msgb_talloc_ctx_init(tall_sgsn_ctx, 0);
	vty_info.tall_ctx = tall_sgsn_ctx;

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);

	osmo_init_ignore_signals();
	osmo_init_logging2(tall_sgsn_ctx, &gprs_log_info);
	osmo_stats_init(tall_sgsn_ctx);

	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	sgsn_vty_init(&sgsn->cfg);
	ctrl_vty_init(tall_sgsn_ctx);

#if BUILD_IU
	osmo_ss7_init();
	osmo_ss7_vty_init_asp(tall_sgsn_ctx);
	osmo_sccp_vty_init();
#endif

	handle_options(argc, argv);

	/* Backwards compatibility: for years, the default config file name was
	 * osmo_sgsn.cfg. All other Osmocom programs use osmo-*.cfg with a
	 * dash. To be able to use the new config file name without breaking
	 * previous setups that might rely on the legacy default config file
	 * name, we need to look for the old config file if no -c option was
	 * passed AND no file exists with the new default file name. */
	if (!sgsn->config_file) {
		/* No -c option was passed */
		if (file_exists(CONFIG_FILE_LEGACY)
		    && !file_exists(CONFIG_FILE_DEFAULT))
			osmo_talloc_replace_string(sgsn, &sgsn->config_file, CONFIG_FILE_LEGACY);
		else
			osmo_talloc_replace_string(sgsn, &sgsn->config_file, CONFIG_FILE_DEFAULT);
	}

	rate_ctr_init(tall_sgsn_ctx);

	gprs_ns_set_log_ss(DNS);
	bssgp_set_log_ss(DBSSGP);

	sgsn_nsi = gprs_ns_instantiate(&sgsn_ns_cb, tall_sgsn_ctx);
	if (!sgsn_nsi) {
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}
	bssgp_nsi = sgsn->cfg.nsi = sgsn_nsi;

	gprs_llc_init("/usr/local/lib/osmocom/crypt/");
	sgsn_rate_ctr_init();
	sgsn_inst_init(sgsn);

	gprs_ns_vty_init(bssgp_nsi);
	bssgp_vty_init();
	gprs_llc_vty_init();
	gprs_sndcp_vty_init();
	sgsn_auth_init(sgsn);
	sgsn_cdr_init(sgsn);
	/* FIXME: register signal handler for SS_L_NS */

	rc = sgsn_parse_config(sgsn->config_file);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Error in config file\n");
		exit(2);
	}

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_sgsn_ctx, NULL,
			       vty_get_bind_addr(), OSMO_VTY_PORT_SGSN);
	if (rc < 0)
		exit(1);

	/* start control interface after reading config for
	 * ctrl_vty_get_bind_addr() */
	g_ctrlh = ctrl_interface_setup_dynip(NULL, ctrl_vty_get_bind_addr(),
				    OSMO_CTRL_PORT_SGSN, NULL);
	if (!g_ctrlh) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to create CTRL interface.\n");
		exit(1);
	}

	if (sgsn_ctrl_cmds_install() != 0) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to install CTRL commands.\n");
		exit(1);
	}


	rc = sgsn_gtp_init(sgsn);
	if (rc) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot bind/listen on GTP socket\n");
		exit(2);
	} else
		LOGP(DGPRS, LOGL_NOTICE, "libGTP v%s initialized\n", gtp_version());

	rc = gprs_subscr_init(sgsn);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot set up subscriber management\n");
		exit(2);
	}

	rc = gprs_ns_nsip_listen(sgsn_nsi);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot bind/listen on NSIP socket\n");
		exit(2);
	}

	rc = gprs_ns_frgre_listen(sgsn_nsi);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot bind/listen GRE "
			"socket. Do you have CAP_NET_RAW?\n");
		exit(2);
	}

	if (sgsn->cfg.dynamic_lookup) {
		if (sgsn_ares_init(sgsn) != 0) {
			LOGP(DGPRS, LOGL_FATAL,
				"Failed to initialize c-ares(%d)\n", rc);
			exit(4);
		}
	}

#if BUILD_IU
	/* Note that these are mostly defaults and can be overriden from the VTY */
	sccp = osmo_sccp_simple_client_on_ss7_id(tall_sgsn_ctx,
						 sgsn->cfg.iu.cs7_instance,
						 "OsmoSGSN",
						 (23 << 3) + 4,
						 OSMO_SS7_ASP_PROT_M3UA,
						 0, NULL,
						 0, "127.0.0.1");
	if (!sccp) {
		printf("Setting up SCCP client failed.\n");
		return 8;
	}

	ranap_iu_init(tall_sgsn_ctx, DRANAP, "OsmoSGSN-IuPS", sccp, gsm0408_gprs_rcvmsg_iu, sgsn_ranap_iu_event);
#endif

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	/* not reached */
	exit(0);
}
