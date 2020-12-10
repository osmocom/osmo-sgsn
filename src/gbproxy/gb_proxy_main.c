/* NS-over-IP proxy */

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
#include <osmocom/core/stats.h>

#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/sgsn/signal.h>
#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/vty.h>
#include <osmocom/sgsn/gb_proxy.h>

#include <osmocom/ctrl/control_vty.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/misc.h>

#include "../../bscconfig.h"

#define _GNU_SOURCE
#include <getopt.h>

void *tall_sgsn_ctx;

const char *openbsc_copyright =
	"Copyright (C) 2010 Harald Welte and On-Waves\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

#define CONFIG_FILE_DEFAULT "osmo-gbproxy.cfg"
#define CONFIG_FILE_LEGACY "osmo_gbproxy.cfg"

static char *config_file = NULL;
struct gbproxy_config *gbcfg;
static int daemonize = 0;

/* Pointer to the SGSN peer */
extern struct gbprox_peer *gbprox_peer_sgsn;

static void signal_handler(int signum)
{
	fprintf(stdout, "signal %u received\n", signum);

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(1);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report and
		 * then run default SIGABRT handler, who will generate coredump
		 * and abort the process. abort() should do this for us after we
		 * return, but program wouldn't exit if an external SIGABRT is
		 * received.
		 */
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_sgsn_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
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

static void print_usage()
{
	printf("Usage: bsc_hack\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -d option --debug=DNS:DGPRS,0:0 enable debugging\n");
	printf("  -D --daemonize Fork the process into a background daemon\n");
	printf("  -c --config-file filename The config file to use [%s]\n", CONFIG_FILE_DEFAULT);
	printf("  -s --disable-color\n");
	printf("  -T --timestamp Prefix every log line with a timestamp\n");
	printf("  -V --version. Print the version.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "debug", 1, 0, 'd' },
			{ "daemonize", 0, 0, 'D' },
			{ "config-file", 1, 0, 'c' },
			{ "disable-color", 0, 0, 's' },
			{ "timestamp", 0, 0, 'T' },
			{ "version", 0, 0, 'V' },
			{ "log-level", 1, 0, 'e' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hd:Dc:sTVe:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
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
			config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
	}
}

static struct vty_app_info vty_info = {
	.name 		= "OsmoGbProxy",
	.version	= PACKAGE_VERSION,
};

/* default categories */
static struct log_info_cat gprs_categories[] = {
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DNS] = {
		.name = "DNS",
		.description = "GPRS Network Service (NS)",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
};

static const struct log_info gprs_log_info = {
	.filter_fn = gprs_log_filter_fn,
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

static bool file_exists(const char *path)
{
	struct stat sb;
	return stat(path, &sb) ? false : true;
}

int gbprox_bssgp_send_cb(void *ctx, struct msgb *msg);

int main(int argc, char **argv)
{
	int rc;
	struct ctrl_handle *ctrl;

	tall_sgsn_ctx = talloc_named_const(NULL, 0, "nsip_proxy");
	msgb_talloc_ctx_init(tall_sgsn_ctx, 0);
	vty_info.tall_ctx = tall_sgsn_ctx;

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	osmo_init_logging2(tall_sgsn_ctx, &gprs_log_info);

	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	gbproxy_vty_init();

	handle_options(argc, argv);

	/* Backwards compatibility: for years, the default config file name was
	 * osmo_gbproxy.cfg. All other Osmocom programs use osmo-*.cfg with a
	 * dash. To be able to use the new config file name without breaking
	 * previous setups that might rely on the legacy default config file
	 * name, we need to look for the old config file if no -c option was
	 * passed AND no file exists with the new default file name. */
	if (!config_file) {
		/* No -c option was passed */
		if (file_exists(CONFIG_FILE_LEGACY)
		    && !file_exists(CONFIG_FILE_DEFAULT))
			config_file = CONFIG_FILE_LEGACY;
		else
			config_file = CONFIG_FILE_DEFAULT;
	}

	rate_ctr_init(tall_sgsn_ctx);
	osmo_stats_init(tall_sgsn_ctx);

	gbcfg = talloc_zero(tall_sgsn_ctx, struct gbproxy_config);
	if (!gbcfg) {
		LOGP(DGPRS, LOGL_FATAL, "Unable to allocate config\n");
		exit(1);
	}
	gbproxy_init_config(gbcfg);
	gbcfg->nsi = gprs_ns2_instantiate(tall_sgsn_ctx, gprs_ns2_prim_cb, gbcfg);
	if (!gbcfg->nsi) {
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}

	gprs_ns2_vty_init(gbcfg->nsi, NULL);
	logging_vty_add_deprecated_subsys(tall_sgsn_ctx, "bssgp");
	gprs_ns2_dynamic_create_nse(gbcfg->nsi, true);

	bssgp_set_bssgp_callback(gbprox_bssgp_send_cb, gbcfg);

	rc = gbproxy_parse_config(config_file, gbcfg);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot parse config file '%s'\n", config_file);
		exit(2);
	}

	gprs_ns2_vty_create();

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_sgsn_ctx, NULL,
			       vty_get_bind_addr(), OSMO_VTY_PORT_GBPROXY);
	if (rc < 0)
		exit(1);

	/* Start control interface after getting config for
	 * ctrl_vty_get_bind_addr() */
	ctrl = ctrl_interface_setup_dynip(gbcfg, ctrl_vty_get_bind_addr(), OSMO_CTRL_PORT_GBPROXY, NULL);
	if (!ctrl) {
		LOGP(DGPRS, LOGL_FATAL, "Failed to create CTRL interface.\n");
		exit(1);
	}

	if (gb_ctrl_cmds_install() != 0) {
		LOGP(DGPRS, LOGL_FATAL, "Failed to install CTRL commands.\n");
		exit(1);
	}

	if (!gprs_ns2_nse_by_nsei(gbcfg->nsi, gbcfg->nsip_sgsn_nsei)) {
		LOGP(DGPRS, LOGL_FATAL, "You cannot proxy to NSE(%05u) "
			"without creating that NSEI before\n",
			gbcfg->nsip_sgsn_nsei);
		exit(2);
	}

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

	exit(0);
}
