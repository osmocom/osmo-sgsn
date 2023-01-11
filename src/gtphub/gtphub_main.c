/* GTP Hub main program */

/* (C) 2015 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/stat.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <osmocom/core/signal.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/msgb.h>

#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/misc.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/gtphub/gtphub.h>
#include <osmocom/sgsn/vty.h>

#include "../../config.h"

#if BUILD_IU
#include <osmocom/sigtran/osmo_ss7.h>
#endif

extern void *osmo_gtphub_ctx;
void *tall_sgsn_ctx;

const char *gtphub_copyright =
	"Copyright (C) 2015 sysmocom s.f.m.c GmbH <info@sysmocom.de>\r\n"
	"License AGPLv3+: GNU AGPL version 2 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static struct log_info_cat gtphub_categories[] = {
	[DGTPHUB] = {
		.name = "DGTPHUB",
		.description = "GTP Hub",
		.color = "\033[1;33m",
		.enabled = 1,
		.loglevel = LOGL_INFO,
	},
};

int gtphub_log_filter_fn(const struct log_context *ctx,
			 struct log_target *tar)
{
	return 0;
}

static const struct log_info gtphub_log_info = {
	.filter_fn = gtphub_log_filter_fn,
	.cat = gtphub_categories,
	.num_cat = ARRAY_SIZE(gtphub_categories),
};

void log_cfg(struct gtphub_cfg *cfg)
{
	int side_idx, plane_idx;
	for_each_side_and_plane(side_idx, plane_idx) {
		struct gtphub_cfg_addr *a;
		a = &cfg->to_gsns[side_idx][plane_idx].bind;
		LOGP(DGTPHUB, LOGL_NOTICE,
		     "to-%ss bind, %s: %s port %d\n",
		     gtphub_side_idx_names[side_idx],
		     gtphub_plane_idx_names[plane_idx],
		     a->addr_str, a->port);
	}
}

static void signal_handler(int signum)
{
	fprintf(stdout, "signal %d received\n", signum);

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
		talloc_report_full(osmo_gtphub_ctx, stderr);
		signal(SIGABRT, SIG_DFL);
		raise(SIGABRT);
		break;
	case SIGUSR1:
	case SIGUSR2:
		talloc_report_full(osmo_gtphub_ctx, stderr);
		break;
	default:
		break;
	}
}

static struct vty_app_info vty_info = {
	.name 		= "OsmoGTPhub",
	.version	= PACKAGE_VERSION,
#if BUILD_IU
	.go_parent_cb	= osmo_ss7_vty_go_parent,
#endif
};

struct cmdline_cfg {
	const char *config_file;
	const char *restart_counter_file;
	int daemonize;
};

static uint8_t next_restart_count(const char *path)
{
	int umask_was = umask(022);

	uint8_t counter = 0;

	FILE *f = fopen(path, "r");
	if (f) {
		int rc = fscanf(f, "%hhu", &counter);

		if (rc != 1)
			goto failed_to_read;

		char c;
		while (fread(&c, 1, 1, f) > 0) {
			switch (c) {
			case ' ':
			case '\t':
			case '\n':
			case '\r':
				break;
			default:
				goto failed_to_read;
			}
		}
		fclose(f);
	}

	counter ++;

	f = fopen(path, "w");
	if (!f)
		goto failed_to_write;
	if (fprintf(f, "%" PRIu8 "\n", counter) < 2)
		goto failed_to_write;
	if (fclose(f)) {
		f = NULL;
		goto failed_to_write;
	}

	umask(umask_was);

	LOGP(DGTPHUB, LOGL_NOTICE, "Restarted with counter %hhu\n", counter);
	return counter;

failed_to_read:
	fclose(f);
	umask(umask_was);
	LOGP(DGTPHUB, LOGL_FATAL, "Restart counter file cannot be parsed:"
	     " %s\n", path);
	exit(1);

failed_to_write:
	if (f)
		fclose(f);
	umask(umask_was);
	LOGP(DGTPHUB, LOGL_FATAL, "Restart counter file cannot be written:"
	     " %s\n", path);
	exit(1);
}

static void print_help(struct cmdline_cfg *ccfg)
{
	printf("gtphub commandline options\n");
	printf("  -h,--help            This text.\n");
	printf("  -D,--daemonize       Fork the process into a background daemon.\n");
	printf("  -d,--debug <cat>     Enable Debugging for this category.\n");
	printf("                       Pass '-d list' to get a category listing.\n");
	printf("  -s,--disable-color\n");
	printf("  -c,--config-file <path>  The config file to use [%s].\n",
	       ccfg->config_file);
	printf("  -e,--log-level <nr>      Set a global log level.\n");
	printf("  -r,--restart-file <path> File for counting restarts [%s].\n",
	       ccfg->restart_counter_file);
	printf("  -V,--version         Print the version.\n");
}

static void list_categories(void)
{
	printf("Available debug categories:\n");
	int i;
	for (i = 0; i < gtphub_log_info.num_cat; ++i) {
		if (!gtphub_log_info.cat[i].name)
			continue;

		printf("%s\n", gtphub_log_info.cat[i].name);
	}
}

static void handle_options(struct cmdline_cfg *ccfg, int argc, char **argv)
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
			{"log-level", 1, 0, 'e'},
			{"restart-file", 1, 0, 'r'},
			{ "version", 0, 0, 'V' },
			{NULL, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:Dc:sTe:r:V",
				long_options, &option_index);
		if (c == -1) {
			if (optind < argc) {
				LOGP(DGTPHUB, LOGL_FATAL,
				     "Excess commandline arguments ('%s').\n",
				     argv[optind]);
				exit(2);
			}
			break;
		}

		switch (c) {
		case 'h':
			//print_usage();
			print_help(ccfg);
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			if (strcmp("list", optarg) == 0) {
				list_categories();
				exit(0);
			} else
				log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			ccfg->daemonize = 1;
			break;
		case 'c':
			ccfg->config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'r':
			ccfg->restart_counter_file = optarg;
			break;
		case 'V':
			print_version(1);
			exit(EXIT_SUCCESS);
			break;
		default:
			LOGP(DGTPHUB, LOGL_FATAL, "Invalid command line argument, abort.\n");
			exit(1);
			break;
		}
	}

	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
	}
}

int main(int argc, char **argv)
{
	int rc;

	struct cmdline_cfg _ccfg;
	struct cmdline_cfg *ccfg = &_ccfg;
	memset(ccfg, '\0', sizeof(*ccfg));
	ccfg->config_file = "./gtphub.conf";
	ccfg->restart_counter_file = "./gtphub_restart_count";

	struct gtphub_cfg _cfg;
	struct gtphub_cfg *cfg = &_cfg;
	memset(cfg, '\0', sizeof(*cfg));

	struct gtphub _hub;
	struct gtphub *hub = &_hub;

	osmo_gtphub_ctx = talloc_named_const(NULL, 0, "osmo_gtphub");
	msgb_talloc_ctx_init(osmo_gtphub_ctx, 0);
	vty_info.tall_ctx = osmo_gtphub_ctx;

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	osmo_init_logging2(osmo_gtphub_ctx, &gtphub_log_info);

	vty_info.copyright = gtphub_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
        gtphub_vty_init(hub, cfg);

	rate_ctr_init(osmo_gtphub_ctx);

	handle_options(ccfg, argc, argv);

	rc = gtphub_cfg_read(cfg, ccfg->config_file);
	if (rc < 0) {
		LOGP(DGTPHUB, LOGL_FATAL, "Cannot parse config file '%s'\n",
		     ccfg->config_file);
		exit(2);
	}

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(osmo_gtphub_ctx, 0, vty_get_bind_addr(),
			       OSMO_VTY_PORT_GTPHUB);
	if (rc < 0)
		exit(1);

	if (gtphub_start(hub, cfg,
			 next_restart_count(ccfg->restart_counter_file))
	    != 0)
		return -1;

	log_cfg(cfg);

	if (ccfg->daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			LOGP(DGTPHUB, LOGL_FATAL, "Error during daemonize");
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
