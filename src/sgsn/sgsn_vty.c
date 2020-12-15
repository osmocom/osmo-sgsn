/*
 * (C) 2010-2016 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * (C) 2015 by Holger Hans Peter Freyther
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
#include <time.h>
#include <inttypes.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/tdef.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/apn.h>

#include <osmocom/sgsn/debug.h>
#include <osmocom/sgsn/sgsn.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/sgsn/gprs_gmm.h>
#include <osmocom/sgsn/gprs_sgsn.h>
#include <osmocom/sgsn/vty.h>
#include <osmocom/gsupclient/gsup_client.h>

#include <osmocom/vty/tdef_vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>
#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/abis/ipa.h>

#include <osmocom/gprs/gprs_bssgp.h>

#include <pdp.h>
#include <gtp.h>

#include "../../bscconfig.h"

#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

extern void *tall_sgsn_ctx;

static struct sgsn_config *g_cfg = NULL;

const struct value_string sgsn_auth_pol_strs[] = {
	{ SGSN_AUTH_POLICY_OPEN,	"accept-all" },
	{ SGSN_AUTH_POLICY_CLOSED,	"closed" },
	{ SGSN_AUTH_POLICY_ACL_ONLY,    "acl-only" },
	{ SGSN_AUTH_POLICY_REMOTE,      "remote" },
	{ 0, NULL }
};

/* Section 11.2.2 / Table 11.3a GPRS Mobility management timers – MS side */
#define GSM0408_T3312_SECS	(10*60)	/* periodic RAU interval, default 54min */

/* Section 11.2.2 / Table 11.4 MM timers netwokr side */
#define GSM0408_T3322_SECS	6	/* DETACH_REQ -> DETACH_ACC */
#define GSM0408_T3350_SECS	6	/* waiting for ATT/RAU/TMSI COMPL */
#define GSM0408_T3360_SECS	6	/* waiting for AUTH/CIPH RESP */
#define GSM0408_T3370_SECS	6	/* waiting for ID RESP */

/* Section 11.2.2 / Table 11.4a MM timers network side */
#define GSM0408_T3313_SECS	30	/* waiting for paging response */
#define GSM0408_T3314_SECS	44	/* force to STBY on expiry, Ready timer */
#define GSM0408_T3316_SECS	44

/* Section 11.3 / Table 11.2d Timers of Session Management - network side */
#define GSM0408_T3385_SECS	8	/* wait for ACT PDP CTX REQ */
#define GSM0408_T3386_SECS	8	/* wait for MODIFY PDP CTX ACK */
#define GSM0408_T3395_SECS	8	/* wait for DEACT PDP CTX ACK */
#define GSM0408_T3397_SECS	8	/* wait for DEACT AA PDP CTX ACK */

/* Non spec timer */
#define NONSPEC_X1001_SECS     5       /* wait for a RANAP Release Complete */


static struct osmo_tdef sgsn_T_defs[] = {
	{ .T=3312, .default_val=GSM0408_T3312_SECS, .desc="Periodic RA Update timer (s)" },
	{ .T=3313, .default_val=GSM0408_T3313_SECS, .desc="Waiting for paging response timer (s)" },
	{ .T=3314, .default_val=GSM0408_T3314_SECS, .desc="READY timer. Force to STANDBY on expiry timer (s)" },
	{ .T=3316, .default_val=GSM0408_T3316_SECS, .desc="AA-Ready timer (s)" },
	{ .T=3322, .default_val=GSM0408_T3322_SECS, .desc="Detach request -> accept timer (s)" },
	{ .T=3350, .default_val=GSM0408_T3350_SECS, .desc="Waiting for ATT/RAU/TMSI_COMPL timer (s)" },
	{ .T=3360, .default_val=GSM0408_T3360_SECS, .desc="Waiting for AUTH/CIPH response timer (s)" },
	{ .T=3370, .default_val=GSM0408_T3370_SECS, .desc="Waiting for IDENTITY response timer (s)" },
	{ .T=3385, .default_val=GSM0408_T3385_SECS, .desc="Wait for ACT PDP CTX REQ timer (s)" },
	{ .T=3386, .default_val=GSM0408_T3386_SECS, .desc="Wait for MODIFY PDP CTX ACK timer (s)" },
	{ .T=3395, .default_val=GSM0408_T3395_SECS, .desc="Wait for DEACT PDP CTX ACK timer (s)" },
	{ .T=3397, .default_val=GSM0408_T3397_SECS, .desc="Wait for DEACT AA PDP CTX ACK timer (s)" },
	/* non spec timers */
	{ .T=-1001, .default_val=NONSPEC_X1001_SECS, .desc="RANAP Release timeout. Wait for RANAP Release Complete."
							   "On expiry release Iu connection (s)" },
	{ .T=-3314, .default_val=GSM0408_T3314_SECS, .desc="Iu User inactivity timer. On expiry release Iu connection (s)" },
	{}
};

DEFUN(show_timer, show_timer_cmd,
      "show timer " OSMO_TDEF_VTY_ARG_T_OPTIONAL,
      SHOW_STR "Show timers\n"
      OSMO_TDEF_VTY_DOC_T)
{
	const char *T_arg = argc > 0 ? argv[0] : NULL;
	return osmo_tdef_vty_show_cmd(vty, g_cfg->T_defs, T_arg, NULL);
}

DEFUN(cfg_sgsn_timer, cfg_sgsn_timer_cmd,
      "timer " OSMO_TDEF_VTY_ARG_SET_OPTIONAL,
      "Configure or show timers\n"
      OSMO_TDEF_VTY_DOC_SET)
{
	/* If any arguments are missing, redirect to 'show' */
	if (argc < 2)
		return show_timer(self, vty, argc, argv);
	return osmo_tdef_vty_set_cmd(vty, g_cfg->T_defs, argv);
}

char *gprs_pdpaddr2str(uint8_t *pdpa, uint8_t len)
{
	static char str[INET6_ADDRSTRLEN + 10];

	if (!pdpa || len < 2)
		return "none";

	switch (pdpa[0] & 0x0f) {
	case PDP_TYPE_ORG_IETF:
		switch (pdpa[1]) {
		case PDP_TYPE_N_IETF_IPv4:
			if (len < 2 + 4)
				break;
			strcpy(str, "IPv4 ");
			inet_ntop(AF_INET, pdpa+2, str+5, sizeof(str)-5);
			return str;
		case PDP_TYPE_N_IETF_IPv6:
			if (len < 2 + 8)
				break;
			strcpy(str, "IPv6 ");
			inet_ntop(AF_INET6, pdpa+2, str+5, sizeof(str)-5);
			return str;
		default:
			break;
		}
		break;
	case PDP_TYPE_ORG_ETSI:
		if (pdpa[1] == PDP_TYPE_N_ETSI_PPP)
			return "PPP";
		break;
	default:
		break;
	}

	return "invalid";
}

static struct cmd_node sgsn_node = {
	SGSN_NODE,
	"%s(config-sgsn)# ",
	1,
};

static int config_write_sgsn(struct vty *vty)
{
	struct sgsn_ggsn_ctx *gctx;
	struct imsi_acl_entry *acl;
	struct apn_ctx *actx;
	struct ares_addr_node *server;

	vty_out(vty, "sgsn%s", VTY_NEWLINE);

	vty_out(vty, " gtp state-dir %s%s",
		g_cfg->gtp_statedir, VTY_NEWLINE);
	vty_out(vty, " gtp local-ip %s%s",
		inet_ntoa(g_cfg->gtp_listenaddr.sin_addr), VTY_NEWLINE);

	llist_for_each_entry(gctx, &sgsn_ggsn_ctxts, list) {
		if (gctx->id == UINT32_MAX)
			continue;

		vty_out(vty, " ggsn %u remote-ip %s%s", gctx->id,
			inet_ntoa(gctx->remote_addr), VTY_NEWLINE);
		vty_out(vty, " ggsn %u gtp-version %u%s", gctx->id,
			gctx->gtp_version, VTY_NEWLINE);
		if (gctx->echo_interval)
			vty_out(vty, " ggsn %u echo-interval %u%s",
				gctx->id, gctx->echo_interval, VTY_NEWLINE);
		else
			vty_out(vty, " ggsn %u no echo-interval%s",
				gctx->id, VTY_NEWLINE);
	}

	if (sgsn->cfg.dynamic_lookup)
		vty_out(vty, " ggsn dynamic%s", VTY_NEWLINE);

	for (server = sgsn->ares_servers; server; server = server->next)
		vty_out(vty, " grx-dns-add %s%s", inet_ntoa(server->addr.addr4), VTY_NEWLINE);

	if (g_cfg->cipher != GPRS_ALGO_GEA0)
		vty_out(vty, " encryption %s%s",
			get_value_string(gprs_cipher_names, g_cfg->cipher),
			VTY_NEWLINE);
	if (g_cfg->sgsn_ipa_name)
		vty_out(vty, " gsup ipa-name %s%s", g_cfg->sgsn_ipa_name, VTY_NEWLINE);
	if (g_cfg->gsup_server_addr.sin_addr.s_addr)
		vty_out(vty, " gsup remote-ip %s%s",
			inet_ntoa(g_cfg->gsup_server_addr.sin_addr), VTY_NEWLINE);
	if (g_cfg->gsup_server_port)
		vty_out(vty, " gsup remote-port %d%s",
			g_cfg->gsup_server_port, VTY_NEWLINE);
	if (g_cfg->auth_policy == SGSN_AUTH_POLICY_REMOTE && !g_cfg->require_authentication)
		vty_out(vty, " authentication optional%s", VTY_NEWLINE);
	vty_out(vty, " auth-policy %s%s",
		get_value_string(sgsn_auth_pol_strs, g_cfg->auth_policy),
		VTY_NEWLINE);

	vty_out(vty, " gsup oap-id %d%s",
		(int)g_cfg->oap.client_id, VTY_NEWLINE);
	if (g_cfg->oap.secret_k_present != 0)
		vty_out(vty, " gsup oap-k %s%s",
			osmo_hexdump_nospc(g_cfg->oap.secret_k, sizeof(g_cfg->oap.secret_k)),
			VTY_NEWLINE);
	if (g_cfg->oap.secret_opc_present != 0)
		vty_out(vty, " gsup oap-opc %s%s",
			osmo_hexdump_nospc(g_cfg->oap.secret_opc, sizeof(g_cfg->oap.secret_opc)),
			VTY_NEWLINE);

	llist_for_each_entry(acl, &g_cfg->imsi_acl, list)
		vty_out(vty, " imsi-acl add %s%s", acl->imsi, VTY_NEWLINE);

	if (llist_empty(&sgsn_apn_ctxts))
		vty_out(vty, " ! apn * ggsn 0%s", VTY_NEWLINE);
	llist_for_each_entry(actx, &sgsn_apn_ctxts, list) {
		if (strlen(actx->imsi_prefix) > 0)
			vty_out(vty, " apn %s imsi-prefix %s ggsn %u%s",
				actx->name, actx->imsi_prefix, actx->ggsn->id,
				VTY_NEWLINE);
		else
			vty_out(vty, " apn %s ggsn %u%s", actx->name,
				actx->ggsn->id, VTY_NEWLINE);
	}

	if (g_cfg->cdr.filename)
		vty_out(vty, " cdr filename %s%s", g_cfg->cdr.filename, VTY_NEWLINE);
	else
		vty_out(vty, " no cdr filename%s", VTY_NEWLINE);
	if (g_cfg->cdr.trap)
		vty_out(vty, " cdr trap%s", VTY_NEWLINE);
	else
		vty_out(vty, " no cdr trap%s", VTY_NEWLINE);
	vty_out(vty, " cdr interval %d%s", g_cfg->cdr.interval, VTY_NEWLINE);

	osmo_tdef_vty_write(vty, g_cfg->T_defs, " timer ");

	if (g_cfg->pcomp_rfc1144.active) {
		vty_out(vty, " compression rfc1144 active slots %d%s",
			g_cfg->pcomp_rfc1144.s01 + 1, VTY_NEWLINE);
	} else if (g_cfg->pcomp_rfc1144.passive) {
		vty_out(vty, " compression rfc1144 passive%s", VTY_NEWLINE);
	} else
		vty_out(vty, " no compression rfc1144%s", VTY_NEWLINE);

	if (g_cfg->dcomp_v42bis.active && g_cfg->dcomp_v42bis.p0 == 1) {
		vty_out(vty,
			" compression v42bis active direction sgsn codewords %d strlen %d%s",
			g_cfg->dcomp_v42bis.p1, g_cfg->dcomp_v42bis.p2,
			VTY_NEWLINE);
	} else if (g_cfg->dcomp_v42bis.active && g_cfg->dcomp_v42bis.p0 == 2) {
		vty_out(vty,
			" compression v42bis active direction ms codewords %d strlen %d%s",
			g_cfg->dcomp_v42bis.p1, g_cfg->dcomp_v42bis.p2,
			VTY_NEWLINE);
	} else if (g_cfg->dcomp_v42bis.active && g_cfg->dcomp_v42bis.p0 == 3) {
		vty_out(vty,
			" compression v42bis active direction both codewords %d strlen %d%s",
			g_cfg->dcomp_v42bis.p1, g_cfg->dcomp_v42bis.p2,
			VTY_NEWLINE);
	} else if (g_cfg->dcomp_v42bis.passive) {
		vty_out(vty, " compression v42bis passive%s", VTY_NEWLINE);
	} else
		vty_out(vty, " no compression v42bis%s", VTY_NEWLINE);

#ifdef BUILD_IU
	vty_out(vty, " cs7-instance-iu %u%s", g_cfg->iu.cs7_instance,
		VTY_NEWLINE);
	ranap_iu_vty_config_write(vty, " ");
#endif

	return CMD_SUCCESS;
}

#define SGSN_STR	"Configure the SGSN\n"
#define GGSN_STR	"Configure the GGSN information\n"

DEFUN(cfg_sgsn, cfg_sgsn_cmd,
	"sgsn",
	SGSN_STR)
{
	vty->node = SGSN_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_sgsn_state_dir, cfg_sgsn_state_dir_cmd,
	"gtp state-dir PATH",
	"GTP Parameters\n"
	"Set the directory for the GTP State file\n"
	"Local Directory\n")
{
	osmo_talloc_replace_string(sgsn, &sgsn->cfg.gtp_statedir, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_sgsn_bind_addr, cfg_sgsn_bind_addr_cmd,
	"gtp local-ip A.B.C.D",
	"GTP Parameters\n"
	"Set the IP address for the local GTP bind for the Gp interface (towards the GGSNs)."
	" Note: in case you would like to run the GGSN on the same machine as the SGSN, you can not run"
	" both on the same IP address, since both sides are specified to use the same GTP port numbers"
	" (" OSMO_STRINGIFY_VAL(GTP1C_PORT) " and " OSMO_STRINGIFY_VAL(GTP1U_PORT) ")."
	" For example, you could use 127.0.0.1 for the SGSN and 127.0.0.2 for the GGSN in such"
	" situations.\n"
	"IPv4 Address\n")
{
	inet_aton(argv[0], &g_cfg->gtp_listenaddr.sin_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_remote_ip, cfg_ggsn_remote_ip_cmd,
	"ggsn <0-255> remote-ip A.B.C.D",
	GGSN_STR "GGSN Number\n"
	"Configure this static GGSN to use the specified remote IP address.\n"
	"IPv4 Address\n")
{
	uint32_t id = atoi(argv[0]);
	struct sgsn_ggsn_ctx *ggc = sgsn_ggsn_ctx_find_alloc(id);

	inet_aton(argv[1], &ggc->remote_addr);

	return CMD_SUCCESS;
}

#if 0
DEFUN(cfg_ggsn_remote_port, cfg_ggsn_remote_port_cmd,
	"ggsn <0-255> remote-port <0-65535>",
	"")
{
	uint32_t id = atoi(argv[0]);
	struct sgsn_ggsn_ctx *ggc = sgsn_ggsn_ctx_find_alloc(id);
	uint16_t port = atoi(argv[1]);

}
#endif

DEFUN(cfg_ggsn_gtp_version, cfg_ggsn_gtp_version_cmd,
	"ggsn <0-255> gtp-version (0|1)",
	GGSN_STR "GGSN Number\n" "GTP Version\n"
	"Version 0\n" "Version 1\n")
{
	uint32_t id = atoi(argv[0]);
	struct sgsn_ggsn_ctx *ggc = sgsn_ggsn_ctx_find_alloc(id);

	if (atoi(argv[1]))
		ggc->gtp_version = 1;
	else
		ggc->gtp_version = 0;

	return CMD_SUCCESS;
}

/* Seee 3GPP TS 29.060 section 7.2.1 */
DEFUN(cfg_ggsn_echo_interval, cfg_ggsn_echo_interval_cmd,
	"ggsn <0-255> echo-interval <1-36000>",
	GGSN_STR "GGSN Number\n"
	"Send an echo request to this static GGSN every interval.\n"
	"Interval between echo requests in seconds.\n")
{
	uint32_t id = atoi(argv[0]);
	struct sgsn_ggsn_ctx *ggc = sgsn_ggsn_ctx_find_alloc(id);

	ggc->echo_interval = atoi(argv[1]);

	if (ggc->echo_interval < 60)
		vty_out(vty, "%% 3GPP TS 29.060 section 7.2.1 states interval should " \
			     "not be lower than 60 seconds, use this value for " \
			     "testing purposes only!%s", VTY_NEWLINE);

	sgsn_ggsn_ctx_check_echo_timer(ggc);
	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_no_echo_interval, cfg_ggsn_no_echo_interval_cmd,
	"ggsn <0-255> no echo-interval",
	GGSN_STR "GGSN Number\n"
	NO_STR "Send an echo request to this static GGSN every interval.\n")
{
	uint32_t id = atoi(argv[0]);
	struct sgsn_ggsn_ctx *ggc = sgsn_ggsn_ctx_find_alloc(id);

	ggc->echo_interval = 0;
	sgsn_ggsn_ctx_check_echo_timer(ggc);

	return CMD_SUCCESS;
}

DEFUN(cfg_ggsn_dynamic_lookup, cfg_ggsn_dynamic_lookup_cmd,
	"ggsn dynamic",
	GGSN_STR
	"Enable dynamic resolving of GGSNs based on DNS resolving the APN name like in a GRX-style setup."
	" Changing this setting requires a restart.\n")
{
	sgsn->cfg.dynamic_lookup = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_grx_ggsn, cfg_grx_ggsn_cmd,
	"grx-dns-add A.B.C.D",
	"Use the specified IP address for DNS-resolving the AP names to GGSN IP addresses\n"
	"IPv4 address\n")
{
	struct ares_addr_node *node = talloc_zero(tall_sgsn_ctx, struct ares_addr_node);
	node->family = AF_INET;
	inet_aton(argv[0], &node->addr.addr4);

	node->next = sgsn->ares_servers;
	sgsn->ares_servers = node;
	return CMD_SUCCESS;
}

#define APN_STR	"Configure the information per APN\n"
#define APN_GW_STR "The APN gateway name optionally prefixed by '*' (wildcard)\n"

static int add_apn_ggsn_mapping(struct vty *vty, const char *apn_str,
				const char *imsi_prefix, int ggsn_id)
{
	struct apn_ctx *actx;
	struct sgsn_ggsn_ctx *ggsn;

	ggsn = sgsn_ggsn_ctx_by_id(ggsn_id);
	if (ggsn == NULL) {
		vty_out(vty, "%% a GGSN with id %d has not been defined%s",
			ggsn_id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	actx = sgsn_apn_ctx_find_alloc(apn_str, imsi_prefix);
	if (!actx) {
		vty_out(vty, "%% unable to create APN context for %s/%s%s",
			apn_str, imsi_prefix, VTY_NEWLINE);
		return CMD_WARNING;
	}

	actx->ggsn = ggsn;

	return CMD_SUCCESS;
}

DEFUN(cfg_apn_ggsn, cfg_apn_ggsn_cmd,
	"apn APNAME ggsn <0-255>",
	APN_STR APN_GW_STR
	"Select the GGSN to use for the given APN gateway prefix\n"
	"The GGSN id")
{

	return add_apn_ggsn_mapping(vty, argv[0], "", atoi(argv[1]));
}

DEFUN(cfg_apn_imsi_ggsn, cfg_apn_imsi_ggsn_cmd,
	"apn APNAME imsi-prefix IMSIPRE ggsn <0-255>",
	APN_STR APN_GW_STR
	"Select the GGSN to use for the given APN gateway prefix if and only if the IMSI matches the"
	" given prefix.\n"
	"An IMSI prefix\n"
	"Select the GGSN to use when APN gateway and IMSI prefix match\n"
	"The GGSN id")
{

	return add_apn_ggsn_mapping(vty, argv[0], argv[1], atoi(argv[2]));
}

char *sgsn_gtp_ntoa(struct ul16_t *ul)
{
	struct in_addr ia;

	if (gsna2in_addr(&ia, ul) != 0)
		return "UNKNOWN";

	return inet_ntoa(ia);
}

static void vty_dump_pdp(struct vty *vty, const char *pfx,
			 struct sgsn_pdp_ctx *pdp)
{
	const char *imsi = pdp->mm ? pdp->mm->imsi : "(detaching)";
	vty_out(vty, "%sPDP Context IMSI: %s, SAPI: %u, NSAPI: %u, TI: %u%s",
		pfx, imsi, pdp->sapi, pdp->nsapi, pdp->ti, VTY_NEWLINE);
	if (pdp->lib) {
		char apnbuf[APN_MAXLEN + 1];
		vty_out(vty, "%s  APN: %s%s", pfx,
			osmo_apn_to_str(apnbuf, pdp->lib->apn_use.v, pdp->lib->apn_use.l),
			VTY_NEWLINE);
		vty_out(vty, "%s  PDP Address: %s%s", pfx,
			gprs_pdpaddr2str(pdp->lib->eua.v, pdp->lib->eua.l),
			VTY_NEWLINE);
		vty_out(vty, "%s  GTPv%d Local Control(%s / TEIC: 0x%08x) ", pfx, pdp->lib->version,
			sgsn_gtp_ntoa(&pdp->lib->gsnlc), pdp->lib->teic_own);
		vty_out(vty, "Data(%s / TEID: 0x%08x)%s",
			sgsn_gtp_ntoa(&pdp->lib->gsnlu), pdp->lib->teid_own, VTY_NEWLINE);
		vty_out(vty, "%s  GTPv%d Remote Control(%s / TEIC: 0x%08x) ", pfx, pdp->lib->version,
			sgsn_gtp_ntoa(&pdp->lib->gsnrc), pdp->lib->teic_gn);
		vty_out(vty, "Data(%s / TEID: 0x%08x)%s",
			sgsn_gtp_ntoa(&pdp->lib->gsnru), pdp->lib->teid_gn, VTY_NEWLINE);
	}

	vty_out_rate_ctr_group(vty, " ", pdp->ctrg);
}

static void vty_dump_mmctx(struct vty *vty, const char *pfx,
			   struct sgsn_mm_ctx *mm, int pdp)
{
	uint32_t id = 0;
	const char *mm_state_name = NULL;

	switch(mm->ran_type) {
	case MM_CTX_T_UTRAN_Iu:
#if BUILD_IU
		id = mm->iu.ue_ctx->conn_id;
		mm_state_name = osmo_fsm_inst_state_name(mm->iu.mm_state_fsm);
#endif
		break;
	case MM_CTX_T_GERAN_Gb:
		id = mm->gb.tlli;
		mm_state_name = osmo_fsm_inst_state_name(mm->gb.mm_state_fsm);
		break;
	}

	vty_out(vty, "%sMM Context for IMSI %s, IMEI %s, P-TMSI %08x%s",
		pfx, mm->imsi, mm->imei, mm->p_tmsi, VTY_NEWLINE);
	vty_out(vty, "%s  MSISDN: %s, TLLI: %08x%s HLR: %s",
		pfx, mm->msisdn, id, mm->hlr, VTY_NEWLINE);
	vty_out(vty, "%s  GMM State: %s, Routeing Area: %s, Cell ID: %u%s",
		pfx, osmo_fsm_inst_state_name(mm->gmm_fsm),
		osmo_rai_name(&mm->ra), mm->gb.cell_id, VTY_NEWLINE);
	vty_out(vty, "%s  MM State: %s, RAN Type: %s%s", pfx, mm_state_name,
		get_value_string(sgsn_ran_type_names, mm->ran_type), VTY_NEWLINE);

	vty_out_rate_ctr_group(vty, "  ", mm->ctrg);

	if (pdp) {
		struct sgsn_pdp_ctx *pdp;

		llist_for_each_entry(pdp, &mm->pdp_list, list)
			vty_dump_pdp(vty, "  ", pdp);
	}
}

DEFUN(show_sgsn, show_sgsn_cmd, "show sgsn",
      SHOW_STR "Display information about the SGSN")
{
	if (sgsn->gsup_client) {
		struct ipa_client_conn *link = sgsn->gsup_client->link;
		vty_out(vty,
			"  Remote authorization: %sconnected to %s:%d via GSUP%s",
			sgsn->gsup_client->is_connected ? "" : "not ",
			link->addr, link->port,
			VTY_NEWLINE);
	}
	if (sgsn->gsn)
		vty_out(vty, "  GSN: signalling %s, user traffic %s%s",
			inet_ntoa(sgsn->gsn->gsnc), inet_ntoa(sgsn->gsn->gsnu), VTY_NEWLINE);

	/* FIXME: statistics */
	return CMD_SUCCESS;
}

#define MMCTX_STR "MM Context\n"
#define INCLUDE_PDP_STR "Include PDP Context Information\n"

#if 0
DEFUN(show_mmctx_tlli, show_mmctx_tlli_cmd,
	"show mm-context tlli HEX [pdp]",
	SHOW_STR MMCTX_STR "Identify by TLLI\n" "TLLI\n" INCLUDE_PDP_STR)
{
	uint32_t tlli;
	struct sgsn_mm_ctx *mm;

	tlli = strtoul(argv[0], NULL, 16);
	mm = sgsn_mm_ctx_by_tlli(tlli);
	if (!mm) {
		vty_out(vty, "No MM context for TLLI %08x%s",
			tlli, VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty_dump_mmctx(vty, "", mm, argv[1] ? 1 : 0);
	return CMD_SUCCESS;
}
#endif

DEFUN(swow_mmctx_imsi, show_mmctx_imsi_cmd,
	"show mm-context imsi IMSI [pdp]",
	SHOW_STR MMCTX_STR "Identify by IMSI\n" "IMSI of the MM Context\n"
	INCLUDE_PDP_STR)
{
	struct sgsn_mm_ctx *mm;

	mm = sgsn_mm_ctx_by_imsi(argv[0]);
	if (!mm) {
		vty_out(vty, "No MM context for IMSI %s%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty_dump_mmctx(vty, "", mm, argv[1] ? 1 : 0);
	return CMD_SUCCESS;
}

DEFUN(swow_mmctx_all, show_mmctx_all_cmd,
	"show mm-context all [pdp]",
	SHOW_STR MMCTX_STR "All MM Contexts\n" INCLUDE_PDP_STR)
{
	struct sgsn_mm_ctx *mm;

	llist_for_each_entry(mm, &sgsn_mm_ctxts, list)
		vty_dump_mmctx(vty, "", mm, argv[0] ? 1 : 0);

	return CMD_SUCCESS;
}

DEFUN(show_pdpctx_all, show_pdpctx_all_cmd,
	"show pdp-context all",
	SHOW_STR "Display information on PDP Context\n" "Show everything\n")
{
	struct sgsn_pdp_ctx *pdp;

	llist_for_each_entry(pdp, &sgsn_pdp_ctxts, g_list)
		vty_dump_pdp(vty, "", pdp);

	return CMD_SUCCESS;
}


DEFUN(imsi_acl, cfg_imsi_acl_cmd,
	"imsi-acl (add|del) IMSI",
	"Access Control List of foreign IMSIs\n"
	"Add IMSI to ACL\n"
	"Remove IMSI from ACL\n"
	"IMSI of subscriber\n")
{
	char imsi_sanitized[GSM23003_IMSI_MAX_DIGITS + 1];
	const char *op = argv[0];
	const char *imsi = imsi_sanitized;
	size_t len = strnlen(argv[1], GSM23003_IMSI_MAX_DIGITS + 1);
	int rc;

	memset(imsi_sanitized, '0', GSM23003_IMSI_MAX_DIGITS);
	imsi_sanitized[GSM23003_IMSI_MAX_DIGITS] = '\0';

	/* Sanitize IMSI */
	if (len > GSM23003_IMSI_MAX_DIGITS) {
		vty_out(vty, "%% IMSI (%s) too long (max %u digits) -- ignored!%s",
			argv[1], GSM23003_IMSI_MAX_DIGITS, VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_strlcpy(imsi_sanitized + GSM23003_IMSI_MAX_DIGITS - len, argv[1],
		     sizeof(imsi_sanitized) - (GSM23003_IMSI_MAX_DIGITS - len));

	if (!strcmp(op, "add"))
		rc = sgsn_acl_add(imsi, g_cfg);
	else
		rc = sgsn_acl_del(imsi, g_cfg);

	if (rc < 0) {
		vty_out(vty, "%% unable to %s ACL%s", op, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_encrypt, cfg_encrypt_cmd,
      "encryption (GEA0|GEA1|GEA2|GEA3|GEA4)",
      "Set encryption algorithm for SGSN\n"
      "Use GEA0 (no encryption)\n"
      "Use GEA1\nUse GEA2\nUse GEA3\nUse GEA4\n")
{
	enum gprs_ciph_algo c = get_string_value(gprs_cipher_names, argv[0]);
	if (c != GPRS_ALGO_GEA0) {
		if (!gprs_cipher_supported(c)) {
			vty_out(vty, "%% cipher %s is unsupported in current version%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}

		if (!g_cfg->require_authentication) {
			vty_out(vty, "%% unable to use encryption %s without authentication: please adjust auth-policy%s",
				argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	g_cfg->cipher = c;

	return CMD_SUCCESS;
}

DEFUN(cfg_authentication, cfg_authentication_cmd,
      "authentication (optional|required)",
      "Whether to enforce MS authentication in GERAN (only with auth-policy remote)\n"
      "Allow MS to attach via GERAN without authentication (default and only possible value for non-remote auth-policy)\n"
      "Always require authentication (only available for auth-policy remote, default with that auth-policy)\n")
{
	int required = (argv[0][0] == 'r');

	if (vty->type != VTY_FILE) {
		if (g_cfg->auth_policy != SGSN_AUTH_POLICY_REMOTE && required) {
			vty_out(vty, "%% Authentication is not possible without HLR, "
				     "consider setting 'auth-policy' to 'remote'%s",
				     VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	g_cfg->require_authentication = required;
	return CMD_SUCCESS;
}

DEFUN(cfg_auth_policy, cfg_auth_policy_cmd,
	"auth-policy (accept-all|closed|acl-only|remote)",
	"Configure the Authorization policy of the SGSN. This setting determines which subscribers are"
	" permitted to register to the network.\n"
	"Accept all IMSIs (DANGEROUS)\n"
	"Accept only home network subscribers or those in the ACL\n"
	"Accept only subscribers in the ACL\n"
	"Use remote subscription data only (HLR)\n")
{
	int val = get_string_value(sgsn_auth_pol_strs, argv[0]);
	OSMO_ASSERT(val >= SGSN_AUTH_POLICY_OPEN && val <= SGSN_AUTH_POLICY_REMOTE);
	g_cfg->auth_policy = val;
	g_cfg->require_update_location = (val == SGSN_AUTH_POLICY_REMOTE);

	return CMD_SUCCESS;
}

/* Subscriber */
#include <osmocom/sgsn/gprs_subscriber.h>

static void subscr_dump_full_vty(struct vty *vty, struct gprs_subscr *gsub, int pending)
{
#if 0
	char expire_time[200];
#endif
	struct gsm_auth_tuple *at;
	int at_idx;
	struct sgsn_subscriber_pdp_data *pdp;

	vty_out(vty, "    Authorized: %d%s",
		gsub->authorized, VTY_NEWLINE);
	vty_out(vty, "    LAC: %d/0x%x%s",
		gsub->lac, gsub->lac, VTY_NEWLINE);
	vty_out(vty, "    IMSI: %s%s", gsub->imsi, VTY_NEWLINE);
	if (gsub->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: %08X%s", gsub->tmsi,
			VTY_NEWLINE);
	if (gsub->sgsn_data->msisdn_len > 0)
		vty_out(vty, "    MSISDN (BCD): %s%s",
			osmo_hexdump(gsub->sgsn_data->msisdn,
				     gsub->sgsn_data->msisdn_len),
			VTY_NEWLINE);

	if (strlen(gsub->imei) > 0)
		vty_out(vty, "    IMEI: %s%s", gsub->imei, VTY_NEWLINE);

	for (at_idx = 0; at_idx < ARRAY_SIZE(gsub->sgsn_data->auth_triplets);
	     at_idx++) {
		at = &gsub->sgsn_data->auth_triplets[at_idx];
		if (at->key_seq == GSM_KEY_SEQ_INVAL)
			continue;

		vty_out(vty, "    A3A8 tuple (used %d times): ",
			at->use_count);
		vty_out(vty, "     CKSN: %d, ",
			at->key_seq);
		if (at->vec.auth_types & OSMO_AUTH_TYPE_GSM) {
			vty_out(vty, "RAND: %s, ",
				osmo_hexdump_nospc(at->vec.rand,
					     sizeof(at->vec.rand)));
			vty_out(vty, "SRES: %s, ",
				osmo_hexdump_nospc(at->vec.sres,
					     sizeof(at->vec.sres)));
			vty_out(vty, "Kc: %s%s",
				osmo_hexdump_nospc(at->vec.kc,
					     sizeof(at->vec.kc)), VTY_NEWLINE);
		}
		if (at->vec.auth_types & OSMO_AUTH_TYPE_UMTS) {
			vty_out(vty, "     AUTN: %s, ",
				osmo_hexdump(at->vec.autn,
					     sizeof(at->vec.autn)));
			vty_out(vty, "RES: %s, ",
				osmo_hexdump_nospc(at->vec.res, at->vec.res_len));
			vty_out(vty, "IK: %s, ",
				osmo_hexdump_nospc(at->vec.ik, sizeof(at->vec.ik)));
			vty_out(vty, "CK: %s, ",
				osmo_hexdump_nospc(at->vec.ck, sizeof(at->vec.ck)));
		}
	}

	llist_for_each_entry(pdp, &gsub->sgsn_data->pdp_list, list) {
		vty_out(vty, "    PDP info: Id: %d, Type: 0x%04x, APN: '%s'",
			pdp->context_id, pdp->pdp_type, pdp->apn_str);

		if (pdp->qos_subscribed_len)
			vty_out(vty, " QoS: %s", osmo_hexdump(pdp->qos_subscribed, pdp->qos_subscribed_len));

		vty_out(vty, "%s", VTY_NEWLINE);
	}

#if 0
	/* print the expiration time of a subscriber */
	if (gsub->expire_lu) {
		strftime(expire_time, sizeof(expire_time),
			 "%a, %d %b %Y %T %z", localtime(&gsub->expire_lu));
		expire_time[sizeof(expire_time) - 1] = '\0';
		vty_out(vty, "    Expiration Time: %s%s", expire_time, VTY_NEWLINE);
	}
#endif

	if (gsub->flags)
		vty_out(vty, "    Flags: %s%s%s%s%s%s",
			gsub->flags & GPRS_SUBSCRIBER_FIRST_CONTACT ?
			"FIRST_CONTACT " : "",
			gsub->flags & GPRS_SUBSCRIBER_CANCELLED ?
			"CANCELLED " : "",
			gsub->flags & GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING ?
			"UPDATE_LOCATION_PENDING " : "",
			gsub->flags & GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING ?
			"AUTH_INFO_PENDING " : "",
			gsub->flags & GPRS_SUBSCRIBER_ENABLE_PURGE ?
			"ENABLE_PURGE " : "",
			VTY_NEWLINE);

	vty_out(vty, "    Use count: %u%s", gsub->use_count, VTY_NEWLINE);
}

#define RESET_SGSN_STATE_STR \
      "Remove all known subscribers, MM contexts and flush BSSGP queues." \
      " Useful only when running tests against the SGSN\n"

DEFUN_HIDDEN(reset_sgsn_state,
      reset_sgsn_state_cmd,
      "reset sgsn state",
      RESET_SGSN_STATE_STR RESET_SGSN_STATE_STR RESET_SGSN_STATE_STR)
{
	struct gprs_subscr *subscr, *tmp_subscr;
	struct sgsn_mm_ctx *mm, *tmp_mm;

	llist_for_each_entry_safe(mm, tmp_mm, &sgsn_mm_ctxts, list)
	{
		gsm0408_gprs_access_cancelled(mm, SGSN_ERROR_CAUSE_NONE);
	}
	vty_out(vty, "Cancelled MM Ctx. %s", VTY_NEWLINE);

	llist_for_each_entry_safe(subscr, tmp_subscr, gprs_subscribers, entry) {
		gprs_subscr_get(subscr);
		gprs_subscr_cancel(subscr);
		gprs_subscr_put(subscr);
	}
	vty_out(vty, "Removed all gprs subscribers.%s", VTY_NEWLINE);

	bssgp_flush_all_queues();
	vty_out(vty, "Flushed all BSSGPs queues.%s", VTY_NEWLINE);

	gtp_clear_queues(sgsn->gsn);
	vty_out(vty, "Flushed rx & tx queus towards the GGSN.%s", VTY_NEWLINE);

	/* remove all queues to bssgp */
	return CMD_SUCCESS;
}

DEFUN(show_subscr_cache,
      show_subscr_cache_cmd,
      "show subscriber cache",
	SHOW_STR "Show information about subscribers\n"
	"Display contents of subscriber cache\n")
{
	struct gprs_subscr *subscr;

	llist_for_each_entry(subscr, gprs_subscribers, entry) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_full_vty(vty, subscr, 0);
	}

	return CMD_SUCCESS;
}

#define UPDATE_SUBSCR_STR "update-subscriber imsi IMSI "
#define UPDATE_SUBSCR_HELP "Update subscriber list\n" \
	"Use the IMSI to select the subscriber\n" \
	"The IMSI\n"

#define UPDATE_SUBSCR_INSERT_HELP "Insert data into the subscriber record\n"

DEFUN(update_subscr_insert_auth_triplet, update_subscr_insert_auth_triplet_cmd,
	UPDATE_SUBSCR_STR "insert auth-triplet <1-5> sres SRES rand RAND kc KC",
	UPDATE_SUBSCR_HELP
	UPDATE_SUBSCR_INSERT_HELP
	"Update authentication triplet\n"
	"Triplet index\n"
	"Set SRES value\nSRES value (4 byte) in hex\n"
	"Set RAND value\nRAND value (16 byte) in hex\n"
	"Set Kc value\nKc value (8 byte) in hex\n")
{
	const char *imsi = argv[0];
	const int cksn = atoi(argv[1]) - 1;
	const char *sres_str = argv[2];
	const char *rand_str = argv[3];
	const char *kc_str = argv[4];
	struct gsm_auth_tuple at = {0,};

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% unable get subscriber record for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	OSMO_ASSERT(subscr->sgsn_data);

	if (osmo_hexparse(sres_str, &at.vec.sres[0], sizeof(at.vec.sres)) < 0) {
		vty_out(vty, "%% invalid SRES value '%s'%s",
			sres_str, VTY_NEWLINE);
		goto failed;
	}
	if (osmo_hexparse(rand_str, &at.vec.rand[0], sizeof(at.vec.rand)) < 0) {
		vty_out(vty, "%% invalid RAND value '%s'%s",
			rand_str, VTY_NEWLINE);
		goto failed;
	}
	if (osmo_hexparse(kc_str, &at.vec.kc[0], sizeof(at.vec.kc)) < 0) {
		vty_out(vty, "%% invalid Kc value '%s'%s",
			kc_str, VTY_NEWLINE);
		goto failed;
	}
	at.key_seq = cksn;

	subscr->sgsn_data->auth_triplets[cksn] = at;
	subscr->sgsn_data->auth_triplets_updated = 1;

	gprs_subscr_put(subscr);

	return CMD_SUCCESS;

failed:
	gprs_subscr_put(subscr);
	return CMD_SUCCESS;
}

DEFUN(update_subscr_cancel, update_subscr_cancel_cmd,
	UPDATE_SUBSCR_STR "cancel (update-procedure|subscription-withdraw)",
	UPDATE_SUBSCR_HELP
	"Cancel (remove) subscriber record\n"
	"The MS moved to another SGSN\n"
	"The subscription is no longer valid\n")
{
	const char *imsi = argv[0];
	const char *cancel_type = argv[1];

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% no subscriber record for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strcmp(cancel_type, "update-procedure") == 0)
		subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	else
		subscr->sgsn_data->error_cause = GMM_CAUSE_IMPL_DETACHED;

	gprs_subscr_cancel(subscr);
	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(update_subscr_create, update_subscr_create_cmd,
	UPDATE_SUBSCR_STR "create",
	UPDATE_SUBSCR_HELP
	"Create a subscriber entry\n")
{
	const char *imsi = argv[0];

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (subscr) {
		vty_out(vty, "%% subscriber record already exists for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr = gprs_subscr_get_or_create(imsi);
	if (!subscr) {
		vty_out(vty, "Can not create subscriber. Out of memory.%s", imsi);
		return CMD_WARNING;
	}
	subscr->keep_in_ram = 1;
	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(update_subscr_destroy, update_subscr_destroy_cmd,
	UPDATE_SUBSCR_STR "destroy",
	UPDATE_SUBSCR_HELP
	"Destroy a subscriber entry\n")
{
	const char *imsi = argv[0];

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% subscriber record does not exist for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr->keep_in_ram = 0;
	subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	gprs_subscr_cancel(subscr);
	if (subscr->use_count > 1)
		vty_out(vty, "%% subscriber is still in use%s",
			VTY_NEWLINE);
	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

#define UL_ERR_STR "system-failure|data-missing|unexpected-data-value|" \
		   "unknown-subscriber|roaming-not-allowed"

#define UL_ERR_HELP \
		"Force error code SystemFailure\n" \
		"Force error code DataMissing\n" \
		"Force error code UnexpectedDataValue\n" \
		"Force error code UnknownSubscriber\n" \
		"Force error code RoamingNotAllowed\n"

DEFUN(update_subscr_update_location_result, update_subscr_update_location_result_cmd,
	UPDATE_SUBSCR_STR "update-location-result (ok|" UL_ERR_STR ")",
	UPDATE_SUBSCR_HELP
	"Complete the update location procedure\n"
	"The update location request succeeded\n"
	UL_ERR_HELP)
{
	const char *imsi = argv[0];
	const char *ret_code_str = argv[1];

	struct gprs_subscr *subscr;

	const struct value_string cause_mapping[] = {
		{ GMM_CAUSE_NET_FAIL,		"system-failure" },
		{ GMM_CAUSE_INV_MAND_INFO,	"data-missing" },
		{ GMM_CAUSE_PROTO_ERR_UNSPEC,   "unexpected-data-value" },
		{ GMM_CAUSE_IMSI_UNKNOWN,       "unknown-subscriber" },
		{ GMM_CAUSE_GPRS_NOTALLOWED,    "roaming-not-allowed" },
		{ 0, NULL }
	};

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% unable to get subscriber record for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strcmp(ret_code_str, "ok") == 0) {
		subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
		subscr->authorized = 1;
	} else {
		subscr->sgsn_data->error_cause =
			get_string_value(cause_mapping, ret_code_str);
		subscr->authorized = 0;
	}

	gprs_subscr_update(subscr);

	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(update_subscr_update_auth_info, update_subscr_update_auth_info_cmd,
	UPDATE_SUBSCR_STR "update-auth-info",
	UPDATE_SUBSCR_HELP
	"Complete the send authentication info procedure\n")
{
	const char *imsi = argv[0];

	struct gprs_subscr *subscr;

	subscr = gprs_subscr_get_by_imsi(imsi);
	if (!subscr) {
		vty_out(vty, "%% unable to get subscriber record for %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	gprs_subscr_update_auth_info(subscr);

	gprs_subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_ipa_name,
	cfg_gsup_ipa_name_cmd,
	"gsup ipa-name NAME",
	"GSUP Parameters\n"
	"Set the IPA name of this SGSN\n"
	"A unique name for this SGSN. For example: PLMN + redundancy server number: SGSN-901-70-0. "
	"This name is used for GSUP routing and must be set if more than one SGSN is connected to the network. "
	"The default is 'SGSN-00-00-00-00-00-00'.\n")
{
	if (vty->type != VTY_FILE) {
		vty_out(vty, "The IPA name cannot be changed at run-time; "
			"It can only be set in the configuraton file.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_cfg->sgsn_ipa_name = talloc_strdup(tall_vty_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_remote_ip, cfg_gsup_remote_ip_cmd,
	"gsup remote-ip A.B.C.D",
	"GSUP Parameters\n"
	"Set the IP address of the remote GSUP server (e.g. OsmoHLR)."
	" This setting only applies if 'auth-policy remote' is used.\n"
	"IPv4 Address\n")
{
	inet_aton(argv[0], &g_cfg->gsup_server_addr.sin_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_remote_port, cfg_gsup_remote_port_cmd,
	"gsup remote-port <0-65535>",
	"GSUP Parameters\n"
	"Set the TCP port of the remote GSUP server, see also 'gsup remote-ip'\n"
	"Remote TCP port\n")
{
	g_cfg->gsup_server_port = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_oap_id, cfg_gsup_oap_id_cmd,
	"gsup oap-id <0-65535>",
	"GSUP Parameters\n"
	"Set the OAP client ID for authentication on the GSUP protocol."
	" This setting only applies if 'auth-policy remote' is used.\n"
	"OAP client ID (0 == disabled)\n")
{
	/* VTY ensures range */
	g_cfg->oap.client_id = (uint16_t)atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_oap_k, cfg_gsup_oap_k_cmd,
	"gsup oap-k K",
	"GSUP Parameters\n"
	"Set the OAP shared secret key K for authentication on the GSUP protocol."
	" This setting only applies if auth-policy remote is used.\n"
	"K value (16 byte) hex\n")
{
	const char *k = argv[0];

	g_cfg->oap.secret_k_present = 0;

	if ((!k) || (strlen(k) == 0))
		goto disable;

	int k_len = osmo_hexparse(k,
				  g_cfg->oap.secret_k,
				  sizeof(g_cfg->oap.secret_k));
	if (k_len != 16) {
		vty_out(vty, "%% need exactly 16 octets for oap-k, got %d.%s",
			k_len, VTY_NEWLINE);
		goto disable;
	}

	g_cfg->oap.secret_k_present = 1;
	return CMD_SUCCESS;

disable:
	if (g_cfg->oap.client_id > 0) {
		vty_out(vty, "%% OAP client ID set, but invalid oap-k value disables OAP.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_gsup_oap_opc, cfg_gsup_oap_opc_cmd,
	"gsup oap-opc OPC",
	"GSUP Parameters\n"
	"Set the OAP shared secret OPC for authentication on the GSUP protocol."
	" This setting only applies if auth-policy remote is used.\n"
	"OPC value (16 byte) hex\n")
{
	const char *opc = argv[0];

	g_cfg->oap.secret_opc_present = 0;

	if ((!opc) || (strlen(opc) == 0))
		goto disable;

	int opc_len = osmo_hexparse(opc,
				    g_cfg->oap.secret_opc,
				    sizeof(g_cfg->oap.secret_opc));
	if (opc_len != 16) {
		vty_out(vty, "%% need exactly 16 octets for oap-opc, got %d.%s",
			opc_len, VTY_NEWLINE);
		goto disable;
	}

	g_cfg->oap.secret_opc_present = 1;
	return CMD_SUCCESS;

disable:
	if (g_cfg->oap.client_id > 0) {
		vty_out(vty, "%% OAP client ID set, but invalid oap-opc value disables OAP.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_apn_name, cfg_apn_name_cmd,
	"access-point-name NAME",
	"Globally allow the given APN name for all subscribers.\n"
	"Add this NAME to the list\n")
{
	return add_apn_ggsn_mapping(vty, argv[0], "", 0);
}

DEFUN(cfg_no_apn_name, cfg_no_apn_name_cmd,
	"no access-point-name NAME",
	NO_STR "Configure a global list of allowed APNs\n"
	"Remove entry with NAME\n")
{
	struct apn_ctx *apn_ctx = sgsn_apn_ctx_by_name(argv[0], "");
	if (!apn_ctx)
		return CMD_SUCCESS;

	sgsn_apn_ctx_free(apn_ctx);
	return CMD_SUCCESS;
}

DEFUN(cfg_cdr_filename, cfg_cdr_filename_cmd,
	"cdr filename NAME",
	"CDR\n"
	"Set the file name for the call-data-record file, logging the data usage of each subscriber.\n"
	"filename\n")
{
	talloc_free(g_cfg->cdr.filename);
	g_cfg->cdr.filename = talloc_strdup(tall_vty_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_no_cdr_filename, cfg_no_cdr_filename_cmd,
	"no cdr filename",
	NO_STR "CDR\nDisable saving CDR to file\n")
{
	talloc_free(g_cfg->cdr.filename);
	g_cfg->cdr.filename = NULL;
	return CMD_SUCCESS;
}

DEFUN(cfg_cdr_trap, cfg_cdr_trap_cmd,
	"cdr trap",
	"CDR\nEnable sending CDR via TRAP CTRL messages\n")
{
	g_cfg->cdr.trap = true;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_cdr_trap, cfg_no_cdr_trap_cmd,
	"no cdr trap",
	NO_STR "CDR\nDisable sending CDR via TRAP CTRL messages\n")
{
	g_cfg->cdr.trap = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_cdr_interval, cfg_cdr_interval_cmd,
	"cdr interval <1-2147483647>",
	"CDR\n"
	"Set the interval for the call-data-record file\n"
	"interval in seconds\n")
{
	g_cfg->cdr.interval = atoi(argv[0]);
	return CMD_SUCCESS;
}

#define COMPRESSION_STR "Configure compression\n"
DEFUN(cfg_no_comp_rfc1144, cfg_no_comp_rfc1144_cmd,
      "no compression rfc1144",
      NO_STR COMPRESSION_STR "disable rfc1144 TCP/IP header compression\n")
{
	g_cfg->pcomp_rfc1144.active = 0;
	g_cfg->pcomp_rfc1144.passive = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_comp_rfc1144, cfg_comp_rfc1144_cmd,
      "compression rfc1144 active slots <1-256>",
      COMPRESSION_STR
      "RFC1144 Header compression scheme\n"
      "Compression is actively proposed\n"
      "Number of compression state slots\n"
      "Number of compression state slots\n")
{
	g_cfg->pcomp_rfc1144.active = 1;
	g_cfg->pcomp_rfc1144.passive = 1;
	g_cfg->pcomp_rfc1144.s01 = atoi(argv[0]) - 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_comp_rfc1144p, cfg_comp_rfc1144p_cmd,
      "compression rfc1144 passive",
      COMPRESSION_STR
      "RFC1144 Header compression scheme\n"
      "Compression is available on request\n")
{
	g_cfg->pcomp_rfc1144.active = 0;
	g_cfg->pcomp_rfc1144.passive = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_comp_v42bis, cfg_no_comp_v42bis_cmd,
      "no compression v42bis",
      NO_STR COMPRESSION_STR "disable V.42bis data compression\n")
{
	g_cfg->dcomp_v42bis.active = 0;
	g_cfg->dcomp_v42bis.passive = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_comp_v42bis, cfg_comp_v42bis_cmd,
      "compression v42bis active direction (ms|sgsn|both) codewords <512-65535> strlen <6-250>",
      COMPRESSION_STR
      "V.42bis data compression scheme\n"
      "Compression is actively proposed\n"
      "Direction in which the compression shall be active (p0)\n"
      "Compress ms->sgsn direction only\n"
      "Compress sgsn->ms direction only\n"
      "Both directions\n"
      "Number of codewords (p1)\n"
      "Number of codewords\n"
      "Maximum string length (p2)\n" "Maximum string length\n")
{
	g_cfg->dcomp_v42bis.active = 1;
	g_cfg->dcomp_v42bis.passive = 1;

	switch (argv[0][0]) {
	case 'm':
		g_cfg->dcomp_v42bis.p0 = 1;
		break;
	case 's':
		g_cfg->dcomp_v42bis.p0 = 2;
		break;
	case 'b':
		g_cfg->dcomp_v42bis.p0 = 3;
		break;
	}

	g_cfg->dcomp_v42bis.p1 = atoi(argv[1]);
	g_cfg->dcomp_v42bis.p2 = atoi(argv[2]);
	return CMD_SUCCESS;
}

DEFUN(cfg_comp_v42bisp, cfg_comp_v42bisp_cmd,
      "compression v42bis passive",
      COMPRESSION_STR
      "V.42bis data compression scheme\n"
      "Compression is available on request\n")
{
	g_cfg->dcomp_v42bis.active = 0;
	g_cfg->dcomp_v42bis.passive = 1;
	return CMD_SUCCESS;
}

#if BUILD_IU
DEFUN(cfg_sgsn_cs7_instance_iu,
      cfg_sgsn_cs7_instance_iu_cmd,
      "cs7-instance-iu <0-15>",
      "Set SS7 to be used by the Iu-Interface.\n" "SS7 instance reference number (default: 0)\n")
{
	g_cfg->iu.cs7_instance = atoi(argv[0]);
	return CMD_SUCCESS;
}
#endif

int sgsn_vty_init(struct sgsn_config *cfg)
{
	g_cfg = cfg;

	g_cfg->T_defs = sgsn_T_defs;
	osmo_tdefs_reset(g_cfg->T_defs);

	install_element_ve(&show_sgsn_cmd);
	//install_element_ve(&show_mmctx_tlli_cmd);
	install_element_ve(&show_mmctx_imsi_cmd);
	install_element_ve(&show_mmctx_all_cmd);
	install_element_ve(&show_pdpctx_all_cmd);
	install_element_ve(&show_subscr_cache_cmd);
	install_element_ve(&show_timer_cmd);

	install_element(ENABLE_NODE, &update_subscr_insert_auth_triplet_cmd);
	install_element(ENABLE_NODE, &update_subscr_create_cmd);
	install_element(ENABLE_NODE, &update_subscr_destroy_cmd);
	install_element(ENABLE_NODE, &update_subscr_cancel_cmd);
	install_element(ENABLE_NODE, &update_subscr_update_location_result_cmd);
	install_element(ENABLE_NODE, &update_subscr_update_auth_info_cmd);
	install_element(ENABLE_NODE, &reset_sgsn_state_cmd);

	install_element(CONFIG_NODE, &cfg_sgsn_cmd);
	install_node(&sgsn_node, config_write_sgsn);
	install_element(SGSN_NODE, &cfg_sgsn_state_dir_cmd);
	install_element(SGSN_NODE, &cfg_sgsn_bind_addr_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_remote_ip_cmd);
	//install_element(SGSN_NODE, &cfg_ggsn_remote_port_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_gtp_version_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_echo_interval_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_no_echo_interval_cmd);
	install_element(SGSN_NODE, &cfg_imsi_acl_cmd);
	install_element(SGSN_NODE, &cfg_auth_policy_cmd);
	install_element(SGSN_NODE, &cfg_authentication_cmd);
	install_element(SGSN_NODE, &cfg_encrypt_cmd);
	install_element(SGSN_NODE, &cfg_gsup_ipa_name_cmd);
	install_element(SGSN_NODE, &cfg_gsup_remote_ip_cmd);
	install_element(SGSN_NODE, &cfg_gsup_remote_port_cmd);
	install_element(SGSN_NODE, &cfg_gsup_oap_id_cmd);
	install_element(SGSN_NODE, &cfg_gsup_oap_k_cmd);
	install_element(SGSN_NODE, &cfg_gsup_oap_opc_cmd);
	install_element(SGSN_NODE, &cfg_apn_ggsn_cmd);
	install_element(SGSN_NODE, &cfg_apn_imsi_ggsn_cmd);
	install_element(SGSN_NODE, &cfg_apn_name_cmd);
	install_element(SGSN_NODE, &cfg_no_apn_name_cmd);
	install_element(SGSN_NODE, &cfg_cdr_filename_cmd);
	install_element(SGSN_NODE, &cfg_no_cdr_filename_cmd);
	install_element(SGSN_NODE, &cfg_cdr_trap_cmd);
	install_element(SGSN_NODE, &cfg_no_cdr_trap_cmd);
	install_element(SGSN_NODE, &cfg_cdr_interval_cmd);
	install_element(SGSN_NODE, &cfg_ggsn_dynamic_lookup_cmd);
	install_element(SGSN_NODE, &cfg_grx_ggsn_cmd);

	install_element(SGSN_NODE, &cfg_sgsn_timer_cmd);

	install_element(SGSN_NODE, &cfg_no_comp_rfc1144_cmd);
	install_element(SGSN_NODE, &cfg_comp_rfc1144_cmd);
	install_element(SGSN_NODE, &cfg_comp_rfc1144p_cmd);
	install_element(SGSN_NODE, &cfg_no_comp_v42bis_cmd);
	install_element(SGSN_NODE, &cfg_comp_v42bis_cmd);
	install_element(SGSN_NODE, &cfg_comp_v42bisp_cmd);

#ifdef BUILD_IU
	install_element(SGSN_NODE, &cfg_sgsn_cs7_instance_iu_cmd);
	ranap_iu_vty_init(SGSN_NODE, &g_cfg->iu.rab_assign_addr_enc);
#endif
	return 0;
}

int sgsn_parse_config(const char *config_file)
{
	int rc;

	/* make sure sgsn_vty_init() was called before this */
	OSMO_ASSERT(g_cfg);

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	if (g_cfg->auth_policy == SGSN_AUTH_POLICY_REMOTE
	    && !(g_cfg->gsup_server_addr.sin_addr.s_addr
		 && g_cfg->gsup_server_port)) {
		fprintf(stderr, "Configuration error:"
			" 'auth-policy remote' requires both"
			" 'gsup remote-ip' and 'gsup remote-port'\n");
		return -EINVAL;
	}

	return 0;
}
