#ifndef _SGSN_H
#define _SGSN_H


#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/sgsn/auth.h>
#include <osmocom/sgsn/gtp_mme.h>
#include <osmocom/gsm/oap_client.h>
#include <osmocom/gsupclient/gsup_client.h>
#include <osmocom/sgsn/common.h>

#include "../../config.h"

#if BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

#include <ares.h>
#include <gtp.h>

struct hostent;

#define SGSN_ERROR_CAUSE_NONE (-1)

enum sgsn_auth_policy {
	SGSN_AUTH_POLICY_OPEN,
	SGSN_AUTH_POLICY_CLOSED,
	SGSN_AUTH_POLICY_ACL_ONLY,
	SGSN_AUTH_POLICY_REMOTE
};


enum sgsn_rate_ctr_keys {
	CTR_LLC_DL_BYTES,
	CTR_LLC_UL_BYTES,
	CTR_LLC_DL_PACKETS,
	CTR_LLC_UL_PACKETS,
	CTR_GPRS_ATTACH_REQUEST,
	CTR_GPRS_ATTACH_ACKED,
	CTR_GPRS_ATTACH_REJECTED,
	CTR_GPRS_DETACH_REQUEST,
	CTR_GPRS_DETACH_ACKED,
	CTR_GPRS_ROUTING_AREA_REQUEST,
	CTR_GPRS_ROUTING_AREA_ACKED,
	CTR_GPRS_ROUTING_AREA_REJECT,
	/* PDP single packet counter / GSM 04.08 9.5.1 - 9.5.9 */
	CTR_PDP_ACTIVATE_REQUEST,
	CTR_PDP_ACTIVATE_REJECT,
	CTR_PDP_ACTIVATE_ACCEPT,
	CTR_PDP_REQUEST_ACTIVATE, /* unused */
	CTR_PDP_REQUEST_ACTIVATE_REJ, /* unused */
	CTR_PDP_MODIFY_REQUEST, /* unsued */
	CTR_PDP_MODIFY_ACCEPT, /* unused */
	CTR_PDP_DL_DEACTIVATE_REQUEST,
	CTR_PDP_DL_DEACTIVATE_ACCEPT,
	CTR_PDP_UL_DEACTIVATE_REQUEST,
	CTR_PDP_UL_DEACTIVATE_ACCEPT,
};

struct sgsn_cdr {
	char *filename;
	bool trap;
	int interval;
};

struct sgsn_config {
	/* parsed from config file */

	char *gtp_statedir;
	struct sockaddr_in gtp_listenaddr;

	/* misc */
	struct gprs_ns2_inst *nsi;

	char *crypt_cipher_plugin_path;
	enum sgsn_auth_policy auth_policy;
	uint8_t gea_encryption_mask;
	uint8_t uea_encryption_mask;
	struct llist_head imsi_acl;

	struct sockaddr_in gsup_server_addr;
	int gsup_server_port;

	/* Only meaningful if auth_policy is SGSN_AUTH_POLICY_REMOTE */
	int require_authentication;

	int require_update_location;

	/* CDR configuration */
	struct sgsn_cdr cdr;

	/* Timer defintions */
	struct osmo_tdef *T_defs;
	struct osmo_tdef *T_defs_gtp;

	int dynamic_lookup;

	struct osmo_oap_client_config oap;

	/* RFC1144 TCP/IP header compression */
	struct {
		int active;
		int passive;
		int s01;
	} pcomp_rfc1144;

	/* V.42vis data compression */
	struct {
		int active;
		int passive;
		int p0;
		int p1;
		int p2;
	} dcomp_v42bis;

#if BUILD_IU
	struct {
		enum ranap_nsap_addr_enc rab_assign_addr_enc;
		uint32_t cs7_instance;
	} iu;
#endif

	/* This is transmitted as IPA Serial Number tag, which is used for GSUP routing (e.g. in OsmoHLR).
	 * This name must be set in a multi-SGSN network, and it must be unique to each SGSN.
	 * If no name is set, the IPA Serial Number will be the same as the Unit Name,
	 * and will be of the form 'SGSN-00-00-00-00-00-00' */
	char *sgsn_ipa_name;
};

struct sgsn_instance {
	char *config_file;
	struct sgsn_config cfg;
	/* File descriptor wrappers for LibGTP */
	struct osmo_fd gtp_fd0;
	struct osmo_fd gtp_fd1c;
	struct osmo_fd gtp_fd1u;
	/* GSN instance for libgtp */
	struct gsn_t *gsn;
	/* Subscriber */
	struct osmo_gsup_client *gsup_client;
	/* LLME inactivity timer */
	struct osmo_timer_list llme_timer;

	/* c-ares event loop integration */
	struct osmo_timer_list ares_timer;
	struct llist_head ares_fds;
	ares_channel ares_channel;
	struct ares_addr_node *ares_servers;

	struct rate_ctr_group *rate_ctrs;

	struct llist_head apn_list; /* list of struct sgsn_apn_ctx */
	struct llist_head ggsn_list; /* list of struct sgsn_ggsn_ctx */
	struct llist_head mme_list; /* list of struct sgsn_mme_ctx */
	struct llist_head mm_list; /* list of struct sgsn_mm_ctx */
	struct llist_head pdp_list; /* list of struct sgsn_pdp_ctx */

	struct ctrl_handle *ctrlh;
};

extern struct sgsn_instance *sgsn;
extern void *tall_sgsn_ctx;

/*
 * ctrl interface related work (sgsn_ctrl.c)
 */
int sgsn_ctrl_cmds_install(void);

/* sgsn_vty.c */

int sgsn_vty_init(struct sgsn_config *cfg);
int sgsn_parse_config(const char *config_file);
char *sgsn_gtp_ntoa(struct ul16_t *ul);

/* sgsn.c */
struct sgsn_instance *sgsn_instance_alloc(void *talloc_ctx);
int sgsn_inst_init(struct sgsn_instance *sgsn);
/*
 * CDR related functionality
 */
int sgsn_cdr_init(struct sgsn_instance *sgsn);
void sgsn_cdr_release(struct sgsn_instance *sgsn);


/*
 * C-ARES related functionality
 */
int sgsn_ares_init(struct sgsn_instance *sgsn);
int sgsn_ares_query(struct sgsn_instance *sgsm, const char *name, ares_host_callback cb, void *data);

#endif
