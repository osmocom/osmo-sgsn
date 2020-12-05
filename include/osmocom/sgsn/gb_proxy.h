#ifndef _GB_PROXY_H
#define _GB_PROXY_H


#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/hashtable.h>
#include <osmocom/gsm/gsm23003.h>

#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/vty/command.h>

#include <sys/types.h>
#include <regex.h>
#include <stdbool.h>

#define GBPROXY_INIT_VU_GEN_TX 256

/* BVCI uses 16 bits */
#define BVC_LOG_CTX_FLAG (1<<17)

struct rate_ctr_group;
struct gprs_gb_parse_context;
struct tlv_parsed;

enum gbproxy_global_ctr {
	GBPROX_GLOB_CTR_INV_BVCI,
	GBPROX_GLOB_CTR_INV_LAI,
	GBPROX_GLOB_CTR_INV_RAI,
	GBPROX_GLOB_CTR_INV_NSEI,
	GBPROX_GLOB_CTR_PROTO_ERR_BSS,
	GBPROX_GLOB_CTR_PROTO_ERR_SGSN,
	GBPROX_GLOB_CTR_NOT_SUPPORTED_BSS,
	GBPROX_GLOB_CTR_NOT_SUPPORTED_SGSN,
	GBPROX_GLOB_CTR_RESTART_RESET_SGSN,
	GBPROX_GLOB_CTR_TX_ERR_SGSN,
	GBPROX_GLOB_CTR_OTHER_ERR,
};

enum gbproxy_bvc_ctr {
	GBPROX_PEER_CTR_BLOCKED,
	GBPROX_PEER_CTR_UNBLOCKED,
	GBPROX_PEER_CTR_DROPPED,
	GBPROX_PEER_CTR_INV_NSEI,
	GBPROX_PEER_CTR_TX_ERR,
	GBPROX_PEER_CTR_LAST,
};

/* global gb-proxy configuration */
struct gbproxy_config {
	/* NS instance of libosmogb */
	struct gprs_ns2_inst *nsi;

	/* Linked list of all BSS side Gb peers */
	DECLARE_HASHTABLE(bss_nses, 8);

	/* hash table of all SGSN-side Gb peers */
	DECLARE_HASHTABLE(sgsn_nses, 8);

	/* hash table of all gbproxy_cell */
	DECLARE_HASHTABLE(cells, 8);

	/* Counter */
	struct rate_ctr_group *ctrg;
};

/* One Cell within the BSS: Links BSS-side BVC to SGSN-side BVCs */
struct gbproxy_cell {
	/* linked to gbproxy_config.cells hashtable */
	struct hlist_node list;

	/* point back to the config */
	struct gbproxy_config *cfg;

	/*  BVCI of PTP BVCs associated to this cell */
	uint16_t bvci;

	/* Routing Area that this BVC is part of (raw 04.08 encoding) */
	uint8_t ra[6];

	/* pointer to the BSS-side BVC */
	struct gbproxy_bvc *bss_bvc;

	/* pointers to SGSN-side BVC (one for each pool member) */
	struct gbproxy_bvc *sgsn_bvc[16];
};

/* One BVC inside an NSE */
struct gbproxy_bvc {
	/* linked to gbproxy_nse.bvcs */
	struct hlist_node list;

	/* The NSE this BVC belongs to */
	struct gbproxy_nse *nse;

	/* PTP BVCI of this BVC */
	uint16_t bvci;

	/* Routing Area that this BVC is part of (raw 04.08 encoding) */
	uint8_t ra[6];

	/* Counter */
	struct rate_ctr_group *ctrg;

	/* the cell to which this BVC belongs */
	struct gbproxy_cell *cell;

	/* per-BVC FSM instance */
	struct osmo_fsm_inst *fi;
};

/* one NS Entity that we interact with (BSS/PCU) */
struct gbproxy_nse {
	/* linked to gbproxy_config.bss_nses */
	struct hlist_node list;

	/* point back to the config */
	struct gbproxy_config *cfg;

	/* NSEI of the NSE */
	uint16_t nsei;

	/* Are we facing towards a SGSN (true) or BSS (false) */
	bool sgsn_facing;

	/* List of all BVCs in this NSE */
	DECLARE_HASHTABLE(bvcs, 10);
};

/* Convenience logging macros for NSE/BVC */
#define LOGPNSE_CAT(NSE, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "NSE(%05u/%s) " FMT, (NSE)->nsei, \
		(NSE)->sgsn_facing ? "SGSN" : "BSS", ## ARGS)
#define LOGPNSE(NSE, LEVEL, FMT, ARGS...) \
	LOGPNSE_CAT(NSE, DGPRS, LEVEL, FMT, ## ARGS)

#define LOGPBVC_CAT(BVC, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "NSE(%05u/%s)-BVC(%05u/%s) " FMT, (BVC)->nse->nsei, \
		(BVC)->nse->sgsn_facing ? "SGSN" : "BSS", (BVC)->bvci, \
		osmo_fsm_inst_state_name((BVC)->fi), ## ARGS)
#define LOGPBVC(BVC, LEVEL, FMT, ARGS...) \
	LOGPBVC_CAT(BVC, DGPRS, LEVEL, FMT, ## ARGS)

/* gb_proxy_vty .c */

int gbproxy_vty_init(void);
int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg);

/* gb_proxy_ctrl.c */
int gb_ctrl_cmds_install(void);


/* gb_proxy.c */
int gbproxy_init_config(struct gbproxy_config *cfg);

/* Main input function for Gb proxy */
int gbprox_rcvmsg(void *ctx, struct msgb *msg);

int gbprox_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data);


int gprs_ns2_prim_cb(struct osmo_prim_hdr *oph, void *ctx);

void gbprox_reset(struct gbproxy_config *cfg);

/* Peer handling */
#define NSE_F_SGSN	0x0001
#define NSE_F_BSS	0x0002

struct gbproxy_bvc *gbproxy_bvc_by_bvci(struct gbproxy_nse *nse, uint16_t bvci);
struct gbproxy_bvc *gbproxy_bvc_alloc(struct gbproxy_nse *nse, uint16_t bvci);
void gbproxy_bvc_free(struct gbproxy_bvc *bvc);
int gbproxy_cleanup_bvcs(struct gbproxy_nse *nse, uint16_t bvci);

struct gbproxy_cell *gbproxy_cell_alloc(struct gbproxy_config *cfg, uint16_t bvci);
struct gbproxy_cell *gbproxy_cell_by_bvci(struct gbproxy_config *cfg, uint16_t bvci);
void gbproxy_cell_free(struct gbproxy_cell *cell);
bool gbproxy_cell_add_sgsn_bvc(struct gbproxy_cell *cell, struct gbproxy_bvc *bvc);

/* NSE handling */
struct gbproxy_nse *gbproxy_nse_alloc(struct gbproxy_config *cfg, uint16_t nsei, bool sgsn_facing);
void gbproxy_nse_free(struct gbproxy_nse *nse);
struct gbproxy_nse *gbproxy_nse_by_nsei(struct gbproxy_config *cfg, uint16_t nsei, uint32_t flags);
struct gbproxy_nse *gbproxy_nse_by_nsei_or_new(struct gbproxy_config *cfg, uint16_t nsei, bool sgsn_facing);

#endif
