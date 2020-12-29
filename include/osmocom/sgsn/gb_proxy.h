#ifndef _GB_PROXY_H
#define _GB_PROXY_H


#include <osmocom/core/msgb.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/hashtable.h>
#include <osmocom/gsm/gsm23003.h>
#include <osmocom/gsm/gsm23236.h>

#include <osmocom/gprs/gprs_ns2.h>
#include <osmocom/vty/command.h>

#include <sys/types.h>
#include <regex.h>
#include <stdbool.h>

#define GBPROXY_INIT_VU_GEN_TX 256
#define GBPROXY_MAX_NR_SGSN	16

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

	struct {
		/* percentage of BVC flow control advertised to each SGSN in the pool */
		uint8_t bvc_fc_ratio;
		/* NRI bitlen and usable NULL-NRI ranges */
		uint8_t nri_bitlen;
		struct osmo_nri_ranges *null_nri_ranges;

		/* Used for testing: If not NULL then this SGSN is returned by
		 * gbproxy_sgsn_by_tlli() */
		struct gbproxy_sgsn *nsf_override;
	} pool;

	/* hash table of all BSS side Gb peers */
	DECLARE_HASHTABLE(bss_nses, 8);

	/* hash table of all SGSN-side Gb peers */
	DECLARE_HASHTABLE(sgsn_nses, 8);

	/* hash table of all gbproxy_cell */
	DECLARE_HASHTABLE(cells, 8);

	/* tlli<->nse cache used to map SUSPEND/RESUME (N)ACKS */
	struct {
		DECLARE_HASHTABLE(entries, 10);
		struct osmo_timer_list timer;
		/* Time in seconds that the entries should be valid */
		uint8_t timeout;
	} tlli_cache;

	/* List of all SGSNs */
	struct llist_head sgsns;

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
	struct gbproxy_bvc *sgsn_bvc[GBPROXY_MAX_NR_SGSN];
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

/* SGSN configuration such as pool options (only for NSE where sgsn_facing == true) */
struct gbproxy_sgsn {
	/* linked to gbproxy_config.sgsns */
	struct llist_head list;

	/* The NSE belonging to this SGSN */
	struct gbproxy_nse *nse;

	/* Name of the SGSN */
	char *name;

	/* Pool configuration for the sgsn (only valid if sgsn_facing == true) */
	struct {
		bool allow_attach;
		struct osmo_nri_ranges *nri_ranges;
	} pool;
};

/* TLLI cache */
struct gbproxy_tlli_cache_entry {
	/* linked to gbproxy_config.tlli_cache */
	struct hlist_node list;

	/* TLLI of the entry */
	uint32_t tlli;
	/* When was this entry last seen */
	time_t tstamp;
	/* The Cell this TLLI was last seen */
	struct gbproxy_nse *nse;
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

#define LOGPCELL_CAT(CELL, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "CELL(%05u) " FMT, (CELL)->bvci, ## ARGS)
#define LOGPCELL(CELL, LEVEL, FMT, ARGS...) \
	LOGPCELL_CAT(CELL, DGPRS, LEVEL, FMT, ## ARGS)

#define LOGPSGSN_CAT(SGSN, SUBSYS, LEVEL, FMT, ARGS...) \
	LOGP(SUBSYS, LEVEL, "NSE(%05u)-SGSN(%s) " FMT, (SGSN)->nse->nsei, (SGSN)->name, ## ARGS)
#define LOGPSGSN(SGSN, LEVEL, FMT, ARGS...) \
	LOGPSGSN_CAT(SGSN, DGPRS, LEVEL, FMT, ## ARGS)

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
struct gbproxy_nse *gbproxy_nse_by_tlli(struct gbproxy_config *cfg, uint32_t tlli);

/* TLLI cache */
void gbproxy_tlli_cache_update(struct gbproxy_nse *nse, uint32_t tlli);
void gbproxy_tlli_cache_remove(struct gbproxy_config *cfg, uint32_t tlli);
int gbproxy_tlli_cache_cleanup(struct gbproxy_config *cfg);

/* SGSN handling */
struct gbproxy_sgsn *gbproxy_sgsn_alloc(struct gbproxy_config *cfg, uint16_t nsei, const char *name);
void gbproxy_sgsn_free(struct gbproxy_sgsn *sgsn);
struct gbproxy_sgsn *gbproxy_sgsn_by_name(struct gbproxy_config *cfg, const char *name);
struct gbproxy_sgsn *gbproxy_sgsn_by_nsei(struct gbproxy_config *cfg, uint16_t nsei);
struct gbproxy_sgsn *gbproxy_sgsn_by_nsei_or_new(struct gbproxy_config *cfg, uint16_t nsei);
struct gbproxy_sgsn *gbproxy_sgsn_by_nri(struct gbproxy_config *cfg, uint16_t nri, bool *null_nri);
struct gbproxy_sgsn *gbproxy_sgsn_by_tlli(struct gbproxy_config *cfg, struct gbproxy_sgsn *sgsn_avoid,
					  uint32_t tlli);

#endif
