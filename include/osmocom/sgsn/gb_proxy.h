#ifndef _GB_PROXY_H
#define _GB_PROXY_H


#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsm23003.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/vty/command.h>

#include <sys/types.h>
#include <regex.h>
#include <stdbool.h>

#define GBPROXY_INIT_VU_GEN_TX 256

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
	GBPROX_GLOB_CTR_PATCH_PEER_ERR,
};

enum gbproxy_peer_ctr {
	GBPROX_PEER_CTR_BLOCKED,
	GBPROX_PEER_CTR_UNBLOCKED,
	GBPROX_PEER_CTR_DROPPED,
	GBPROX_PEER_CTR_INV_NSEI,
	GBPROX_PEER_CTR_TX_ERR,
	GBPROX_PEER_CTR_RAID_PATCHED_BSS,
	GBPROX_PEER_CTR_RAID_PATCHED_SGSN,
	GBPROX_PEER_CTR_APN_PATCHED,
	GBPROX_PEER_CTR_TLLI_PATCHED_BSS,
	GBPROX_PEER_CTR_TLLI_PATCHED_SGSN,
	GBPROX_PEER_CTR_PTMSI_PATCHED_BSS,
	GBPROX_PEER_CTR_PTMSI_PATCHED_SGSN,
	GBPROX_PEER_CTR_PATCH_CRYPT_ERR,
	GBPROX_PEER_CTR_PATCH_ERR,
	GBPROX_PEER_CTR_ATTACH_REQS,
	GBPROX_PEER_CTR_ATTACH_REJS,
	GBPROX_PEER_CTR_ATTACH_ACKS,
	GBPROX_PEER_CTR_ATTACH_COMPLS,
	GBPROX_PEER_CTR_RA_UPD_REQS,
	GBPROX_PEER_CTR_RA_UPD_REJS,
	GBPROX_PEER_CTR_RA_UPD_ACKS,
	GBPROX_PEER_CTR_RA_UPD_COMPLS,
	GBPROX_PEER_CTR_GMM_STATUS_BSS,
	GBPROX_PEER_CTR_GMM_STATUS_SGSN,
	GBPROX_PEER_CTR_DETACH_REQS,
	GBPROX_PEER_CTR_DETACH_ACKS,
	GBPROX_PEER_CTR_PDP_ACT_REQS,
	GBPROX_PEER_CTR_PDP_ACT_REJS,
	GBPROX_PEER_CTR_PDP_ACT_ACKS,
	GBPROX_PEER_CTR_PDP_DEACT_REQS,
	GBPROX_PEER_CTR_PDP_DEACT_ACKS,
	GBPROX_PEER_CTR_TLLI_UNKNOWN,
	GBPROX_PEER_CTR_TLLI_CACHE_SIZE,
	GBPROX_PEER_CTR_LAST,
};

enum gbproxy_keep_mode {
	GBPROX_KEEP_NEVER,	/* don't ever keep TLLI/IMSI state of de-registered subscribers */
	GBPROX_KEEP_REATTACH,	/* keep if re-attach has been requested by SGSN */
	GBPROX_KEEP_IDENTIFIED,	/* keep if we had resolved an IMSI */
	GBPROX_KEEP_ALWAYS,	/* always keep */
};

enum gbproxy_match_id {
	GBPROX_MATCH_PATCHING,	/* match rule on whether or not we should patch */
	GBPROX_MATCH_ROUTING,	/* match rule on whether or not we should route (2-SGSN) */
	GBPROX_MATCH_LAST
};

struct gbproxy_match {
	bool  enable;		/* is this match enabled? */
	char *re_str;		/* regular expression (for IMSI) in string format */
	regex_t re_comp;	/* compiled regular expression (for IMSI) */
};

/* global gb-proxy configuration */
struct gbproxy_config {
	/* parsed from config file */
	uint16_t nsip_sgsn_nsei;

	/* NS instance of libosmogb */
	struct gprs_ns_inst *nsi;

	/* Linked list of all Gb peers (except SGSN) */
	struct llist_head bts_peers;

	/* Counter */
	struct rate_ctr_group *ctrg;

	/* MCC/MNC to be patched into RA-ID on the way from BSS to SGSN? */
	struct osmo_plmn_id core_plmn;

	/* APN to be patched into PDP CTX ACT REQ on the way from BSS to SGSN */
	uint8_t* core_apn;
	size_t core_apn_size;

	/* Frequency (sec) at which timer to clean stale links is fired (0 disabled) */
	unsigned int clean_stale_timer_freq;
	/* If !0, Max age to consider a struct gbproxy_link_info as stale */
	int tlli_max_age;
	/* If !0, Max len of gbproxy_peer->list (list of struct gbproxy_link_info) */
	int tlli_max_len;
	/* If !0, Max len of gbproxy_link_info->stored_msgs (list of msgb) */
	uint32_t stored_msgs_max_len;

	/* Should the P-TMSI be patched on the fly (required for 2-SGSN config) */
	bool patch_ptmsi;
	/* Should the IMSI be acquired by the proxy (required for 2-SGSN config) */
	bool acquire_imsi;
	/* Should we route subscribers to two different SGSNs? */
	bool route_to_sgsn2;
	/* NSEI of the second SGSN */
	uint16_t nsip_sgsn2_nsei;
	/* should we keep a cache of per-subscriber state even after de-registration? */
	enum gbproxy_keep_mode keep_link_infos;

	/* IMSI checking/matching for 2-SGSN routing and patching */
	struct gbproxy_match matches[GBPROX_MATCH_LAST];
};

struct gbproxy_patch_state {
	struct osmo_plmn_id local_plmn;

	/* List of TLLIs for which patching is enabled */
	struct llist_head logical_links;
	int logical_link_count;
};

/* one peer at NS level that we interact with (BSS/PCU) */
struct gbproxy_peer {
	/* linked to gbproxy_config.bts_peers */
	struct llist_head list;

	/* point back to the config */
	struct gbproxy_config *cfg;

	/* NSEI of the peer entity */
	uint16_t nsei;

	/* BVCI used for Point-to-Point to this peer */
	uint16_t bvci;
	bool blocked;

	/* Routeing Area that this peer is part of (raw 04.08 encoding) */
	uint8_t ra[6];

	/* Counter */
	struct rate_ctr_group *ctrg;

	/* State related to on-the-fly patching of certain messages */
	struct gbproxy_patch_state patch_state;

	/* Fired periodically to clean up stale links from list */
	struct osmo_timer_list clean_stale_timer;
};

struct gbproxy_tlli_state {
	/* currently active TLLI */
	uint32_t current;
	/* newly-assigned TLLI (e.g. during P-TMSI allocation procedure) */
	uint32_t assigned;
	/* has the BSS side validated (confirmed) the new TLLI? */
	bool bss_validated;
	/* has the SGSN side validated (confirmed) the new TLLI? */
	bool net_validated;
	/* NOTE: once both are validated, we set current = assigned and assigned = 0 */

	/* The P-TMSI for this subscriber */
	uint32_t ptmsi;
};

/* One TLLI (= UE, = Subscriber) served via this proxy */
struct gbproxy_link_info {
	/* link to gbproxy_peer.patch_state.logical_links */
	struct llist_head list;

	/* TLLI on the BSS/PCU side */
	struct gbproxy_tlli_state tlli;
	/* TLLI on the SGSN side (can be different in case of P-TMSI patching) */
	struct gbproxy_tlli_state sgsn_tlli;
	/* NSEI of the SGSN serving this link */
	uint32_t sgsn_nsei;

	/* timestamp when we last had any contact with this UE */
	time_t timestamp;

	/* IMSI of the subscriber (if/once known) */
	uint8_t *imsi;
	size_t imsi_len;

	/* is the IMSI acquisition still pending? */
	bool imsi_acq_pending;

	/* queue of stored UL messages (until IMSI acquisition completes and we can
	 * determine which of the SGSNs we should route this to */
	struct llist_head stored_msgs;
	uint32_t stored_msgs_len;

	/* generated N(U) we use (required due to IMSI acquisition */
	unsigned vu_gen_tx_bss;

	/* is this subscriber deregistered (TLLI invalidated)? */
	bool is_deregistered;

	/* does this link match either the (2-SGSN) routing or the patching rule? */
	bool is_matching[GBPROX_MATCH_LAST];
};


/* gb_proxy_vty .c */

int gbproxy_vty_init(void);
int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg);

/* gb_proxy_ctrl.c */
int gb_ctrl_cmds_install(void);


/* gb_proxy.c */
int gbproxy_init_config(struct gbproxy_config *cfg);

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct gbproxy_config *cfg, struct msgb *msg, uint16_t nsei, uint16_t ns_bvci, uint16_t nsvci);

int gbprox_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data);

/* Reset all persistent NS-VC's */
int gbprox_reset_persistent_nsvcs(struct gprs_ns_inst *nsi);

void gbprox_reset(struct gbproxy_config *cfg);

/* TLLI info handling */
void gbproxy_delete_link_infos(struct gbproxy_peer *peer);
struct gbproxy_link_info *gbproxy_update_link_state_ul(
	struct gbproxy_peer *peer, time_t now,
	struct gprs_gb_parse_context *parse_ctx);
struct gbproxy_link_info *gbproxy_update_link_state_dl(
	struct gbproxy_peer *peer, time_t now,
	struct gprs_gb_parse_context *parse_ctx);
int gbproxy_update_link_state_after(
	struct gbproxy_peer *peer, struct gbproxy_link_info *link_info,
	time_t now, struct gprs_gb_parse_context *parse_ctx);
int gbproxy_remove_stale_link_infos(struct gbproxy_peer *peer, time_t now);
void gbproxy_delete_link_info(struct gbproxy_peer *peer,
			 struct gbproxy_link_info *link_info);
void gbproxy_link_info_discard_messages(struct gbproxy_link_info *link_info);

void gbproxy_attach_link_info(struct gbproxy_peer *peer, time_t now,
			      struct gbproxy_link_info *link_info);
void gbproxy_update_link_info(struct gbproxy_link_info *link_info,
			      const uint8_t *imsi, size_t imsi_len);
void gbproxy_detach_link_info(struct gbproxy_peer *peer,
			      struct gbproxy_link_info *link_info);
struct gbproxy_link_info *gbproxy_link_info_alloc( struct gbproxy_peer *peer);

struct gbproxy_link_info *gbproxy_link_info_by_tlli(
	struct gbproxy_peer *peer, uint32_t tlli);
struct gbproxy_link_info *gbproxy_link_info_by_imsi(
	struct gbproxy_peer *peer, const uint8_t *imsi, size_t imsi_len);
struct gbproxy_link_info *gbproxy_link_info_by_any_sgsn_tlli(
	struct gbproxy_peer *peer, uint32_t tlli);
struct gbproxy_link_info *gbproxy_link_info_by_sgsn_tlli(
	struct gbproxy_peer *peer,
	uint32_t tlli, uint32_t sgsn_nsei);
struct gbproxy_link_info *gbproxy_link_info_by_ptmsi(
	struct gbproxy_peer *peer,
	uint32_t ptmsi);

int gbproxy_imsi_matches(
	struct gbproxy_config *cfg,
	enum gbproxy_match_id match_id,
	struct gbproxy_link_info *link_info);
uint32_t gbproxy_map_tlli(
	uint32_t other_tlli, struct gbproxy_link_info *link_info, int to_bss);

/* needed by gb_proxy_tlli.h */
uint32_t gbproxy_make_bss_ptmsi(struct gbproxy_peer *peer, uint32_t sgsn_ptmsi);
uint32_t gbproxy_make_sgsn_tlli(
	struct gbproxy_peer *peer, struct gbproxy_link_info *link_info,
	uint32_t bss_tlli);
void gbproxy_reset_link(struct gbproxy_link_info *link_info);
int gbproxy_check_imsi(
	struct gbproxy_match *match, const uint8_t *imsi, size_t imsi_len);

/* Message patching */
void gbproxy_patch_bssgp(
	struct msgb *msg, uint8_t *bssgp, size_t bssgp_len,
	struct gbproxy_peer *peer, struct gbproxy_link_info *link_info,
	int *len_change, struct gprs_gb_parse_context *parse_ctx);

int gbproxy_patch_llc(
	struct msgb *msg, uint8_t *llc, size_t llc_len,
	struct gbproxy_peer *peer, struct gbproxy_link_info *link_info,
	int *len_change, struct gprs_gb_parse_context *parse_ctx);

int gbproxy_set_patch_filter(
	struct gbproxy_match *match, const char *filter, const char **err_msg);
void gbproxy_clear_patch_filter(struct gbproxy_match *match);

/* Peer handling */
struct gbproxy_peer *gbproxy_peer_by_bvci(
	struct gbproxy_config *cfg, uint16_t bvci);
struct gbproxy_peer *gbproxy_peer_by_nsei(
	struct gbproxy_config *cfg, uint16_t nsei);
struct gbproxy_peer *gbproxy_peer_by_rai(
	struct gbproxy_config *cfg, const uint8_t *ra);
struct gbproxy_peer *gbproxy_peer_by_lai(
	struct gbproxy_config *cfg, const uint8_t *la);
struct gbproxy_peer *gbproxy_peer_by_lac(
	struct gbproxy_config *cfg, const uint8_t *la);
struct gbproxy_peer *gbproxy_peer_by_bssgp_tlv(
	struct gbproxy_config *cfg, struct tlv_parsed *tp);
struct gbproxy_peer *gbproxy_peer_alloc(struct gbproxy_config *cfg, uint16_t bvci);
void gbproxy_peer_free(struct gbproxy_peer *peer);
int gbproxy_cleanup_peers(struct gbproxy_config *cfg, uint16_t nsei, uint16_t bvci);

#endif
