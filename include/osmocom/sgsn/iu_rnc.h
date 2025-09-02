#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/defs.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/iuh/common.h>
#include <osmocom/sigtran/sccp_sap.h>

struct iu_lac_rac_entry {
	struct llist_head entry;
	struct osmo_routing_area_id rai;
};

/* A remote RNC (Radio Network Controller, like BSC but for UMTS) that has
 * called us and is currently reachable at the given osmo_sccp_addr. So, when we
 * know a LAC for a subscriber, we can page it at the RNC matching that LAC or
 * RAC. An HNB-GW typically presents itself as if it were a single RNC, even
 * though it may have several RNCs in hNodeBs connected to it. Those will then
 * share the same RNC id, which they actually receive and adopt from the HNB-GW
 * in the HNBAP HNB REGISTER ACCEPT message. */
struct ranap_iu_rnc {
	struct llist_head entry;

	struct osmo_rnc_id rnc_id;
	struct sgsn_sccp_user_iups *scu_iups;
	struct osmo_sccp_addr sccp_addr;
	struct osmo_fsm_inst *fi;

	/* A list of struct iu_lac_rac_entry */
	struct llist_head lac_rac_list;
};

struct ranap_iu_rnc *iu_rnc_find_or_create(const struct osmo_rnc_id *rnc_id,
					   struct sgsn_sccp_user_iups *scu_iups,
					   const struct osmo_sccp_addr *addr);

struct ranap_iu_rnc *iu_rnc_find_by_addr(const struct osmo_sccp_addr *rnc_sccp_addr);

void iu_rnc_update_rai_seen(struct ranap_iu_rnc *rnc, const struct osmo_routing_area_id *rai);

void iu_rnc_discard_all_ue_ctx(struct ranap_iu_rnc *rnc);

int iu_rnc_tx_paging_cmd(struct ranap_iu_rnc *rnc,
			 const char *imsi,
			 const uint32_t *tmsi,
			 bool is_ps,
			 uint32_t paging_cause);

#define LOG_RNC_CAT(IU_RNC, subsys, loglevel, fmt, args ...) \
	LOGPFSMSL((IU_RNC)->fi, subsys, loglevel, fmt, ## args)

#define LOG_RNC(IU_RNC, loglevel, fmt, args ...) \
	LOG_RNC_CAT(IU_RNC, DRANAP, loglevel, fmt, ## args)
