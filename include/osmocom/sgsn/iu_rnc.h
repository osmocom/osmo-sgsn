#pragma once

#include <stdbool.h>

#include <osmocom/core/defs.h>
#include <osmocom/core/linuxlist.h>
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
	struct osmo_sccp_addr sccp_addr;

	/* A list of struct iu_lac_rac_entry */
	struct llist_head lac_rac_list;
};

struct ranap_iu_rnc *iu_rnc_register(struct osmo_rnc_id *rnc_id,
				     const struct osmo_routing_area_id *rai,
				     const struct osmo_sccp_addr *addr);
