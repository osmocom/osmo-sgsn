#pragma once

#include <osmocom/core/msgb.h>

struct osmo_prim_hdr;
struct sgsn_mm_ctx;
struct osmo_gprs_llc_prim;

int sgsn_bssgp_init(void);

/* Called by bssgp layer when a prim is received from lower layers. */
int sgsn_bssgp_rx_prim(struct osmo_prim_hdr *oph);

/* called by the bssgp layer to send NS PDUs */
int sgsn_bssgp_dispatch_ns_unitdata_req_cb(void *ctx, struct msgb *msg);

/* called by the LLC layer */
int sgsn_bssgp_tx_dl_unitdata(struct osmo_gprs_llc_prim *llc_prim);

/* page a MS in its routing area */
int sgsn_bssgp_page_ps_ra(struct sgsn_mm_ctx *mmctx);
