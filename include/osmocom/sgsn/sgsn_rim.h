#pragma once

struct sgsn_mme_ctx;

int sgsn_rim_rx_from_gb(struct osmo_bssgp_prim *bp, struct msgb *msg);
int sgsn_rim_rx_from_gtp(struct msgb *msg, struct bssgp_rim_routing_info *ra, struct sgsn_mme_ctx *mme);
