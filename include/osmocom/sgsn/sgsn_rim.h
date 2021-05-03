#pragma once

struct sgsn_mme_ctx;

int sgsn_rim_rx_from_gb(struct osmo_bssgp_prim *bp, struct msgb *msg);
int sgsn_rim_rx_from_gtp(struct bssgp_ran_information_pdu *pdu, struct sgsn_mme_ctx *mme);
