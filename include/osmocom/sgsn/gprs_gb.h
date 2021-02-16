#pragma once

#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/sgsn/gprs_llc.h>

int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable);
/* Has to be called whenever any PDU (signaling, data, ...) has been received */
void gprs_gb_recv_pdu(struct sgsn_mm_ctx *mmctx, const struct msgb *msg);

/* page a MS in its routing area */
int gprs_gb_page_ps_ra(struct sgsn_mm_ctx *mmctx);

/* called by the bssgp layer to send NS PDUs */
int gprs_gb_send_cb(void *ctx, struct msgb *msg);

/* called by the ns layer */
int gprs_ns_prim_cb(struct osmo_prim_hdr *oph, void *ctx);
